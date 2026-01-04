import { execSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { join } from "path";

// Types for npm audit output
interface NpmAuditVulnerability {
  name: string;
  severity: "critical" | "high" | "moderate" | "low" | "info";
  isDirect: boolean;
  via: (string | { name: string; url?: string; title?: string; severity?: string })[];
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

interface NpmAuditOutput {
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
    dependencies: {
      prod: number;
      dev: number;
      optional: number;
      peer: number;
      peerOptional: number;
      total: number;
    };
  };
}

interface SecurityException {
  id: string;
  reason: string;
  expires?: string;
  approvedBy?: string;
}

interface ExceptionsFile {
  exceptions: SecurityException[];
}

export interface ParsedVulnerability {
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  isDirect: boolean;
  range: string;
  fixVersion: string | null;
  isSemVerMajor: boolean;
  cve: string | null;
  title: string | null;
  url: string | null;
  dependencyPath: string[];
  isAccepted: boolean;
  acceptedReason?: string;
}

export interface AuditResult {
  success: boolean;
  hasVulnerabilities: boolean;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    fixable: number;
    accepted: number;
  };
  vulnerabilities: ParsedVulnerability[];
  acceptedVulnerabilities: ParsedVulnerability[];
  error?: string;
}

function normalizeSeverity(severity: string): "critical" | "high" | "medium" | "low" {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
    case "info":
    default:
      return "low";
  }
}

function loadExceptions(cwd: string): Map<string, SecurityException> {
  const exceptionsPath = join(cwd, "security-exceptions.json");
  const exceptions = new Map<string, SecurityException>();

  if (!existsSync(exceptionsPath)) {
    return exceptions;
  }

  try {
    const content = readFileSync(exceptionsPath, "utf-8");
    const data: ExceptionsFile = JSON.parse(content);

    if (data.exceptions && Array.isArray(data.exceptions)) {
      for (const exception of data.exceptions) {
        // Check if exception has expired
        if (exception.expires) {
          const expiryDate = new Date(exception.expires);
          if (expiryDate < new Date()) {
            continue; // Skip expired exceptions
          }
        }
        exceptions.set(exception.id, exception);
      }
    }
  } catch (error) {
    console.error("Warning: Failed to parse security-exceptions.json:", error);
  }

  return exceptions;
}

function extractVulnInfo(
  via: (string | { name: string; url?: string; title?: string; severity?: string })[]
): { cve: string | null; title: string | null; url: string | null } {
  for (const v of via) {
    if (typeof v === "object") {
      // Extract CVE from URL if available
      let cve: string | null = null;
      if (v.url) {
        const cveMatch = v.url.match(/CVE-\d{4}-\d+/i);
        if (cveMatch) {
          cve = cveMatch[0].toUpperCase();
        }
        // Also check for GHSA
        const ghsaMatch = v.url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
        if (ghsaMatch && !cve) {
          cve = ghsaMatch[0].toUpperCase();
        }
      }
      return {
        cve,
        title: v.title || null,
        url: v.url || null,
      };
    }
  }
  return { cve: null, title: null, url: null };
}

export function runAudit(cwd: string): AuditResult {
  const exceptions = loadExceptions(cwd);

  // Check if package.json exists
  const packageJsonPath = join(cwd, "package.json");
  if (!existsSync(packageJsonPath)) {
    return {
      success: false,
      hasVulnerabilities: false,
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, fixable: 0, accepted: 0 },
      vulnerabilities: [],
      acceptedVulnerabilities: [],
      error: "No package.json found in the current directory",
    };
  }

  let auditOutput: NpmAuditOutput;

  try {
    // npm audit exits with non-zero when vulnerabilities are found, so we need to handle that
    const output = execSync("npm audit --json 2>/dev/null", {
      cwd,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large projects
    });
    auditOutput = JSON.parse(output);
  } catch (error: unknown) {
    // npm audit returns non-zero exit code when vulnerabilities are found
    // but still outputs valid JSON
    if (error && typeof error === "object" && "stdout" in error) {
      const execError = error as { stdout?: string; stderr?: string };
      if (execError.stdout) {
        try {
          auditOutput = JSON.parse(execError.stdout);
        } catch {
          return {
            success: false,
            hasVulnerabilities: false,
            summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, fixable: 0, accepted: 0 },
            vulnerabilities: [],
            acceptedVulnerabilities: [],
            error: `Failed to parse npm audit output: ${execError.stderr || "Unknown error"}`,
          };
        }
      } else {
        return {
          success: false,
          hasVulnerabilities: false,
          summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, fixable: 0, accepted: 0 },
          vulnerabilities: [],
          acceptedVulnerabilities: [],
          error: `npm audit failed: ${execError.stderr || "Unknown error"}`,
        };
      }
    } else {
      return {
        success: false,
        hasVulnerabilities: false,
        summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, fixable: 0, accepted: 0 },
        vulnerabilities: [],
        acceptedVulnerabilities: [],
        error: `npm audit failed: ${String(error)}`,
      };
    }
  }

  // Handle case where no vulnerabilities exist
  if (!auditOutput.vulnerabilities || Object.keys(auditOutput.vulnerabilities).length === 0) {
    return {
      success: true,
      hasVulnerabilities: false,
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, fixable: 0, accepted: 0 },
      vulnerabilities: [],
      acceptedVulnerabilities: [],
    };
  }

  const vulnerabilities: ParsedVulnerability[] = [];
  const acceptedVulnerabilities: ParsedVulnerability[] = [];
  let fixableCount = 0;

  for (const [name, vuln] of Object.entries(auditOutput.vulnerabilities)) {
    const severity = normalizeSeverity(vuln.severity);
    const { cve, title, url } = extractVulnInfo(vuln.via);

    let fixVersion: string | null = null;
    let isSemVerMajor = false;

    if (typeof vuln.fixAvailable === "object") {
      fixVersion = vuln.fixAvailable.version;
      isSemVerMajor = vuln.fixAvailable.isSemVerMajor;
      fixableCount++;
    } else if (vuln.fixAvailable === true) {
      fixVersion = "available";
      fixableCount++;
    }

    // Build dependency path
    const dependencyPath = vuln.isDirect ? [name] : [...vuln.effects, name];

    // Check if this vulnerability is accepted
    const isAccepted = cve ? exceptions.has(cve) : false;
    const exception = cve ? exceptions.get(cve) : undefined;

    const parsed: ParsedVulnerability = {
      name,
      severity,
      isDirect: vuln.isDirect,
      range: vuln.range,
      fixVersion,
      isSemVerMajor,
      cve,
      title,
      url,
      dependencyPath,
      isAccepted,
      acceptedReason: exception?.reason,
    };

    if (isAccepted) {
      acceptedVulnerabilities.push(parsed);
    } else {
      vulnerabilities.push(parsed);
    }
  }

  // Sort by severity (critical first)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  acceptedVulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Count by severity (excluding accepted)
  const summary = {
    critical: vulnerabilities.filter((v) => v.severity === "critical").length,
    high: vulnerabilities.filter((v) => v.severity === "high").length,
    medium: vulnerabilities.filter((v) => v.severity === "medium").length,
    low: vulnerabilities.filter((v) => v.severity === "low").length,
    total: vulnerabilities.length,
    fixable: fixableCount,
    accepted: acceptedVulnerabilities.length,
  };

  return {
    success: true,
    hasVulnerabilities: vulnerabilities.length > 0,
    summary,
    vulnerabilities,
    acceptedVulnerabilities,
  };
}

export function generateMarkdownReport(result: AuditResult): string {
  if (!result.success) {
    return `## Security Audit Report

### Error
${result.error}
`;
  }

  if (!result.hasVulnerabilities && result.acceptedVulnerabilities.length === 0) {
    return `## Security Audit Report

### Summary
No vulnerabilities found. Your dependencies are secure.
`;
  }

  const lines: string[] = [];

  lines.push("## Security Audit Report");
  lines.push("");
  lines.push("### Summary");
  lines.push("| Severity | Count | Fixable | Action |");
  lines.push("|----------|-------|---------|--------|");

  const { summary } = result;

  if (summary.critical > 0) {
    const fixable = result.vulnerabilities.filter(
      (v) => v.severity === "critical" && v.fixVersion
    ).length;
    lines.push(`| Critical | ${summary.critical} | ${fixable} | Fix immediately |`);
  }
  if (summary.high > 0) {
    const fixable = result.vulnerabilities.filter(
      (v) => v.severity === "high" && v.fixVersion
    ).length;
    lines.push(`| High | ${summary.high} | ${fixable} | Fix immediately |`);
  }
  if (summary.medium > 0) {
    const fixable = result.vulnerabilities.filter(
      (v) => v.severity === "medium" && v.fixVersion
    ).length;
    lines.push(`| Medium | ${summary.medium} | ${fixable} | Fix soon |`);
  }
  if (summary.low > 0) {
    const fixable = result.vulnerabilities.filter(
      (v) => v.severity === "low" && v.fixVersion
    ).length;
    lines.push(`| Low | ${summary.low} | ${fixable} | Track |`);
  }

  if (summary.accepted > 0) {
    lines.push(`| Accepted | ${summary.accepted} | - | Tracked |`);
  }

  lines.push("");
  lines.push(`**Total**: ${summary.total} vulnerabilities (${summary.fixable} auto-fixable)`);
  lines.push("");

  // Critical and High severity details
  const highPriority = result.vulnerabilities.filter(
    (v) => v.severity === "critical" || v.severity === "high"
  );

  if (highPriority.length > 0) {
    lines.push("### High Priority Issues");
    lines.push("");

    for (const vuln of highPriority) {
      const id = vuln.cve || vuln.name;
      const title = vuln.title || `Vulnerability in ${vuln.name}`;
      lines.push(`#### ${id}: ${title}`);
      lines.push(`- **Package**: \`${vuln.name}\` ${vuln.range}`);
      lines.push(`- **Severity**: ${vuln.severity.toUpperCase()}`);
      lines.push(`- **Direct Dependency**: ${vuln.isDirect ? "Yes" : "No"}`);

      if (vuln.fixVersion) {
        lines.push(`- **Fix**: Update to \`${vuln.fixVersion}\``);
        if (vuln.isSemVerMajor) {
          lines.push(`- **Warning**: This is a major version update`);
        }
        lines.push(`- **Command**: \`npm update ${vuln.name}\``);
      } else {
        lines.push(`- **Fix**: No fix available yet`);
      }

      if (!vuln.isDirect && vuln.dependencyPath.length > 1) {
        lines.push(`- **Path**: ${vuln.dependencyPath.join(" > ")}`);
      }

      if (vuln.url) {
        lines.push(`- **Advisory**: ${vuln.url}`);
      }

      lines.push("");
    }
  }

  // Transitive dependencies section
  const transitive = result.vulnerabilities.filter((v) => !v.isDirect);
  if (transitive.length > 0) {
    lines.push("### Transitive Dependencies");
    lines.push("");
    lines.push("| Vulnerable Package | Via | Severity |");
    lines.push("|-------------------|-----|----------|");

    for (const vuln of transitive) {
      const via = vuln.dependencyPath.length > 1 ? vuln.dependencyPath[0] : "direct";
      lines.push(`| ${vuln.name} | ${via} | ${vuln.severity} |`);
    }

    lines.push("");
  }

  // Remediation plan
  const fixable = result.vulnerabilities.filter((v) => v.fixVersion);
  const unfixable = result.vulnerabilities.filter((v) => !v.fixVersion);

  if (fixable.length > 0 || unfixable.length > 0) {
    lines.push("### Remediation Plan");
    lines.push("");

    if (fixable.length > 0) {
      lines.push("```bash");
      lines.push("# Run these commands to fix auto-fixable issues:");
      lines.push("");

      // Group by fix command
      const directFixes = fixable.filter((v) => v.isDirect);
      const transitiveFixes = fixable.filter((v) => !v.isDirect);

      if (directFixes.length > 0) {
        lines.push("# Direct dependency updates:");
        for (const vuln of directFixes) {
          lines.push(`npm update ${vuln.name}`);
        }
        lines.push("");
      }

      if (transitiveFixes.length > 0) {
        lines.push("# Or run npm audit fix for all auto-fixable:");
        lines.push("npm audit fix");
        lines.push("");

        const majorUpdates = transitiveFixes.filter((v) => v.isSemVerMajor);
        if (majorUpdates.length > 0) {
          lines.push("# For breaking changes (review carefully!):");
          lines.push("npm audit fix --force");
        }
      }

      lines.push("```");
      lines.push("");
    }

    if (unfixable.length > 0) {
      lines.push("**Manual Intervention Required:**");
      lines.push("");
      for (const vuln of unfixable) {
        lines.push(`- \`${vuln.name}\`: No fix available - consider alternative packages`);
      }
      lines.push("");
    }
  }

  // Accepted risks section
  if (result.acceptedVulnerabilities.length > 0) {
    lines.push("### Accepted Risks");
    lines.push("");
    lines.push("The following vulnerabilities have been explicitly accepted:");
    lines.push("");
    lines.push("| Package | CVE | Severity | Reason |");
    lines.push("|---------|-----|----------|--------|");

    for (const vuln of result.acceptedVulnerabilities) {
      const reason = vuln.acceptedReason || "No reason provided";
      lines.push(`| ${vuln.name} | ${vuln.cve || "N/A"} | ${vuln.severity} | ${reason} |`);
    }

    lines.push("");
  }

  return lines.join("\n");
}

export function generateJsonReport(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}

export function shouldFail(result: AuditResult, failOn: string): boolean {
  if (!result.success || !result.hasVulnerabilities) {
    return false;
  }

  const { summary } = result;

  switch (failOn) {
    case "critical":
      return summary.critical > 0;
    case "high":
      return summary.critical > 0 || summary.high > 0;
    case "medium":
      return summary.critical > 0 || summary.high > 0 || summary.medium > 0;
    case "low":
      return summary.total > 0;
    default:
      return false;
  }
}
