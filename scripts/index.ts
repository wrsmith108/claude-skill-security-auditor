#!/usr/bin/env npx tsx

import { runAudit, generateMarkdownReport, generateJsonReport, shouldFail } from "./audit.js";

function parseArgs(args: string[]): {
  json: boolean;
  failOn: string | null;
  help: boolean;
  cwd: string;
} {
  const result = {
    json: false,
    failOn: null as string | null,
    help: false,
    cwd: process.cwd(),
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === "--json") {
      result.json = true;
    } else if (arg === "--fail-on") {
      const next = args[i + 1];
      if (next && ["critical", "high", "medium", "low"].includes(next)) {
        result.failOn = next;
        i++;
      } else {
        console.error("Error: --fail-on requires one of: critical, high, medium, low");
        process.exit(2);
      }
    } else if (arg === "--help" || arg === "-h") {
      result.help = true;
    } else if (arg === "--cwd") {
      const next = args[i + 1];
      if (next) {
        result.cwd = next;
        i++;
      }
    }
  }

  return result;
}

function printHelp(): void {
  console.log(`
Security Auditor - Run structured security audits with actionable remediation plans

Usage:
  npx tsx scripts/index.ts [options]

Options:
  --json              Output in JSON format
  --fail-on <level>   Exit with code 1 if vulnerabilities at or above level found
                      Levels: critical, high, medium, low
  --cwd <path>        Run audit in specified directory (default: current directory)
  --help, -h          Show this help message

Examples:
  # Basic audit with markdown report
  npx tsx scripts/index.ts

  # JSON output for CI integration
  npx tsx scripts/index.ts --json

  # Fail CI on high or critical vulnerabilities
  npx tsx scripts/index.ts --fail-on high

  # Audit a specific project
  npx tsx scripts/index.ts --cwd /path/to/project

Exit Codes:
  0 - Success (no vulnerabilities above threshold)
  1 - Vulnerabilities found above threshold
  2 - Error running audit
`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  console.error("Running security audit...\n");

  const result = runAudit(args.cwd);

  if (!result.success) {
    if (args.json) {
      console.log(generateJsonReport(result));
    } else {
      console.log(generateMarkdownReport(result));
    }
    process.exit(2);
  }

  if (args.json) {
    console.log(generateJsonReport(result));
  } else {
    console.log(generateMarkdownReport(result));
  }

  // Check if we should fail based on threshold
  if (args.failOn && shouldFail(result, args.failOn)) {
    console.error(`\nFailing: Found vulnerabilities at or above '${args.failOn}' severity.`);
    process.exit(1);
  }

  if (result.hasVulnerabilities) {
    console.error(`\nAudit complete: ${result.summary.total} vulnerabilities found.`);
  } else {
    console.error("\nAudit complete: No vulnerabilities found.");
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(2);
});
