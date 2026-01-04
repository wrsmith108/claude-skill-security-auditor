# Security Auditor Skill

Run structured security audits with actionable remediation plans.

## Trigger Phrases
- "npm audit"
- "security vulnerability"
- "dependency vulnerability"
- "CVE"
- "security check"
- "audit dependencies"
- "check vulnerabilities"

## Description
This skill performs comprehensive security audits on npm projects, parsing vulnerability data and generating actionable remediation plans with prioritized fixes.

## Capabilities
- Execute `npm audit --json` and parse structured output
- Classify vulnerabilities by severity (critical, high, medium, low)
- Extract CVE identifiers, affected versions, and fix versions
- Distinguish direct vs transitive dependencies
- Generate markdown reports with remediation commands
- Support risk acceptance via `security-exceptions.json`
- Provide CI-friendly exit codes

## Usage

### Basic Audit
```bash
npx tsx scripts/index.ts
```

### JSON Output
```bash
npx tsx scripts/index.ts --json
```

### Fail on High+ Severity (for CI)
```bash
npx tsx scripts/index.ts --fail-on high
```

### Fail on Critical Only
```bash
npx tsx scripts/index.ts --fail-on critical
```

## Risk Acceptance

Create a `security-exceptions.json` file in your project root to accept known risks:

```json
{
  "exceptions": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "reason": "Not exploitable in our usage context",
      "expires": "2025-06-01",
      "approvedBy": "security-team"
    }
  ]
}
```

## Exit Codes
- `0` - No vulnerabilities above threshold
- `1` - Vulnerabilities found above threshold (with `--fail-on`)
- `2` - Error running audit

## Requirements
- Node.js and npm installed
- Valid `package.json` in target directory
- Optional: `package-lock.json` for accurate audit
