# Security Auditor

A Claude Code skill for running structured security audits with actionable remediation plans.

## Installation

### As a Claude Code Skill

```bash
# Clone to your Claude skills directory
git clone https://github.com/wrsmith108/claude-skill-security-auditor.git ~/.claude/skills/security-auditor
```

### Standalone Usage

```bash
npx tsx scripts/index.ts [options]
```

## Trigger Phrases

This skill activates when you mention:
- "npm audit"
- "security vulnerability"
- "dependency vulnerability"
- "CVE"
- "security check"
- "audit dependencies"
- "check vulnerabilities"

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

### Audit a Specific Project

```bash
npx tsx scripts/index.ts --cwd /path/to/project
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

Accepted vulnerabilities are tracked separately in the report.

## Output Format

The skill generates a markdown report with:
- Summary table by severity
- Detailed breakdown of high+ severity issues
- Transitive dependency analysis
- Copy-paste remediation commands
- List of accepted risks (if any)

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities above threshold |
| `1` | Vulnerabilities found above threshold (with `--fail-on`) |
| `2` | Error running audit |

## CI Integration

```yaml
- name: Security Audit
  run: npx tsx scripts/index.ts --fail-on high
```

## Requirements

- Node.js and npm installed
- Valid `package.json` in target directory
- Optional: `package-lock.json` for accurate audit

## License

MIT

## Related Skills

- [ci-doctor](https://github.com/wrsmith108/claude-skill-ci-doctor) - Diagnose CI/CD pipeline issues
- [version-sync](https://github.com/wrsmith108/claude-skill-version-sync) - Sync Node.js versions
- [flaky-test-detector](https://github.com/wrsmith108/claude-skill-flaky-test-detector) - Detect flaky tests
- [docker-optimizer](https://github.com/wrsmith108/claude-skill-docker-optimizer) - Optimize Dockerfiles
