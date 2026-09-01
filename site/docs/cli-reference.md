# CLI Reference

Complete command reference for AuditKit.

---

## Command Structure

```bash
auditkit [command] [flags]
```

---

## Commands

### scan

Run a compliance scan against your cloud infrastructure.

```bash
auditkit scan [flags]
```

**Examples:**
```bash
# Basic scan (defaults to AWS, SOC2)
auditkit scan

# Specify provider and framework
auditkit scan -provider aws -framework soc2
auditkit scan -provider azure -framework pci
auditkit scan -provider gcp -framework cmmc

# All frameworks
auditkit scan -framework all

# Verbose output
auditkit scan -verbose

# Show all controls (no truncation)
auditkit scan --full
```

**Flags:**
- `-provider` - Cloud provider: `aws`, `azure`, `gcp` (default: `aws`)
- `-framework` - Compliance framework: `soc2`, `pci`, `cmmc`, `cmmc-l2`, `800-53`, `hipaa`, `all` (default: `soc2`)
- `-verbose` - Show detailed output
- `--full` - Show all controls without truncation
- `-format` - Output format: `text`, `json`, `html`, `pdf` (default: `text`)
- `-output` - Output file path (e.g., `report.pdf`)
- `-profile` - AWS profile name (AWS only)
- `--scan-all` - Scan all accounts/subscriptions/projects (Pro only)
- `--max-concurrent` - Max concurrent scans (Pro only, default: 3)
- `--summary-only` - Show summary only, skip detailed results (Pro only)

---

### integrate

Import results from third-party tools (Prowler, ScubaGear).

```bash
auditkit integrate -source [tool] -file [path] [flags]
```

**Examples:**
```bash
# Import Prowler results (AWS/Azure/GCP)
auditkit integrate -source prowler -file prowler-output.json

# Generate PDF from Prowler results
auditkit integrate -source prowler -file prowler-output.json -format pdf -output prowler-report.pdf

# Import ScubaGear results (M365)
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json

# Generate PDF from ScubaGear results
auditkit integrate -source scubagear -file ScubaResults.json -format pdf -output m365-report.pdf
```

**Flags:**
- `-source` - Source tool: `prowler`, `scubagear`
- `-file` - Path to results file
- `-format` - Output format: `text`, `json`, `html`, `pdf` (default: `text`)
- `-output` - Output file path

---

### fix

Generate remediation scripts for failed controls.

```bash
auditkit fix [flags]
```

**Examples:**
```bash
# Generate fix script
auditkit fix

# Save to file
auditkit fix -output fixes.sh

# Review before running
cat fixes.sh
bash fixes.sh  # Run after review
```

**Flags:**
- `-output` - Output file path (default: stdout)
- `-provider` - Cloud provider (uses last scan if omitted)

---

### progress

Show compliance improvement over time.

```bash
auditkit progress
```

**Output:**
```
Compliance Progress Report
==========================
Framework: SOC2
Provider: AWS

Scan History:
2025-10-15: 65.0% (42/64 passed)
2025-10-18: 72.5% (46/64 passed)
2025-10-19: 78.1% (50/64 passed)

Improvement: +13.1% over 4 days
Trend: Increasing
```

---

### compare

Compare the last two scans.

```bash
auditkit compare
```

**Output:**
```
Compliance Comparison
=====================
Framework: SOC2
Provider: AWS

Previous Scan: 2025-10-18 (72.5%)
Current Scan:  2025-10-19 (78.1%)

Improvements:
+ CC6.1 - IAM Key Rotation (now passing)
+ CC6.2 - S3 Public Access (now passing)
+ CC7.1 - CloudTrail Logging (now passing)
+ CC8.1 - Encryption at Rest (now passing)

New Failures:
- None

Score Change: +5.6%
```

---

### evidence

Track the evidence an assessor will ask for. Auditors want evidence for every
control, including the ones that pass, so this covers the whole scan rather than
just failures.

```bash
auditkit evidence [flags]
```

Runs a scan, writes an HTML checklist, and records the controls in a durable
tracker at `~/.auditkit/evidence_<account>.json`. The checklist keeps ticks in
your browser; the tracker is the copy you can share, review, or hand over.

**Flags:**
- `-provider` - Cloud provider: `aws`, `azure`, `gcp` (default: `aws`)
- `-profile` - AWS profile, Azure subscription, or GCP project
- `-output` - Where to write the HTML checklist (default: `evidence-tracker.html`)

---

### evidence status

Show what evidence has been collected, what is outstanding, and what has gone
stale. Runs against the stored tracker, so it needs no cloud credentials.

```bash
auditkit evidence status [flags]
```

**Flags:**
- `-account` - Account ID, if you track more than one
- `-stale-after` - Days before collected evidence is considered stale (default: 90)
- `-all` - List every outstanding control rather than the first 20

Evidence older than the staleness window is reported as outstanding rather than
collected. Assessors sample evidence from within the period under review, so a
screenshot from last year is not evidence.

---

### evidence collect

Record that evidence has been captured for a control.

```bash
auditkit evidence collect CONTROL-ID [flags]
```

**Examples:**
```bash
auditkit evidence collect CC6.1 -notes "IAM policy export and console screenshot" -by rob
auditkit evidence collect CC7.2 -artifact ./evidence/cloudwatch-alarms.png
```

**Flags:**
- `-notes` - What was captured and where it came from
- `-artifact` - Path to the screenshot or export
- `-by` - Who collected it
- `-account` - Account ID, if you track more than one

---

### evidence import

Load the JSON exported from the HTML checklist, so ticks made in the browser
become part of the durable record.

```bash
auditkit evidence import PROGRESS.json [-by name]
```

Controls in the file that the scanner has not seen are reported and skipped.

---

### update

Check for newer version of AuditKit.

```bash
auditkit update
```

**Output:**
```
Current version: v0.7.0
Latest version:  v0.7.1
Update available!

Download: https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/tag/v0.7.1
```

---

### version

Show AuditKit version.

```bash
auditkit version
```

**Output:**
```
AuditKit v0.8.4 - Multi-cloud compliance scanning (AWS, Azure, GCP, M365)
```

---

## Global Flags

These flags work with all commands:

- `-h`, `--help` - Show help for command
- `-v`, `--version` - Show version

---

## Output Formats

### text (default)

Human-readable terminal output with colors.

```bash
auditkit scan
```

### json

Machine-readable JSON for automation.

```bash
auditkit scan -format json -output results.json
```

**JSON Structure:**
```json
{
  "timestamp": "2025-10-19T14:30:00Z",
  "provider": "aws",
  "framework": "soc2",
  "account_id": "123456789012",
  "score": 72.5,
  "total_controls": 64,
  "passed_controls": 46,
  "failed_controls": 18,
  "controls": [
    {
      "id": "CC6.6",
      "name": "User MFA Enforcement",
      "status": "FAIL",
      "severity": "CRITICAL",
      "evidence": "12 users without MFA",
      "remediation": "Enable MFA for all users"
    }
  ]
}
```

### html

Interactive HTML report with search and filtering.

```bash
auditkit scan -format html -output report.html
```

### pdf

Audit-ready PDF report for auditors and management.

```bash
auditkit scan -format pdf -output report.pdf
```

**PDF includes:**
- Executive summary
- Compliance score
- Passed/failed controls
- Evidence collection guides
- Remediation commands
- Compliance mappings

---

## Environment Variables

### AWS

```bash
AWS_ACCESS_KEY_ID          # AWS access key
AWS_SECRET_ACCESS_KEY      # AWS secret key
AWS_DEFAULT_REGION         # Default AWS region
AWS_PROFILE                # AWS CLI profile name
```

### Azure

```bash
AZURE_CLIENT_ID            # Service principal client ID
AZURE_CLIENT_SECRET        # Service principal secret
AZURE_TENANT_ID            # Azure tenant ID
AZURE_SUBSCRIPTION_ID      # Subscription to scan
```

### GCP

```bash
GOOGLE_APPLICATION_CREDENTIALS  # Path to service account JSON
GOOGLE_CLOUD_PROJECT            # GCP project ID
GCP_PROJECT                     # Alternative project ID variable
```

---

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Authentication error
- `3` - Permission denied
- `4` - Invalid arguments
- `5` - Scan failed

---

## Examples by Use Case

### Initial Assessment

```bash
# Run first scan
auditkit scan -provider aws -framework soc2 -verbose

# Generate PDF report for auditor
auditkit scan -provider aws -framework soc2 -format pdf -output initial-assessment.pdf

# Generate evidence tracker
auditkit evidence -format html -output evidence-tracker.html
```

### Fix and Verify

```bash
# Generate fix script
auditkit fix -output fixes.sh

# Review and run fixes
cat fixes.sh
bash fixes.sh

# Re-scan to verify
auditkit scan -provider aws -framework soc2

# Compare improvements
auditkit compare
```

### Multi-Cloud Scanning

```bash
# Scan all providers
auditkit scan -provider aws -framework soc2 -output aws-results.json -format json
auditkit scan -provider azure -framework soc2 -output azure-results.json -format json
auditkit scan -provider gcp -framework soc2 -output gcp-results.json -format json

# Generate individual reports
auditkit scan -provider aws -framework soc2 -format pdf -output aws-report.pdf
auditkit scan -provider azure -framework soc2 -format pdf -output azure-report.pdf
auditkit scan -provider gcp -framework soc2 -format pdf -output gcp-report.pdf
```

### CI/CD Integration

```bash
# Run scan in pipeline
auditkit scan -provider aws -framework soc2 -format json -output results.json

# Check exit code
if [ $? -eq 0 ]; then
  echo "Scan completed successfully"
else
  echo "Scan failed"
  exit 1
fi

# Parse results
jq '.score' results.json  # Get compliance score
jq '.failed_controls' results.json  # Get failed control count
```

### Progress Tracking

```bash
# Weekly scans
# Monday
auditkit scan -provider aws -framework soc2

# Friday (after fixes)
auditkit scan -provider aws -framework soc2

# Show progress
auditkit progress

# Compare before/after
auditkit compare
```

---

## Pro-Only Features

These features require [AuditKit](https://auditkit.io/):

### Multi-Account Scanning

```bash
# Scan entire AWS Organization
auditkit-pro scan -provider aws -framework soc2 --scan-all

# Scan Azure Management Group
auditkit-pro scan -provider azure -framework soc2 --scan-all

# Scan GCP Organization
auditkit-pro scan -provider gcp -framework soc2 --scan-all

# Control concurrency
auditkit-pro scan -provider aws --scan-all --max-concurrent 5
```

### CMMC Level 2

```bash
# Scan for CMMC Level 2 (110 practices)
auditkit scan -provider aws -framework cmmc-l2

# Generate Level 2 report
auditkit scan -provider aws -framework cmmc-l2 -format pdf -output cmmc-l2-report.pdf
```

### Advanced GCP

```bash
# Scan GKE clusters (Pro only)
auditkit scan -provider gcp -framework soc2  # Includes GKE checks

# Scan Vertex AI (Pro only)
auditkit scan -provider gcp -framework soc2  # Includes Vertex AI checks
```

---

## Getting Help

- **Command help:** `auditkit [command] --help`
- **Documentation:** [Full docs →](../)
- **Examples:** [Sample usage →](../examples/)
- **Issues:** [GitHub Issues](https://github.com/guardian-nexus/AuditKit-Community-Edition/issues)
