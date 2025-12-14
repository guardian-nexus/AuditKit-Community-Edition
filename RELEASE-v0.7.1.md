# AuditKit v0.7.1 Release Notes

**Release Date:** December 14, 2025

---

## Compliance Check Accuracy Fixes

This release focuses on fixing compliance check accuracy issues across all three major cloud providers.

### GCP PCI-DSS

Connected the comprehensive PCI-DSS v4.0 implementation covering all 12 requirements. The implementation existed but was not being used by the scanner.

- Requirement 1: Network Segmentation (firewall rules)
- Requirement 2: Default Passwords (manual checks with guidance)
- Requirement 3: Storage Encryption (CMEK verification, key rotation)
- Requirement 4: Encryption in Transit (SQL SSL enforcement)
- Requirement 5: Malware Protection (guidance for endpoint protection)
- Requirement 6: Secure Systems (patching, SDLC, WAF)
- Requirement 7: Access Control (least privilege, IAM)
- Requirement 8: Authentication (MFA, session timeout, key rotation)
- Requirement 9: Physical Access (inherited controls documentation)
- Requirement 10: Logging (audit logs, 12-month retention)
- Requirement 11: Security Testing (ASV scans, pen testing, FIM)
- Requirement 12: Security Policy (policies, risk assessment, training)

### Azure PCI-DSS

Connected the comprehensive AzurePCIChecks implementation. Previously, Azure PCI scans were using filtered basic checks instead of the dedicated PCI implementation.

### AWS Credential Report

Fixed CSV parsing for IAM credential reports. The unused credentials check was returning empty results due to parsing errors when processing the credential report CSV.

### Azure VM Public IP Detection

Added proper NetworkInterfaces and PublicIPAddresses client integration for accurate detection of VMs with public IP exposure. Previous implementation was incomplete and could miss exposed VMs.

---

## Upgrade Instructions

Download the new binary for your platform and replace your existing `auditkit` binary.

```bash
# Verify version
./auditkit --version
# Should show: AuditKit v0.7.1
```

---

## Checksums

See `auditkit-v0.7.1-checksums.txt` in the release assets.
