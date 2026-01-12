# Changelog

All notable changes to AuditKit will be documented in this file.

## [v0.8.0] - 2026-01-11

### Added
- **AWS Data Analytics & ML Services**
  - SageMaker: 6 security checks (notebook encryption, direct internet access, root access, endpoint encryption, training job encryption, model network isolation)
  - Redshift: 7 security checks (cluster encryption, audit logging, public access, SSL enforcement, backup retention, automatic upgrades, enhanced VPC routing)
  - ElastiCache: 5 security checks (encryption at rest, encryption in transit, automatic minor version upgrade, auth token, backup retention)
  - OpenSearch: 6 security checks (encryption at rest, node-to-node encryption, HTTPS enforcement, VPC deployment, audit logs, fine-grained access control)
  - CIS AWS Benchmark mappings added (sections 19-22)
- **Offline Mode** - Scan without cloud connectivity
  - `--offline` flag to use cached scan results
  - `--cache-file` to specify cache file path
  - Automatic caching of scan results to ~/.auditkit/cache/
  - `auditkit cache` command to manage cached scans
  - Essential for air-gapped and classified environments
- **GDPR Framework** - General Data Protection Regulation mapping
  - 27 GDPR articles mapped via NIST 800-53 crosswalk
  - Data protection, privacy rights, and security controls
  - Use `-framework gdpr`
- **NIST CSF** - NIST Cybersecurity Framework mapping
  - All 5 functions (Identify, Protect, Detect, Respond, Recover)
  - 23 categories mapped to existing controls
  - Use `-framework nist-csf`

### Improved
- AWS service coverage increased from 64 to 90+ automated checks
- All framework remediation guidance updated to January 2026 standards
- CIS AWS Benchmark mappings updated to v3.0
- PCI-DSS v4.0 remediation updated to reflect 2026 requirements
- HIPAA guidance updated for 2026 enforcement requirements

### Technical
- Added elasticache, opensearch, redshift, sagemaker AWS SDK integrations
- New offline/cache.go package for scan result caching
- Updated types.go with framework mappings for all new services
- Fixed pointer handling for AWS SDK v2 *bool fields

## [v0.7.1] - 2025-12-14

### Fixed
- **GCP PCI-DSS** - Connected comprehensive PCI-DSS v4.0 implementation covering all 12 requirements (was using filtered basic checks)
- **Azure PCI-DSS** - Connected comprehensive AzurePCIChecks implementation (was using filtered basic checks)
- **AWS Credential Report** - Fixed CSV parsing for IAM credential reports in unused credentials check (was returning empty results)
- **Azure VM Public IP** - Added NetworkInterfaces and PublicIPAddresses client integration for accurate public IP detection

These fixes improve compliance check accuracy across all three major cloud providers.

## [v0.7.0] - 2025-11-04

### Added
- **NIST 800-53 Rev 5 Support** - Federal contractor requirements / FedRAMP foundation
  - ~150 automated technical controls across AWS, Azure, GCP
  - Covers FedRAMP Low/Moderate/High baseline requirements
  - Use `-framework 800-53`
  - Note: Dedicated FedRAMP baseline filtering (fedramp-low/moderate/high) coming in v0.8.0
- **ISO 27001:2022 Support** - International information security standard
  - 93 controls mapped via 800-53 crosswalk
  - Focus on Annex A technical controls (A.8)
  - Includes organizational (A.5), people (A.6), and physical (A.7) controls
  - Use `-framework iso27001`
- **CIS Benchmarks Support** - Security hardening best practices
  - AWS: 126+ automated controls (combines CIS v1.4 and v3.0)
  - Azure: ~40+ automated controls (CIS Microsoft Azure Foundations v3.0)
  - GCP: 61 automated controls (CIS Google Cloud Platform Foundations)
  - Proactive security hardening complements compliance frameworks
  - Use `-framework cis-aws`, `-framework cis-azure`, `-framework cis-gcp`
- **Enhanced CIS AWS Controls** (2025-11-04)
  - NEW: CIS-1.3 - Credentials unused for 45+ days (automated)
  - NEW: CIS-1.16 - IAM policies on groups/roles only (automated)
  - NEW: CIS-5.8 - VPC peering routing least access (manual)
  - NEW: CIS-5.20 - VPC endpoints for S3 (manual)
  - UPDATED: Added CIS labels to existing controls (CIS-1.5, CIS-1.14, CIS-3.1, CIS-3.9, CIS-1.11)
  - Improved AWS CIS coverage from 121 to 129 unique controls
  - Section 1 (IAM): 82% coverage (18/22 controls)
  - Section 3 (Logging): 100% coverage (11/11 controls)
  - Section 5 (Networking): 100% coverage (20/20 controls)
- **CSV Export** - Spreadsheet-friendly report format
  - Export compliance results to CSV for Excel/Google Sheets
  - Includes: Control ID, Name, Status, Severity, Evidence, Remediation, URLs
  - Proper CSV escaping for commas and quotes
  - Use `-format csv -output report.csv`
- **GCP Provider Support** - Complete Google Cloud Platform scanning
  - Cloud Storage (GCS) security checks (public access, encryption, versioning, logging)
  - IAM security checks (service account keys, MFA, primitive roles)
  - VPC Network security (firewall rules, default network, private access)
  - Compute Engine security (disk encryption, public IPs, patch management)
  - Cloud SQL security (public IP, backups, SSL enforcement)
  - Cloud KMS security (key rotation)
  - Cloud Logging security (audit logs, log retention)
- Framework support for GCP: SOC2, PCI-DSS, CMMC Level 1, NIST 800-53, ISO 27001
- 170+ automated security checks for GCP (FREE version)
- Screenshot guides and remediation commands using `gcloud` CLI
- **Provider-Specific Binaries** - Choose between single-cloud or multi-cloud scanners
  - `auditkit` (280MB) - Universal scanner supporting all cloud providers
  - `auditkit-aws` (20MB) - AWS-only scanner (93% smaller, faster deployment)
  - `auditkit-azure` (26MB) - Azure-only scanner (91% smaller)
  - `auditkit-gcp` (44MB) - GCP-only scanner (84% smaller)
  - Use provider-specific binaries for faster CI/CD pipelines and reduced resource usage

### Fixed Framework Gaps (2025-10-23)
- **PCI-DSS Completion** - Filled in missing requirements across all clouds
  - Added Requirement 2: Default Passwords & Configurations (2 controls per cloud)
  - Added Requirement 5: Malware Protection (3 controls per cloud)
  - Added Requirement 6: Secure Systems & Patching (3 controls per cloud)
  - Added Requirement 9: Physical Access Controls (3-4 controls per cloud)
  - Added Requirement 11: Security Testing & Scanning (4 controls per cloud)
  - Added Requirement 12: Information Security Policy (7 controls per cloud)
  - All new controls added as INFO/MANUAL with detailed remediation guidance
  - All 12 PCI-DSS requirements now fully documented across AWS, GCP, Azure
- **HIPAA Framework Mappings** - Completed control-to-framework mappings
  - AWS: Expanded from partial to 70 HIPAA framework mappings
  - GCP: Added all 40 HIPAA framework mappings (was 0)
  - Azure: Expanded from partial to 62 HIPAA framework mappings
  - Updated status from Experimental to Production for Technical Safeguards
  - Note: Administrative and Physical Safeguards remain manual/organizational controls
- **CMMC Level 1 Verification** - Confirmed complete coverage
  - Verified all 17 official CMMC Level 1 controls present across all clouds
  - Removed 3 mislabeled Level 2 controls (SC.L1-3.13.11, SC.L1-3.13.16, SI.L1-3.14.4)
  - Added missing PS (Personnel Security) controls where gaps existed

### Technical
- Added complete GCP SDK integration
- Framework wrapper files matching AWS/Azure structure
- Unified multi-cloud reporting (AWS + Azure + GCP)
- Enhanced PCI-DSS coverage with organizational controls
- Improved HIPAA framework crosswalk mappings

### Documentation
- **Restructured documentation** - Moved detailed content from README to dedicated docs
  - New framework-specific guides: `docs/frameworks/cis-benchmarks.md`, `docs/frameworks/iso27001.md`, `docs/frameworks/fedramp.md`
  - Provider setup guides in `docs/setup/` and `docs/providers/`
  - CI/CD integration examples in `docs/examples/cicd.md`
  - Cleaner README with links to detailed documentation
  - Easier navigation and discovery of features
- GCP usage examples and authentication methods
- GCP required permissions
- Updated framework coverage tables to reflect accurate control counts

## [v0.6.8] - 2025-10-13

### Added
- **NIST 800-53 Rev 5 support** via framework crosswalk
  - Maps SOC2, PCI-DSS, and CMMC controls to NIST 800-53 control families
  - ~150 automated checks across 19 control families
  - Works with both AWS and Azure providers
  - Shows source control in output (e.g., "via CC6.6")
- New `pkg/mappings/crosswalk.go` - Framework crosswalk engine
- New `pkg/mappings/framework-crosswalk.yaml` - SOC2/PCI/CMMC to 800-53 mappings
- 800-53 specific PDF report sections (checklist, evidence guide)
- 800-53 framework validation in main.go

### Changed
- Control filtering logic now supports crosswalk-based framework mapping
- PDF generator updated to handle 800-53 control IDs
- Long control IDs (>60 chars) now truncated to prevent page overflow
- Unicode characters in control names cleaned for PDF compatibility

### Technical
- Added `Get800_53ByControlID()` - Direct control ID lookup
- Added `Get800_53StringByControlID()` - Fallback for controls without framework maps
- Updated `ControlHas800_53()` - Tries framework map first, then control ID
- Enhanced `cleanString()` function for better unicode handling

### Documentation
- Updated README with NIST 800-53 section
- Added 800-53 examples and usage patterns

## [v0.6.7] - 2025-10-12

### Fixed
- PDF generation errors with special characters
- Control ID display in evidence collection guides
- Framework label detection for CMMC levels

## [v0.6.6] - 2025-10-12

### Fixed
- PCI-DSS nil pointer crash when AWS API calls fail
- Duplicate `min` function compilation error
- Stripped debug paths from release binaries

### Added
- Sample reports and examples in `docs/examples/`
- Real-world use case documentation

### Changed
- Binary size reduced ~30% via debug symbol stripping
- Enhanced build process with path leak detection

## [v0.6.5] - 2025-10-11

### Fixed
- **CRITICAL:** Fixed PCI-DSS scanner crash when AWS credentials lack EC2:DescribeSecurityGroups permission
- Improved error handling in network segmentation checks (Req 1.2.1, 2.2.2)
- Removed hardcoded development paths from source files

## [v0.6.4] - 2025-10-10

### Enhanced Compliance Reporting

**Report Improvements:**
- Added comprehensive compliance disclaimers to PDF and HTML reports
- Enhanced clarity on automated vs manual control requirements
- Improved CMMC Level 1 reporting with FCI-specific guidance
- Fixed HTML percentage display formatting in score circles
- Added framework-specific assessor requirements (C3PAO, QSA, etc.)

**Technical Updates:**
- Updated Azure scanner parameter ordering for CMMC Level 1 checks
- Improved report structure to distinguish automated checks from manual documentation
- Enhanced evidence collection guidance in all report formats

**User Experience:**
- Reports now clearly show:
  - Automated technical checks (infrastructure/configurations)
  - Manual documentation requirements (policies/procedures)
  - Formal assessment requirements by qualified auditors
- Better guidance on what constitutes full compliance vs automated check scores

### Why This Matters

High automated check scores do not equal full compliance. This update helps users:
- Understand the scope of automated scanning
- Identify manual documentation gaps
- Prepare properly for formal assessments
- Avoid misinterpreting technical scores as compliance certifications

## [v0.6.3] - 2025-10-09

### Fixed
- PDF Unicode rendering issues (bullets, checkmarks now display correctly)
- Spacing in passed controls section ([PASS] now has proper spacing)

### Added
- Professional PDF cover page with circular compliance score
- Executive summary section in plain English
- Full HTML report generator with modern, responsive design
- Interactive tabs in HTML reports (Failed/Passed controls)
- Clickable Console URLs in HTML reports
- Copy-paste ready remediation commands in code blocks

### Changed
- Improved evidence collection guide formatting
- Enhanced visual hierarchy in both PDF and HTML outputs

### Technical
- Created new `/pkg/report/html.go` with 644 lines of clean HTML generation
- Refactored PDF generation functions to avoid naming conflicts
- Updated `main.go` HTML output to use new generator

## [v0.6.2] - 2025-10-09

### Fixed
- Fixed CMMC showing 0/17 controls (now properly returns results)
- Fixed SOC2 showing 0/0 controls (framework filtering bug)
- Fixed PCI showing 0/0 controls (framework filtering bug)
- Fixed import path issues

**This is a hotfix for v0.6.1**

## [v0.6.1] - 2025-10-07

### Added
- **M365 Integration**: New `integrate` command for importing ScubaGear M365 security results
- **Community Contribution**: Comprehensive Entra ID mappings (29 rules) contributed by community member
- Unified compliance reporting across AWS, Azure, and M365
- Step-by-step remediation guidance for M365 controls
- Screenshot evidence collection instructions for Entra ID policies
- Direct Azure portal console URLs for each control
- Framework mappings: M365 findings now map to SOC2, PCI-DSS, HIPAA

### Changed
- Updated version to v0.6.1
- Improved error messages for integration failures
- Enhanced verbose mode for debugging integration parsing

### Removed
- Telemetry tracking completely removed (no analytics or usage tracking)

### Technical
- New integration framework at `pkg/integrations/`
- ScubaGear parser implementation
- Community-contributed mappings at `mappings/scubagear/entra.json`

### Credits
Special thanks to our community contributor for the comprehensive Entra ID security mappings that make AuditKit the first open-source tool providing unified AWS, Azure, and M365 compliance reporting.


## [v0.6.0] - 2025-09-27
Added

CMMC Level 1 Support: Complete implementation of all 17 CMMC Level 1 practices for both AWS and Azure
DoD Contractor Compliance: Support for Federal Contract Information (FCI) protection requirements
November 10, 2025 Deadline Tracking: Built-in countdown and deadline warnings for CMMC compliance
CMMC Evidence Collection: Screenshot guides and console URLs for all 17 Level 1 practices
Framework-Specific Help: Enhanced verbose output with control counts and deadline information
Upgrade Messaging: Clear path to CMMC Level 2 Pro for organizations handling CUI

Enhanced

Multi-Framework Support: CMMC now joins SOC2 and PCI-DSS as fully supported compliance frameworks
Deadline Awareness: Time-sensitive compliance requirements now show days remaining
Evidence Collection: Consistent screenshot guide format across all frameworks
Framework Validation: Improved error handling and help text for supported frameworks

Technical

Added cmmc_level1.go for AWS provider with all 17 practices
Added cmmc_level1.go for Azure provider with all 17 practices
Enhanced main.go with CMMC-specific verbose output and deadline calculations
Improved framework filtering logic to handle CMMC controls
Added CMMC control name mappings and categorization

Business

Open Source Strategy: CMMC Level 1 freely available to build credibility with DoD contractors
Clear Monetization Path: Level 2 Pro offering for organizations requiring CUI protection (110 practices)
Market Timing: Release aligns with growing urgency around November 2025 deadline

## [0.5.0] - 2025-10-22

### Added
- **Azure Support** - Complete Azure provider implementation
  - Full SOC2 Common Criteria coverage (all 64 controls across CC1-CC9)
  - Full PCI-DSS v4.0 implementation (30 technical controls)
  - Storage Account security (public access, encryption, secure transfer)
  - Azure AD/Entra ID validation (MFA, privileged roles, guest access)
  - Network Security Group analysis (open ports, dangerous rules)
  - VM and Disk encryption checks
  - Key Vault security (purge protection, soft delete)
  - Activity Log retention validation (12-month for PCI-DSS)
  - Azure SQL security assessment (TDE, auditing)
  - Dedicated SOC2 modules (soc2_cc1_cc2.go, soc2_cc3_cc5.go, soc2_cc6_cc9.go)

### Changed
- **Improved Error Messages** - Better guidance when credentials not configured
- **Framework Consistency** - Aligned control mappings between AWS and Azure
- **Updated Dependencies** - Added Azure SDK for Go

### Fixed
- Azure SDK compatibility issues (method names, field access)
- Compilation errors in Azure check files
- Missing package declarations in some files
- Types.go emoji field removed completely

### Technical
- Added `/pkg/azure/` provider structure
- Implemented 10+ Azure check files (storage, aad, network, compute, etc.)
- Updated main.go to support multi-cloud providers
- Added Azure authentication support (CLI, Service Principal, Managed Identity)

## [0.4.1] - 2025-09-21
### Added
- Complete SOC2 Common Criteria implementation (64 controls across CC1-CC9)
- AWS connectivity check before scanning (prevents false results)
- Defensive nil checks for all AWS API responses

### Fixed
- Critical: Nil pointer dereferences in SOC2 checks when AWS APIs fail
- AWS SDK v2 type mismatches (pointer vs value types)
- Scanner reporting fake pass/fail results when not connected to AWS
- Memory access violations in CC6.2, CC6.5, and CC3-CC5 checks

### Changed
- Help text clarifies Azure/GCP "coming soon" status
- Help text marks PCI/HIPAA as "EXPERIMENTAL - limited controls"
- Improved error messages when AWS credentials not configured

### Technical
- Fixed soc2_cc1_cc2.go, soc2_cc3_cc5.go, soc2_cc6_cc9.go
- Updated scanner.go to check AWS connectivity first
- Removed duplicate/conflicting SSM client initialization

## [0.4.0] - 2025-09-20
### Added
- Multi-framework support (SOC2, PCI-DSS, HIPAA)
- Framework-specific priority mapping
- Cross-framework control comparison
- Framework-aware evidence collection
- 64 complete SOC2 controls

## [0.3.0] - 2024-09-20
### Added
- Evidence collection tracker (`auditkit evidence`)
- Progress tracking over time (`auditkit progress`)
- Auto-generate remediation scripts (`auditkit fix`)
- Compare scans (`auditkit compare`)
- 25+ SOC2 controls (up from ~10)
- Enhanced PDF reports with screenshot guides
- Success celebration at 90%+ compliance
