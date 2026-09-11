package mappings

// CMMC practice reporting.
//
// CMMC Level 2 is the 110 requirements of NIST SP 800-171 Rev 2. A report that
// lists only the practices a scanner happens to automate is the wrong
// denominator: the reader cannot tell an absent practice from a satisfied one,
// and most of the 110 are organisational - training records, screening,
// physical access logs - which no cloud API can answer.
//
// So every practice is named here with the evidence an assessor asks for, and
// the provider suites report the ones they do not themselves measure. The
// wording is deliberately provider-neutral: these are the requirements, not the
// portal path to them, and the same table therefore serves AWS, Azure and GCP.
//
// The names are the NIST SP 800-171 Rev 2 requirement titles. Several of the
// names carried by the automated checks were wrong - RA.L2-3.11.1 was called
// "Contingency Plan" when 3.11.1 is the periodic risk assessment, and the CA
// family carried the RA family's titles - which is worth knowing before
// treating a check's own Name as authoritative.
type CMMCPractice struct {
	ID       string
	Name     string
	Evidence string // what an assessor asks to see
	Remedy   string
}

// CMMCPracticeCount is the size of NIST SP 800-171 Rev 2, and so of CMMC
// Level 2. Asserted against the catalog by the tests rather than trusted.
const CMMCPracticeCount = 110

// CMMCPractices returns every practice, in requirement order.
func CMMCPractices() []CMMCPractice {
	out := make([]CMMCPractice, len(cmmcPractices))
	copy(out, cmmcPractices)
	return out
}

// CMMCPracticesExcept returns the practices not in the given set, which is how
// a provider suite reports what its own checks did not measure. Computed from
// the results actually produced rather than from a hand-kept exclusion list,
// so adding an automated check cannot leave a practice reported twice.
func CMMCPracticesExcept(covered map[string]bool) []CMMCPractice {
	var out []CMMCPractice
	for _, p := range cmmcPractices {
		if !covered[p.ID] {
			out = append(out, p)
		}
	}
	return out
}

var cmmcPractices = []CMMCPractice{
	{
		ID:       "AC.L1-3.1.1",
		Name:     "Limit System Access to Authorized Users",
		Evidence: "the account inventory and the role assignments that grant access, showing each holder is authorised",
		Remedy:   "Keep an approved list of who may reach the system and review the role assignments against it",
	},
	{
		ID:       "AC.L1-3.1.2",
		Name:     "Limit System Access to Permitted Transactions",
		Evidence: "the role definitions in force, showing each limits its holder to the functions their job needs",
		Remedy:   "Replace broad built-in roles with ones scoped to the transactions each role performs",
	},
	{
		ID:       "AC.L2-3.1.3",
		Name:     "Control the Flow of CUI",
		Evidence: "the network rules, data loss prevention policy or labelling scheme that governs where CUI may travel",
		Remedy:   "Define where CUI may flow and enforce it with network rules or a data loss prevention policy",
	},
	{
		ID:       "AC.L2-3.1.4",
		Name:     "Separate the Duties of Individuals",
		Evidence: "the duty separation matrix, showing no one person can both request and approve a privileged change",
		Remedy:   "Split conflicting duties across roles and record the matrix",
	},
	{
		ID:       "AC.L2-3.1.5",
		Name:     "Employ the Principle of Least Privilege",
		Evidence: "the privileged role holders and the justification for each",
		Remedy:   "Reduce standing privilege and grant elevated roles just in time",
	},
	{
		ID:       "AC.L2-3.1.6",
		Name:     "Use Non-Privileged Accounts for Non-Security Functions",
		Evidence: "that administrators hold a separate everyday account and use it for routine work",
		Remedy:   "Issue a separate unprivileged account to every administrator",
	},
	{
		ID:       "AC.L2-3.1.7",
		Name:     "Prevent Non-Privileged Users Executing Privileged Functions",
		Evidence: "the audit record of privileged function execution, and that unprivileged users are refused",
		Remedy:   "Restrict privileged functions by role and log every execution",
	},
	{
		ID:       "AC.L2-3.1.8",
		Name:     "Limit Unsuccessful Logon Attempts",
		Evidence: "the lockout threshold and duration in the authentication policy",
		Remedy:   "Set a lockout threshold and duration on the identity provider",
	},
	{
		ID:       "AC.L2-3.1.9",
		Name:     "Provide Privacy and Security Notices",
		Evidence: "the system use notice shown at sign-in",
		Remedy:   "Configure the sign-in page to display the approved notice",
	},
	{
		ID:       "AC.L2-3.1.10",
		Name:     "Use Session Lock with Pattern-Hiding Displays",
		Evidence: "the endpoint policy enforcing a screen lock that conceals the display",
		Remedy:   "Set a screen lock timeout in the endpoint management policy",
	},
	{
		ID:       "AC.L2-3.1.11",
		Name:     "Terminate a User Session After a Defined Condition",
		Evidence: "the idle and absolute session timeouts in force",
		Remedy:   "Configure session timeouts in the identity provider's session controls",
	},
	{
		ID:       "AC.L2-3.1.12",
		Name:     "Monitor and Control Remote Access Sessions",
		Evidence: "the remote access logs and the controls applied to those sessions",
		Remedy:   "Route remote access through a controlled path and retain its logs",
	},
	{
		ID:       "AC.L2-3.1.13",
		Name:     "Employ Cryptographic Mechanisms to Protect Remote Access",
		Evidence: "that remote access uses an encrypted channel, and which protocol version",
		Remedy:   "Require TLS or an encrypted VPN for every remote access path",
	},
	{
		ID:       "AC.L2-3.1.14",
		Name:     "Route Remote Access via Managed Access Control Points",
		Evidence: "the managed access points remote sessions must pass through",
		Remedy:   "Funnel remote access through a bastion, VPN concentrator or equivalent",
	},
	{
		ID:       "AC.L2-3.1.15",
		Name:     "Authorize Remote Execution of Privileged Commands",
		Evidence: "the authorisation record for remote privileged command execution",
		Remedy:   "Restrict remote privileged commands to named roles and log each use",
	},
	{
		ID:       "AC.L2-3.1.16",
		Name:     "Authorize Wireless Access Prior to Allowing Connections",
		Evidence: "the wireless authorisation record and the networks permitted",
		Remedy:   "Approve wireless networks before connection and keep the record",
	},
	{
		ID:       "AC.L2-3.1.17",
		Name:     "Protect Wireless Access Using Authentication and Encryption",
		Evidence: "the wireless authentication method and encryption in use",
		Remedy:   "Require WPA2-Enterprise or better with certificate authentication",
	},
	{
		ID:       "AC.L2-3.1.18",
		Name:     "Control Connection of Mobile Devices",
		Evidence: "the mobile device enrolment policy and the devices permitted to connect",
		Remedy:   "Require enrolment and compliance before a mobile device may connect",
	},
	{
		ID:       "AC.L2-3.1.19",
		Name:     "Encrypt CUI on Mobile Devices and Platforms",
		Evidence: "the device encryption policy and its compliance report",
		Remedy:   "Require full-disk encryption on mobile devices through endpoint policy",
	},
	{
		ID:       "AC.L1-3.1.20",
		Name:     "Verify and Control Connections to External Systems",
		Evidence: "the inventory of external connections and their approvals",
		Remedy:   "Record every external system connection and review the list periodically",
	},
	{
		ID:       "AC.L2-3.1.21",
		Name:     "Limit Use of Portable Storage on External Systems",
		Evidence: "the policy restricting portable storage on external systems",
		Remedy:   "Block or restrict removable media through endpoint policy",
	},
	{
		ID:       "AC.L1-3.1.22",
		Name:     "Control CUI Posted or Processed on Public Systems",
		Evidence: "the review record showing what is published and who approved it",
		Remedy:   "Require review and approval before anything is posted publicly",
	},

	{
		ID:       "AT.L2-3.2.1",
		Name:     "Ensure Personnel Are Trained on Security Risks",
		Evidence: "the training records for all personnel with their completion dates",
		Remedy:   "Run security awareness training and keep the attendance record",
	},
	{
		ID:       "AT.L2-3.2.2",
		Name:     "Ensure Personnel Are Trained on Their Security Duties",
		Evidence: "the role-specific training records",
		Remedy:   "Train each role in the security duties it carries and record it",
	},
	{
		ID:       "AT.L2-3.2.3",
		Name:     "Provide Insider Threat Awareness Training",
		Evidence: "the insider threat training material and the attendance record",
		Remedy:   "Include insider threat recognition and reporting in the training programme",
	},

	{
		ID:       "AU.L2-3.3.1",
		Name:     "Create and Retain System Audit Records",
		Evidence: "the audit log configuration and its retention period",
		Remedy:   "Enable audit logging on every system and retain the records",
	},
	{
		ID:       "AU.L2-3.3.2",
		Name:     "Ensure Actions Are Traceable to Individual Users",
		Evidence: "that audit records name the individual who acted, not a shared account",
		Remedy:   "Remove shared accounts and ensure logs carry the acting identity",
	},
	{
		ID:       "AU.L2-3.3.3",
		Name:     "Review and Update Logged Events",
		Evidence: "the record of the periodic review of what is logged",
		Remedy:   "Review the logged event set periodically and record the outcome",
	},
	{
		ID:       "AU.L2-3.3.4",
		Name:     "Alert on Audit Logging Process Failure",
		Evidence: "the alert that fires when audit logging stops or fails",
		Remedy:   "Configure an alert on logging failure and route it to a monitored destination",
	},
	{
		ID:       "AU.L2-3.3.5",
		Name:     "Correlate Audit Review and Reporting Processes",
		Evidence: "the correlation queries or SIEM rules used to investigate",
		Remedy:   "Centralise logs and build the queries that correlate across sources",
	},
	{
		ID:       "AU.L2-3.3.6",
		Name:     "Provide Audit Reduction and Report Generation",
		Evidence: "a generated audit report and the tooling that produced it",
		Remedy:   "Provide a reporting capability over the retained audit records",
	},
	{
		ID:       "AU.L2-3.3.7",
		Name:     "Synchronize System Clocks for Audit Records",
		Evidence: "the time source every system synchronises to",
		Remedy:   "Point every system at an authoritative time source",
	},
	{
		ID:       "AU.L2-3.3.8",
		Name:     "Protect Audit Information and Tooling",
		Evidence: "the access control on the audit logs and the audit tooling",
		Remedy:   "Restrict audit log access to a named role and make the store immutable",
	},
	{
		ID:       "AU.L2-3.3.9",
		Name:     "Limit Audit Log Management to a Privileged Subset",
		Evidence: "the list of who may manage audit logging",
		Remedy:   "Restrict audit configuration to a small named group",
	},

	{
		ID:       "CM.L2-3.4.1",
		Name:     "Establish and Maintain Baseline Configurations",
		Evidence: "the baseline configuration document and the inventory it covers",
		Remedy:   "Record the approved baseline for each system type and keep it current",
	},
	{
		ID:       "CM.L2-3.4.2",
		Name:     "Enforce Security Configuration Settings",
		Evidence: "the configuration policy in force and its compliance report",
		Remedy:   "Enforce the baseline through policy and report on drift",
	},
	{
		ID:       "CM.L2-3.4.3",
		Name:     "Track, Review, Approve and Log Changes",
		Evidence: "the change record for a sample of changes, with approvals",
		Remedy:   "Route changes through a tracked approval process",
	},
	{
		ID:       "CM.L2-3.4.4",
		Name:     "Analyze the Security Impact of Changes",
		Evidence: "the security impact analysis attached to a sample change",
		Remedy:   "Require a security impact assessment before a change is approved",
	},
	{
		ID:       "CM.L2-3.4.5",
		Name:     "Define and Enforce Access Restrictions for Changes",
		Evidence: "who may make changes and the enforcement behind it",
		Remedy:   "Restrict change rights to named roles and enforce with access control",
	},
	{
		ID:       "CM.L2-3.4.6",
		Name:     "Employ the Principle of Least Functionality",
		Evidence: "the list of enabled services and the justification for each",
		Remedy:   "Disable services, ports and functions not required",
	},
	{
		ID:       "CM.L2-3.4.7",
		Name:     "Restrict Nonessential Programs, Ports and Services",
		Evidence: "the port, protocol and service inventory with approvals",
		Remedy:   "Close nonessential ports and remove unused software",
	},
	{
		ID:       "CM.L2-3.4.8",
		Name:     "Apply Deny-by-Exception for Unauthorized Software",
		Evidence: "the application allow-list or deny-list policy in force",
		Remedy:   "Deploy application control with an approved software list",
	},
	{
		ID:       "CM.L2-3.4.9",
		Name:     "Control and Monitor User-Installed Software",
		Evidence: "the policy on user-installed software and its monitoring",
		Remedy:   "Restrict installation rights and monitor what gets installed",
	},

	{
		ID:       "IA.L1-3.5.1",
		Name:     "Identify System Users and Processes",
		Evidence: "the identity inventory covering users, services and devices",
		Remedy:   "Give every user, service and device a unique identity",
	},
	{
		ID:       "IA.L1-3.5.2",
		Name:     "Authenticate Users, Processes and Devices",
		Evidence: "the authentication method required for each identity type",
		Remedy:   "Require authentication for every identity before granting access",
	},
	{
		ID:       "IA.L2-3.5.3",
		Name:     "Use Multifactor Authentication",
		Evidence: "that multifactor is required for privileged accounts and remote access",
		Remedy:   "Enforce multifactor authentication through conditional access policy",
	},
	{
		ID:       "IA.L2-3.5.4",
		Name:     "Employ Replay-Resistant Authentication",
		Evidence: "the authentication protocol in use and that it resists replay",
		Remedy:   "Use a modern protocol such as OIDC, Kerberos or certificate authentication",
	},
	{
		ID:       "IA.L2-3.5.5",
		Name:     "Prevent Reuse of Identifiers for a Defined Period",
		Evidence: "the policy preventing an identifier being reissued",
		Remedy:   "Retain retired identifiers rather than reissuing them",
	},
	{
		ID:       "IA.L2-3.5.6",
		Name:     "Disable Identifiers After a Period of Inactivity",
		Evidence: "the inactivity threshold and the accounts disabled by it",
		Remedy:   "Disable accounts automatically after the defined inactive period",
	},
	{
		ID:       "IA.L2-3.5.7",
		Name:     "Enforce Minimum Password Complexity",
		Evidence: "the password policy in force",
		Remedy:   "Set complexity and length requirements on the identity provider",
	},
	{
		ID:       "IA.L2-3.5.8",
		Name:     "Prohibit Password Reuse for a Number of Generations",
		Evidence: "the password history setting",
		Remedy:   "Configure password history in the identity provider",
	},
	{
		ID:       "IA.L2-3.5.9",
		Name:     "Allow Temporary Passwords Only for an Immediate Change",
		Evidence: "that a temporary password must be changed at first sign-in",
		Remedy:   "Require a password change at first use",
	},
	{
		ID:       "IA.L2-3.5.10",
		Name:     "Store and Transmit Only Cryptographically-Protected Passwords",
		Evidence: "that credentials are hashed at rest and encrypted in transit",
		Remedy:   "Ensure no credential is stored or sent in clear text",
	},
	{
		ID:       "IA.L2-3.5.11",
		Name:     "Obscure Feedback of Authentication Information",
		Evidence: "that the sign-in screen masks the credential as it is entered",
		Remedy:   "Confirm authentication feedback is obscured on every entry point",
	},

	{
		ID:       "IR.L2-3.6.1",
		Name:     "Establish an Operational Incident-Handling Capability",
		Evidence: "the incident response plan, naming roles and escalation paths",
		Remedy:   "Write and maintain an incident response plan",
	},
	{
		ID:       "IR.L2-3.6.2",
		Name:     "Track, Document and Report Incidents",
		Evidence: "the incident register and a sample incident record",
		Remedy:   "Record every incident and its reporting to the required authorities",
	},
	{
		ID:       "IR.L2-3.6.3",
		Name:     "Test the Organizational Incident Response Capability",
		Evidence: "the record of the most recent incident response exercise",
		Remedy:   "Run a tabletop or live exercise periodically and record it",
	},

	{
		ID:       "MA.L2-3.7.1",
		Name:     "Perform Maintenance on Organizational Systems",
		Evidence: "the maintenance record for the systems in scope",
		Remedy:   "Keep a maintenance log covering the systems in scope",
	},
	{
		ID:       "MA.L2-3.7.2",
		Name:     "Control Tools, Techniques and Personnel Used for Maintenance",
		Evidence: "the approval record for maintenance tools and who may use them",
		Remedy:   "Approve maintenance tooling and restrict who may run it",
	},
	{
		ID:       "MA.L2-3.7.3",
		Name:     "Sanitize Equipment Removed for Off-Site Maintenance",
		Evidence: "the sanitisation record for equipment sent off site",
		Remedy:   "Sanitise equipment before it leaves and record it",
	},
	{
		ID:       "MA.L2-3.7.4",
		Name:     "Check Media with Diagnostic Programs for Malicious Code",
		Evidence: "that diagnostic media is scanned before use",
		Remedy:   "Scan diagnostic and maintenance media before connecting it",
	},
	{
		ID:       "MA.L2-3.7.5",
		Name:     "Require Multifactor Authentication for Nonlocal Maintenance",
		Evidence: "that remote maintenance sessions require multifactor authentication",
		Remedy:   "Require multifactor authentication and terminate the session on completion",
	},
	{
		ID:       "MA.L2-3.7.6",
		Name:     "Supervise Maintenance Activities of Personnel Without Access",
		Evidence: "the supervision record for maintenance by uncleared personnel",
		Remedy:   "Escort and supervise maintenance staff who lack authorisation",
	},

	{
		ID:       "MP.L2-3.8.1",
		Name:     "Protect System Media Containing CUI",
		Evidence: "where CUI media is held and how it is protected",
		Remedy:   "Store CUI media in controlled locations, paper and digital alike",
	},
	{
		ID:       "MP.L2-3.8.2",
		Name:     "Limit Access to CUI on System Media",
		Evidence: "who may reach CUI media and the authorisation for it",
		Remedy:   "Restrict media access to authorised personnel",
	},
	{
		ID:       "MP.L1-3.8.3",
		Name:     "Sanitize or Destroy Media Before Disposal",
		Evidence: "the sanitisation or destruction certificate for disposed media",
		Remedy:   "Sanitise or destroy media before disposal and keep the certificate",
	},
	{
		ID:       "MP.L2-3.8.4",
		Name:     "Mark Media with Necessary CUI Markings",
		Evidence: "the marking convention and marked media",
		Remedy:   "Mark CUI media with its distribution limitations",
	},
	{
		ID:       "MP.L2-3.8.5",
		Name:     "Control Access to Media and Maintain Accountability",
		Evidence: "the custody record for media moved outside controlled areas",
		Remedy:   "Log custody of media in transit",
	},
	{
		ID:       "MP.L2-3.8.6",
		Name:     "Use Cryptographic Mechanisms to Protect CUI on Transported Media",
		Evidence: "that transported media is encrypted",
		Remedy:   "Encrypt media before it is transported",
	},
	{
		ID:       "MP.L2-3.8.7",
		Name:     "Control Use of Removable Media",
		Evidence: "the removable media policy and its enforcement",
		Remedy:   "Restrict removable media through endpoint policy",
	},
	{
		ID:       "MP.L2-3.8.8",
		Name:     "Prohibit Portable Storage Devices with No Identifiable Owner",
		Evidence: "the policy prohibiting unowned portable storage",
		Remedy:   "Block portable storage that has no identifiable owner",
	},
	{
		ID:       "MP.L2-3.8.9",
		Name:     "Protect the Confidentiality of Backup CUI",
		Evidence: "that backups holding CUI are encrypted and access-controlled",
		Remedy:   "Encrypt backups and restrict who may restore them",
	},

	{
		ID:       "PS.L2-3.9.1",
		Name:     "Screen Individuals Prior to Authorizing Access",
		Evidence: "the screening record for personnel with CUI access",
		Remedy:   "Screen personnel before granting access and keep the record",
	},
	{
		ID:       "PS.L2-3.9.2",
		Name:     "Protect CUI During Personnel Actions",
		Evidence: "the leaver checklist showing access removal and asset return",
		Remedy:   "Revoke access and recover assets when someone leaves or transfers",
	},

	{
		ID:       "PE.L1-3.10.1",
		Name:     "Limit Physical Access to Systems and Equipment",
		Evidence: "the physical access list for facilities holding systems",
		Remedy:   "Restrict facility access to authorised personnel",
	},
	{
		ID:       "PE.L2-3.10.2",
		Name:     "Protect and Monitor the Physical Facility",
		Evidence: "the facility monitoring arrangement and its records",
		Remedy:   "Monitor the facility and retain the records",
	},
	{
		ID:       "PE.L1-3.10.3",
		Name:     "Escort Visitors and Monitor Visitor Activity",
		Evidence: "the visitor log and the escort policy",
		Remedy:   "Escort visitors and log their visits",
	},
	{
		ID:       "PE.L1-3.10.4",
		Name:     "Maintain Audit Logs of Physical Access",
		Evidence: "the physical access log for the period under review",
		Remedy:   "Keep physical access logs and retain them",
	},
	{
		ID:       "PE.L1-3.10.5",
		Name:     "Control and Manage Physical Access Devices",
		Evidence: "the inventory of keys, badges and access devices",
		Remedy:   "Inventory access devices and reconcile them periodically",
	},
	{
		ID:       "PE.L2-3.10.6",
		Name:     "Enforce Safeguarding Measures for CUI at Alternate Sites",
		Evidence: "the safeguards applied at remote and alternate work sites",
		Remedy:   "Extend the physical safeguards to alternate work locations",
	},

	{
		ID:       "RA.L2-3.11.1",
		Name:     "Periodically Assess Risk to Operations and Assets",
		Evidence: "the most recent risk assessment and its date",
		Remedy:   "Carry out a risk assessment periodically and record the outcome",
	},
	{
		ID:       "RA.L2-3.11.2",
		Name:     "Scan for Vulnerabilities Periodically",
		Evidence: "the vulnerability scan coverage and the date of the last scan",
		Remedy:   "Enable vulnerability scanning across the estate and keep it current",
	},
	{
		ID:       "RA.L2-3.11.3",
		Name:     "Remediate Vulnerabilities in Accordance with Risk",
		Evidence: "the remediation record showing findings closed within the policy window",
		Remedy:   "Set remediation windows by severity and track findings against them",
	},

	{
		ID:       "CA.L2-3.12.1",
		Name:     "Periodically Assess Security Controls for Effectiveness",
		Evidence: "the most recent control assessment and its findings",
		Remedy:   "Assess the security controls periodically and record the results",
	},
	{
		ID:       "CA.L2-3.12.2",
		Name:     "Develop Plans of Action to Correct Deficiencies",
		Evidence: "the plan of action and milestones, with owners and dates",
		Remedy:   "Maintain a plan of action and milestones for open deficiencies",
	},
	{
		ID:       "CA.L2-3.12.3",
		Name:     "Monitor Security Controls on an Ongoing Basis",
		Evidence: "the continuous monitoring arrangement and its output",
		Remedy:   "Monitor the controls continuously rather than only at assessment time",
	},
	{
		ID:       "CA.L2-3.12.4",
		Name:     "Develop and Update System Security Plans",
		Evidence: "the system security plan, showing scope, boundaries and control implementation",
		Remedy:   "Write the system security plan and keep it current",
	},

	{
		ID:       "SC.L1-3.13.1",
		Name:     "Monitor and Protect Communications at Boundaries",
		Evidence: "the boundary controls and the monitoring applied to them",
		Remedy:   "Control and monitor traffic at the system boundary",
	},
	{
		ID:       "SC.L2-3.13.2",
		Name:     "Employ Architectural Designs Promoting Effective Security",
		Evidence: "the architecture documentation showing the security design",
		Remedy:   "Record the security architecture and the principles behind it",
	},
	{
		ID:       "SC.L2-3.13.3",
		Name:     "Separate User Functionality from System Management",
		Evidence: "that management interfaces are separated from user-facing functions",
		Remedy:   "Separate administrative interfaces from user functionality",
	},
	{
		ID:       "SC.L2-3.13.4",
		Name:     "Prevent Unauthorized Information Transfer via Shared Resources",
		Evidence: "the controls preventing data leaking through shared resources",
		Remedy:   "Ensure shared resources are cleared between tenants or users",
	},
	{
		ID:       "SC.L1-3.13.5",
		Name:     "Implement Subnetworks for Publicly Accessible Components",
		Evidence: "the network segmentation separating public components from internal ones",
		Remedy:   "Place publicly reachable components in their own segment",
	},
	{
		ID:       "SC.L2-3.13.6",
		Name:     "Deny Network Traffic by Default, Permit by Exception",
		Evidence: "that the default network rule denies and exceptions are enumerated",
		Remedy:   "Set the default action to deny and permit only what is required",
	},
	{
		ID:       "SC.L2-3.13.7",
		Name:     "Prevent Remote Devices Communicating via Split Tunneling",
		Evidence: "the VPN configuration showing split tunnelling is disabled",
		Remedy:   "Disable split tunnelling on the remote access configuration",
	},
	{
		ID:       "SC.L2-3.13.8",
		Name:     "Use Cryptographic Mechanisms to Protect CUI in Transit",
		Evidence: "that CUI in transit is encrypted, and the protocol version",
		Remedy:   "Require TLS 1.2 or better on every path carrying CUI",
	},
	{
		ID:       "SC.L2-3.13.9",
		Name:     "Terminate Network Connections After Sessions End",
		Evidence: "the connection timeout applied to idle sessions",
		Remedy:   "Terminate idle network connections after the defined period",
	},
	{
		ID:       "SC.L2-3.13.10",
		Name:     "Establish and Manage Cryptographic Keys",
		Evidence: "the key management arrangement, covering generation, storage and rotation",
		Remedy:   "Manage keys in a key vault with defined rotation",
	},
	{
		ID:       "SC.L2-3.13.11",
		Name:     "Employ FIPS-Validated Cryptography to Protect CUI",
		Evidence: "that the cryptographic modules protecting CUI are FIPS-validated",
		Remedy:   "Use FIPS-validated modules wherever CUI is encrypted",
	},
	{
		ID:       "SC.L2-3.13.12",
		Name:     "Control Remote Activation of Collaborative Devices",
		Evidence: "the policy on cameras and microphones, and the indication given to users",
		Remedy:   "Restrict remote activation of collaborative computing devices",
	},
	{
		ID:       "SC.L2-3.13.13",
		Name:     "Control and Monitor Use of Mobile Code",
		Evidence: "the mobile code policy and its enforcement",
		Remedy:   "Define which mobile code is permitted and enforce it",
	},
	{
		ID:       "SC.L2-3.13.14",
		Name:     "Control and Monitor Use of Voice over IP",
		Evidence: "the VoIP controls and the monitoring applied",
		Remedy:   "Control and monitor VoIP use",
	},
	{
		ID:       "SC.L2-3.13.15",
		Name:     "Protect Authenticity of Communications Sessions",
		Evidence: "the session protection in use, such as mutual TLS or signed tokens",
		Remedy:   "Protect session authenticity end to end",
	},
	{
		ID:       "SC.L2-3.13.16",
		Name:     "Protect the Confidentiality of CUI at Rest",
		Evidence: "that storage holding CUI is encrypted and the key custody arrangement",
		Remedy:   "Encrypt data at rest everywhere CUI is held",
	},

	{
		ID:       "SI.L1-3.14.1",
		Name:     "Identify, Report and Correct System Flaws",
		Evidence: "the flaw remediation record showing identification through to correction",
		Remedy:   "Track flaws from discovery to correction with defined timeframes",
	},
	{
		ID:       "SI.L1-3.14.2",
		Name:     "Provide Protection from Malicious Code",
		Evidence: "the anti-malware deployment and its coverage",
		Remedy:   "Deploy malicious code protection across the estate",
	},
	{
		ID:       "SI.L2-3.14.3",
		Name:     "Monitor Security Alerts and Advisories and Act on Them",
		Evidence: "the advisory subscription and the record of action taken",
		Remedy:   "Subscribe to relevant advisories and record what was done about each",
	},
	{
		ID:       "SI.L1-3.14.4",
		Name:     "Update Malicious Code Protection Mechanisms",
		Evidence: "that malicious code protection updates automatically, and its currency",
		Remedy:   "Enable automatic signature and engine updates",
	},
	{
		ID:       "SI.L1-3.14.5",
		Name:     "Perform Periodic and Real-Time Malicious Code Scans",
		Evidence: "the scan schedule and the real-time protection setting",
		Remedy:   "Enable real-time scanning and schedule periodic full scans",
	},
	{
		ID:       "SI.L2-3.14.6",
		Name:     "Monitor Systems Including Inbound and Outbound Traffic",
		Evidence: "the monitoring in place for inbound and outbound traffic",
		Remedy:   "Monitor traffic in both directions and alert on the indicators that matter",
	},
	{
		ID:       "SI.L2-3.14.7",
		Name:     "Identify Unauthorized Use of Organizational Systems",
		Evidence: "the detections that identify unauthorised use, and a sample alert",
		Remedy:   "Define what unauthorised use looks like and alert on it",
	},
}
