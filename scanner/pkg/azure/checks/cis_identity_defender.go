package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
)

// CISIdentityDefenderChecks answers the two subscription-administration
// recommendations in CIS Microsoft Azure Foundations v6.0.0 section 5.3-5.4 and
// four Defender for Cloud settings in 8.1 that no other check reads.
//
// Grouped by the client they need rather than by benchmark section: role
// assignments and definitions come from armauthorization, the rest from
// armsecurity. Splitting them by section would mean two suites each holding one
// client, and a suite per section is not what makes a check correct.
type CISIdentityDefenderChecks struct {
	roles    *armauthorization.RoleAssignmentsClient
	roleDefs *armauthorization.RoleDefinitionsClient
	pricing  *armsecurity.PricingsClient
	contacts *armsecurity.ContactsClient
	// The assessments client reads Defender's own recommendation results,
	// which is the only place the operating-system update check surfaces.
	assessments *armsecurity.AssessmentsClient

	subscriptionID string
}

func NewCISIdentityDefenderChecks(roles *armauthorization.RoleAssignmentsClient,
	roleDefs *armauthorization.RoleDefinitionsClient, pricing *armsecurity.PricingsClient,
	contacts *armsecurity.ContactsClient, assessments *armsecurity.AssessmentsClient,
	subscriptionID string) *CISIdentityDefenderChecks {
	return &CISIdentityDefenderChecks{
		roles: roles, roleDefs: roleDefs, pricing: pricing, contacts: contacts,
		assessments: assessments, subscriptionID: subscriptionID,
	}
}

func (c *CISIdentityDefenderChecks) Name() string { return "CIS Azure Identity and Defender Settings" }

// userAccessAdministratorRoleID is the built-in definition's GUID. The role can
// be renamed in the portal display but the definition id is fixed, so matching
// on the id rather than the name is what makes this reliable.
const userAccessAdministratorRoleID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

func (c *CISIdentityDefenderChecks) scope() string {
	return "/subscriptions/" + c.subscriptionID
}

func (c *CISIdentityDefenderChecks) consoleIAM() string {
	return fmt.Sprintf("https://portal.azure.com/#@/resource/subscriptions/%s/users", c.subscriptionID)
}

func (c *CISIdentityDefenderChecks) consoleDefender() string {
	return "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings"
}

func (c *CISIdentityDefenderChecks) Run(ctx context.Context) ([]CheckResult, error) {
	return []CheckResult{
		c.userAccessAdministrator(ctx),
		c.customAdministratorRoles(ctx),
		c.defenderCSPM(ctx),
		c.osUpdateAssessment(ctx),
		c.ownerNotifications(ctx),
		c.attackPathNotifications(ctx),
	}, nil
}

func (c *CISIdentityDefenderChecks) userAccessAdministrator(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-5.3.3",
		Name:        "User Access Administrator Role Restricted",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Remove the standing User Access Administrator assignments and grant the role just in time through Privileged Identity Management",
		RemediationDetail: `The role can grant any other role, including to itself, so a standing
assignment is equivalent to permanent ownership.

az role assignment delete \
  --role "User Access Administrator" \
  --assignee <principal-id> \
  --scope <scope>

Where the role is genuinely needed, make it eligible rather than active in
Privileged Identity Management so each use is requested, approved and logged.`,
		ScreenshotGuide: "Subscription -> Access control (IAM) -> Roles -> User Access Administrator -> View -> Assignments -> Screenshot the (empty) list",
		ConsoleURL:      c.consoleIAM(),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "5.3.3", "SOC2": "CC6.3", "PCI-DSS": "7.2.2"},
	}
	if c.roles == nil {
		base.Status = StatusError
		base.Evidence = "Role assignments client not configured"
		return base
	}
	// atScope() returns assignments on this subscription and the ones it
	// inherits from management groups and the tenant root, which is the set an
	// auditor sees for the subscription.
	filter := "atScope()"
	pager := c.roles.NewListPager(&armauthorization.RoleAssignmentsClientListOptions{Filter: &filter})
	holders, total := []string{}, 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = StatusError
			base.Evidence = fmt.Sprintf("Unable to list role assignments: %v", err)
			return base
		}
		for _, a := range page.Value {
			if a == nil || a.Properties == nil {
				continue
			}
			total++
			if !strings.Contains(strings.ToLower(deref(a.Properties.RoleDefinitionID)), userAccessAdministratorRoleID) {
				continue
			}
			holders = append(holders, fmt.Sprintf("%s at %s",
				shortPrincipal(deref(a.Properties.PrincipalID)), deref(a.Properties.Scope)))
		}
	}
	if total == 0 {
		// No assignments at all means the listing was empty, not that the
		// subscription is clean; say which it is rather than passing.
		base.Status = StatusError
		base.Evidence = "No role assignments were returned for this subscription, so the assignment list could not be evaluated"
		return base
	}
	if len(holders) > 0 {
		base.Status = StatusFail
		base.Evidence = fmt.Sprintf("%d of %d role assignment(s) grant User Access Administrator: %v",
			len(holders), total, capList(holders, 5))
		return base
	}
	base.Status = StatusPass
	base.Priority = PriorityInfo
	base.Evidence = fmt.Sprintf("None of the %d role assignment(s) visible to this subscription grant User Access Administrator", total)
	return base
}

func (c *CISIdentityDefenderChecks) customAdministratorRoles(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-5.4",
		Name:        "No Custom Subscription Administrator Roles",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Replace the custom role's wildcard action with the specific actions its holders need, or use a built-in role",
		RemediationDetail: `A custom role assignable at the subscription with an action of * is a
second Owner role that the built-in role review does not show.

az role definition list --custom-role-only true \
  --query "[].{name:roleName, scopes:assignableScopes, actions:permissions[].actions}"

Then either narrow the actions to those actually required, or delete the role
and assign a built-in one:

az role definition delete --name "<role name>"`,
		ScreenshotGuide: "Subscription -> Access control (IAM) -> Roles -> filter Type = CustomRole -> for each, View -> JSON -> Screenshot assignableScopes and actions",
		ConsoleURL:      c.consoleIAM(),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "5.4", "SOC2": "CC6.3", "PCI-DSS": "7.2.2"},
	}
	if c.roleDefs == nil {
		base.Status = StatusError
		base.Evidence = "Role definitions client not configured"
		return base
	}
	filter := "type eq 'CustomRole'"
	pager := c.roleDefs.NewListPager(c.scope(), &armauthorization.RoleDefinitionsClientListOptions{Filter: &filter})
	offenders, total := []string{}, 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = StatusError
			base.Evidence = fmt.Sprintf("Unable to list custom role definitions: %v", err)
			return base
		}
		for _, d := range page.Value {
			if d == nil || d.Properties == nil {
				continue
			}
			total++
			if grantsSubscriptionAdmin(d.Properties) {
				offenders = append(offenders, deref(d.Properties.RoleName))
			}
		}
	}
	if total == 0 {
		base.Status = StatusPass
		base.Priority = PriorityInfo
		base.Evidence = "No custom role definitions exist in this subscription"
		return base
	}
	if len(offenders) > 0 {
		base.Status = StatusFail
		base.Evidence = fmt.Sprintf("%d of %d custom role(s) are assignable at the subscription with an action of *: %v",
			len(offenders), total, capList(offenders, 5))
		return base
	}
	base.Status = StatusPass
	base.Priority = PriorityInfo
	base.Evidence = fmt.Sprintf("None of the %d custom role(s) combine a subscription scope with a wildcard action", total)
	return base
}

// grantsSubscriptionAdmin is the pair of conditions the benchmark names: the
// role reaches the whole subscription, and it permits every action. Either
// alone is ordinary - a wildcard scoped to one resource group is not a
// subscription administrator, and a subscription-scoped reader is not either.
func grantsSubscriptionAdmin(p *armauthorization.RoleDefinitionProperties) bool {
	subscriptionScoped := false
	for _, s := range p.AssignableScopes {
		raw := strings.TrimSpace(strings.ToLower(deref(s)))
		// The tenant root contains every subscription. Checked before the
		// trailing slash is trimmed, because trimming turns "/" into "" and an
		// earlier version of this condition was therefore unreachable.
		if raw == "/" {
			subscriptionScoped = true
			continue
		}
		v := strings.TrimRight(raw, "/")
		// "/subscriptions/<id>" and nothing deeper: two slashes.
		if strings.HasPrefix(v, "/subscriptions/") && strings.Count(v, "/") == 2 {
			subscriptionScoped = true
		}
	}
	if !subscriptionScoped {
		return false
	}
	for _, perm := range p.Permissions {
		if perm == nil {
			continue
		}
		for _, a := range perm.Actions {
			if strings.TrimSpace(deref(a)) == "*" {
				return true
			}
		}
	}
	return false
}

func (c *CISIdentityDefenderChecks) defenderCSPM(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.1.1.1",
		Name:        "Microsoft Defender CSPM Enabled",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Turn the Defender CSPM plan on for the subscription",
		RemediationDetail: `az security pricing create --name CloudPosture --tier standard

Defender CSPM is what produces the attack paths and the agentless scanning
results the other recommendations in this section rely on; with it off, several
of them have nothing to report.`,
		ScreenshotGuide: "Defender for Cloud -> Environment settings -> the subscription -> Defender plans -> Screenshot Defender CSPM set to On",
		ConsoleURL:      c.consoleDefender(),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.1.1.1", "SOC2": "CC7.1"},
	}
	if c.pricing == nil {
		base.Status = StatusError
		base.Evidence = "Defender pricing client not configured"
		return base
	}
	res, err := c.pricing.Get(ctx, c.scope(), "CloudPosture", nil)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to read the Defender CSPM plan: %v", err)
		return base
	}
	if res.Properties == nil || res.Properties.PricingTier == nil {
		base.Status = StatusError
		base.Evidence = "The Defender CSPM plan returned no pricing tier"
		return base
	}
	tier := string(*res.Properties.PricingTier)
	if !strings.EqualFold(tier, "Standard") {
		base.Status = StatusFail
		base.Evidence = fmt.Sprintf("The Defender CSPM plan is on the %s tier, not Standard", tier)
		return base
	}
	base.Status = StatusPass
	base.Priority = PriorityInfo
	base.Evidence = "The Defender CSPM plan is on the Standard tier"
	return base
}

// osUpdateAssessmentName is the Defender assessment behind "System updates
// should be installed on your machines (powered by Update Center)". Assessment
// names are the policy definition GUID.
const osUpdateAssessmentName = "f85bf3e0-d513-442e-89c3-1784ad63382b"

func (c *CISIdentityDefenderChecks) osUpdateAssessment(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.1.10",
		Name:        "Defender Checks VM Operating Systems for Updates",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Enable periodic assessment in Azure Update Manager so Defender reports which machines are missing operating system updates",
		RemediationDetail: `az vm update --name <vm> --resource-group <rg> \
  --set osProfile.windowsConfiguration.patchSettings.assessmentMode=AutomaticByPlatform

For Linux use linuxConfiguration.patchSettings.assessmentMode. With periodic
assessment off, Defender has no update data for the machine and the
recommendation neither passes nor fails - it simply does not appear, which
reads as compliant and is not.`,
		ScreenshotGuide: "Defender for Cloud -> Recommendations -> Screenshot 'System updates should be installed on your machines', with its affected-resource count",
		ConsoleURL:      "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.1.10", "SOC2": "CC7.5", "PCI-DSS": "6.3.3"},
	}
	if c.assessments == nil {
		base.Status = StatusError
		base.Evidence = "Defender assessments client not configured"
		return base
	}
	pager := c.assessments.NewListPager(c.scope(), nil)
	var unhealthy, healthy, notAssessed int
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = StatusError
			base.Evidence = fmt.Sprintf("Unable to list Defender assessments: %v", err)
			return base
		}
		for _, a := range page.Value {
			if a == nil || !strings.EqualFold(deref(a.Name), osUpdateAssessmentName) {
				continue
			}
			if a.Properties == nil || a.Properties.Status == nil || a.Properties.Status.Code == nil {
				notAssessed++
				continue
			}
			switch *a.Properties.Status.Code {
			case armsecurity.AssessmentStatusCodeUnhealthy:
				unhealthy++
			case armsecurity.AssessmentStatusCodeHealthy:
				healthy++
			default:
				// NotApplicable means the assessment did not happen for that
				// machine, which is not the same as the machine being patched.
				notAssessed++
			}
		}
	}
	measured := unhealthy + healthy
	if measured == 0 {
		// Nothing was assessed, so there is no verdict to give. This is the
		// reading most likely to be got wrong: an estate with update
		// assessment switched off returns exactly what a fully patched one
		// does - no unhealthy rows - and passing on that would be a verdict
		// from data nobody examined.
		base.Status = StatusManual
		base.Evidence = fmt.Sprintf("Defender assessed no machine for operating system updates (%d row(s) reported as not applicable), "+
			"so whether updates are being checked could not be determined from the API", notAssessed)
		return base
	}
	if unhealthy > 0 {
		base.Status = StatusFail
		base.Evidence = fmt.Sprintf("Defender reports %d of %d assessed machine(s) missing operating system updates%s",
			unhealthy, measured, notAssessedSuffix(notAssessed))
		return base
	}
	base.Status = StatusPass
	base.Priority = PriorityInfo
	base.Evidence = fmt.Sprintf("Defender assesses operating system updates and reports all %d machine(s) up to date%s",
		measured, notAssessedSuffix(notAssessed))
	return base
}

func (c *CISIdentityDefenderChecks) ownerNotifications(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.1.12",
		Name:        "Defender Alerts Notify Subscription Owners",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Set the security contact to notify all users holding the Owner role",
		RemediationDetail: `Defender for Cloud -> Environment settings -> the subscription ->
Email notifications -> tick "All users with the following roles" and choose
Owner.

An address list alone goes stale as people move on; the role notification
follows whoever actually holds the subscription.`,
		ScreenshotGuide: "Defender for Cloud -> Environment settings -> the subscription -> Email notifications -> Screenshot 'All users with the following roles' set to Owner",
		ConsoleURL:      c.consoleDefender(),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.1.12", "SOC2": "CC7.2"},
	}
	contacts, err := c.gatherContacts(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to read the security contacts: %v", err)
		return base
	}
	if len(contacts) == 0 {
		base.Status = StatusFail
		base.Evidence = "No security contact is configured for this subscription, so no role is notified"
		return base
	}
	for _, p := range contacts {
		if p == nil || p.NotificationsByRole == nil {
			continue
		}
		// The SDK types this field with the regulatory-compliance State enum,
		// whose values are Passed/Failed/Skipped - the wire value here is
		// On/Off, so compare the string rather than an SDK constant.
		if p.NotificationsByRole.State == nil || !strings.EqualFold(string(*p.NotificationsByRole.State), "On") {
			continue
		}
		for _, r := range p.NotificationsByRole.Roles {
			if r != nil && *r == armsecurity.SecurityContactRoleOwner {
				base.Status = StatusPass
				base.Priority = PriorityInfo
				base.Evidence = "Defender alert notifications are sent to all users holding the Owner role"
				return base
			}
		}
	}
	base.Status = StatusFail
	base.Evidence = fmt.Sprintf("None of the %d security contact(s) notify the Owner role with notifications switched on", len(contacts))
	return base
}

func (c *CISIdentityDefenderChecks) attackPathNotifications(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.1.15",
		Name:        "Defender Notifies on Attack Paths",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Enable attack path notifications on the security contact and choose a risk level",
		RemediationDetail: `Defender for Cloud -> Environment settings -> the subscription ->
Email notifications -> under Notification types, tick "Notify about attack
paths with the following risk level (or higher)" and select a level.

An attack path is a chain of findings that together reach something valuable;
the individual findings may each be below the severity that triggers an alert.`,
		ScreenshotGuide: "Defender for Cloud -> Environment settings -> the subscription -> Email notifications -> Screenshot the attack path notification and its risk level",
		ConsoleURL:      c.consoleDefender(),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.1.15", "SOC2": "CC7.2"},
	}
	contacts, err := c.gatherContacts(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to read the security contacts: %v", err)
		return base
	}
	if len(contacts) == 0 {
		base.Status = StatusFail
		base.Evidence = "No security contact is configured for this subscription, so no attack path notification can be sent"
		return base
	}
	for _, p := range contacts {
		if p == nil {
			continue
		}
		for _, src := range p.NotificationsSources {
			ap, ok := src.(*armsecurity.NotificationsSourceAttackPath)
			if !ok || ap == nil || ap.MinimalRiskLevel == nil {
				continue
			}
			base.Status = StatusPass
			base.Priority = PriorityInfo
			base.Evidence = fmt.Sprintf("Attack path notifications are enabled at risk level %s and above",
				string(*ap.MinimalRiskLevel))
			return base
		}
	}
	base.Status = StatusFail
	base.Evidence = fmt.Sprintf("None of the %d security contact(s) enable attack path notifications", len(contacts))
	return base
}

func (c *CISIdentityDefenderChecks) gatherContacts(ctx context.Context) ([]*armsecurity.ContactProperties, error) {
	if c.contacts == nil {
		return nil, fmt.Errorf("security contacts client not configured")
	}
	var out []*armsecurity.ContactProperties
	pager := c.contacts.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, contact := range page.Value {
			if contact != nil && contact.Properties != nil {
				out = append(out, contact.Properties)
			}
		}
	}
	return out, nil
}

// shortPrincipal keeps evidence readable without losing which principal it
// names: the object id is a GUID, and the first segment identifies it in the
// portal's own search.
func shortPrincipal(id string) string {
	if len(id) > 8 {
		return "principal " + id[:8]
	}
	if id == "" {
		return "an unnamed principal"
	}
	return "principal " + id
}

// notAssessedSuffix keeps the machines Defender skipped visible in the
// evidence. A pass over three machines when forty were skipped is not the same
// finding as a pass over forty-three, and the assessor needs to see which.
func notAssessedSuffix(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; %d further machine(s) were not assessed", n)
}

func capList(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return items[:n]
}
