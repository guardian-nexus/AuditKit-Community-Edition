package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
)

// CISActivityAlertChecks answers the activity log alert recommendations in CIS
// Microsoft Azure Foundations v6.0.0 section 6.1.2, and the Application
// Insights recommendation in 6.1.3.
//
// Eleven of the twelve are the same question asked about a different operation
// name, so the measurement is shared and each recommendation is a short
// function holding its own identifier. The identifier stays a literal in a
// Control: position deliberately - a value assembled at runtime, or passed as a
// helper argument, is invisible to the guards that check what we claim, and
// that has already hidden 31 recommendations once in this migration.
//
// Reported per operation rather than as one "alerts configured" verdict,
// because the benchmark scores them separately and an estate typically has
// some and not others.
type CISActivityAlertChecks struct {
	alerts   *armmonitor.ActivityLogAlertsClient
	insights *armapplicationinsights.ComponentsClient

	subscriptionID string
}

func NewCISActivityAlertChecks(alerts *armmonitor.ActivityLogAlertsClient,
	insights *armapplicationinsights.ComponentsClient, subscriptionID string) *CISActivityAlertChecks {
	return &CISActivityAlertChecks{alerts: alerts, insights: insights, subscriptionID: subscriptionID}
}

func (c *CISActivityAlertChecks) Name() string { return "CIS Azure Activity Log Alerts" }

// alertRule is one activity log alert rule reduced to what the benchmark asks
// about: which condition fields it matches on, whether it is switched on,
// whether it covers the whole subscription, and whether anyone is told.
type alertRule struct {
	name      string
	enabled   bool
	subScoped bool
	hasAction bool
	// fields maps a lowercased condition field to the lowercased values it
	// accepts, flattened across anyOf and leaf conditions alike.
	fields map[string]map[string]bool
}

// narrowing lists the condition fields CIS says these rules must not filter on.
// A rule that also requires Level=Critical fires on a subset of the operation's
// events, so it does not satisfy the recommendation even though the operation
// name matches.
var narrowing = []string{"level", "status", "substatus", "caller"}

func (r alertRule) matches(field, value string) bool {
	vals := r.fields[strings.ToLower(field)]
	return vals != nil && vals[strings.ToLower(value)]
}

func (r alertRule) narrowedBy() []string {
	var out []string
	for _, f := range narrowing {
		if len(r.fields[f]) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// faults names everything wrong with a rule that already matches the operation,
// so a FAIL says what to change rather than only that something is missing.
func (r alertRule) faults() []string {
	var out []string
	if !r.enabled {
		out = append(out, "it is disabled")
	}
	if !r.subScoped {
		out = append(out, "its scope is narrower than the subscription")
	}
	if !r.hasAction {
		out = append(out, "it has no action group, so nobody is notified")
	}
	if n := r.narrowedBy(); len(n) > 0 {
		out = append(out, "it also filters on "+strings.Join(n, " and "))
	}
	return out
}

func (c *CISActivityAlertChecks) subscriptionScope() string {
	return "/subscriptions/" + c.subscriptionID
}

func (c *CISActivityAlertChecks) gather(ctx context.Context) ([]alertRule, error) {
	if c.alerts == nil {
		return nil, fmt.Errorf("activity log alerts client not configured")
	}
	var out []alertRule
	pager := c.alerts.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range page.Value {
			if a == nil || a.Properties == nil {
				continue
			}
			out = append(out, c.reduce(a))
		}
	}
	return out, nil
}

// reduce is separate from gather so the judgement can be tested against the
// real API shapes without a live subscription. Every fixture bug in this
// codebase has come from a shape nobody exercised.
func (c *CISActivityAlertChecks) reduce(a *armmonitor.ActivityLogAlertResource) alertRule {
	r := alertRule{
		name:   deref(a.Name),
		fields: map[string]map[string]bool{},
	}
	if a.Properties == nil {
		return r
	}
	// A rule the API returns without an Enabled field is enabled; reading the
	// nil as false would fail every such rule.
	r.enabled = a.Properties.Enabled == nil || *a.Properties.Enabled
	for _, s := range a.Properties.Scopes {
		if strings.EqualFold(strings.TrimRight(deref(s), "/"), c.subscriptionScope()) {
			r.subScoped = true
		}
	}
	if a.Properties.Actions != nil && len(a.Properties.Actions.ActionGroups) > 0 {
		r.hasAction = true
	}
	if a.Properties.Condition == nil {
		return r
	}
	for _, cond := range a.Properties.Condition.AllOf {
		if cond == nil {
			continue
		}
		// A condition is either a leaf or a set of leaves under anyOf; the two
		// shapes never carry each other's fields.
		if len(cond.AnyOf) > 0 {
			for _, leaf := range cond.AnyOf {
				if leaf != nil {
					r.record(deref(leaf.Field), leaf.Equals, leaf.ContainsAny)
				}
			}
			continue
		}
		r.record(deref(cond.Field), cond.Equals, cond.ContainsAny)
	}
	return r
}

func (r *alertRule) record(field string, equals *string, containsAny []*string) {
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "" {
		return
	}
	if r.fields[field] == nil {
		r.fields[field] = map[string]bool{}
	}
	if equals != nil {
		r.fields[field][strings.ToLower(*equals)] = true
	}
	for _, v := range containsAny {
		if v != nil {
			r.fields[field][strings.ToLower(*v)] = true
		}
	}
}

// assess is the whole measurement, shared by the eleven alert recommendations.
// It never reports a verdict without having read the rules: an unreachable API
// is ERROR, an estate with no matching rule is FAIL, and a PASS names the rule
// it was satisfied by.
func (c *CISActivityAlertChecks) assess(ctx context.Context, field, value string) (string, string) {
	rules, err := c.gather(ctx)
	if err != nil {
		return StatusError, fmt.Sprintf("Unable to read activity log alert rules: %v", err)
	}
	var matched []alertRule
	for _, r := range rules {
		if r.matches(field, value) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return StatusFail, fmt.Sprintf("None of the %d activity log alert rule(s) in this subscription "+
			"condition on %s = %s", len(rules), field, value)
	}
	for _, r := range matched {
		if len(r.faults()) == 0 {
			return StatusPass, fmt.Sprintf("Alert rule %q fires on %s = %s across the subscription "+
				"and notifies an action group", r.name, field, value)
		}
	}
	names := make([]string, 0, len(matched))
	for _, r := range matched {
		names = append(names, fmt.Sprintf("%s (%s)", r.name, strings.Join(r.faults(), "; ")))
	}
	sort.Strings(names)
	return StatusFail, fmt.Sprintf("%d alert rule(s) condition on %s = %s but none of them qualifies: %s",
		len(matched), field, value, strings.Join(names, ", "))
}

// operationRemediation is the fix text, which differs between recommendations
// only by the operation name. Deliberately takes no control identifier.
func (c *CISActivityAlertChecks) operationRemediation(operation string) string {
	return fmt.Sprintf(`Create a subscription-wide activity log alert for this operation:

az monitor activity-log alert create \
  --subscription %s \
  --resource-group <resource-group> \
  --name <alert-rule-name> \
  --scope /subscriptions/%s \
  --condition category=Administrative and operationName=%s \
  --action-group <action-group-id>

Leave Level, Status and Caller unfiltered - a rule narrowed to one of those
fires on a subset of the events the recommendation is about. The alert needs an
action group or nothing is delivered.`, c.subscriptionID, c.subscriptionID, operation)
}

func (c *CISActivityAlertChecks) alertConsoleURL() string {
	return "https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/alertsV2"
}

func (c *CISActivityAlertChecks) Run(ctx context.Context) ([]CheckResult, error) {
	return []CheckResult{
		c.policyAssignmentCreate(ctx),
		c.policyAssignmentDelete(ctx),
		c.securityGroupCreate(ctx),
		c.securityGroupDelete(ctx),
		c.securitySolutionCreate(ctx),
		c.securitySolutionDelete(ctx),
		c.sqlFirewallRuleCreate(ctx),
		c.sqlFirewallRuleDelete(ctx),
		c.publicIPCreate(ctx),
		c.publicIPDelete(ctx),
		c.serviceHealth(ctx),
		c.applicationInsights(ctx),
	}, nil
}

func (c *CISActivityAlertChecks) policyAssignmentCreate(ctx context.Context) CheckResult {
	const op = "Microsoft.Authorization/policyAssignments/write"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.1",
		Name:              "Activity Log Alert for Policy Assignment Creation",
		Status:            status,
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Evidence:          evidence,
		Remediation:       "Alert on policy assignments being created",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.1", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.2"},
	}
}

func (c *CISActivityAlertChecks) policyAssignmentDelete(ctx context.Context) CheckResult {
	const op = "Microsoft.Authorization/policyAssignments/delete"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.2",
		Name:              "Activity Log Alert for Policy Assignment Deletion",
		Status:            status,
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Evidence:          evidence,
		Remediation:       "Alert on policy assignments being deleted",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.2", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.2"},
	}
}

func (c *CISActivityAlertChecks) securityGroupCreate(ctx context.Context) CheckResult {
	const op = "Microsoft.Network/networkSecurityGroups/write"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.3",
		Name:              "Activity Log Alert for Network Security Group Changes",
		Status:            status,
		Severity:          "HIGH",
		Priority:          PriorityHigh,
		Evidence:          evidence,
		Remediation:       "Alert on network security groups being created or updated",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.3", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.7"},
	}
}

func (c *CISActivityAlertChecks) securityGroupDelete(ctx context.Context) CheckResult {
	const op = "Microsoft.Network/networkSecurityGroups/delete"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.4",
		Name:              "Activity Log Alert for Network Security Group Deletion",
		Status:            status,
		Severity:          "HIGH",
		Priority:          PriorityHigh,
		Evidence:          evidence,
		Remediation:       "Alert on network security groups being deleted",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.4", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.7"},
	}
}

func (c *CISActivityAlertChecks) securitySolutionCreate(ctx context.Context) CheckResult {
	const op = "Microsoft.Security/securitySolutions/write"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.5",
		Name:              "Activity Log Alert for Security Solution Changes",
		Status:            status,
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Evidence:          evidence,
		Remediation:       "Alert on security solutions being created or updated",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.5", "SOC2": "CC7.2"},
	}
}

func (c *CISActivityAlertChecks) securitySolutionDelete(ctx context.Context) CheckResult {
	const op = "Microsoft.Security/securitySolutions/delete"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.6",
		Name:              "Activity Log Alert for Security Solution Deletion",
		Status:            status,
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Evidence:          evidence,
		Remediation:       "Alert on security solutions being deleted",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.6", "SOC2": "CC7.2"},
	}
}

func (c *CISActivityAlertChecks) sqlFirewallRuleCreate(ctx context.Context) CheckResult {
	const op = "Microsoft.Sql/servers/firewallRules/write"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.7",
		Name:              "Activity Log Alert for SQL Firewall Rule Changes",
		Status:            status,
		Severity:          "HIGH",
		Priority:          PriorityHigh,
		Evidence:          evidence,
		Remediation:       "Alert on SQL server firewall rules being created or updated",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.7", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.7"},
	}
}

func (c *CISActivityAlertChecks) sqlFirewallRuleDelete(ctx context.Context) CheckResult {
	const op = "Microsoft.Sql/servers/firewallRules/delete"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.8",
		Name:              "Activity Log Alert for SQL Firewall Rule Deletion",
		Status:            status,
		Severity:          "HIGH",
		Priority:          PriorityHigh,
		Evidence:          evidence,
		Remediation:       "Alert on SQL server firewall rules being deleted",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.8", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.7"},
	}
}

func (c *CISActivityAlertChecks) publicIPCreate(ctx context.Context) CheckResult {
	const op = "Microsoft.Network/publicIPAddresses/write"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.9",
		Name:              "Activity Log Alert for Public IP Address Changes",
		Status:            status,
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Evidence:          evidence,
		Remediation:       "Alert on public IP addresses being created or updated",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.9", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.7"},
	}
}

func (c *CISActivityAlertChecks) publicIPDelete(ctx context.Context) CheckResult {
	const op = "Microsoft.Network/publicIPAddresses/delete"
	status, evidence := c.assess(ctx, "operationName", op)
	return CheckResult{
		Control:           "CIS-6.1.2.10",
		Name:              "Activity Log Alert for Public IP Address Deletion",
		Status:            status,
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Evidence:          evidence,
		Remediation:       "Alert on public IP addresses being deleted",
		RemediationDetail: c.operationRemediation(op),
		ScreenshotGuide:   "Monitor -> Alerts -> Alert rules -> Screenshot the rule, its condition showing the operation, and its action group",
		ConsoleURL:        c.alertConsoleURL(),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-Azure": "6.1.2.10", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.7"},
	}
}

func (c *CISActivityAlertChecks) serviceHealth(ctx context.Context) CheckResult {
	// Service health is the one rule in the section that conditions on the
	// event category rather than an operation name.
	status, evidence := c.assess(ctx, "category", "ServiceHealth")
	return CheckResult{
		Control:     "CIS-6.1.2.11",
		Name:        "Activity Log Alert for Service Health",
		Status:      status,
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    evidence,
		Remediation: "Alert on service health events for the subscription",
		RemediationDetail: fmt.Sprintf(`Create a subscription-wide service health alert:

az monitor activity-log alert create \
  --subscription %s \
  --resource-group <resource-group> \
  --name <alert-rule-name> \
  --scope /subscriptions/%s \
  --condition category=ServiceHealth \
  --action-group <action-group-id>

Leave the service and region filters at All so the alert covers every service
the subscription uses.`, c.subscriptionID, c.subscriptionID),
		ScreenshotGuide: "Monitor -> Alerts -> Alert rules -> Screenshot the service health rule with services and regions set to All, and its action group",
		ConsoleURL:      c.alertConsoleURL(),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "6.1.2.11", "SOC2": "CC7.2"},
	}
}

func (c *CISActivityAlertChecks) applicationInsights(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-6.1.3.1",
		Name:        "Application Insights Configured",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Create a workspace-based Application Insights resource for the applications in this subscription",
		RemediationDetail: `az monitor app-insights component create \
  --app <name> \
  --resource-group <resource-group> \
  --location <region> \
  --kind web \
  --workspace <log-analytics-workspace-id>

Application Insights bills through its Log Analytics workspace, so size the
retention to what you actually need.`,
		ScreenshotGuide: "Application Insights -> Screenshot the resources, showing each is workspace-based",
		ConsoleURL:      "https://portal.azure.com/#browse/microsoft.insights%2Fcomponents",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "6.1.3.1", "SOC2": "CC7.2"},
	}
	if c.insights == nil {
		base.Status = StatusError
		base.Evidence = "Application Insights client not configured"
		return base
	}
	names := []string{}
	pager := c.insights.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = StatusError
			base.Evidence = fmt.Sprintf("Unable to list Application Insights resources: %v", err)
			return base
		}
		for _, comp := range page.Value {
			if comp != nil && comp.Name != nil {
				names = append(names, *comp.Name)
			}
		}
	}
	if len(names) == 0 {
		base.Status = StatusFail
		base.Evidence = "No Application Insights resources exist in this subscription"
		return base
	}
	shown := names
	if len(shown) > 5 {
		shown = shown[:5]
	}
	base.Status = StatusPass
	base.Evidence = fmt.Sprintf("%d Application Insights resource(s) configured: %v", len(names), shown)
	base.Priority = PriorityInfo
	return base
}
