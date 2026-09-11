package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The Cloud SQL database-flag recommendations in CIS GCP Foundation v5.0.0
// that the original flag checks did not cover, and the two flag semantics the
// generic helper cannot express.
//
// checkDatabaseFlag asks "is this flag set to this value", which is right for
// most of section 6 and wrong for two recommendations:
//
//   - 6.3.4 requires the flag to be absent. Asking for a value would pass an
//     instance that sets it to something.
//   - 6.3.7 says "if the flag is present, ensure it is off". Requiring it to be
//     present and off fails an instance that never set it, which is compliant -
//     a false positive on the most common configuration.

// checkFlagAbsent reports instances where a flag is set at all. Used where the
// benchmark's requirement is the absence of the flag rather than its value.
func (c *SQLChecks) checkFlagAbsent(ctx context.Context, dbType, flagName, control, checkName, remediation string) []CheckResult {
	instances, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil
	}
	offenders, relevant := []string{}, 0
	for _, inst := range instances.Items {
		if !strings.HasPrefix(inst.DatabaseVersion, dbType) {
			continue
		}
		relevant++
		if inst.Settings == nil {
			continue
		}
		for _, flag := range inst.Settings.DatabaseFlags {
			if flag.Name == flagName {
				offenders = append(offenders, fmt.Sprintf("%s (%s=%s)", inst.Name, flagName, flag.Value))
				break
			}
		}
	}
	return c.flagVerdict(control, checkName, remediation,
		fmt.Sprintf("%s must not be configured", flagName),
		fmt.Sprintf("gcloud sql instances patch INSTANCE_NAME --clear-database-flags"),
		dbType, offenders, relevant)
}

// checkFlagIfPresent reports instances where a flag is set to something other
// than the required value, and passes those that do not set it - which is what
// the benchmark asks for where a flag's default is already compliant.
func (c *SQLChecks) checkFlagIfPresent(ctx context.Context, dbType, flagName, want, control, checkName, remediation string) []CheckResult {
	instances, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil
	}
	offenders, relevant := []string{}, 0
	for _, inst := range instances.Items {
		if !strings.HasPrefix(inst.DatabaseVersion, dbType) {
			continue
		}
		relevant++
		if inst.Settings == nil {
			continue
		}
		for _, flag := range inst.Settings.DatabaseFlags {
			if flag.Name == flagName && !strings.EqualFold(flag.Value, want) {
				offenders = append(offenders, fmt.Sprintf("%s (%s=%s)", inst.Name, flagName, flag.Value))
				break
			}
		}
	}
	return c.flagVerdict(control, checkName, remediation,
		fmt.Sprintf("%s is either unset or set to %s", flagName, want),
		fmt.Sprintf("gcloud sql instances patch INSTANCE_NAME --database-flags %s=%s", flagName, want),
		dbType, offenders, relevant)
}

// flagVerdict renders the result for both helpers above, so neither can report
// a verdict without the denominator it was computed from.
func (c *SQLChecks) flagVerdict(control, checkName, remediation, requirement, fix, dbType string,
	offenders []string, relevant int) []CheckResult {
	base := CheckResult{
		Control:           control,
		Name:              fmt.Sprintf("[%s] %s", control, checkName),
		Severity:          "MEDIUM",
		Priority:          PriorityMedium,
		Remediation:       remediation,
		RemediationDetail: fix,
		ScreenshotGuide:   fmt.Sprintf("Cloud SQL -> Instance -> Edit -> Flags -> Screenshot showing %s", requirement),
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/sql/instances?project=%s", c.projectID),
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"CIS-GCP": strings.TrimPrefix(control, "CIS-GCP-"), "SOC2": "CC6.1"},
	}
	if relevant == 0 {
		base.Status = "PASS"
		base.Evidence = fmt.Sprintf("No %s instances exist in this project", dbType)
		base.Priority = PriorityInfo
		return []CheckResult{base}
	}
	if len(offenders) == 0 {
		base.Status = "PASS"
		base.Evidence = fmt.Sprintf("All %d %s instance(s): %s", relevant, dbType, requirement)
		base.Priority = PriorityInfo
		return []CheckResult{base}
	}
	shown := offenders
	if len(shown) > 5 {
		shown = shown[:5]
	}
	base.Status = "FAIL"
	base.Evidence = fmt.Sprintf("%d of %d %s instance(s) do not satisfy \"%s\": %v",
		len(offenders), relevant, dbType, requirement, shown)
	return []CheckResult{base}
}

// CheckPostgreSQLLogMinMessages answers 6.2.5.
func (c *SQLChecks) CheckPostgreSQLLogMinMessages(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "POSTGRES", "log_min_messages", "warning", "CIS-GCP-6.2.5",
		"PostgreSQL Log Min Messages",
		"Set log_min_messages to warning or stricter so the log carries the events an investigation needs")
}

// CheckPostgreSQLPgAudit answers 6.2.8.
func (c *SQLChecks) CheckPostgreSQLPgAudit(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "POSTGRES", "cloudsql.enable_pgaudit", "on", "CIS-GCP-6.2.8",
		"PostgreSQL pgAudit Enabled",
		"Enable cloudsql.enable_pgaudit, which is what produces a database audit trail at all")
}

// CheckSQLServerExternalScripts answers 6.3.1.
func (c *SQLChecks) CheckSQLServerExternalScripts(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "SQLSERVER", "external scripts enabled", "off", "CIS-GCP-6.3.1",
		"SQL Server External Scripts Disabled",
		"Disable external scripts: with them on, R and Python run on the database host")
}

// CheckSQLServerUserConnections answers 6.3.3. The benchmark asks for 0, which
// is the non-limiting value - a cap risks refusing legitimate connections
// rather than protecting anything.
func (c *SQLChecks) CheckSQLServerUserConnections(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "SQLSERVER", "user connections", "0", "CIS-GCP-6.3.3",
		"SQL Server User Connections Not Limited",
		"Set user connections to 0, the non-limiting value")
}

// CheckSQLServerUserOptions answers 6.3.4, where the requirement is that the
// flag is not configured at all.
func (c *SQLChecks) CheckSQLServerUserOptions(ctx context.Context) []CheckResult {
	return c.checkFlagAbsent(ctx, "SQLSERVER", "user options", "CIS-GCP-6.3.4",
		"SQL Server User Options Not Configured",
		"Remove the user options flag so sessions take the server defaults")
}

// CheckSQLAuthorizedNetworks answers 6.5: an authorized network of 0.0.0.0/0
// whitelists the whole internet, which makes the instance's other network
// controls beside the point.
func (c *SQLChecks) CheckSQLAuthorizedNetworks(ctx context.Context) []CheckResult {
	instances, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil
	}
	offenders, total := []string{}, 0
	for _, inst := range instances.Items {
		total++
		if inst.Settings == nil || inst.Settings.IpConfiguration == nil {
			continue
		}
		for _, net := range inst.Settings.IpConfiguration.AuthorizedNetworks {
			if net == nil {
				continue
			}
			if net.Value == "0.0.0.0/0" || net.Value == "::/0" {
				offenders = append(offenders, fmt.Sprintf("%s (%s)", inst.Name, net.Value))
				break
			}
		}
	}
	base := CheckResult{
		Control:     "CIS-GCP-6.5",
		Name:        "[CIS-GCP-6.5] Cloud SQL Does Not Whitelist All Public IPs",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Remove the 0.0.0.0/0 authorized network and name the ranges that actually need to connect",
		RemediationDetail: `gcloud sql instances patch INSTANCE_NAME \
  --authorized-networks=<comma-separated-ranges>

Better still, use a private IP with Private Service Connect and no authorized
networks at all.`,
		ScreenshotGuide: "Cloud SQL -> Instance -> Connections -> Networking -> Screenshot the authorized networks",
		ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/sql/instances?project=%s", c.projectID),
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-GCP": "6.5", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
	}
	if total == 0 {
		base.Status, base.Evidence, base.Priority = "PASS", "No Cloud SQL instances exist in this project", PriorityInfo
		return []CheckResult{base}
	}
	if len(offenders) == 0 {
		base.Status = "PASS"
		base.Evidence = fmt.Sprintf("None of the %d Cloud SQL instance(s) authorize 0.0.0.0/0", total)
		base.Priority = PriorityInfo
		return []CheckResult{base}
	}
	base.Status = "FAIL"
	base.Evidence = fmt.Sprintf("%d of %d Cloud SQL instance(s) authorize the whole internet: %v",
		len(offenders), total, offenders)
	return []CheckResult{base}
}
