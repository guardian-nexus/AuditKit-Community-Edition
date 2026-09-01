package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
)

type SQLChecks struct {
	dbClient     *armsql.DatabasesClient
	serverClient *armsql.ServersClient
}

// Updated constructor to accept both clients
func NewSQLChecks(dbClient *armsql.DatabasesClient, serverClient *armsql.ServersClient) *SQLChecks {
	return &SQLChecks{
		dbClient:     dbClient,
		serverClient: serverClient,
	}
}

func (c *SQLChecks) Name() string {
	return "Azure SQL Database Security"
}

func (c *SQLChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// SQL Server checks (CIS 5.1.x)
	results = append(results, c.CheckSQLTDE(ctx)...)
	results = append(results, c.CheckSQLAuditing(ctx)...)
	results = append(results, c.CheckSQLFirewall(ctx)...)
	results = append(results, c.CheckSQLEntraID(ctx)...)
	results = append(results, c.CheckSQLDefender(ctx)...)

	// PostgreSQL checks (CIS 5.2.x) - Manual for now
	results = append(results, c.CheckPostgreSQLConfig()...)

	// MySQL checks (CIS 5.3.x) - Manual for now
	results = append(results, c.CheckMySQLConfig()...)

	return results, nil
}

func (c *SQLChecks) CheckSQLTDE(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	if c.serverClient == nil {
		return append(results, CheckResult{
			Control:    "CIS-5.1.3",
			Name:       "[CIS Azure 5.1.3] SQL TDE Encryption",
			Status:     "INFO",
			Evidence:   "CIS 5.1.3: Server client not available - manual check required",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_TDE"),
		})
	}

	// List all SQL servers
	pager := c.serverClient.NewListPager(nil)

	totalServers := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return append(results, CheckResult{
				Control:    "CIS-5.1.3",
				Name:       "[CIS Azure 5.1.3] SQL TDE Check",
				Status:     "ERROR",
				Evidence:   fmt.Sprintf("Unable to check SQL servers: %v", err),
				Priority:   PriorityHigh,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("SQL_TDE"),
			})
		}

		totalServers += len(page.Value)
	}

	if totalServers > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-5.1.3",
			Name:        "[CIS Azure 5.1.3, 5.1.5] SQL Transparent Data Encryption",
			Status:      "INFO",
			Evidence:    fmt.Sprintf("CIS 5.1.3, 5.1.5: Found %d SQL servers - MANUAL CHECK required to verify TDE on all databases", totalServers),
			Remediation: "Verify TDE is enabled on all SQL databases",
			RemediationDetail: `CIS Azure 5.1.3: Ensure SQL server's TDE protector is encrypted with Customer-managed key
CIS Azure 5.1.5: Ensure that 'Data encryption' is set to 'On' on a SQL Database

TDE is enabled by default on Azure SQL Database (since 2017).
For enhanced security (CIS 5.1.3), use customer-managed keys (CMK) in Key Vault.

Azure CLI (verify TDE):
az sql db tde show --database <db> --server <server> --resource-group <rg>

Azure CLI (enable CMK for TDE):
az sql server tde-key set \
  --server <server> \
  --resource-group <rg> \
  --server-key-type AzureKeyVault \
  --kid <key-vault-key-id>`,
			ScreenshotGuide: "SQL Database → Security → Transparent data encryption → Screenshot showing:\n- Data encryption = On\n- (Optional) Customer-managed key configured",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("SQL_TDE"),
		})
	}

	return results
}

func (c *SQLChecks) CheckSQLAuditing(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	if c.serverClient == nil {
		return append(results, CheckResult{
			Control:    "CIS-5.1.1",
			Name:       "[CIS Azure 5.1.1] SQL Auditing",
			Status:     "INFO",
			Evidence:   "CIS 5.1.1: Server client not available - manual check required",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_AUDITING"),
		})
	}

	pager := c.serverClient.NewListPager(nil)

	totalServers := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		totalServers += len(page.Value)
	}

	if totalServers > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-5.1.1",
			Name:        "[CIS Azure 5.1.1, 5.1.6] SQL Server Auditing",
			Status:      "INFO",
			Evidence:    fmt.Sprintf("CIS 5.1.1, 5.1.6: MANUAL CHECK - Verify auditing is enabled for %d SQL servers with 90+ day retention", totalServers),
			Remediation: "Enable SQL auditing with 90+ day retention",
			RemediationDetail: `CIS Azure 5.1.1: Ensure that 'Auditing' is set to 'On' for SQL servers
CIS Azure 5.1.6: Ensure that 'Auditing' Retention is 'greater than 90 days'

Requirements:
1. Enable auditing at SQL Server level (applies to all databases)
2. Retention: 90+ days minimum
3. Destinations: Storage account AND/OR Log Analytics
4. Audit all events (successful and failed operations)

Azure CLI:
az sql server audit-policy update \
  --resource-group <rg> \
  --name <server> \
  --state Enabled \
  --storage-account <storage> \
  --retention-days 90

Best practice: Send to both Storage (long-term retention) and Log Analytics (querying/alerts).`,
			ScreenshotGuide: "SQL Server → Auditing → Screenshot showing:\n- Auditing = On\n- Storage account configured with 90+ day retention\n- Log Analytics workspace configured\n- All audit events enabled",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("SQL_AUDITING"),
		})
	}

	return results
}

func (c *SQLChecks) CheckSQLFirewall(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	if c.serverClient == nil {
		return append(results, CheckResult{
			Control:    "CIS-5.1.2",
			Name:       "[CIS Azure 5.1.2] SQL Firewall Rules",
			Status:     "INFO",
			Evidence:   "CIS 5.1.2: Server client not available - manual check required",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_FIREWALL"),
		})
	}

	pager := c.serverClient.NewListPager(nil)

	serversWithOpenFirewall := []string{}
	totalServers := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, server := range page.Value {
			totalServers++

			// Check public network access - FIXED: Use string comparison instead of enum constant
			if server.Properties != nil && server.Properties.PublicNetworkAccess != nil {
				// Convert to string and check if NOT "Disabled"
				publicAccessValue := string(*server.Properties.PublicNetworkAccess)
				if publicAccessValue != "Disabled" {
					// Public access enabled - need to check firewall rules
					if server.Name != nil {
						serversWithOpenFirewall = append(serversWithOpenFirewall, *server.Name)
					}
				}
			} else {
				// Assume public if not explicitly disabled
				if server.Name != nil {
					serversWithOpenFirewall = append(serversWithOpenFirewall, *server.Name)
				}
			}
		}
	}

	if len(serversWithOpenFirewall) > 0 {
		displayServers := serversWithOpenFirewall
		if len(serversWithOpenFirewall) > 3 {
			displayServers = serversWithOpenFirewall[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-5.1.2",
			Name:        "[CIS Azure 5.1.2, 5.1.7] SQL Server Firewall & Public Access",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 5.1.2, 5.1.7: %d SQL servers allow public network access: %s", len(serversWithOpenFirewall), strings.Join(displayServers, ", ")),
			Remediation: "Disable public network access and use Private Link",
			RemediationDetail: fmt.Sprintf(`CIS Azure 5.1.2: Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)
CIS Azure 5.1.7: Ensure Public Network Access is Disabled for SQL servers

CRITICAL: SQL servers with public network access are exposed to internet attacks.

Azure CLI (disable public access):
az sql server update \
  --resource-group <rg> \
  --name %s \
  --public-network-access Disabled

Then configure Private Endpoints for secure VNet access.

If public access is required, ensure NO firewall rules allow:
- 0.0.0.0 to 255.255.255.255
- 0.0.0.0/0
- Any IP range that includes internet addresses`, serversWithOpenFirewall[0]),
			ScreenshotGuide: "SQL Server → Networking → Screenshot showing:\n- Public network access = Disabled\n- Private endpoints configured\nOR if public access required:\n- No firewall rules with 0.0.0.0/0\n- Only specific IPs/VNets allowed",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("SQL_FIREWALL"),
		})
	} else if totalServers > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-5.1.2",
			Name:       "[CIS Azure 5.1.2] SQL Server Public Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 5.1.2, 5.1.7: All %d SQL servers have public network access disabled", totalServers),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_FIREWALL"),
		})
	}

	return results
}

func (c *SQLChecks) CheckSQLEntraID(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	if c.serverClient == nil {
		return append(results, CheckResult{
			Control:    "CIS-5.1.4",
			Name:       "[CIS Azure 5.1.4] SQL Entra ID Authentication",
			Status:     "INFO",
			Evidence:   "CIS 5.1.4: Server client not available - manual check required",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_ENTRA_AUTH"),
		})
	}

	pager := c.serverClient.NewListPager(nil)

	serversWithoutEntraID := []string{}
	totalServers := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, server := range page.Value {
			totalServers++

			// Check if Entra ID (Azure AD) admin is configured
			if server.Properties != nil && server.Properties.Administrators != nil {
				// Has Entra ID configured
				continue
			} else {
				if server.Name != nil {
					serversWithoutEntraID = append(serversWithoutEntraID, *server.Name)
				}
			}
		}
	}

	if len(serversWithoutEntraID) > 0 {
		displayServers := serversWithoutEntraID
		if len(serversWithoutEntraID) > 3 {
			displayServers = serversWithoutEntraID[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-5.1.4",
			Name:        "[CIS Azure 5.1.4] SQL Entra ID Authentication",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 5.1.4: %d SQL servers lack Entra ID authentication: %s", len(serversWithoutEntraID), strings.Join(displayServers, ", ")),
			Remediation: "Configure Entra ID (Azure AD) authentication for SQL",
			RemediationDetail: fmt.Sprintf(`CIS Azure 5.1.4: Ensure that Microsoft Entra authentication is Configured for SQL Servers

Entra ID (formerly Azure AD) authentication provides:
- Centralized identity management
- MFA support
- Conditional Access policies
- No local SQL passwords

Azure CLI:
az sql server ad-admin create \
  --resource-group <rg> \
  --server-name %s \
  --display-name <admin-name> \
  --object-id <user-or-group-object-id>

Best practice: Use Entra ID authentication exclusively and disable SQL authentication.`, serversWithoutEntraID[0]),
			ScreenshotGuide: "SQL Server → Azure Active Directory admin → Screenshot showing Entra ID admin configured",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("SQL_ENTRA_AUTH"),
		})
	} else if totalServers > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-5.1.4",
			Name:       "[CIS Azure 5.1.4] SQL Entra ID Authentication",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 5.1.4: All %d SQL servers have Entra ID authentication configured", totalServers),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_ENTRA_AUTH"),
		})
	}

	return results
}

func (c *SQLChecks) CheckSQLDefender(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Microsoft Defender for SQL check
	// This is a subscription-level setting checked via Defender API

	results = append(results, CheckResult{
		Control:     "CIS-3.1.7.3",
		Name:        "[CIS Azure 3.1.7.3, 3.1.7.4] Microsoft Defender for SQL",
		Status:      "INFO",
		Evidence:    "CIS 3.1.7.3, 3.1.7.4: MANUAL CHECK - Verify Microsoft Defender for SQL is enabled at subscription level",
		Remediation: "Enable Microsoft Defender for SQL Databases",
		RemediationDetail: `CIS Azure 3.1.7.3: Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'
CIS Azure 3.1.7.4: Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'

Microsoft Defender for SQL provides:
- Vulnerability assessment and recommendations
- Advanced threat detection (SQL injection, anomalous access)
- Security alerts and incident response

Enable via:
Azure Portal:
Defender for Cloud → Environment settings → Azure subscription → Databases → SQL databases on machines = On

This is a subscription-level setting that protects all SQL resources.`,
		ScreenshotGuide: "Defender for Cloud → Environment settings → Azure subscription → Screenshot showing:\n- Databases: SQL databases on machines = On\n- Databases: Azure SQL Databases = On",
		ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/overview",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("SQL_THREAT_DETECTION"),
	})

	return results
}

func (c *SQLChecks) CheckPostgreSQLConfig() []CheckResult {
	results := []CheckResult{}

	// CIS 5.2.1: PostgreSQL SSL
	results = append(results, CheckResult{
		Control:     "CIS-5.2.1",
		Name:        "[CIS Azure 5.2.1] PostgreSQL Require Secure Transport",
		Status:      "INFO",
		Evidence:    "CIS 5.2.1: MANUAL CHECK - Verify 'require_secure_transport' is ON for PostgreSQL flexible servers",
		Remediation: "Enable require_secure_transport for PostgreSQL",
		RemediationDetail: `CIS Azure 5.2.1: Ensure server parameter 'require_secure_transport' is set to 'ON' for PostgreSQL flexible server

Azure CLI:
az postgres flexible-server parameter set \
  --resource-group <rg> \
  --server-name <server> \
  --name require_secure_transport \
  --value ON

This forces all connections to use SSL/TLS encryption.`,
		ScreenshotGuide: "PostgreSQL flexible server → Server parameters → Screenshot 'require_secure_transport' = ON",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforPostgreSQL%2Fflexibleservers",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.1",
			"PCI-DSS":   "4.2.1",
		},
	})

	// CIS 5.2.2-5.2.4: PostgreSQL logging
	results = append(results, CheckResult{
		Control:     "CIS-5.2.2",
		Name:        "[CIS Azure 5.2.2-5.2.4] PostgreSQL Logging Configuration",
		Status:      "INFO",
		Evidence:    "CIS 5.2.2-5.2.4: MANUAL CHECK - Verify PostgreSQL logging parameters are properly configured",
		Remediation: "Configure PostgreSQL logging parameters",
		RemediationDetail: `CIS Azure 5.2.2: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL flexible server
CIS Azure 5.2.3: Ensure server parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL flexible server
CIS Azure 5.2.4: Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server

Required settings:
- log_checkpoints = ON (logs checkpoint operations)
- connection_throttle.enable = ON (prevents brute force attacks)
- logfiles.retention_days >= 3 (CIS minimum, recommend 7-90 days)

Configure via: PostgreSQL flexible server → Server parameters`,
		ScreenshotGuide: "PostgreSQL flexible server → Server parameters → Screenshot showing:\n- log_checkpoints = ON\n- connection_throttle.enable = ON\n- logfiles.retention_days >= 3",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforPostgreSQL%2Fflexibleservers",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.2, 5.2.3, 5.2.4",
			"SOC2":      "CC7.1",
		},
	})

	// CIS 5.2.5: PostgreSQL public access
	results = append(results, CheckResult{
		Control:     "CIS-5.2.5",
		Name:        "[CIS Azure 5.2.5] PostgreSQL Public Network Access",
		Status:      "INFO",
		Evidence:    "CIS 5.2.5: MANUAL CHECK - Verify 'Allow public access from any Azure service' is disabled for PostgreSQL",
		Remediation: "Disable public network access for PostgreSQL",
		RemediationDetail: `CIS Azure 5.2.5: Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled

Azure CLI:
az postgres flexible-server update \
  --resource-group <rg> \
  --name <server> \
  --public-network-access Disabled

Use Private Link or VNet integration for secure connectivity.`,
		ScreenshotGuide: "PostgreSQL flexible server → Networking → Screenshot showing 'Public access' = Disabled with Private endpoints configured",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforPostgreSQL%2Fflexibleservers",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.5",
			"PCI-DSS":   "1.4.2",
		},
	})

	// Legacy PostgreSQL checks (5.2.6-5.2.8)
	results = append(results, CheckResult{
		Control:     "CIS-5.2.6",
		Name:        "[CIS Azure 5.2.6-5.2.8] PostgreSQL Single Server (Legacy)",
		Status:      "INFO",
		Evidence:    "CIS 5.2.6-5.2.8: LEGACY - If using PostgreSQL Single Server, verify log_connections, log_disconnections, and infrastructure encryption",
		Remediation: "Migrate to PostgreSQL Flexible Server (Single Server is deprecated)",
		RemediationDetail: `CIS Azure 5.2.6: [LEGACY] Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL single server
CIS Azure 5.2.7: [LEGACY] Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL single server
CIS Azure 5.2.8: [LEGACY] Ensure 'Infrastructure double encryption' for PostgreSQL single server is 'Enabled'

IMPORTANT: PostgreSQL Single Server is deprecated. Migrate to Flexible Server.

For existing Single Servers, configure these parameters via Server parameters page.`,
		ScreenshotGuide: "If using Single Server: Show migration plan to Flexible Server",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforPostgreSQL%2Fservers",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.6, 5.2.7, 5.2.8",
		},
	})

	return results
}

func (c *SQLChecks) CheckMySQLConfig() []CheckResult {
	results := []CheckResult{}

	// CIS 5.3.1: MySQL SSL
	results = append(results, CheckResult{
		Control:     "CIS-5.3.1",
		Name:        "[CIS Azure 5.3.1] MySQL Require Secure Transport",
		Status:      "INFO",
		Evidence:    "CIS 5.3.1: MANUAL CHECK - Verify 'require_secure_transport' is ON for MySQL flexible servers",
		Remediation: "Enable require_secure_transport for MySQL",
		RemediationDetail: `CIS Azure 5.3.1: Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server

Azure CLI:
az mysql flexible-server parameter set \
  --resource-group <rg> \
  --server-name <server> \
  --name require_secure_transport \
  --value ON

Ensures all client connections use SSL/TLS encryption.`,
		ScreenshotGuide: "MySQL flexible server → Server parameters → Screenshot 'require_secure_transport' = ON",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforMySQL%2Fflexibleservers",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.3.1",
			"PCI-DSS":   "4.2.1",
		},
	})

	// CIS 5.3.2: MySQL TLS version
	results = append(results, CheckResult{
		Control:     "CIS-5.3.2",
		Name:        "[CIS Azure 5.3.2] MySQL TLS Version",
		Status:      "INFO",
		Evidence:    "CIS 5.3.2: MANUAL CHECK - Verify 'tls_version' is set to 'TLSv1.2' or higher for MySQL",
		Remediation: "Set minimum TLS version to 1.2",
		RemediationDetail: `CIS Azure 5.3.2: Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server

Azure CLI:
az mysql flexible-server parameter set \
  --resource-group <rg> \
  --server-name <server> \
  --name tls_version \
  --value "TLSv1.2,TLSv1.3"

Disables weak TLS 1.0 and 1.1 protocols.`,
		ScreenshotGuide: "MySQL flexible server → Server parameters → Screenshot 'tls_version' = TLSv1.2 or TLSv1.3",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforMySQL%2Fflexibleservers",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.3.2",
			"PCI-DSS":   "4.2.1",
		},
	})

	// CIS 5.3.3, 5.3.4: MySQL audit logging
	results = append(results, CheckResult{
		Control:     "CIS-5.3.3",
		Name:        "[CIS Azure 5.3.3, 5.3.4] MySQL Audit Logging",
		Status:      "INFO",
		Evidence:    "CIS 5.3.3, 5.3.4: MANUAL CHECK - Verify audit logging is enabled with CONNECTION events",
		Remediation: "Enable MySQL audit logging",
		RemediationDetail: `CIS Azure 5.3.3: Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL flexible server
CIS Azure 5.3.4: Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server

Required settings:
- audit_log_enabled = ON
- audit_log_events must include 'CONNECTION' (logs all connections/disconnections)

Configure via: MySQL flexible server → Server parameters`,
		ScreenshotGuide: "MySQL flexible server → Server parameters → Screenshot showing:\n- audit_log_enabled = ON\n- audit_log_events includes 'CONNECTION'",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.DBforMySQL%2Fflexibleservers",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "5.3.3, 5.3.4",
			"SOC2":      "CC7.1",
		},
	})

	return results
}
