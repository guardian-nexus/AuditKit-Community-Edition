package checks

import (
	"context"
	"time"
)

// AppServiceChecks handles Azure App Service security configuration
// Note: Requires App Service SDK for full automation
type AppServiceChecks struct {
	subscriptionID string
}

func NewAppServiceChecks(subscriptionID string) *AppServiceChecks {
	return &AppServiceChecks{
		subscriptionID: subscriptionID,
	}
}

func (c *AppServiceChecks) Name() string {
	return "Azure App Service Security"
}

func (c *AppServiceChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Note: Full automation requires importing App Service SDK
	// For now, providing manual checks with comprehensive guidance

	results = append(results, c.checkAuthentication())
	results = append(results, c.checkHTTPSRedirect())
	results = append(results, c.checkTLSVersion())
	results = append(results, c.checkClientCertificates())
	results = append(results, c.checkManagedIdentity())
	results = append(results, c.checkRuntimeVersions())
	results = append(results, c.checkFTPDeployment())

	return results, nil
}

func (c *AppServiceChecks) checkAuthentication() CheckResult {
	return CheckResult{
		Control:     "CIS-9.1",
		Name:        "[CIS Azure 9.1] App Service Authentication",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "CIS 9.1: MANUAL CHECK - Verify App Service Authentication is enabled for all apps",
		Remediation: "Enable authentication for App Service apps per CIS 9.1",
		RemediationDetail: `CIS Azure 9.1: Ensure App Service Authentication is set up for apps in Azure App Service

Configure authentication via:
1. App Service → Settings → Authentication
2. Add identity provider:
   - Microsoft Entra ID (recommended)
   - Facebook, Google, Twitter, or custom OpenID Connect
3. Configure:
   - Require authentication
   - Action when request is not authenticated: Return HTTP 401/403

Azure CLI:
az webapp auth update \
  --resource-group <rg> \
  --name <app> \
  --enabled true \
  --action LoginWithAzureActiveDirectory

This ensures only authenticated users can access the application.`,
		ScreenshotGuide: "App Service → Authentication → Screenshot showing:\n- Authentication enabled\n- Identity provider configured\n- 'Require authentication' enabled",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.1",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "8.2.1",
		},
	}
}

func (c *AppServiceChecks) checkHTTPSRedirect() CheckResult {
	return CheckResult{
		Control:     "CIS-9.2",
		Name:        "[CIS Azure 9.2] HTTPS Only Redirect",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "CIS 9.2: MANUAL CHECK - Verify all App Service apps redirect HTTP to HTTPS",
		Remediation: "Enable HTTPS-only mode per CIS 9.2",
		RemediationDetail: `CIS Azure 9.2: Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service

Azure CLI:
az webapp update \
  --resource-group <rg> \
  --name <app> \
  --https-only true

Azure Portal:
App Service → Settings → Configuration → General settings → HTTPS Only = On

This forces all traffic to use encrypted connections.`,
		ScreenshotGuide: "App Service → Configuration → General settings → Screenshot 'HTTPS Only' = On",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.2",
			"PCI-DSS":   "4.2.1",
			"HIPAA":     "164.312(e)(1)",
		},
	}
}

func (c *AppServiceChecks) checkTLSVersion() CheckResult {
	return CheckResult{
		Control:     "CIS-9.3",
		Name:        "[CIS Azure 9.3] TLS Version",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "CIS 9.3: MANUAL CHECK - Verify App Service is using TLS 1.2 or higher",
		Remediation: "Set minimum TLS version to 1.2 per CIS 9.3",
		RemediationDetail: `CIS Azure 9.3: Ensure Web App is using the latest version of TLS encryption

Configure minimum TLS version:
App Service → Configuration → General settings → Minimum TLS version = 1.2 (or 1.3)

TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.

Azure CLI:
az webapp config set \
  --resource-group <rg> \
  --name <app> \
  --min-tls-version 1.2`,
		ScreenshotGuide: "App Service → Configuration → General settings → Screenshot 'Minimum TLS version' = 1.2 or 1.3",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.3",
			"PCI-DSS":   "4.2.1",
		},
	}
}

func (c *AppServiceChecks) checkClientCertificates() CheckResult {
	return CheckResult{
		Control:     "CIS-9.4",
		Name:        "[CIS Azure 9.4] Client Certificates",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "CIS 9.4: MANUAL CHECK - Verify client certificates are enabled where appropriate",
		Remediation: "Enable client certificates for mutual TLS authentication",
		RemediationDetail: `CIS Azure 9.4: Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'

Client certificates provide mutual TLS authentication - both client and server verify each other's identity.

Enable for apps requiring strong authentication:
App Service → Configuration → General settings → Incoming client certificates = On

Note: Only enable if your application is designed to validate client certificates.`,
		ScreenshotGuide: "App Service → Configuration → General settings → Screenshot 'Incoming client certificates' setting",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.4",
		},
	}
}

func (c *AppServiceChecks) checkManagedIdentity() CheckResult {
	return CheckResult{
		Control:     "CIS-9.5",
		Name:        "[CIS Azure 9.5] Managed Identity",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "CIS 9.5: MANUAL CHECK - Verify App Service apps use managed identities",
		Remediation: "Enable managed identity per CIS 9.5",
		RemediationDetail: `CIS Azure 9.5: Ensure that 'Register with Azure Active Directory' is enabled on App Service

Managed identities eliminate the need for credentials in code:
- System-assigned: Tied to app lifecycle
- User-assigned: Shared across resources

Enable:
App Service → Settings → Identity → System assigned = On

Benefits:
- No credentials in code or config
- Automatic credential rotation
- Fine-grained RBAC permissions

Azure CLI:
az webapp identity assign \
  --resource-group <rg> \
  --name <app>`,
		ScreenshotGuide: "App Service → Identity → Screenshot showing System assigned managed identity = On with Object (principal) ID",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.5",
			"SOC2":      "CC6.1",
		},
	}
}

func (c *AppServiceChecks) checkRuntimeVersions() CheckResult {
	return CheckResult{
		Control:     "CIS-9.6",
		Name:        "[CIS Azure 9.6, 9.7, 9.8] Runtime Versions",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "CIS 9.6-9.8: MANUAL CHECK - Verify PHP, Python, and Java versions are current",
		Remediation: "Use latest stable runtime versions",
		RemediationDetail: `CIS Azure 9.6: Ensure 'PHP version' is the latest, if used
CIS Azure 9.7: Ensure 'Python version' is the latest stable version, if used
CIS Azure 9.8: Ensure 'Java version' is the latest, if used

Check current runtime versions:
App Service → Configuration → General settings → Stack settings

Update to latest stable versions:
- PHP: 8.2+
- Python: 3.11+
- Java: 17 or 21
- .NET: 8.0+
- Node.js: 20.x LTS

Older versions may have unpatched security vulnerabilities.`,
		ScreenshotGuide: "App Service → Configuration → General settings → Stack settings → Screenshot showing current runtime version",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.6, 9.7, 9.8",
		},
	}
}

func (c *AppServiceChecks) checkFTPDeployment() CheckResult {
	return CheckResult{
		Control:     "CIS-9.10",
		Name:        "[CIS Azure 9.10] FTP Deployment Disabled",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "CIS 9.10: MANUAL CHECK - Verify FTP deployments are disabled",
		Remediation: "Disable FTP and require FTPS per CIS 9.10",
		RemediationDetail: `CIS Azure 9.10: Ensure FTP deployments are Disabled

FTP transmits credentials and data in plaintext.

Configure:
App Service → Configuration → General settings → FTP state = FTPS only (or Disabled)

Options:
- Disabled: No FTP/FTPS access (most secure)
- FTPS only: Encrypted FTP (acceptable)
- All allowed: Insecure (non-compliant)

Use modern deployment methods instead:
- Azure DevOps
- GitHub Actions
- Zip deploy via Azure CLI`,
		ScreenshotGuide: "App Service → Configuration → General settings → Screenshot 'FTP state' = FTPS only or Disabled",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites",
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"CIS-Azure": "9.10",
			"PCI-DSS":   "4.2.1",
		},
	}
}
