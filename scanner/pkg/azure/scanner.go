package azure

import (
	"context"
	"fmt"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
	"os"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/azure/checks"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/vuln/azuredefender"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

type AzureScanner struct {
	// Cached result of runSuites, so the shared suite list runs once per scan.
	suiteCache  []ScanResult
	suiteCached bool

	subscriptionID      string
	cred                *azidentity.DefaultAzureCredential
	graphClient         *msgraphsdk.GraphServiceClient
	storageClient       *armstorage.AccountsClient
	aksClient           *armcontainerservice.ManagedClustersClient
	computeClient       *armcompute.VirtualMachinesClient
	disksClient         *armcompute.DisksClient
	networkClient       *armnetwork.VirtualNetworksClient
	nsgClient           *armnetwork.SecurityGroupsClient
	nicClient           *armnetwork.InterfacesClient
	publicIPClient      *armnetwork.PublicIPAddressesClient
	appGatewayClient    *armnetwork.ApplicationGatewaysClient
	wafPolicyClient     *armnetwork.WebApplicationFirewallPoliciesClient
	watcherClient       *armnetwork.WatchersClient
	flowLogClient       *armnetwork.FlowLogsClient
	vpnGatewayClient    *armnetwork.VirtualNetworkGatewaysClient
	bastionClient       *armnetwork.BastionHostsClient
	kvKeysClient        *armkeyvault.KeysClient
	kvSecretsClient     *armkeyvault.SecretsClient
	databricksClient    *armdatabricks.WorkspacesClient
	sqlClient           *armsql.ServersClient
	sqlDBClient         *armsql.DatabasesClient
	keyVaultClient      *armkeyvault.VaultsClient
	monitorClient       *armmonitor.ActivityLogsClient
	diagnosticClient    *armmonitor.DiagnosticSettingsClient
	policyClient        *armstorage.ManagementPoliciesClient
	autoscaleClient     *armmonitor.AutoscaleSettingsClient
	alertClient         *armmonitor.ActivityLogAlertsClient
	insightsClient      *armapplicationinsights.ComponentsClient
	blobServiceClient   *armstorage.BlobServicesClient
	fileServiceClient   *armstorage.FileServicesClient
	roleClient          *armauthorization.RoleAssignmentsClient
	roleDefClient       *armauthorization.RoleDefinitionsClient
	securityClient      *armsecurity.PricingsClient // For Defender checks
	subAssessClient     *armsecurity.SubAssessmentsClient
	autoProvisionClient *armsecurity.AutoProvisioningSettingsClient // For auto-provisioning
	contactsClient      *armsecurity.ContactsClient                 // For security contacts
	assessmentsClient   *armsecurity.AssessmentsClient              // Defender's own recommendation results
}

type ScanResult struct {
	Control           string
	Name              string
	Status            string
	Evidence          string
	Remediation       string
	RemediationDetail string
	Severity          string
	ScreenshotGuide   string
	ConsoleURL        string
	Frameworks        map[string]string
}

func NewScanner(subscriptionID string) (*AzureScanner, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %v", err)
	}

	// Create Microsoft Graph client
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return nil, fmt.Errorf("failed to create Graph client: %v", err)
	}

	// Create Azure Resource Manager clients
	storageClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %v", err)
	}

	// CIS AKS coverage is free in both editions: the benchmark is published
	// free, so the paid tier differs by capability - evidence packages,
	// multi-account, monitoring - not by which requirements you may see.
	aksClient, err := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client: %v", err)
	}

	computeClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %v", err)
	}

	disksClient, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create disks client: %v", err)
	}

	networkClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create network client: %v", err)
	}

	nsgClient, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NSG client: %v", err)
	}

	nicClient, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NIC client: %v", err)
	}

	publicIPClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create public IP client: %v", err)
	}

	// The section 7 networking recommendations read five different resources.
	// networkClient is already the virtual networks client, so it serves the
	// subnet and resource-group enumeration. The rest are optional: each check
	// reports ERROR when its own client is absent rather than passing on data
	// it never saw.
	appGatewayClient, err := armnetwork.NewApplicationGatewaysClient(subscriptionID, cred, nil)
	if err != nil {
		appGatewayClient = nil
	}
	wafPolicyClient, err := armnetwork.NewWebApplicationFirewallPoliciesClient(subscriptionID, cred, nil)
	if err != nil {
		wafPolicyClient = nil
	}
	watcherClient, err := armnetwork.NewWatchersClient(subscriptionID, cred, nil)
	if err != nil {
		watcherClient = nil
	}
	flowLogClient, err := armnetwork.NewFlowLogsClient(subscriptionID, cred, nil)
	if err != nil {
		flowLogClient = nil
	}
	vpnGatewayClient, err := armnetwork.NewVirtualNetworkGatewaysClient(subscriptionID, cred, nil)
	if err != nil {
		vpnGatewayClient = nil
	}
	bastionClient, err := armnetwork.NewBastionHostsClient(subscriptionID, cred, nil)
	if err != nil {
		bastionClient = nil
	}

	// The key and secret objects, for the section 8.3 expiry and rotation
	// recommendations. The vault client alone cannot see them.
	kvKeysClient, err := armkeyvault.NewKeysClient(subscriptionID, cred, nil)
	if err != nil {
		kvKeysClient = nil
	}
	kvSecretsClient, err := armkeyvault.NewSecretsClient(subscriptionID, cred, nil)
	if err != nil {
		kvSecretsClient = nil
	}
	databricksClient, err := armdatabricks.NewWorkspacesClient(subscriptionID, cred, nil)
	if err != nil {
		databricksClient = nil
	}

	sqlClient, err := armsql.NewServersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL client: %v", err)
	}

	sqlDBClient, err := armsql.NewDatabasesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL DB client: %v", err)
	}

	keyVaultClient, err := armkeyvault.NewVaultsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault client: %v", err)
	}

	monitorClient, err := armmonitor.NewActivityLogsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor client: %v", err)
	}

	// Diagnostic settings are addressed by resource URI rather than subscription.
	// A failure here is not fatal: the checks that use it degrade to manual.
	diagnosticClient, err := armmonitor.NewDiagnosticSettingsClient(cred, nil)
	if err != nil {
		diagnosticClient = nil
	}

	// Blob lifecycle policies. Optional: the checks that use it degrade to manual.
	policyClient, err := armstorage.NewManagementPoliciesClient(subscriptionID, cred, nil)
	if err != nil {
		policyClient = nil
	}

	// Capacity and blob retention. Optional: checks degrade to manual.
	autoscaleClient, err := armmonitor.NewAutoscaleSettingsClient(subscriptionID, cred, nil)
	if err != nil {
		autoscaleClient = nil
	}

	// Activity log alert rules and Application Insights answer CIS Azure
	// section 6.1.2 and 6.1.3. Constructed here, with the field, on purpose:
	// a field declared without its constructor is a nil client, which fails
	// every recommendation for want of data instead of reporting a finding.
	alertClient, err := armmonitor.NewActivityLogAlertsClient(subscriptionID, cred, nil)
	if err != nil {
		alertClient = nil
	}
	insightsClient, err := armapplicationinsights.NewComponentsClient(subscriptionID, cred, nil)
	if err != nil {
		insightsClient = nil
	}
	blobServiceClient, err := armstorage.NewBlobServicesClient(subscriptionID, cred, nil)
	if err != nil {
		blobServiceClient = nil
	}
	fileServiceClient, err := armstorage.NewFileServicesClient(subscriptionID, cred, nil)
	if err != nil {
		fileServiceClient = nil
	}

	roleClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %v", err)
	}

	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %v", err)
	}

	// FIXED: Security Center clients - removed subscriptionID from constructor
	securityClient, err := armsecurity.NewPricingsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create security pricing client: %v", err)
	}

	subAssessClient, err := armsecurity.NewSubAssessmentsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sub-assessments client: %v", err)
	}

	autoProvisionClient, err := armsecurity.NewAutoProvisioningSettingsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auto-provisioning client: %v", err)
	}

	contactsClient, err := armsecurity.NewContactsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create security contacts client: %v", err)
	}

	// Defender's own recommendation results, which is where the operating
	// system update assessment surfaces. Constructed with its field, not
	// declared and left nil.
	assessmentsClient, err := armsecurity.NewAssessmentsClient(cred, nil)
	if err != nil {
		assessmentsClient = nil
	}

	return &AzureScanner{
		subscriptionID:      subscriptionID,
		cred:                cred,
		graphClient:         graphClient,
		storageClient:       storageClient,
		aksClient:           aksClient,
		computeClient:       computeClient,
		disksClient:         disksClient,
		networkClient:       networkClient,
		nsgClient:           nsgClient,
		nicClient:           nicClient,
		publicIPClient:      publicIPClient,
		appGatewayClient:    appGatewayClient,
		wafPolicyClient:     wafPolicyClient,
		watcherClient:       watcherClient,
		flowLogClient:       flowLogClient,
		vpnGatewayClient:    vpnGatewayClient,
		bastionClient:       bastionClient,
		kvKeysClient:        kvKeysClient,
		kvSecretsClient:     kvSecretsClient,
		databricksClient:    databricksClient,
		sqlClient:           sqlClient,
		sqlDBClient:         sqlDBClient,
		keyVaultClient:      keyVaultClient,
		monitorClient:       monitorClient,
		diagnosticClient:    diagnosticClient,
		policyClient:        policyClient,
		autoscaleClient:     autoscaleClient,
		alertClient:         alertClient,
		insightsClient:      insightsClient,
		blobServiceClient:   blobServiceClient,
		fileServiceClient:   fileServiceClient,
		roleClient:          roleClient,
		roleDefClient:       roleDefClient,
		securityClient:      securityClient,
		subAssessClient:     subAssessClient,
		autoProvisionClient: autoProvisionClient,
		contactsClient:      contactsClient,
		assessmentsClient:   assessmentsClient,
	}, nil
}

func (s *AzureScanner) GetSubscriptionID() string {
	return s.subscriptionID
}

func (s *AzureScanner) GetAccountID(ctx context.Context) string {
	return s.subscriptionID
}

func (s *AzureScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]ScanResult, error) {
	// Check if Azure credentials are configured
	if os.Getenv("AZURE_SUBSCRIPTION_ID") == "" {
		if verbose {
			fmt.Println("Error: Not connected to Azure. Please configure Azure credentials.")
			fmt.Println("Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
		}
		return nil, fmt.Errorf("Azure connection failed: credentials not configured")
	}

	var results []ScanResult
	framework = strings.ToLower(framework)

	switch framework {
	case "soc2":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	case "pci", "pci-dss":
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	case "cmmc":
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
	case "cis", "cis-azure":
		results = append(results, s.runCISChecks(ctx, verbose)...)
	case "all",
		// Derived frameworks are reported through the crosswalk, which can
		// map any suite's findings. Falling through to the SOC2 suite alone
		// meant an 800-53, ISO or HIPAA scan never saw the PCI, CMMC or CIS
		// checks that map onto it.
		"800-53", "nist800-53", "nist-800-53", "iso27001", "iso-27001", "gdpr", "nist-csf", "csf", "hipaa", "fedramp-low", "fedramp-moderate", "fedramp-high":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
		results = append(results, s.runCISChecks(ctx, verbose)...)
		// The paths share one suite list, so the same finding arrives once
		// per path.
		results = dedupeIdenticalResults(results)
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

// allSuites is every check suite this provider has, constructed once.
//
// Each framework path used to hand-pick its own subset, so a suite claiming a
// framework ran only if somebody had remembered to add it to that path. The PCI
// path built four suites while more than thirty carried PCI tags, so a PCI scan
// reported a fraction of what the mappings already covered.
//
// The framework filter belongs at the report layer, where
// controlMatchesFramework already applies it - including to the results that
// carry no Frameworks field and match through their control id in the
// framework's catalog, which an in-scan filter on tag presence drops.
//
// Every framework path runs this list exactly once, through runSuites, and
// constructs no suite of its own. A path that built a suite here as well ran
// it twice and reported every one of its rows twice, with each FAIL counted
// twice in the score.
func (s *AzureScanner) allSuites() []checks.Check {
	return []checks.Check{
		checks.NewDefenderChecks(s.subscriptionID, s.securityClient, s.autoProvisionClient, s.contactsClient),
		checks.NewAKSChecks(s.aksClient, s.subscriptionID), // CIS AKS v1.8.0
		checks.NewAzureCISManualChecks(s.subscriptionID),
		checks.NewCISFoundationsManualChecks(),                                                // CIS Azure Foundations v6.0.0, the Manual recommendations
		checks.NewCISStorageChecks(s.storageClient, s.blobServiceClient, s.fileServiceClient), // CIS Azure v6.0.0 section 9
		checks.NewCISActivityAlertChecks(s.alertClient, s.insightsClient, s.subscriptionID),   // CIS Azure v6.0.0 sections 6.1.2 and 6.1.3
		checks.NewCISIdentityDefenderChecks(s.roleClient, s.roleDefClient, s.securityClient, // CIS Azure v6.0.0 sections 5.3.3, 5.4 and 8.1
			s.contactsClient, s.assessmentsClient, s.subscriptionID),
		checks.NewCISNetworkChecks(s.appGatewayClient, s.wafPolicyClient, s.networkClient, // CIS Azure v6.0.0 section 7
			s.watcherClient, s.flowLogClient, s.vpnGatewayClient, s.bastionClient),
		checks.NewCISKeyVaultChecks(s.keyVaultClient, s.kvKeysClient, s.kvSecretsClient),       // CIS Azure v6.0.0 section 8.3
		checks.NewCISDatabricksChecks(s.databricksClient, s.networkClient, s.diagnosticClient), // CIS Azure v6.0.0 section 2.1
		checks.NewAppServiceChecks(s.subscriptionID),
		checks.NewAzureCC1Checks(s.roleClient, s.roleDefClient),
		checks.NewAzureCC2Checks(),
		checks.NewAzureCC3Checks(s.monitorClient),
		checks.NewAzureCC4Checks(s.monitorClient),
		checks.NewAzureCC5Checks(s.keyVaultClient),
		checks.NewAzureCC6Wrapper(),
		checks.NewAzureCC7Checks(),
		checks.NewAzureCC8Checks(),
		checks.NewAzureCC9Checks(),
		checks.NewAzureAvailabilityConfidentialityChecks(s.storageClient, s.policyClient, s.autoscaleClient, s.blobServiceClient),
		checks.NewStorageChecks(s.storageClient),
		checks.NewAADChecks(s.roleClient, s.roleDefClient, s.graphClient),
		checks.NewComputeChecks(s.computeClient, s.disksClient, s.nicClient, s.publicIPClient),
		checks.NewNetworkChecks(s.nsgClient),
		checks.NewSQLChecks(s.sqlDBClient, s.sqlClient),
		checks.NewKeyVaultChecks(s.keyVaultClient),
		checks.NewMonitoringChecks(s.monitorClient, s.subscriptionID),
		checks.NewIdentityChecks(s.subscriptionID),
		checks.NewAzureCMMCLevel1Checks(s.roleClient, s.storageClient, s.nsgClient, s.graphClient, s.subscriptionID),
		// PCI-DSS v4.0.1 requirements. Previously constructed by the PCI path
		// alone, which is the one place a suite must not be built.
		checks.NewAzurePCIChecks(s.storageClient, s.nsgClient, s.roleClient, s.sqlDBClient,
			s.monitorClient, s.graphClient, s.diagnosticClient, s.subscriptionID),
	}
}

// runSuites runs every suite and converts the results. Shared by the framework
// paths so none of them can quietly run a different set.
func (s *AzureScanner) runSuites(ctx context.Context, verbose bool) []ScanResult {
	// Run once per scan. The framework paths share this list, so a scan
	// that calls several of them would otherwise re-run every suite.
	if s.suiteCached {
		return append([]ScanResult(nil), s.suiteCache...)
	}
	var results []ScanResult
	for _, check := range s.allSuites() {
		if verbose {
			fmt.Printf("   Running %s...\n", check.Name())
		}
		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("     Warning in %s: %v\n", check.Name(), err)
		}
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Name:              cr.Name,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          severityOf(cr),
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}
	s.suiteCache, s.suiteCached = results, true
	return append([]ScanResult(nil), results...)
}

// severityOf reads a result's severity from whichever field the suite filled.
// The AWS and Azure suites mostly set Severity; a few set only Priority.Level,
// and the framework paths that used to run those suites directly read that
// field. Now that every suite reaches the report through runSuites, a blank
// here would drop a HIGH finding to LOW at the report layer.
func severityOf(cr checks.CheckResult) string {
	if cr.Severity != "" {
		return cr.Severity
	}
	return cr.Priority.Level
}
func (s *AzureScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running SOC2 compliance checks for Azure...")
	}

	// Run SOC2 CC1-CC9 check modules

	results = append(results, s.runSuites(ctx, verbose)...)

	return results
}

// runVulnCoverage builds the vulnerability coverage check for one framework and
// converts its results. emit keeps the CMMC and PCI passes from each reporting
// the other's control, which would double-count it on a scan of all frameworks.
func (s *AzureScanner) runVulnCoverage(ctx context.Context, emit checks.Emit) []ScanResult {
	vc := checks.NewVulnCoverageChecks(azuredefender.Clients{
		Pricing:        s.securityClient,
		SubAssessments: s.subAssessClient,
		VMs:            s.computeClient,
	}, s.subscriptionID, emit)
	crs, err := vc.Run(ctx)
	if err != nil {
		return nil
	}
	out := make([]ScanResult, 0, len(crs))
	for _, cr := range crs {
		out = append(out, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	return out
}

func (s *AzureScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Println("Running PCI-DSS v4.0.1 checks for Azure...")
	}

	// Every suite, once. The PCI requirements suite is in allSuites with the
	// rest; building it here as well ran it twice.
	//
	// runSuites hands back the per-scan cache. Clone it before appending, or
	// this path's extra rows land in the cache's spare capacity, where the next
	// path to append would overwrite them.
	results := slices.Clone(s.runSuites(ctx, verbose))

	// PCI-DSS 11.3.1 wants scans quarterly across every in-scope system.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitPCI)...)

	return results
}

func (s *AzureScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Println("Running CMMC - all 110 practices reported, the technical ones measured")
		fmt.Println("")
		fmt.Println("IMPORTANT DISCLAIMER:")
		fmt.Println("This scanner tests technical controls that can be automated.")
		fmt.Println("")
		fmt.Println("CMMC Level 1 requires 17 practices. Many controls require")
		fmt.Println("organizational documentation and policies that cannot be")
		fmt.Println("verified through automated scanning.")
		fmt.Println("")
		fmt.Println("A high automated check score does NOT mean you are CMMC")
		fmt.Println("compliant. This is a technical assessment tool, not a")
		fmt.Println("compliance certification.")
		fmt.Println("")
	}

	// Every suite, once. The Level 1 suite is in allSuites with the rest;
	// building it here as well reported each practice it measures twice.
	results := slices.Clone(s.runSuites(ctx, verbose))

	// Vulnerability scan coverage, read from Defender rather than asked for as a document.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitCMMC)...)

	// Every practice nothing above reported, reported as a manual requirement.
	// A CMMC report's denominator is the benchmark's 110, not the subset this
	// provider can automate, or a reader cannot tell an absent practice from a
	// satisfied one. This runs after every suite, so a practice a non-CMMC
	// suite answered is not reported again as unanswered.
	results = append(results, s.reportRemainingCMMCPractices(ctx, results)...)
	results = append(results, s.reportRemainingCISAKS(ctx, results)...)

	if verbose {
		fmt.Printf("\nCMMC scan complete: all %d practices reported\n", mappings.CMMCPracticeCount)
		fmt.Println("")
		fmt.Println("WHAT AUDITKIT PRO ADDS:")
		fmt.Println("  - More of the 110 practices measured rather than asked for")
		fmt.Println("  - Evidence packages an assessor can read directly")
		fmt.Println("  - Multi-account scanning and continuous monitoring")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro")
	}

	return results
}

// reportRemainingCMMCPractices fills in the practices the suites above did not
// name. The covered set is computed from the results just produced rather than
// kept by hand, so adding an automated check for a practice removes it from
// here automatically instead of leaving it reported twice.
func (s *AzureScanner) reportRemainingCMMCPractices(ctx context.Context, reported []ScanResult) []ScanResult {
	covered := map[string]bool{}
	for _, r := range reported {
		covered[r.Control] = true
		// A tag may name more than one practice. None do today, but a
		// single-key read would silently report both of them again.
		for _, id := range strings.Split(r.Frameworks["CMMC"], ",") {
			if id = strings.TrimSpace(id); id != "" {
				covered[id] = true
			}
		}
	}
	var out []ScanResult
	rows, _ := checks.NewCMMCPracticeReport(covered).Run(ctx)
	for _, cr := range rows {
		out = append(out, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	return out
}

func (s *AzureScanner) runCISChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		cisEd, _ := mappings.EditionFor("CIS-Azure")
		fmt.Println("Running " + cisEd.Describe())
	}

	// Every suite, once. This path used to build eleven suites of its own and
	// never call runSuites, so the CIS Azure v6.0.0 suites never ran on a
	// cis-azure scan; it also kept only the rows tagged CIS-Azure, dropping a
	// recommendation answered under its control id alone. The framework filter
	// lives at the report layer, in controlMatchesFramework.
	return slices.Clone(s.runSuites(ctx, verbose))
}

// dedupeIdenticalResults removes results that are the same finding reported by
// more than one framework path. It keys on control, status and evidence, so
// genuinely distinct findings that share a control id - several resources
// failing the same criterion - are preserved.
//
// Needed since the framework paths share one suite list: a scan that runs
// several of them, which is what the derived frameworks do, would otherwise
// report every finding once per path.
func dedupeIdenticalResults(results []ScanResult) []ScanResult {
	seen := make(map[string]bool, len(results))
	deduped := make([]ScanResult, 0, len(results))
	for _, result := range results {
		key := result.Control + "\x00" + result.Status + "\x00" + result.Evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, result)
	}
	return deduped
}

// reportRemainingCISAKS accounts for the CIS-AKS recommendations the checks
// above did not reach. The assessed set is derived from the results just
// produced, so answering one removes it from the gap rather than leaving it
// counted both ways.
func (s *AzureScanner) reportRemainingCISAKS(ctx context.Context, reported []ScanResult) []ScanResult {
	assessed := map[string]bool{}
	for _, r := range reported {
		for _, id := range strings.Split(r.Frameworks["CIS-AKS"], ",") {
			if id = strings.TrimSpace(id); id != "" {
				assessed[id] = true
			}
		}
	}
	rows, _ := checks.NewCISAKSReport(assessed).Run(ctx)
	var out []ScanResult
	for _, cr := range rows {
		out = append(out, ScanResult{
			Control:         cr.Control,
			Name:            cr.Name,
			Status:          cr.Status,
			Evidence:        cr.Evidence,
			Remediation:     cr.Remediation,
			Severity:        cr.Severity,
			ScreenshotGuide: cr.ScreenshotGuide,
			Frameworks:      cr.Frameworks,
		})
	}
	return out
}
