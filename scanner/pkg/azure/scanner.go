package azure

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/guardian-nexus/auditkit/scanner/pkg/azure/checks"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

type AzureScanner struct {
	subscriptionID      string
	cred                *azidentity.DefaultAzureCredential
	graphClient         *msgraphsdk.GraphServiceClient
	storageClient       *armstorage.AccountsClient
	computeClient       *armcompute.VirtualMachinesClient
	disksClient         *armcompute.DisksClient
	networkClient       *armnetwork.VirtualNetworksClient
	nsgClient           *armnetwork.SecurityGroupsClient
	nicClient           *armnetwork.InterfacesClient
	publicIPClient      *armnetwork.PublicIPAddressesClient
	sqlClient           *armsql.ServersClient
	sqlDBClient         *armsql.DatabasesClient
	keyVaultClient      *armkeyvault.VaultsClient
	monitorClient       *armmonitor.ActivityLogsClient
	diagnosticClient    *armmonitor.DiagnosticSettingsClient
	policyClient        *armstorage.ManagementPoliciesClient
	roleClient          *armauthorization.RoleAssignmentsClient
	roleDefClient       *armauthorization.RoleDefinitionsClient
	securityClient      *armsecurity.PricingsClient                 // For Defender checks
	autoProvisionClient *armsecurity.AutoProvisioningSettingsClient // For auto-provisioning
	contactsClient      *armsecurity.ContactsClient                 // For security contacts
}

type ScanResult struct {
	Control           string
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

	autoProvisionClient, err := armsecurity.NewAutoProvisioningSettingsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auto-provisioning client: %v", err)
	}

	contactsClient, err := armsecurity.NewContactsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create security contacts client: %v", err)
	}

	return &AzureScanner{
		subscriptionID:      subscriptionID,
		cred:                cred,
		graphClient:         graphClient,
		storageClient:       storageClient,
		computeClient:       computeClient,
		disksClient:         disksClient,
		networkClient:       networkClient,
		nsgClient:           nsgClient,
		nicClient:           nicClient,
		publicIPClient:      publicIPClient,
		sqlClient:           sqlClient,
		sqlDBClient:         sqlDBClient,
		keyVaultClient:      keyVaultClient,
		monitorClient:       monitorClient,
		diagnosticClient:    diagnosticClient,
		policyClient:        policyClient,
		roleClient:          roleClient,
		roleDefClient:       roleDefClient,
		securityClient:      securityClient,
		autoProvisionClient: autoProvisionClient,
		contactsClient:      contactsClient,
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
	case "all":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
		results = append(results, s.runCISChecks(ctx, verbose)...)
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

func (s *AzureScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running SOC2 compliance checks for Azure...")
	}

	// Run SOC2 CC1-CC9 check modules
	soc2Checks := []checks.Check{
		checks.NewAzureCC1Checks(s.roleClient, s.roleDefClient),
		checks.NewAzureCC2Checks(),
		checks.NewAzureCC3Checks(s.monitorClient),
		checks.NewAzureCC4Checks(s.monitorClient),
		checks.NewAzureCC5Checks(s.keyVaultClient),
		checks.NewAzureCC6Wrapper(),
		checks.NewAzureCC7Checks(),
		checks.NewAzureCC8Checks(),
		checks.NewAzureCC9Checks(),
		checks.NewAzureAvailabilityConfidentialityChecks(s.storageClient, s.policyClient),
		checks.NewStorageChecks(s.storageClient),
		checks.NewAADChecks(s.roleClient, s.roleDefClient, s.graphClient),
		checks.NewComputeChecks(s.computeClient, s.disksClient, s.nicClient, s.publicIPClient),
		checks.NewNetworkChecks(s.nsgClient),
		checks.NewSQLChecks(s.sqlDBClient, s.sqlClient),
		checks.NewKeyVaultChecks(s.keyVaultClient),
		checks.NewMonitoringChecks(s.monitorClient, s.subscriptionID),
		checks.NewIdentityChecks(s.subscriptionID),
	}

	for _, check := range soc2Checks {
		if verbose {
			fmt.Printf("  Running %s...\n", check.Name())
		}

		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("    Warning in %s: %v\n", check.Name(), err)
		}

		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          cr.Priority.Level,
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}

	return results
}

func (s *AzureScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running PCI-DSS v4.0.1 checks for Azure...")
		fmt.Println("Checking all 12 PCI-DSS requirements...")
	}

	// Use the comprehensive AzurePCIChecks implementation
	pciChecker := checks.NewAzurePCIChecks(
		s.storageClient,
		s.nsgClient,
		s.roleClient,
		s.sqlDBClient,
		s.monitorClient,
		s.graphClient,
		s.diagnosticClient,
		s.subscriptionID,
	)

	checkResults, _ := pciChecker.Run(ctx)
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results
}

func (s *AzureScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running CMMC Level 1 (17 practices) - Open Source")
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

	level1 := checks.NewAzureCMMCLevel1Checks(s.roleClient, s.storageClient, s.nsgClient, s.graphClient, s.subscriptionID)
	results1, _ := level1.Run(ctx)
	for _, cr := range results1 {
		results = append(results, ScanResult{
			Control:           cr.Control,
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

	if verbose {
		fmt.Printf("\nCMMC Level 1 scan complete: %d controls tested\n", len(results))
		fmt.Println("")
		fmt.Println("UNLOCK CMMC LEVEL 2:")
		fmt.Println("  - 110 additional Level 2 practices for CUI")
		fmt.Println("  - Required for DoD contractors handling CUI")
		fmt.Println("  - Complete evidence collection guides")
		fmt.Println("  - November 10, 2025 deadline compliance")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro for full CMMC Level 2")
	}

	return results
}

func (s *AzureScanner) runCISChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running CIS Microsoft Azure Foundations Benchmark v3.0")
		fmt.Println("")
	}

	// Run existing Azure check modules - they now return results with CIS mappings
	checkModules := []checks.Check{
		checks.NewAADChecks(s.roleClient, s.roleDefClient, s.graphClient),
		checks.NewStorageChecks(s.storageClient),
		checks.NewComputeChecks(s.computeClient, s.disksClient, s.nicClient, s.publicIPClient),
		checks.NewNetworkChecks(s.nsgClient),
		checks.NewSQLChecks(s.sqlDBClient, s.sqlClient),
		checks.NewKeyVaultChecks(s.keyVaultClient),
		checks.NewMonitoringChecks(s.monitorClient, s.subscriptionID),
		checks.NewIdentityChecks(s.subscriptionID),
		// Add CIS manual checks for Azure Monitor alerts
		checks.NewAzureCISManualChecks(s.subscriptionID),
		// Add Microsoft Defender for Cloud checks - NOW AUTOMATED!
		checks.NewDefenderChecks(s.subscriptionID, s.securityClient, s.autoProvisionClient, s.contactsClient),
		// Add App Service checks
		checks.NewAppServiceChecks(s.subscriptionID),
	}

	// Track which CIS sections we're covering
	sectionCounts := make(map[string]int)

	for _, check := range checkModules {
		if verbose {
			fmt.Printf("  Running %s...\n", check.Name())
		}

		checkResults, checkErr := check.Run(ctx)
		if checkErr != nil && verbose {
			fmt.Printf("    Warning: %v\n", checkErr)
		}

		for _, cr := range checkResults {
			// Check if this control has CIS-Azure mapping in Frameworks
			if cr.Frameworks != nil && cr.Frameworks["CIS-Azure"] != "" {
				cisControls := cr.Frameworks["CIS-Azure"]

				// Track section coverage - parse section number from control ID or framework value
				// Handle various formats: "1.1", "1.1, 1.2", "2.1.1", etc.
				section := ""
				if strings.HasPrefix(cr.Control, "CIS-") {
					// Extract from Control ID like "CIS-1.1" or "CIS-2.1.1"
					parts := strings.Split(cr.Control, "-")
					if len(parts) > 1 {
						// Get first character after "CIS-"
						section = string(parts[1][0])
					}
				} else if len(cisControls) > 0 {
					// Extract from Frameworks value like "1.1" or "2.1.1"
					section = string(cisControls[0])
				}

				// Map section number to section name
				switch section {
				case "1":
					sectionCounts["Identity and Access Management"]++
				case "2":
					sectionCounts["Microsoft Defender for Cloud"]++
				case "3":
					sectionCounts["Storage Accounts"]++
				case "4":
					sectionCounts["Database Services"]++
				case "5":
					sectionCounts["Logging and Monitoring"]++
				case "6":
					sectionCounts["Networking"]++
				case "7":
					sectionCounts["Virtual Machines"]++
				case "8":
					sectionCounts["Key Vault"]++
				case "9":
					sectionCounts["AppService"]++
				}

				results = append(results, ScanResult{
					Control:           cr.Control,
					Status:            cr.Status,
					Evidence:          cr.Evidence,
					Remediation:       cr.Remediation,
					RemediationDetail: cr.RemediationDetail,
					Severity:          cr.Priority.Level,
					ScreenshotGuide:   cr.ScreenshotGuide,
					ConsoleURL:        cr.ConsoleURL,
					Frameworks:        cr.Frameworks,
				})
			}
		}
	}

	if verbose {
		fmt.Printf("\nCIS Azure scan complete: %d controls tested\n", len(results))
		if len(sectionCounts) > 0 {
			fmt.Println("\nSection Coverage:")
			for section, count := range sectionCounts {
				fmt.Printf("  %s: %d controls\n", section, count)
			}
		}
		fmt.Println("\nNote: CIS Azure Benchmark v3.0 has ~100 total controls")
		fmt.Println("This scan covers controls automatable via Azure API")
		fmt.Println("")
	}

	return results
}
