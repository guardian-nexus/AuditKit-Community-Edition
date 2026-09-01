package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
)

type ComputeChecks struct {
	service   *compute.Service
	projectID string
}

func NewComputeChecks(service *compute.Service, projectID string) *ComputeChecks {
	return &ComputeChecks{service: service, projectID: projectID}
}

func (c *ComputeChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Existing checks
	results = append(results, c.CheckDiskEncryption(ctx)...)
	results = append(results, c.CheckPublicIPs(ctx)...)
	results = append(results, c.CheckOSPatchManagement(ctx)...)

	// NEW CIS checks
	results = append(results, c.CheckOSLogin(ctx)...)
	results = append(results, c.CheckShieldedVM(ctx)...)
	results = append(results, c.CheckSerialPortAccess(ctx)...)
	results = append(results, c.CheckIPForwarding(ctx)...)
	results = append(results, c.CheckProjectSSHKeys(ctx)...)

	// Additional CIS checks for 100% coverage
	results = append(results, c.CheckDefaultServiceAccountFullAccess(ctx)...)
	results = append(results, c.CheckConfidentialComputing(ctx)...)
	results = append(results, c.CheckShieldedVMEnabled(ctx)...)
	results = append(results, c.CheckInstancePublicIPs(ctx)...)

	return results, nil
}

func (c *ComputeChecks) CheckDiskEncryption(ctx context.Context) []CheckResult {
	var results []CheckResult
	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	unencryptedDisks := []string{}
	totalDisks := 0

	for _, zone := range zones.Items {
		diskList, err := c.service.Disks.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, disk := range diskList.Items {
			totalDisks++
			if disk.DiskEncryptionKey == nil || disk.DiskEncryptionKey.KmsKeyName == "" {
				unencryptedDisks = append(unencryptedDisks, disk.Name)
			}
		}
	}

	if len(unencryptedDisks) > 0 {
		displayDisks := unencryptedDisks
		if len(unencryptedDisks) > 3 {
			displayDisks = unencryptedDisks[:3]
		}

		results = append(results, CheckResult{
			Control:           "CC6.7",
			Name:              "Disk Encryption with CMEK",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d disks using Google-managed keys instead of customer-managed keys: %v | Violates PCI DSS 3.5.1", len(unencryptedDisks), displayDisks),
			Remediation:       "Use customer-managed encryption keys (CMEK) for sensitive data",
			RemediationDetail: "Create new disk with --kms-key flag or enable default CMEK for project",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "Compute Engine → Disks → Select disk → Encryption showing KMS key",
			ConsoleURL:        "https://console.cloud.google.com/compute/disks",
			Frameworks:        GetFrameworkMappings("COMPUTE_DISK_ENCRYPTION"),
		})
	} else if totalDisks > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.7",
			Name:       "Disk Encryption with CMEK",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d disks use customer-managed encryption | Meets PCI DSS 3.5.1", totalDisks),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_DISK_ENCRYPTION"),
		})
	}

	return results
}

func (c *ComputeChecks) CheckPublicIPs(ctx context.Context) []CheckResult {
	var results []CheckResult
	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithPublicIP := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.AccessConfigs != nil && len(networkInterface.AccessConfigs) > 0 {
					instancesWithPublicIP = append(instancesWithPublicIP, instance.Name)
					break
				}
			}
		}
	}

	if len(instancesWithPublicIP) > 0 {
		displayInstances := instancesWithPublicIP
		if len(instancesWithPublicIP) > 3 {
			displayInstances = instancesWithPublicIP[:3]
		}

		results = append(results, CheckResult{
			Control:           "CC6.6",
			Name:              "Compute Instances - Public IP Addresses",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d instances have public IP addresses: %v | Violates PCI DSS 1.4.2", len(instancesWithPublicIP), displayInstances),
			Remediation:       "Use Cloud NAT or VPN for outbound connectivity",
			RemediationDetail: "Remove external IPs and configure Cloud NAT for internet access",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "Compute Engine → VM instances → External IP column showing 'None'",
			ConsoleURL:        "https://console.cloud.google.com/compute/instances",
			Frameworks:        GetFrameworkMappings("COMPUTE_PUBLIC_IP"),
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.6",
			Name:       "Compute Instances - Public IP Addresses",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances use private IPs only | Meets PCI DSS 1.4.2", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_PUBLIC_IP"),
		})
	}

	return results
}

func (c *ComputeChecks) CheckOSPatchManagement(ctx context.Context) []CheckResult {
	var results []CheckResult

	results = append(results, CheckResult{
		Control:           "CC7.1",
		Name:              "OS Patch Management",
		Status:            "INFO",
		Severity:          "MEDIUM",
		Evidence:          "Manual verification required: Verify OS Config patch management is enabled",
		Remediation:       "Enable OS patch management via OS Config API",
		RemediationDetail: "gcloud compute os-config patch-deployments create monthly-patches --project=PROJECT_ID",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		ScreenshotGuide:   "Compute Engine → VM Manager → Patch management → Screenshot of patch policies",
		ConsoleURL:        "https://console.cloud.google.com/compute/osconfig",
		Frameworks: map[string]string{
			"SOC2":    "CC7.1",
			"PCI-DSS": "6.3.3",
		},
	})

	return results
}

// CheckOSLogin verifies OS Login is enabled (CIS 4.4)
func (c *ComputeChecks) CheckOSLogin(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithoutOSLogin := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check metadata for enable-oslogin
			hasOSLogin := false
			if instance.Metadata != nil {
				for _, item := range instance.Metadata.Items {
					if item.Key == "enable-oslogin" && item.Value != nil && *item.Value == "TRUE" {
						hasOSLogin = true
						break
					}
				}
			}

			if !hasOSLogin {
				instancesWithoutOSLogin = append(instancesWithoutOSLogin, instance.Name)
			}
		}
	}

	if len(instancesWithoutOSLogin) > 0 {
		displayInstances := instancesWithoutOSLogin
		if len(instancesWithoutOSLogin) > 3 {
			displayInstances = instancesWithoutOSLogin[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.4",
			Name:        "[CIS GCP 4.4] OS Login Enabled",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 4.4: %d instances do not have OS Login enabled: %v | OS Login provides centralized SSH key management", len(instancesWithoutOSLogin), displayInstances),
			Remediation: "Enable OS Login for centralized SSH access management",
			RemediationDetail: `# Enable OS Login project-wide
gcloud compute project-info add-metadata \
  --metadata enable-oslogin=TRUE

# Or per-instance
gcloud compute instances add-metadata INSTANCE_NAME \
  --zone=ZONE \
  --metadata enable-oslogin=TRUE`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → Metadata → Screenshot showing enable-oslogin=TRUE",
			ConsoleURL:      "https://console.cloud.google.com/compute/metadata",
			Frameworks:      GetFrameworkMappings("COMPUTE_OS_LOGIN"),
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.4",
			Name:       "[CIS GCP 4.4] OS Login Enabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances have OS Login enabled | Meets CIS 4.4", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_OS_LOGIN"),
		})
	}

	return results
}

// CheckShieldedVM verifies Shielded VM features are enabled (CIS 4.8)
func (c *ComputeChecks) CheckShieldedVM(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithoutShieldedVM := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check if Shielded VM features are enabled
			if instance.ShieldedInstanceConfig == nil ||
				!instance.ShieldedInstanceConfig.EnableSecureBoot ||
				!instance.ShieldedInstanceConfig.EnableVtpm ||
				!instance.ShieldedInstanceConfig.EnableIntegrityMonitoring {
				instancesWithoutShieldedVM = append(instancesWithoutShieldedVM, instance.Name)
			}
		}
	}

	if len(instancesWithoutShieldedVM) > 0 {
		displayInstances := instancesWithoutShieldedVM
		if len(instancesWithoutShieldedVM) > 3 {
			displayInstances = instancesWithoutShieldedVM[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.8",
			Name:        "[CIS GCP 4.8] Shielded VM Features",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 4.8: %d instances lack full Shielded VM protection: %v | Should enable vTPM, Secure Boot, and Integrity Monitoring", len(instancesWithoutShieldedVM), displayInstances),
			Remediation: "Enable all Shielded VM features for rootkit and bootkit protection",
			RemediationDetail: `# Enable Shielded VM features
gcloud compute instances update INSTANCE_NAME \
  --zone=ZONE \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → VM instances → Instance details → Shielded VM → All three features enabled",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      GetFrameworkMappings("COMPUTE_SHIELDED_VM"),
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.8",
			Name:       "[CIS GCP 4.8] Shielded VM Features",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances have full Shielded VM protection | Meets CIS 4.8", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_SHIELDED_VM"),
		})
	}

	return results
}

// CheckSerialPortAccess verifies serial port access is disabled (CIS 4.5)
func (c *ComputeChecks) CheckSerialPortAccess(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithSerialPort := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check metadata for serial-port-enable
			if instance.Metadata != nil {
				for _, item := range instance.Metadata.Items {
					if item.Key == "serial-port-enable" && item.Value != nil && (*item.Value == "1" || *item.Value == "true" || *item.Value == "TRUE") {
						instancesWithSerialPort = append(instancesWithSerialPort, instance.Name)
						break
					}
				}
			}
		}
	}

	if len(instancesWithSerialPort) > 0 {
		displayInstances := instancesWithSerialPort
		if len(instancesWithSerialPort) > 3 {
			displayInstances = instancesWithSerialPort[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.5",
			Name:        "[CIS GCP 4.5] Serial Port Access Disabled",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 4.5: %d instances have serial port access enabled: %v | Serial console access should be disabled for security", len(instancesWithSerialPort), displayInstances),
			Remediation: "Disable serial port access unless specifically required",
			RemediationDetail: fmt.Sprintf(`gcloud compute instances add-metadata %s \
  --zone=ZONE \
  --metadata serial-port-enable=0`, instancesWithSerialPort[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → VM instances → Instance details → Remote access → Serial port access disabled",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      GetFrameworkMappings("COMPUTE_SERIAL_PORT"),
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.5",
			Name:       "[CIS GCP 4.5] Serial Port Access Disabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances have serial port access disabled | Meets CIS 4.5", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_SERIAL_PORT"),
		})
	}

	return results
}

// CheckIPForwarding verifies IP forwarding is disabled (CIS 4.6)
func (c *ComputeChecks) CheckIPForwarding(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithIPForwarding := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			if instance.CanIpForward {
				instancesWithIPForwarding = append(instancesWithIPForwarding, instance.Name)
			}
		}
	}

	if len(instancesWithIPForwarding) > 0 {
		displayInstances := instancesWithIPForwarding
		if len(instancesWithIPForwarding) > 3 {
			displayInstances = instancesWithIPForwarding[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.6",
			Name:        "[CIS GCP 4.6] IP Forwarding Disabled",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 4.6: %d instances have IP forwarding enabled: %v | Should only be enabled for routers/VPN gateways", len(instancesWithIPForwarding), displayInstances),
			Remediation: "Disable IP forwarding unless instance is a router or gateway",
			RemediationDetail: `# Note: Cannot change after instance creation
# Must recreate instance with --no-can-ip-forward flag
gcloud compute instances create INSTANCE_NAME \
  --no-can-ip-forward \
  --zone=ZONE`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → VM instances → Instance details → IP forwarding showing 'Off'",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      GetFrameworkMappings("COMPUTE_IP_FORWARDING"),
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.6",
			Name:       "[CIS GCP 4.6] IP Forwarding Disabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances have IP forwarding disabled | Meets CIS 4.6", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_IP_FORWARDING"),
		})
	}

	return results
}

// CheckProjectSSHKeys verifies project-wide SSH keys are not used (CIS 4.3)
func (c *ComputeChecks) CheckProjectSSHKeys(ctx context.Context) []CheckResult {
	var results []CheckResult

	project, err := c.service.Projects.Get(c.projectID).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CIS GCP 4.3",
			Name:        "[CIS GCP 4.3] Project-Wide SSH Keys",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to check project SSH keys: %v", err),
			Remediation: "Verify compute.projects.get permission",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("COMPUTE_PROJECT_SSH_KEYS"),
		})
		return results
	}

	hasProjectSSHKeys := false
	sshKeyCount := 0

	if project.CommonInstanceMetadata != nil {
		for _, item := range project.CommonInstanceMetadata.Items {
			if item.Key == "ssh-keys" && item.Value != nil && *item.Value != "" {
				hasProjectSSHKeys = true
				// Count number of keys (each key is on a new line)
				sshKeyCount = len(strings.Split(*item.Value, "\n"))
				break
			}
		}
	}

	if hasProjectSSHKeys {
		results = append(results, CheckResult{
			Control:     "CIS GCP 4.3",
			Name:        "[CIS GCP 4.3] Project-Wide SSH Keys",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 4.3: Project has %d project-wide SSH keys configured | Project-wide keys grant access to all instances", sshKeyCount),
			Remediation: "Remove project-wide SSH keys and use OS Login or instance-specific keys",
			RemediationDetail: `# Remove project-wide SSH keys
gcloud compute project-info remove-metadata \
  --keys=ssh-keys

# Better: Enable OS Login instead
gcloud compute project-info add-metadata \
  --metadata enable-oslogin=TRUE`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → Metadata → SSH Keys section empty or use OS Login",
			ConsoleURL:      "https://console.cloud.google.com/compute/metadata",
			Frameworks:      GetFrameworkMappings("COMPUTE_PROJECT_SSH_KEYS"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.3",
			Name:       "[CIS GCP 4.3] Project-Wide SSH Keys",
			Status:     "PASS",
			Evidence:   "No project-wide SSH keys configured | Meets CIS 4.3",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("COMPUTE_PROJECT_SSH_KEYS"),
		})
	}

	return results
}

// CheckDefaultServiceAccountFullAccess verifies instances don't use default SA with full API access (CIS 4.2)
func (c *ComputeChecks) CheckDefaultServiceAccountFullAccess(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithFullAccess := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check service accounts
			if instance.ServiceAccounts != nil {
				for _, sa := range instance.ServiceAccounts {
					// Check if using default service account (ends with -compute@developer.gserviceaccount.com)
					// AND has full cloud-platform scope
					if strings.HasSuffix(sa.Email, "-compute@developer.gserviceaccount.com") {
						for _, scope := range sa.Scopes {
							if scope == "https://www.googleapis.com/auth/cloud-platform" {
								instancesWithFullAccess = append(instancesWithFullAccess, instance.Name)
								break
							}
						}
					}
				}
			}
		}
	}

	if len(instancesWithFullAccess) > 0 {
		displayInstances := instancesWithFullAccess
		if len(instancesWithFullAccess) > 3 {
			displayInstances = instancesWithFullAccess[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.2",
			Name:        "[CIS GCP 4.2] Default SA Full Access",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CRITICAL: %d instances use default service account with full API access: %v | Violates CIS 4.2 (excessive permissions)", len(instancesWithFullAccess), displayInstances),
			Remediation: "Use custom service account with minimal required scopes",
			RemediationDetail: fmt.Sprintf(`# Create custom service account
gcloud iam service-accounts create custom-vm-sa \
  --display-name="Custom VM Service Account"

# Grant only required permissions
gcloud projects add-iam-policy-binding %s \
  --member="serviceAccount:custom-vm-sa@%s.iam.gserviceaccount.com" \
  --role="roles/SPECIFIC_ROLE"

# Update instance to use custom SA
gcloud compute instances set-service-account %s \
  --zone=ZONE \
  --service-account=custom-vm-sa@%s.iam.gserviceaccount.com \
  --scopes=SPECIFIC_SCOPES`, c.projectID, c.projectID, instancesWithFullAccess[0], c.projectID),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → VM Instance → Details → Service Account showing custom SA with limited scopes",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      map[string]string{"CIS-GCP": "4.2", "SOC2": "CC6.3"},
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.2",
			Name:       "[CIS GCP 4.2] Default SA Full Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances use custom service accounts or limited scopes | Meets CIS 4.2", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "4.2", "SOC2": "CC6.3"},
		})
	}

	return results
}

// CheckConfidentialComputing verifies Confidential Computing is enabled for sensitive workloads (CIS 4.10)
func (c *ComputeChecks) CheckConfidentialComputing(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithoutConfidential := []string{}
	totalInstances := 0
	confidentialCount := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check if Confidential Computing is enabled
			hasConfidentialComputing := false
			if instance.ConfidentialInstanceConfig != nil && instance.ConfidentialInstanceConfig.EnableConfidentialCompute {
				hasConfidentialComputing = true
				confidentialCount++
			}

			if !hasConfidentialComputing {
				instancesWithoutConfidential = append(instancesWithoutConfidential, instance.Name)
			}
		}
	}

	// This is an informational check - not all workloads need Confidential Computing
	if len(instancesWithoutConfidential) > 0 {
		displayInstances := instancesWithoutConfidential
		if len(instancesWithoutConfidential) > 3 {
			displayInstances = instancesWithoutConfidential[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.10",
			Name:        "[CIS GCP 4.10] Confidential Computing",
			Status:      "INFO",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("INFO: %d/%d instances do not have Confidential Computing enabled: %v | CIS 4.10 recommends for sensitive workloads", len(instancesWithoutConfidential), totalInstances, displayInstances),
			Remediation: "Enable Confidential Computing for VMs processing sensitive data",
			RemediationDetail: fmt.Sprintf(`# Confidential Computing requires N2D machine type
# Create new instance with Confidential Computing
gcloud compute instances create confidential-vm \
  --zone=us-central1-a \
  --machine-type=n2d-standard-2 \
  --confidential-compute \
  --maintenance-policy=TERMINATE

Note: Existing instances cannot be converted. Must create new instance.
Confidential Computing encrypts data in use (memory encryption).`),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → Create Instance → Confidential VM service → Screenshot showing enabled",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      map[string]string{"CIS-GCP": "4.10", "SOC2": "CC6.7"},
		})
	} else if totalInstances > 0 && confidentialCount > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.10",
			Name:       "[CIS GCP 4.10] Confidential Computing",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances have Confidential Computing enabled | Exceeds CIS 4.10", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "4.10", "SOC2": "CC6.7"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.10",
			Name:       "[CIS GCP 4.10] Confidential Computing",
			Status:     "INFO",
			Evidence:   fmt.Sprintf("%d instances found. Confidential Computing recommended for sensitive workloads processing regulated data.", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "4.10", "SOC2": "CC6.7"},
		})
	}

	return results
}

// CheckShieldedVMEnabled verifies instances use Shielded VM (CIS 4.7)
func (c *ComputeChecks) CheckShieldedVMEnabled(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithoutShieldedVM := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check if Shielded VM is enabled with all features
			hasShieldedVM := false
			if instance.ShieldedInstanceConfig != nil {
				// For full compliance, all three features should be enabled
				if instance.ShieldedInstanceConfig.EnableSecureBoot &&
					instance.ShieldedInstanceConfig.EnableVtpm &&
					instance.ShieldedInstanceConfig.EnableIntegrityMonitoring {
					hasShieldedVM = true
				}
			}

			if !hasShieldedVM {
				instancesWithoutShieldedVM = append(instancesWithoutShieldedVM, instance.Name)
			}
		}
	}

	if len(instancesWithoutShieldedVM) > 0 {
		displayInstances := instancesWithoutShieldedVM
		if len(instancesWithoutShieldedVM) > 3 {
			displayInstances = instancesWithoutShieldedVM[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.7",
			Name:        "[CIS GCP 4.7] Shielded VM Enabled",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d instances do not have full Shielded VM protection: %s | Violates CIS 4.7 (missing boot integrity protection)", len(instancesWithoutShieldedVM), totalInstances, strings.Join(displayInstances, ", ")),
			Remediation: "Enable Shielded VM with all features for new instances",
			RemediationDetail: fmt.Sprintf(`# Shielded VM cannot be enabled on existing instances
# Must create new instance with Shielded VM enabled

# Create instance with Shielded VM (all features)
gcloud compute instances create new-instance \
  --zone=us-central1-a \
  --machine-type=n1-standard-1 \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --project=%s

# For existing instance %s:
# 1. Create snapshot/image
# 2. Create new Shielded VM instance from image
# 3. Migrate workload
# 4. Delete old instance`, c.projectID, instancesWithoutShieldedVM[0]),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → VM instances → Instance details → Screenshot showing Shielded VM with all features enabled",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      map[string]string{"CIS-GCP": "4.7", "SOC2": "CC6.1"},
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.7",
			Name:       "[CIS GCP 4.7] Shielded VM Enabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances have full Shielded VM protection enabled | Meets CIS 4.7", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "4.7", "SOC2": "CC6.1"},
		})
	}

	return results
}

// CheckInstancePublicIPs verifies instances don't have public IPs (CIS 4.11)
func (c *ComputeChecks) CheckInstancePublicIPs(ctx context.Context) []CheckResult {
	var results []CheckResult

	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithPublicIP := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++

			// Check if instance has public IP on any network interface
			hasPublicIP := false
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.AccessConfigs != nil && len(networkInterface.AccessConfigs) > 0 {
					for _, accessConfig := range networkInterface.AccessConfigs {
						if accessConfig.NatIP != "" {
							hasPublicIP = true
							break
						}
					}
				}
				if hasPublicIP {
					break
				}
			}

			if hasPublicIP {
				instancesWithPublicIP = append(instancesWithPublicIP, instance.Name)
			}
		}
	}

	if len(instancesWithPublicIP) > 0 {
		displayInstances := instancesWithPublicIP
		if len(instancesWithPublicIP) > 3 {
			displayInstances = instancesWithPublicIP[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 4.11",
			Name:        "[CIS GCP 4.11] No Public IP Addresses",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d instances have external public IP addresses: %s | Violates CIS 4.11 (direct internet exposure)", len(instancesWithPublicIP), totalInstances, strings.Join(displayInstances, ", ")),
			Remediation: "Remove public IPs and use Cloud NAT or Cloud VPN for outbound connectivity",
			RemediationDetail: fmt.Sprintf(`# Remove external IP from instance
gcloud compute instances delete-access-config %s \
  --zone=ZONE \
  --access-config-name="external-nat" \
  --project=%s

# Set up Cloud NAT for outbound internet access
gcloud compute routers create nat-router \
  --network=NETWORK \
  --region=REGION \
  --project=%s

gcloud compute routers nats create nat-config \
  --router=nat-router \
  --auto-allocate-nat-external-ips \
  --nat-all-subnet-ip-ranges \
  --region=REGION \
  --project=%s

# For inbound access, use Cloud Load Balancer or Cloud IAP`, instancesWithPublicIP[0], c.projectID, c.projectID, c.projectID),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Compute Engine → VM instances → External IP column showing 'None' for all instances",
			ConsoleURL:      "https://console.cloud.google.com/compute/instances",
			Frameworks:      map[string]string{"CIS-GCP": "4.11", "SOC2": "CC6.6", "PCI-DSS": "1.4.2"},
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 4.11",
			Name:       "[CIS GCP 4.11] No Public IP Addresses",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d instances use private IP addresses only | Meets CIS 4.11", totalInstances),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "4.11", "SOC2": "CC6.6", "PCI-DSS": "1.4.2"},
		})
	}

	return results
}
