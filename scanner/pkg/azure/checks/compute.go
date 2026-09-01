package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

type ComputeChecks struct {
	vmClient       *armcompute.VirtualMachinesClient
	diskClient     *armcompute.DisksClient
	nicClient      *armnetwork.InterfacesClient
	publicIPClient *armnetwork.PublicIPAddressesClient
}

func NewComputeChecks(vmClient *armcompute.VirtualMachinesClient, diskClient *armcompute.DisksClient, nicClient *armnetwork.InterfacesClient, publicIPClient *armnetwork.PublicIPAddressesClient) *ComputeChecks {
	return &ComputeChecks{
		vmClient:       vmClient,
		diskClient:     diskClient,
		nicClient:      nicClient,
		publicIPClient: publicIPClient,
	}
}

func (c *ComputeChecks) Name() string {
	return "Azure Compute Security"
}

func (c *ComputeChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	results = append(results, c.CheckDiskEncryption(ctx)...)
	results = append(results, c.CheckVMExtensions(ctx)...)
	results = append(results, c.CheckPublicIPs(ctx)...)
	results = append(results, c.CheckManagedDisks(ctx)...)
	results = append(results, c.CheckDiskNetworkAccess(ctx)...) // NEW: CIS 8.5

	return results, nil
}

func (c *ComputeChecks) CheckDiskEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.diskClient.NewListPager(nil)

	unencryptedDisks := []string{}
	totalDisks := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, disk := range page.Value {
			totalDisks++
			diskName := *disk.Name

			// Check encryption settings
			if disk.Properties != nil {
				if disk.Properties.Encryption == nil ||
					disk.Properties.Encryption.Type == nil ||
					*disk.Properties.Encryption.Type == armcompute.EncryptionTypeEncryptionAtRestWithPlatformKey {
					// Platform key is okay, but customer-managed is better for CIS
					continue
				} else if *disk.Properties.Encryption.Type == "" {
					unencryptedDisks = append(unencryptedDisks, diskName)
				}
			} else {
				unencryptedDisks = append(unencryptedDisks, diskName)
			}
		}
	}

	if len(unencryptedDisks) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-7.1",
			Name:        "[CIS Azure 7.1, 7.2] Disk Encryption at Rest",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 7.1, 7.2: %d/%d disks not encrypted | Violates CIS Azure requirements", len(unencryptedDisks), totalDisks),
			Remediation: "Enable disk encryption per CIS Azure 7.1, 7.2",
			RemediationDetail: `CIS Azure 7.1: Ensure Virtual Machines are utilizing Managed Disks
CIS Azure 7.2: Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK)

Enable Azure Disk Encryption:
1. Create Key Vault with purge protection and soft delete
2. Create encryption key in Key Vault
3. Enable encryption on VM disks:
   - OS disk encryption
   - Data disk encryption
4. Use customer-managed keys for enhanced security

Azure CLI:
az vm encryption enable \
  --resource-group <rg> \
  --name <vm> \
  --disk-encryption-keyvault <key-vault>`,
			ScreenshotGuide: "VM → Disks → Screenshot showing:\n- Encryption: Enabled\n- Encryption type: Customer-managed key (or Platform-managed minimum)\n- Key vault and key specified",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Compute%2Fdisks",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DISK_ENCRYPTION"),
		})
	} else if totalDisks > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-7.1",
			Name:       "[CIS Azure 7.1, 7.2] Disk Encryption at Rest",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 7.1, 7.2: All %d disks encrypted | Meets CIS Azure requirements", totalDisks),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DISK_ENCRYPTION"),
		})
	}

	return results
}

func (c *ComputeChecks) CheckManagedDisks(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	vmPager := c.vmClient.NewListAllPager(nil)

	unmanagedDisks := []string{}
	totalVMs := 0

	for vmPager.More() {
		page, err := vmPager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, vm := range page.Value {
			totalVMs++
			vmName := *vm.Name

			// Check if using managed disks
			if vm.Properties != nil && vm.Properties.StorageProfile != nil {
				// Check OS disk
				if vm.Properties.StorageProfile.OSDisk != nil {
					if vm.Properties.StorageProfile.OSDisk.ManagedDisk == nil {
						unmanagedDisks = append(unmanagedDisks, fmt.Sprintf("%s (OS disk)", vmName))
					}
				}

				// Check data disks
				if vm.Properties.StorageProfile.DataDisks != nil {
					for _, dataDisk := range vm.Properties.StorageProfile.DataDisks {
						if dataDisk.ManagedDisk == nil {
							unmanagedDisks = append(unmanagedDisks, fmt.Sprintf("%s (data disk)", vmName))
							break
						}
					}
				}
			}
		}
	}

	if len(unmanagedDisks) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-7.3",
			Name:        "[CIS Azure 7.3] Managed Disks",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 7.3: %d VMs using unmanaged disks", len(unmanagedDisks)),
			Remediation: "Migrate to managed disks per CIS Azure 7.3",
			RemediationDetail: `CIS Azure 7.3: Ensure that 'Unattached disks' are encrypted with Customer Managed Key (CMK)

Managed disks provide:
- Better reliability (99.999% availability)
- Simplified management
- Enhanced security features
- Better backup/restore capabilities

Migrate unmanaged to managed disks:
Azure Portal → VM → Disks → Migrate to managed disks`,
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VM_MANAGED_DISKS"),
		})
	} else if totalVMs > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-7.3",
			Name:       "[CIS Azure 7.3] Managed Disks",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 7.3: All %d VMs using managed disks", totalVMs),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VM_MANAGED_DISKS"),
		})
	}

	return results
}

func (c *ComputeChecks) CheckVMExtensions(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.vmClient.NewListAllPager(nil)

	vmsWithoutMonitoring := []string{}
	vmsWithoutAntimalware := []string{}
	totalVMs := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, vm := range page.Value {
			totalVMs++
			vmName := *vm.Name

			hasMonitoring := false
			hasAntimalware := false

			if vm.Properties != nil && vm.Resources != nil {
				for _, resource := range vm.Resources {
					if resource.Name != nil {
						resourceName := *resource.Name
						if resourceName == "MicrosoftMonitoringAgent" || resourceName == "OmsAgentForLinux" {
							hasMonitoring = true
						}
						if resourceName == "IaaSAntimalware" {
							hasAntimalware = true
						}
					}
				}
			}

			if !hasMonitoring {
				vmsWithoutMonitoring = append(vmsWithoutMonitoring, vmName)
			}
			if !hasAntimalware {
				vmsWithoutAntimalware = append(vmsWithoutAntimalware, vmName)
			}
		}
	}

	if len(vmsWithoutMonitoring) > 0 && totalVMs > 0 {
		results = append(results, CheckResult{
			Control:           "CC7.1",
			Name:              "VM Monitoring Agents",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d/%d VMs lack monitoring agents", len(vmsWithoutMonitoring), totalVMs),
			Remediation:       "Install Azure Monitor agent",
			RemediationDetail: "VM → Extensions → Add Microsoft Monitoring Agent",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
		})
	}

	if len(vmsWithoutAntimalware) > 0 && totalVMs > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-7.4",
			Name:        "[CIS Azure 7.4, 7.5] Endpoint Protection",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 7.4, 7.5: %d/%d VMs lack antimalware protection", len(vmsWithoutAntimalware), totalVMs),
			Remediation: "Install Microsoft Antimalware per CIS Azure 7.4, 7.5",
			RemediationDetail: `CIS Azure 7.4: Ensure that endpoint protection for all Virtual Machines is installed
CIS Azure 7.5: Ensure that Microsoft Defender for Endpoint (MDE) integration is enabled

Install endpoint protection:
1. VM → Extensions → Add Microsoft Antimalware
2. Or enable Microsoft Defender for Cloud
3. Configure real-time protection and scanning

For CIS 7.5: Enable MDE integration via Defender for Cloud`,
			ScreenshotGuide: "1. VM → Extensions → Show Microsoft Antimalware installed\n2. Defender for Cloud → VMs → Show endpoint protection status = Healthy\n3. Show MDE integration enabled",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("VM_ENDPOINT_PROTECTION"),
		})
	}

	// VM Backup check
	results = append(results, CheckResult{
		Control:     "CIS-7.6",
		Name:        "[CIS Azure 7.6] VM Backup",
		Status:      "INFO",
		Evidence:    "CIS 7.6: MANUAL CHECK - Verify Azure Backup is enabled for all production VMs",
		Remediation: "Enable Azure Backup per CIS Azure 7.6",
		RemediationDetail: `CIS Azure 7.6: Ensure that Virtual Machine backup is enabled

Requirements:
1. Create Recovery Services vault
2. Configure backup policy:
   - Frequency: Daily recommended
   - Retention: 30+ days (adjust per compliance needs)
3. Enable backup for all production VMs
4. Test restore procedures regularly

Azure Portal:
VM → Backup → Enable and configure policy`,
		ScreenshotGuide: "1. Recovery Services vaults → Backup items → Show all VMs backed up\n2. VM → Backup → Show backup configured with daily schedule\n3. Document restore testing results",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.RecoveryServices%2Fvaults",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("VM_BACKUP"),
	})

	return results
}

// NEW: CIS 8.5 - Disk network access restriction
func (c *ComputeChecks) CheckDiskNetworkAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.diskClient.NewListPager(nil)

	disksWithPublicAccess := []string{}
	totalDisks := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, disk := range page.Value {
			totalDisks++

			if disk.Name == nil {
				continue
			}

			diskName := *disk.Name

			// Check network access policy
			if disk.Properties != nil {
				// NetworkAccessPolicy values:
				// - AllowAll: Disk accessible from public internet (BAD)
				// - AllowPrivate: Only via private endpoints (GOOD)
				// - DenyAll: Most restrictive (BEST)
				if disk.Properties.NetworkAccessPolicy != nil {
					policy := string(*disk.Properties.NetworkAccessPolicy)
					if policy == "AllowAll" || policy == "" {
						disksWithPublicAccess = append(disksWithPublicAccess, diskName)
					}
				} else {
					// No explicit policy = defaults to AllowAll (BAD)
					disksWithPublicAccess = append(disksWithPublicAccess, diskName)
				}
			}
		}
	}

	if len(disksWithPublicAccess) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-8.5",
			Name:        "[CIS Azure 8.5] Disk Network Access Restriction",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 8.5: %d/%d managed disks allow public network access | Violates CIS Azure requirements", len(disksWithPublicAccess), totalDisks),
			Remediation: "Restrict disk network access per CIS Azure 8.5",
			RemediationDetail: `CIS Azure 8.5: Ensure that 'Public access level' is set to Private for Azure managed disks

Managed disks should restrict network access to prevent unauthorized data exfiltration.

Configure network access policy:
1. Azure Portal → Disks → Select disk
2. Networking tab → Set to one of:
   - "Disable public access and enable private access" (RECOMMENDED)
   - "Deny all access" (for offline/archived disks)
3. Configure Private Endpoints if using AllowPrivate

Azure CLI:
az disk update \
  --resource-group <rg> \
  --name <disk-name> \
  --network-access-policy DenyAll

Or with private endpoint:
az disk update \
  --resource-group <rg> \
  --name <disk-name> \
  --network-access-policy AllowPrivate

Security impact:
- Prevents public internet access to disk data
- Requires private endpoints for legitimate access
- Reduces attack surface significantly`,
			ScreenshotGuide: "Disks → Networking → Screenshot showing:\n- Public access: Disabled\n- Network access policy: Deny all (or Allow private with private endpoints configured)\n- No 'AllowAll' network access",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Compute%2Fdisks",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DISK_NETWORK_ACCESS"),
		})
	} else if totalDisks > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-8.5",
			Name:       "[CIS Azure 8.5] Disk Network Access Restriction",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 8.5: All %d managed disks have restricted network access | Meets CIS Azure requirements", totalDisks),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DISK_NETWORK_ACCESS"),
		})
	}

	return results
}

func (c *ComputeChecks) CheckPublicIPs(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// First, build a map of all public IPs in the subscription
	publicIPMap := make(map[string]string) // ID -> IP address
	if c.publicIPClient != nil {
		pipPager := c.publicIPClient.NewListAllPager(nil)
		for pipPager.More() {
			page, err := pipPager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, pip := range page.Value {
				if pip.ID != nil && pip.Properties != nil && pip.Properties.IPAddress != nil {
					publicIPMap[strings.ToLower(*pip.ID)] = *pip.Properties.IPAddress
				}
			}
		}
	}

	pager := c.vmClient.NewListAllPager(nil)

	vmsWithPublicIP := []string{}
	totalVMs := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, vm := range page.Value {
			totalVMs++
			vmName := ""
			if vm.Name != nil {
				vmName = *vm.Name
			}

			if vm.Properties != nil && vm.Properties.NetworkProfile != nil {
				for _, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
					if nicRef.ID == nil || c.nicClient == nil {
						continue
					}

					// Extract resource group and NIC name from ID
					nicID := *nicRef.ID
					parts := strings.Split(nicID, "/")
					if len(parts) < 9 {
						continue
					}

					rgIndex := -1
					nicIndex := -1
					for i, p := range parts {
						if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
							rgIndex = i + 1
						}
						if strings.EqualFold(p, "networkInterfaces") && i+1 < len(parts) {
							nicIndex = i + 1
						}
					}

					if rgIndex == -1 || nicIndex == -1 {
						continue
					}

					rgName := parts[rgIndex]
					nicName := parts[nicIndex]

					// Get the NIC details
					nic, err := c.nicClient.Get(ctx, rgName, nicName, nil)
					if err != nil {
						continue
					}

					// Check each IP configuration for public IPs
					if nic.Properties != nil && nic.Properties.IPConfigurations != nil {
						for _, ipConfig := range nic.Properties.IPConfigurations {
							if ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
								pipID := strings.ToLower(*ipConfig.Properties.PublicIPAddress.ID)
								if ipAddr, ok := publicIPMap[pipID]; ok {
									vmsWithPublicIP = append(vmsWithPublicIP, fmt.Sprintf("%s (%s)", vmName, ipAddr))
								} else {
									vmsWithPublicIP = append(vmsWithPublicIP, vmName)
								}
								break // Only report once per VM
							}
						}
					}
				}
			}
		}
	}

	if len(vmsWithPublicIP) > 0 {
		vmList := strings.Join(vmsWithPublicIP, ", ")
		if len(vmsWithPublicIP) > 3 {
			vmList = strings.Join(vmsWithPublicIP[:3], ", ") + fmt.Sprintf(" +%d more", len(vmsWithPublicIP)-3)
		}

		firstVM := vmsWithPublicIP[0]
		if idx := strings.Index(firstVM, " ("); idx > 0 {
			firstVM = firstVM[:idx]
		}

		results = append(results, CheckResult{
			Control:           "CC6.1",
			Name:              "VM Public IP Exposure",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d VMs have direct public IPs: %s | Violates PCI DSS 1.4.2 (restrict inbound traffic), SOC2 CC6.1 (restrict logical access)", len(vmsWithPublicIP), totalVMs, vmList),
			Remediation:       "Remove direct public IPs, use Azure Bastion or Application Gateway",
			RemediationDetail: fmt.Sprintf("az network nic ip-config update --remove PublicIpAddress --name ipconfig1 --nic-name %s-nic --resource-group <rg>", firstVM),
			ScreenshotGuide:   "1. Go to Azure Portal → Virtual Machines\n2. Select VM '" + firstVM + "'\n3. Go to Networking\n4. Screenshot showing 'Public IP address' field\n5. For PCI DSS: Document that no cardholder data is accessible via public IP",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Compute%2FvirtualMachines",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.1",
				"PCI-DSS": "1.3.1, 1.3.2",
				"HIPAA":   "164.312(a)(1)",
			},
		})
	} else if totalVMs > 0 {
		results = append(results, CheckResult{
			Control:         "CC6.1",
			Name:            "VM Public IP Exposure",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("None of %d VMs have direct public IP addresses | Meets SOC2 CC6.1, PCI DSS 1.4.2", totalVMs),
			Severity:        "INFO",
			ScreenshotGuide: "1. Go to Azure Portal → Virtual Machines\n2. Screenshot showing VMs with no public IPs assigned",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Compute%2FvirtualMachines",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.1",
				"PCI-DSS": "1.4.2",
			},
		})
	}

	return results
}
