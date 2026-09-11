package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

// EFSChecks answers the Elastic File System part of the CIS AWS Foundations
// benchmark. v7.0.0 places it at 3.3.1, under Storage.
type EFSChecks struct {
	client *efs.Client
}

func NewEFSChecks(client *efs.Client) *EFSChecks {
	return &EFSChecks{client: client}
}

func (c *EFSChecks) Name() string { return "EFS Encryption" }

func (c *EFSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	result, err := c.CheckEncryptionAtRest(ctx)
	if err != nil {
		return nil, err
	}
	return []CheckResult{result}, nil
}

// CheckEncryptionAtRest answers CIS AWS Foundations v7.0.0 3.3.1.
//
// Encryption at rest can only be set when a file system is created, so a
// failure here is not a setting to toggle: the data has to be copied to a new
// encrypted file system. The remediation says so rather than offering a flag
// that does not exist.
func (c *EFSChecks) CheckEncryptionAtRest(ctx context.Context) (CheckResult, error) {
	const control, name = "CIS-3.3.1", "EFS Encryption at Rest"
	frameworks := map[string]string{"CIS-AWS": "3.3.1", "SOC2": "CC6.1", "PCI-DSS": "3.5.1"}

	if c.client == nil {
		return CheckResult{
			Control: control, Name: name, Status: "ERROR",
			Evidence:   "EFS client not configured",
			Severity:   "MEDIUM",
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: frameworks,
		}, nil
	}

	unencrypted := []string{}
	total := 0
	var marker *string
	for page := 0; page < 20; page++ {
		out, err := c.client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{Marker: marker})
		if err != nil {
			return CheckResult{
				Control: control, Name: name, Status: "ERROR",
				Evidence:   fmt.Sprintf("Unable to list EFS file systems: %v", err),
				Severity:   "MEDIUM",
				Priority:   PriorityMedium,
				Timestamp:  time.Now(),
				Frameworks: frameworks,
			}, nil
		}
		for _, fs := range out.FileSystems {
			total++
			if !aws.ToBool(fs.Encrypted) {
				id := aws.ToString(fs.FileSystemId)
				if n := aws.ToString(fs.Name); n != "" {
					id = fmt.Sprintf("%s (%s)", id, n)
				}
				unencrypted = append(unencrypted, id)
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control: control, Name: name, Status: "FAIL",
			Severity: "HIGH",
			Evidence: fmt.Sprintf("%d of %d EFS file system(s) are not encrypted at rest: %v",
				len(unencrypted), total, unencrypted),
			Remediation: "Create a replacement file system with encryption enabled and migrate the data; encryption at rest cannot be turned on after creation",
			RemediationDetail: `# Encryption at rest is fixed at creation time.
aws efs create-file-system --encrypted --kms-key-id <key> --tags Key=Name,Value=<name>
# Then copy the data, for example with AWS DataSync, and repoint the mount targets.`,
			ScreenshotGuide: "EFS -> File systems -> Screenshot the list showing Encrypted for every file system",
			ConsoleURL:      "https://console.aws.amazon.com/efs/home#/file-systems",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      frameworks,
		}, nil
	}

	evidence := fmt.Sprintf("All %d EFS file system(s) are encrypted at rest", total)
	if total == 0 {
		evidence = "No EFS file systems exist in this region"
	}
	return CheckResult{
		Control: control, Name: name, Status: "PASS",
		Evidence:   evidence,
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: frameworks,
	}, nil
}
