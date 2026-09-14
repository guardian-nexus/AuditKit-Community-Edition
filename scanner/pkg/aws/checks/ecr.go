package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

type ECRChecks struct {
	client *ecr.Client
}

func NewECRChecks(client *ecr.Client) *ECRChecks {
	return &ECRChecks{client: client}
}

func (c *ECRChecks) Name() string {
	return "ECR (Container Registry) Security Configuration"
}

func (c *ECRChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckImageScanning(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckImmutableTags(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEncryptionAtRest(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *ECRChecks) CheckImageScanning(ctx context.Context) (CheckResult, error) {
	repos, err := c.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return CheckResult{
			Control:    "AWS-ECR-02",
			Name:       "ECR Image Scanning Enabled",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Failed to list ECR repositories: %v", err),
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ECR_IMAGE_SCANNING"),
		}, err
	}

	if len(repos.Repositories) == 0 {
		return CheckResult{
			Control:    "AWS-ECR-02",
			Name:       "ECR Image Scanning Enabled",
			Status:     "INFO",
			Evidence:   "No ECR repositories found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ECR_IMAGE_SCANNING"),
		}, nil
	}

	without := []string{}
	with := 0

	for _, repo := range repos.Repositories {
		if repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush {
			with++
		} else {
			without = append(without, *repo.RepositoryName)
		}
	}

	if len(without) > 0 {
		return CheckResult{
			Control:     "AWS-ECR-02",
			Name:        "ECR Image Scanning Enabled",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d repositories lack image scanning: %v", len(without), len(repos.Repositories), without),
			Remediation: "Enable scan on push for all ECR repositories",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/ecr/repositories",
			Frameworks:  GetFrameworkMappings("ECR_IMAGE_SCANNING"),
		}, nil
	}

	return CheckResult{
		Control:    "AWS-ECR-02",
		Name:       "ECR Image Scanning Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d repositories have image scanning enabled", with),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/ecr/repositories",
		Frameworks: GetFrameworkMappings("ECR_IMAGE_SCANNING"),
	}, nil
}

func (c *ECRChecks) CheckImmutableTags(ctx context.Context) (CheckResult, error) {
	repos, err := c.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return CheckResult{
			Control:    "AWS-ECR-03",
			Name:       "ECR Immutable Tags",
			Status:     "ERROR",
			Evidence:   "Failed to list repositories",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ECR_IMMUTABLE_TAGS"),
		}, err
	}

	if len(repos.Repositories) == 0 {
		return CheckResult{
			Control:    "AWS-ECR-03",
			Name:       "ECR Immutable Tags",
			Status:     "INFO",
			Evidence:   "No ECR repositories found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ECR_IMMUTABLE_TAGS"),
		}, nil
	}

	without := []string{}
	with := 0

	for _, repo := range repos.Repositories {
		if repo.ImageTagMutability == "IMMUTABLE" {
			with++
		} else {
			without = append(without, *repo.RepositoryName)
		}
	}

	if len(without) > 0 {
		return CheckResult{
			Control:     "AWS-ECR-03",
			Name:        "ECR Immutable Tags",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d repositories allow mutable tags: %v", len(without), len(repos.Repositories), without),
			Remediation: "Enable tag immutability to prevent tag overwriting",
			Severity:    "MEDIUM",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/ecr/repositories",
			Frameworks:  GetFrameworkMappings("ECR_IMMUTABLE_TAGS"),
		}, nil
	}

	return CheckResult{
		Control:    "AWS-ECR-03",
		Name:       "ECR Immutable Tags",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d repositories have immutable tags enabled", with),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/ecr/repositories",
		Frameworks: GetFrameworkMappings("ECR_IMMUTABLE_TAGS"),
	}, nil
}

func (c *ECRChecks) CheckEncryptionAtRest(ctx context.Context) (CheckResult, error) {
	repos, err := c.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return CheckResult{
			Control:    "AWS-ECR-01",
			Name:       "ECR Encryption at Rest",
			Status:     "ERROR",
			Evidence:   "Failed to list repositories",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ECR_ENCRYPTION"),
		}, err
	}

	if len(repos.Repositories) == 0 {
		return CheckResult{
			Control:    "AWS-ECR-01",
			Name:       "ECR Encryption at Rest",
			Status:     "INFO",
			Evidence:   "No ECR repositories found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ECR_ENCRYPTION"),
		}, nil
	}

	// All ECR repositories are encrypted by default with either AWS managed or customer managed KMS keys
	customKMS := 0
	awsManaged := 0

	for _, repo := range repos.Repositories {
		if repo.EncryptionConfiguration != nil && repo.EncryptionConfiguration.KmsKey != nil {
			customKMS++
		} else {
			awsManaged++
		}
	}

	return CheckResult{
		Control:    "AWS-ECR-01",
		Name:       "ECR Encryption at Rest",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All repositories encrypted. %d with custom KMS, %d with AWS managed", customKMS, awsManaged),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/ecr/repositories",
		Frameworks: GetFrameworkMappings("ECR_ENCRYPTION"),
	}, nil
}
