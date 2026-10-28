package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

type SageMakerChecks struct {
	client *sagemaker.Client
}

func NewSageMakerChecks(client *sagemaker.Client) *SageMakerChecks {
	return &SageMakerChecks{client: client}
}

func (c *SageMakerChecks) Name() string {
	return "SageMaker ML Security"
}

func (c *SageMakerChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	results = runCheck(ctx, results, c.CheckNotebookEncryption)

	results = runCheck(ctx, results, c.CheckNotebookDirectInternet)

	results = runCheck(ctx, results, c.CheckNotebookRootAccess)

	results = runCheck(ctx, results, c.CheckEndpointEncryption)

	results = runCheck(ctx, results, c.CheckTrainingJobEncryption)

	results = runCheck(ctx, results, c.CheckModelNetworkIsolation)

	return results, nil
}

func (c *SageMakerChecks) CheckNotebookEncryption(ctx context.Context) (CheckResult, error) {
	skipped := unreadable{}
	notebooks, err := c.client.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{})
	if err != nil {
		return checkError("CC6.3", "SageMaker Notebook Encryption", GetFrameworkMappings("SAGEMAKER_ENCRYPTION"), err), err
	}

	unencrypted := []string{}

	for _, nb := range notebooks.NotebookInstances {
		nbName := aws.ToString(nb.NotebookInstanceName)

		// Get detailed info
		detail, err := c.client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: nb.NotebookInstanceName,
		})
		if err != nil {
			skipped.add("DescribeNotebookInstance", err)
			continue
		}

		if detail.KmsKeyId == nil || *detail.KmsKeyId == "" {
			unencrypted = append(unencrypted, nbName)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "SageMaker Notebook Encryption",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d notebooks without KMS encryption: %v", len(unencrypted), unencrypted),
			Remediation:       "Enable KMS encryption for SageMaker notebooks",
			RemediationDetail: "Create new notebook instance with KMS key or recreate existing notebooks with encryption enabled",
			ScreenshotGuide:   "SageMaker Console → Notebook instances → Select instance → Configuration → Screenshot showing KMS Key ARN",
			ConsoleURL:        "https://console.aws.amazon.com/sagemaker/home#/notebook-instances",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
		}, nil
	}

	if len(notebooks.NotebookInstances) == 0 {
		return skipped.passOrError(CheckResult{
			Control:    "CC6.3",
			Name:       "SageMaker Notebook Encryption",
			Status:     StatusInfo,
			Evidence:   "No SageMaker notebooks found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
		}), nil
	}

	return skipped.passOrError(CheckResult{
		Control:    "CC6.3",
		Name:       "SageMaker Notebook Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d notebooks are encrypted with KMS", len(notebooks.NotebookInstances)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
	}), nil
}

func (c *SageMakerChecks) CheckNotebookDirectInternet(ctx context.Context) (CheckResult, error) {
	skipped := unreadable{}
	notebooks, err := c.client.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{})
	if err != nil {
		return checkError("CC6.1", "SageMaker Direct Internet Access", GetFrameworkMappings("SAGEMAKER_NETWORK"), err), err
	}

	directInternet := []string{}

	for _, nb := range notebooks.NotebookInstances {
		nbName := aws.ToString(nb.NotebookInstanceName)

		detail, err := c.client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: nb.NotebookInstanceName,
		})
		if err != nil {
			skipped.add("DescribeNotebookInstance", err)
			continue
		}

		if detail.DirectInternetAccess == "Enabled" {
			directInternet = append(directInternet, nbName)
		}
	}

	if len(directInternet) > 0 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "SageMaker Direct Internet Access",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d notebooks have direct internet access enabled: %v", len(directInternet), directInternet),
			Remediation:       "Disable direct internet access and use VPC for network isolation",
			RemediationDetail: "Recreate notebook instance in VPC with DirectInternetAccess=Disabled, use NAT gateway for outbound access",
			ScreenshotGuide:   "SageMaker Console → Notebook → Network → Screenshot showing 'Direct internet access: Disabled'",
			ConsoleURL:        "https://console.aws.amazon.com/sagemaker/home#/notebook-instances",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SAGEMAKER_NETWORK"),
		}, nil
	}

	if len(notebooks.NotebookInstances) == 0 {
		return skipped.passOrError(CheckResult{
			Control:    "CC6.1",
			Name:       "SageMaker Direct Internet Access",
			Status:     StatusInfo,
			Evidence:   "No SageMaker notebooks found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SAGEMAKER_NETWORK"),
		}), nil
	}

	return skipped.passOrError(CheckResult{
		Control:    "CC6.1",
		Name:       "SageMaker Direct Internet Access",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d notebooks have direct internet access disabled", len(notebooks.NotebookInstances)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SAGEMAKER_NETWORK"),
	}), nil
}

func (c *SageMakerChecks) CheckNotebookRootAccess(ctx context.Context) (CheckResult, error) {
	skipped := unreadable{}
	notebooks, err := c.client.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{})
	if err != nil {
		return checkError("CC6.6", "SageMaker Root Access", GetFrameworkMappings("SAGEMAKER_ACCESS"), err), err
	}

	rootEnabled := []string{}

	for _, nb := range notebooks.NotebookInstances {
		nbName := aws.ToString(nb.NotebookInstanceName)

		detail, err := c.client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
			NotebookInstanceName: nb.NotebookInstanceName,
		})
		if err != nil {
			skipped.add("DescribeNotebookInstance", err)
			continue
		}

		if detail.RootAccess == "Enabled" {
			rootEnabled = append(rootEnabled, nbName)
		}
	}

	if len(rootEnabled) > 0 {
		return CheckResult{
			Control:           "CC6.6",
			Name:              "SageMaker Root Access",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d notebooks have root access enabled: %v", len(rootEnabled), rootEnabled),
			Remediation:       "Disable root access for notebook instances",
			RemediationDetail: "Update notebook instance to disable root access: aws sagemaker update-notebook-instance --notebook-instance-name NAME --root-access Disabled",
			ScreenshotGuide:   "SageMaker Console → Notebook → Permissions → Screenshot showing 'Root access: Disabled'",
			ConsoleURL:        "https://console.aws.amazon.com/sagemaker/home#/notebook-instances",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SAGEMAKER_ACCESS"),
		}, nil
	}

	if len(notebooks.NotebookInstances) == 0 {
		return skipped.passOrError(CheckResult{
			Control:    "CC6.6",
			Name:       "SageMaker Root Access",
			Status:     StatusInfo,
			Evidence:   "No SageMaker notebooks found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SAGEMAKER_ACCESS"),
		}), nil
	}

	return skipped.passOrError(CheckResult{
		Control:    "CC6.6",
		Name:       "SageMaker Root Access",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d notebooks have root access disabled", len(notebooks.NotebookInstances)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SAGEMAKER_ACCESS"),
	}), nil
}

func (c *SageMakerChecks) CheckEndpointEncryption(ctx context.Context) (CheckResult, error) {
	skipped := unreadable{}
	endpoints, err := c.client.ListEndpoints(ctx, &sagemaker.ListEndpointsInput{})
	if err != nil {
		return checkError("CC6.3", "SageMaker Endpoint Encryption", GetFrameworkMappings("SAGEMAKER_ENCRYPTION"), err), err
	}

	unencrypted := []string{}

	for _, ep := range endpoints.Endpoints {
		epName := aws.ToString(ep.EndpointName)

		detail, err := c.client.DescribeEndpoint(ctx, &sagemaker.DescribeEndpointInput{
			EndpointName: ep.EndpointName,
		})
		if err != nil {
			skipped.add("DescribeEndpoint", err)
			continue
		}

		// Check if endpoint config has KMS key
		configDetail, err := c.client.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{
			EndpointConfigName: detail.EndpointConfigName,
		})
		if err != nil {
			skipped.add("DescribeEndpointConfig", err)
			continue
		}

		if configDetail.KmsKeyId == nil || *configDetail.KmsKeyId == "" {
			unencrypted = append(unencrypted, epName)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "SageMaker Endpoint Encryption",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d endpoints without KMS encryption: %v", len(unencrypted), unencrypted),
			Remediation:       "Enable KMS encryption for SageMaker endpoints",
			RemediationDetail: "Create new endpoint config with KmsKeyId specified, then update endpoint to use new config",
			ScreenshotGuide:   "SageMaker Console → Endpoints → Select endpoint → Configuration → Screenshot showing KMS Key ARN",
			ConsoleURL:        "https://console.aws.amazon.com/sagemaker/home#/endpoints",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
		}, nil
	}

	if len(endpoints.Endpoints) == 0 {
		return skipped.passOrError(CheckResult{
			Control:    "CC6.3",
			Name:       "SageMaker Endpoint Encryption",
			Status:     StatusInfo,
			Evidence:   "No SageMaker endpoints found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
		}), nil
	}

	return skipped.passOrError(CheckResult{
		Control:    "CC6.3",
		Name:       "SageMaker Endpoint Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d endpoints are encrypted with KMS", len(endpoints.Endpoints)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
	}), nil
}

func (c *SageMakerChecks) CheckTrainingJobEncryption(ctx context.Context) (CheckResult, error) {
	skipped := unreadable{}
	jobs, err := c.client.ListTrainingJobs(ctx, &sagemaker.ListTrainingJobsInput{
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		return checkError("CC6.3", "SageMaker Training Job Encryption", GetFrameworkMappings("SAGEMAKER_ENCRYPTION"), err), err
	}

	unencrypted := []string{}

	for _, job := range jobs.TrainingJobSummaries {
		jobName := aws.ToString(job.TrainingJobName)

		detail, err := c.client.DescribeTrainingJob(ctx, &sagemaker.DescribeTrainingJobInput{
			TrainingJobName: job.TrainingJobName,
		})
		if err != nil {
			skipped.add("DescribeTrainingJob", err)
			continue
		}

		// Check volume encryption
		if detail.ResourceConfig != nil && (detail.ResourceConfig.VolumeKmsKeyId == nil || *detail.ResourceConfig.VolumeKmsKeyId == "") {
			unencrypted = append(unencrypted, jobName)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "SageMaker Training Job Encryption",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d training jobs without volume encryption: %v", len(unencrypted), truncateList(unencrypted, 5)),
			Remediation:       "Enable KMS encryption for training job volumes",
			RemediationDetail: "When creating training jobs, specify VolumeKmsKeyId in ResourceConfig",
			ScreenshotGuide:   "SageMaker Console → Training jobs → Select job → Configuration → Screenshot showing encryption settings",
			ConsoleURL:        "https://console.aws.amazon.com/sagemaker/home#/jobs",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
		}, nil
	}

	if len(jobs.TrainingJobSummaries) == 0 {
		return skipped.passOrError(CheckResult{
			Control:    "CC6.3",
			Name:       "SageMaker Training Job Encryption",
			Status:     StatusInfo,
			Evidence:   "No SageMaker training jobs found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
		}), nil
	}

	return skipped.passOrError(CheckResult{
		Control:    "CC6.3",
		Name:       "SageMaker Training Job Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d recent training jobs have volume encryption enabled", len(jobs.TrainingJobSummaries)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SAGEMAKER_ENCRYPTION"),
	}), nil
}

func (c *SageMakerChecks) CheckModelNetworkIsolation(ctx context.Context) (CheckResult, error) {
	skipped := unreadable{}
	models, err := c.client.ListModels(ctx, &sagemaker.ListModelsInput{
		MaxResults: aws.Int32(100),
	})
	if err != nil {
		return checkError("CC6.1", "SageMaker Model Network Isolation", GetFrameworkMappings("SAGEMAKER_NETWORK"), err), err
	}

	notIsolated := []string{}

	for _, model := range models.Models {
		modelName := aws.ToString(model.ModelName)

		detail, err := c.client.DescribeModel(ctx, &sagemaker.DescribeModelInput{
			ModelName: model.ModelName,
		})
		if err != nil {
			skipped.add("DescribeModel", err)
			continue
		}

		// Check if network isolation is enabled
		if detail.EnableNetworkIsolation == nil || !*detail.EnableNetworkIsolation {
			notIsolated = append(notIsolated, modelName)
		}
	}

	if len(notIsolated) > 0 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "SageMaker Model Network Isolation",
			Status:            "FAIL",
			Severity:          "LOW",
			Evidence:          fmt.Sprintf("%d models without network isolation: %v", len(notIsolated), truncateList(notIsolated, 5)),
			Remediation:       "Enable network isolation for SageMaker models",
			RemediationDetail: "When creating models, set EnableNetworkIsolation=true to prevent network access during inference",
			ScreenshotGuide:   "SageMaker Console → Models → Select model → Network → Screenshot showing isolation settings",
			ConsoleURL:        "https://console.aws.amazon.com/sagemaker/home#/models",
			Priority:          PriorityLow,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SAGEMAKER_NETWORK"),
		}, nil
	}

	if len(models.Models) == 0 {
		return skipped.passOrError(CheckResult{
			Control:    "CC6.1",
			Name:       "SageMaker Model Network Isolation",
			Status:     StatusInfo,
			Evidence:   "No SageMaker models found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SAGEMAKER_NETWORK"),
		}), nil
	}

	return skipped.passOrError(CheckResult{
		Control:    "CC6.1",
		Name:       "SageMaker Model Network Isolation",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d models have network isolation enabled", len(models.Models)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SAGEMAKER_NETWORK"),
	}), nil
}
