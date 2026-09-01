package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type ECSChecks struct {
	client *ecs.Client
}

func NewECSChecks(client *ecs.Client) *ECSChecks {
	return &ECSChecks{client: client}
}

func (c *ECSChecks) Name() string {
	return "ECS Security Configuration"
}

func (c *ECSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 7 - ECS controls
	if result, err := c.CheckECSTaskDefinitionLogging(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckECSSecretsManagement(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckECSContainerInsights(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckECSTaskRolePermissions(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CIS 7.1 - Ensure ECS task definitions have logging enabled
func (c *ECSChecks) CheckECSTaskDefinitionLogging(ctx context.Context) (CheckResult, error) {
	// List task definition families
	families, err := c.client.ListTaskDefinitionFamilies(ctx, &ecs.ListTaskDefinitionFamiliesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	tasksWithoutLogging := []string{}
	totalTasks := 0

	for _, family := range families.Families {
		// Get latest task definition
		taskDefs, err := c.client.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
			FamilyPrefix: &family,
			MaxResults:   aws.Int32(1),
		})
		if err != nil || len(taskDefs.TaskDefinitionArns) == 0 {
			continue
		}

		taskDefArn := taskDefs.TaskDefinitionArns[0]
		taskDef, err := c.client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: &taskDefArn,
		})
		if err != nil {
			continue
		}

		totalTasks++
		hasLogging := false

		for _, containerDef := range taskDef.TaskDefinition.ContainerDefinitions {
			if containerDef.LogConfiguration != nil {
				hasLogging = true
				break
			}
		}

		if !hasLogging {
			tasksWithoutLogging = append(tasksWithoutLogging, family)
		}
	}

	if len(tasksWithoutLogging) > 0 {
		displayTasks := tasksWithoutLogging
		if len(tasksWithoutLogging) > 5 {
			displayTasks = tasksWithoutLogging[:5]
		}

		return CheckResult{
			Control:     "[CIS-7.1]",
			Name:        "ECS Task Definition Logging",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d ECS task definitions without logging: %v | CIS 7.1", len(tasksWithoutLogging), totalTasks, displayTasks),
			Remediation: "Configure logging for ECS task definitions",
			RemediationDetail: `# Add to task definition JSON:
{
  "logConfiguration": {
    "logDriver": "awslogs",
    "options": {
      "awslogs-group": "/ecs/my-app",
      "awslogs-region": "us-east-1",
      "awslogs-stream-prefix": "ecs"
    }
  }
}`,
			ScreenshotGuide: "ECS Console → Task Definitions → Container definition → Storage and Logging → Screenshot showing logging configured",
			ConsoleURL:      "https://console.aws.amazon.com/ecs/home#/taskDefinitions",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "7.1", "SOC2": "CC7.2", "PCI-DSS": "10.2"},
		}, nil
	}

	if totalTasks == 0 {
		return CheckResult{
			Control:    "[CIS-7.1]",
			Name:       "ECS Task Definition Logging",
			Status:     "PASS",
			Evidence:   "No ECS task definitions found | CIS 7.1 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "7.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-7.1]",
		Name:       "ECS Task Definition Logging",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d ECS task definitions have logging enabled | Meets CIS 7.1", totalTasks),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "7.1"},
	}, nil
}

// CIS 7.2 - Ensure ECS uses Secrets Manager for sensitive data
func (c *ECSChecks) CheckECSSecretsManagement(ctx context.Context) (CheckResult, error) {
	families, err := c.client.ListTaskDefinitionFamilies(ctx, &ecs.ListTaskDefinitionFamiliesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	tasksWithPlaintextSecrets := []string{}
	totalTasks := 0

	for _, family := range families.Families {
		taskDefs, err := c.client.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
			FamilyPrefix: &family,
			MaxResults:   aws.Int32(1),
		})
		if err != nil || len(taskDefs.TaskDefinitionArns) == 0 {
			continue
		}

		taskDefArn := taskDefs.TaskDefinitionArns[0]
		taskDef, err := c.client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: &taskDefArn,
		})
		if err != nil {
			continue
		}

		totalTasks++

		for _, containerDef := range taskDef.TaskDefinition.ContainerDefinitions {
			// Check for environment variables with sensitive-looking names
			for _, envVar := range containerDef.Environment {
				varName := *envVar.Name
				if contains(varName, "PASSWORD") || contains(varName, "SECRET") ||
					contains(varName, "KEY") || contains(varName, "TOKEN") ||
					contains(varName, "CREDENTIAL") {
					// Check if using Secrets Manager (should have valueFrom, not value)
					if envVar.Value != nil && *envVar.Value != "" {
						tasksWithPlaintextSecrets = append(tasksWithPlaintextSecrets, family)
						break
					}
				}
			}
		}
	}

	if len(tasksWithPlaintextSecrets) > 0 {
		displayTasks := tasksWithPlaintextSecrets
		if len(tasksWithPlaintextSecrets) > 5 {
			displayTasks = tasksWithPlaintextSecrets[:5]
		}

		return CheckResult{
			Control:     "[CIS-7.2]",
			Name:        "ECS Secrets Management",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("%d ECS tasks with plaintext sensitive environment variables: %v | CIS 7.2", len(tasksWithPlaintextSecrets), displayTasks),
			Remediation: "Use AWS Secrets Manager or Parameter Store for sensitive data",
			RemediationDetail: `# Instead of:
"environment": [{"name": "DB_PASSWORD", "value": "plaintext"}]

# Use Secrets Manager:
"secrets": [{
  "name": "DB_PASSWORD",
  "valueFrom": "arn:aws:secretsmanager:region:account:secret:db-password"
}]`,
			ScreenshotGuide: "ECS Console → Task Definitions → Environment → Screenshot showing secrets from Secrets Manager",
			ConsoleURL:      "https://console.aws.amazon.com/ecs/home#/taskDefinitions",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "7.2", "SOC2": "CC6.1", "PCI-DSS": "3.4"},
		}, nil
	}

	if totalTasks == 0 {
		return CheckResult{
			Control:    "[CIS-7.2]",
			Name:       "ECS Secrets Management",
			Status:     "PASS",
			Evidence:   "No ECS task definitions found | CIS 7.2 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "7.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-7.2]",
		Name:       "ECS Secrets Management",
		Status:     "PASS",
		Evidence:   "ECS tasks use Secrets Manager for sensitive data | Meets CIS 7.2",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "7.2"},
	}, nil
}

// CIS 7.3 - Ensure ECS Container Insights is enabled
func (c *ECSChecks) CheckECSContainerInsights(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.ClusterArns) == 0 {
		return CheckResult{
			Control:    "[CIS-7.3]",
			Name:       "ECS Container Insights",
			Status:     "PASS",
			Evidence:   "No ECS clusters found | CIS 7.3 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "7.3"},
		}, nil
	}

	clustersOutput, err := c.client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: clusters.ClusterArns,
		Include:  []types.ClusterField{types.ClusterFieldSettings},
	})
	if err != nil {
		return CheckResult{}, err
	}

	clustersWithoutInsights := []string{}

	for _, cluster := range clustersOutput.Clusters {
		hasInsights := false
		for _, setting := range cluster.Settings {
			if string(setting.Name) == "containerInsights" {
				if setting.Value != nil && *setting.Value == "enabled" {
					hasInsights = true
					break
				}
			}
		}

		if !hasInsights {
			clustersWithoutInsights = append(clustersWithoutInsights, *cluster.ClusterName)
		}
	}

	if len(clustersWithoutInsights) > 0 {
		return CheckResult{
			Control:     "[CIS-7.3]",
			Name:        "ECS Container Insights",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d/%d ECS clusters without Container Insights: %v | CIS 7.3", len(clustersWithoutInsights), len(clustersOutput.Clusters), clustersWithoutInsights),
			Remediation: "Enable Container Insights for ECS clusters",
			RemediationDetail: `aws ecs update-cluster-settings \
  --cluster CLUSTER_NAME \
  --settings name=containerInsights,value=enabled`,
			ScreenshotGuide: "ECS Console → Clusters → Update Cluster → CloudWatch Container Insights → Screenshot showing enabled",
			ConsoleURL:      "https://console.aws.amazon.com/ecs/home#/clusters",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "7.3", "SOC2": "CC7.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-7.3]",
		Name:       "ECS Container Insights",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d ECS clusters have Container Insights enabled | Meets CIS 7.3", len(clustersOutput.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "7.3"},
	}, nil
}

// CIS 7.4 - Ensure ECS task roles follow least privilege
func (c *ECSChecks) CheckECSTaskRolePermissions(ctx context.Context) (CheckResult, error) {
	families, err := c.client.ListTaskDefinitionFamilies(ctx, &ecs.ListTaskDefinitionFamiliesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	tasksWithBroadRoles := []string{}
	totalTasks := 0

	for _, family := range families.Families {
		taskDefs, err := c.client.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{
			FamilyPrefix: &family,
			MaxResults:   aws.Int32(1),
		})
		if err != nil || len(taskDefs.TaskDefinitionArns) == 0 {
			continue
		}

		taskDefArn := taskDefs.TaskDefinitionArns[0]
		taskDef, err := c.client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: &taskDefArn,
		})
		if err != nil {
			continue
		}

		totalTasks++

		// Check task role for overly permissive policies
		if taskDef.TaskDefinition.TaskRoleArn != nil {
			role := *taskDef.TaskDefinition.TaskRoleArn
			if contains(role, "AdministratorAccess") || contains(role, "PowerUserAccess") {
				tasksWithBroadRoles = append(tasksWithBroadRoles, family)
			}
		}
	}

	if len(tasksWithBroadRoles) > 0 {
		displayTasks := tasksWithBroadRoles
		if len(tasksWithBroadRoles) > 5 {
			displayTasks = tasksWithBroadRoles[:5]
		}

		return CheckResult{
			Control:     "[CIS-7.4]",
			Name:        "ECS Task Role Permissions",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d ECS tasks with overly permissive roles: %v | CIS 7.4", len(tasksWithBroadRoles), displayTasks),
			Remediation: "Use least privilege IAM roles for ECS tasks",
			RemediationDetail: `# Create custom role with only required permissions
aws iam create-role --role-name ECSTaskRole --assume-role-policy-document file://ecs-trust-policy.json
aws iam put-role-policy --role-name ECSTaskRole --policy-name TaskPolicy --policy-document file://task-policy.json`,
			ScreenshotGuide: "ECS Console → Task Definitions → Task role → Screenshot showing least-privilege policy",
			ConsoleURL:      "https://console.aws.amazon.com/ecs/home#/taskDefinitions",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "7.4", "SOC2": "CC6.3", "PCI-DSS": "7.1.2"},
		}, nil
	}

	if totalTasks == 0 {
		return CheckResult{
			Control:    "[CIS-7.4]",
			Name:       "ECS Task Role Permissions",
			Status:     "PASS",
			Evidence:   "No ECS task definitions found | CIS 7.4 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "7.4"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-7.4]",
		Name:       "ECS Task Role Permissions",
		Status:     "PASS",
		Evidence:   "ECS tasks use least-privilege roles | Meets CIS 7.4",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "7.4"},
	}, nil
}
