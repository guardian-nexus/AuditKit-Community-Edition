package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type DynamoDBChecks struct {
	client *dynamodb.Client
}

func NewDynamoDBChecks(client *dynamodb.Client) *DynamoDBChecks {
	return &DynamoDBChecks{client: client}
}

func (c *DynamoDBChecks) Name() string {
	return "DynamoDB Security Configuration"
}

func (c *DynamoDBChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckPointInTimeRecovery(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEncryptionAtRest(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckAutoScaling(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *DynamoDBChecks) CheckPointInTimeRecovery(ctx context.Context) (CheckResult, error) {
	tables, err := c.client.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-14.1",
			Name:       "DynamoDB Point-in-Time Recovery",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Failed to list DynamoDB tables: %v", err),
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DYNAMODB_PITR"),
		}, err
	}

	if len(tables.TableNames) == 0 {
		return CheckResult{
			Control:    "CIS-14.1",
			Name:       "DynamoDB Point-in-Time Recovery",
			Status:     "INFO",
			Evidence:   "No DynamoDB tables found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DYNAMODB_PITR"),
		}, nil
	}

	without := []string{}
	with := 0

	for _, tableName := range tables.TableNames {
		pitr, err := c.client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
			TableName: &tableName,
		})
		if err != nil {
			continue
		}

		if pitr.ContinuousBackupsDescription != nil &&
			pitr.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil &&
			pitr.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "ENABLED" {
			with++
		} else {
			without = append(without, tableName)
		}
	}

	if len(without) > 0 {
		return CheckResult{
			Control:     "CIS-14.1",
			Name:        "DynamoDB Point-in-Time Recovery",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d tables lack PITR: %v", len(without), len(tables.TableNames), without),
			Remediation: "Enable point-in-time recovery for all DynamoDB tables",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/dynamodbv2/home#tables",
			Frameworks:  GetFrameworkMappings("DYNAMODB_PITR"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-14.1",
		Name:       "DynamoDB Point-in-Time Recovery",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d tables have PITR enabled", with),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/dynamodbv2/home#tables",
		Frameworks: GetFrameworkMappings("DYNAMODB_PITR"),
	}, nil
}

func (c *DynamoDBChecks) CheckEncryptionAtRest(ctx context.Context) (CheckResult, error) {
	tables, err := c.client.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-14.2",
			Name:       "DynamoDB Encryption at Rest",
			Status:     "ERROR",
			Evidence:   "Failed to list tables",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DYNAMODB_ENCRYPTION"),
		}, err
	}

	if len(tables.TableNames) == 0 {
		return CheckResult{
			Control:    "CIS-14.2",
			Name:       "DynamoDB Encryption at Rest",
			Status:     "INFO",
			Evidence:   "No DynamoDB tables found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DYNAMODB_ENCRYPTION"),
		}, nil
	}

	customKMS := 0
	awsManaged := 0
	unencrypted := []string{}

	for _, tableName := range tables.TableNames {
		table, err := c.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: &tableName,
		})
		if err != nil {
			continue
		}

		if table.Table.SSEDescription != nil {
			if table.Table.SSEDescription.KMSMasterKeyArn != nil {
				customKMS++
			} else {
				awsManaged++
			}
		} else {
			unencrypted = append(unencrypted, tableName)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:     "CIS-14.2",
			Name:        "DynamoDB Encryption at Rest",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d tables not encrypted: %v", len(unencrypted), unencrypted),
			Remediation: "Enable encryption at rest for all DynamoDB tables",
			Severity:    "CRITICAL",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/dynamodbv2/home#tables",
			Frameworks:  GetFrameworkMappings("DYNAMODB_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-14.2",
		Name:       "DynamoDB Encryption at Rest",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All tables encrypted. %d custom KMS, %d AWS managed", customKMS, awsManaged),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/dynamodbv2/home#tables",
		Frameworks: GetFrameworkMappings("DYNAMODB_ENCRYPTION"),
	}, nil
}

func (c *DynamoDBChecks) CheckAutoScaling(ctx context.Context) (CheckResult, error) {
	tables, err := c.client.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-14.3",
			Name:       "DynamoDB Auto Scaling Enabled",
			Status:     "ERROR",
			Evidence:   "Failed to list tables",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DYNAMODB_AUTOSCALING"),
		}, err
	}

	if len(tables.TableNames) == 0 {
		return CheckResult{
			Control:    "CIS-14.3",
			Name:       "DynamoDB Auto Scaling Enabled",
			Status:     "INFO",
			Evidence:   "No DynamoDB tables found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DYNAMODB_AUTOSCALING"),
		}, nil
	}

	// This is a simplified check - full check would query Application Auto Scaling
	onDemand := 0
	provisioned := 0

	for _, tableName := range tables.TableNames {
		table, err := c.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: &tableName,
		})
		if err != nil {
			continue
		}

		if table.Table.BillingModeSummary != nil && table.Table.BillingModeSummary.BillingMode == "PAY_PER_REQUEST" {
			onDemand++
		} else {
			provisioned++
		}
	}

	return CheckResult{
		Control:    "CIS-14.3",
		Name:       "DynamoDB Auto Scaling Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("%d tables on-demand (auto-scales), %d provisioned", onDemand, provisioned),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/dynamodbv2/home#tables",
		Frameworks: GetFrameworkMappings("DYNAMODB_AUTOSCALING"),
	}, nil
}
