package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type MessagingChecks struct {
	snsClient *sns.Client
	sqsClient *sqs.Client
}

func NewMessagingChecks(snsClient *sns.Client, sqsClient *sqs.Client) *MessagingChecks {
	return &MessagingChecks{
		snsClient: snsClient,
		sqsClient: sqsClient,
	}
}

func (c *MessagingChecks) Name() string {
	return "Messaging Services Security Configuration (SNS/SQS)"
}

func (c *MessagingChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 10.13 - SNS Encryption
	if result, err := c.CheckSNSEncryption(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.14 - SQS Encryption
	if result, err := c.CheckSQSEncryption(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.15 - Messaging Access Policies
	if result, err := c.CheckMessagingAccessPolicies(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckSNSEncryption - Ensure SNS topics use encryption at rest
func (c *MessagingChecks) CheckSNSEncryption(ctx context.Context) (CheckResult, error) {
	topics, err := c.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "SNS Topic Encryption",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list SNS topics: %v", err),
			Remediation: "Verify SNS access permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SNS_ENCRYPTION"),
		}, err
	}

	if len(topics.Topics) == 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "SNS Topic Encryption",
			Status:      "INFO",
			Evidence:    "No SNS topics found",
			Remediation: "N/A - No SNS topics to check",
			RemediationDetail: `When creating SNS topics:
1. Open SNS console
2. Create topic
3. Enable encryption at rest
4. Select KMS key (default or custom)
5. Screenshot showing encrypted topic`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "SNS → Topics → Screenshot showing no topics",
			ConsoleURL:      "https://console.aws.amazon.com/sns/home#/topics",
			Frameworks:      GetFrameworkMappings("SNS_ENCRYPTION"),
		}, nil
	}

	unencryptedTopics := []string{}
	encryptedTopics := 0

	for _, topic := range topics.Topics {
		attrs, err := c.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
			TopicArn: topic.TopicArn,
		})
		if err != nil {
			continue
		}

		// Check for KmsMasterKeyId attribute
		if kmsKey, exists := attrs.Attributes["KmsMasterKeyId"]; exists && kmsKey != "" {
			encryptedTopics++
		} else {
			// Extract topic name from ARN
			topicName := *topic.TopicArn
			if idx := strings.LastIndex(topicName, ":"); idx != -1 {
				topicName = topicName[idx+1:]
			}
			unencryptedTopics = append(unencryptedTopics, topicName)
		}
	}

	if len(unencryptedTopics) > 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "SNS Topic Encryption",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d SNS topics lack encryption at rest: %v", len(unencryptedTopics), len(topics.Topics), unencryptedTopics),
			Remediation: "Enable encryption for unencrypted SNS topics",
			RemediationDetail: fmt.Sprintf(`1. Open SNS console
2. For each unencrypted topic: %v
3. Select topic → Edit
4. Enable encryption
5. Select KMS key (custom key recommended for compliance)
6. Save changes
7. Update any applications if KMS permissions are needed
8. Screenshot showing encryption enabled`, unencryptedTopics),
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "SNS → Topics → Topic → Edit → Screenshot showing encryption enabled",
			ConsoleURL:      "https://console.aws.amazon.com/sns/home#/topics",
			Frameworks:      GetFrameworkMappings("SNS_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:     "CC6.3",
		Name:        "SNS Topic Encryption",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d SNS topics use KMS encryption at rest", encryptedTopics),
		Remediation: "N/A - All topics encrypted",
		RemediationDetail: fmt.Sprintf(`All %d SNS topics are encrypted with KMS.
Continue using encryption for all new topics.`, encryptedTopics),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "SNS → Topics → Screenshot showing all topics encrypted",
		ConsoleURL:      "https://console.aws.amazon.com/sns/home#/topics",
		Frameworks:      GetFrameworkMappings("SNS_ENCRYPTION"),
	}, nil
}

// CheckSQSEncryption - Ensure SQS queues use encryption at rest
func (c *MessagingChecks) CheckSQSEncryption(ctx context.Context) (CheckResult, error) {
	queues, err := c.sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "SQS Queue Encryption",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list SQS queues: %v", err),
			Remediation: "Verify SQS access permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SQS_ENCRYPTION"),
		}, err
	}

	if len(queues.QueueUrls) == 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "SQS Queue Encryption",
			Status:      "INFO",
			Evidence:    "No SQS queues found",
			Remediation: "N/A - No SQS queues to check",
			RemediationDetail: `When creating SQS queues:
1. Open SQS console
2. Create queue
3. Enable server-side encryption
4. Select KMS key (default or custom)
5. Screenshot showing encrypted queue`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "SQS → Queues → Screenshot showing no queues",
			ConsoleURL:      "https://console.aws.amazon.com/sqs/home#/queues",
			Frameworks:      GetFrameworkMappings("SQS_ENCRYPTION"),
		}, nil
	}

	unencryptedQueues := []string{}
	encryptedQueues := 0

	for _, queueURL := range queues.QueueUrls {
		attrs, err := c.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       &queueURL,
			AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll},
		})
		if err != nil {
			continue
		}

		// Check for KmsMasterKeyId attribute
		if kmsKey, exists := attrs.Attributes["KmsMasterKeyId"]; exists && kmsKey != "" {
			encryptedQueues++
		} else {
			// Extract queue name from URL
			queueName := queueURL
			if idx := strings.LastIndex(queueName, "/"); idx != -1 {
				queueName = queueName[idx+1:]
			}
			unencryptedQueues = append(unencryptedQueues, queueName)
		}
	}

	if len(unencryptedQueues) > 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "SQS Queue Encryption",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d SQS queues lack encryption at rest: %v", len(unencryptedQueues), len(queues.QueueUrls), unencryptedQueues),
			Remediation: "Enable encryption for unencrypted SQS queues",
			RemediationDetail: fmt.Sprintf(`1. Open SQS console
2. For each unencrypted queue: %v
3. Select queue → Edit
4. Enable server-side encryption (SSE)
5. Select KMS key (custom key recommended)
6. Save changes
7. Update applications with KMS permissions if needed
8. Screenshot showing encryption enabled`, unencryptedQueues),
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "SQS → Queues → Queue → Edit → Screenshot showing SSE enabled",
			ConsoleURL:      "https://console.aws.amazon.com/sqs/home#/queues",
			Frameworks:      GetFrameworkMappings("SQS_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:     "CC6.3",
		Name:        "SQS Queue Encryption",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d SQS queues use KMS encryption at rest", encryptedQueues),
		Remediation: "N/A - All queues encrypted",
		RemediationDetail: fmt.Sprintf(`All %d SQS queues are encrypted with KMS.
Continue using encryption for all new queues.`, encryptedQueues),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "SQS → Queues → Screenshot showing all queues encrypted",
		ConsoleURL:      "https://console.aws.amazon.com/sqs/home#/queues",
		Frameworks:      GetFrameworkMappings("SQS_ENCRYPTION"),
	}, nil
}

// CheckMessagingAccessPolicies - Ensure SNS/SQS use restrictive access policies
func (c *MessagingChecks) CheckMessagingAccessPolicies(ctx context.Context) (CheckResult, error) {
	// Check SNS topics
	topics, err := c.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "Messaging Access Policies",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list topics: %v", err),
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("MESSAGING_ACCESS_POLICY"),
		}, err
	}

	// Check SQS queues
	queues, err := c.sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "Messaging Access Policies",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list queues: %v", err),
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("MESSAGING_ACCESS_POLICY"),
		}, err
	}

	totalResources := len(topics.Topics) + len(queues.QueueUrls)

	if totalResources == 0 {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "Messaging Access Policies",
			Status:      "INFO",
			Evidence:    "No SNS topics or SQS queues found",
			Remediation: "N/A - No messaging resources to check",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("MESSAGING_ACCESS_POLICY"),
		}, nil
	}

	// Access policy review requires manual verification
	// We can't easily detect overly permissive policies programmatically
	return CheckResult{
		Control:     "CC6.1",
		Name:        "Messaging Access Policies",
		Status:      "MANUAL",
		Evidence:    fmt.Sprintf("MANUAL CHECK: Review access policies for %d SNS topics and %d SQS queues", len(topics.Topics), len(queues.QueueUrls)),
		Remediation: "Review and restrict messaging access policies",
		RemediationDetail: fmt.Sprintf(`1. Review SNS topic policies (%d topics):
   - Open SNS console → Topics → Select topic → Access policy
   - Ensure Principal is not "*" (public access)
   - Verify only required AWS services/accounts have access
   - Screenshot showing restrictive policies

2. Review SQS queue policies (%d queues):
   - Open SQS console → Queues → Select queue → Access policy
   - Ensure Principal is not "*" unless specifically required
   - Verify only required services have SendMessage/ReceiveMessage
   - Screenshot showing restrictive policies

3. Best practices:
   - Use least privilege principle
   - Specify exact ARNs instead of wildcards
   - Use Condition elements to restrict access`, len(topics.Topics), len(queues.QueueUrls)),
		Severity:        "CRITICAL",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "SNS/SQS → Resource → Access policy → Screenshot showing restrictive policies",
		ConsoleURL:      "https://console.aws.amazon.com/sns/home#/topics",
		Frameworks:      GetFrameworkMappings("MESSAGING_ACCESS_POLICY"),
	}, nil
}
