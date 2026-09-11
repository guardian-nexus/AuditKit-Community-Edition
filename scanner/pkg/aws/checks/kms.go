package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSChecks answers CIS AWS Foundations v7.0.0 4.6, rotation for
// customer-created symmetric CMKs.
//
// This was previously a MANUAL result scoped to the key CloudTrail encrypts
// with, which was two problems at once: the benchmark marks 4.6 Automated, and
// it covers every customer-created symmetric key rather than one of them.
type KMSChecks struct {
	client *kms.Client
}

func NewKMSChecks(client *kms.Client) *KMSChecks {
	return &KMSChecks{client: client}
}

func (c *KMSChecks) Name() string { return "KMS Key Rotation" }

func (c *KMSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	result, err := c.CheckKeyRotation(ctx)
	if err != nil {
		return nil, err
	}
	return []CheckResult{result}, nil
}

// maxKeyPages bounds the walk. An account with more keys than this gets a
// verdict on the first 5,000, and the evidence says how many were examined.
const maxKeyPages = 50

// CheckKeyRotation answers CIS AWS Foundations v7.0.0 4.6.
//
// Only customer-managed symmetric encryption keys are in scope. AWS-managed
// keys rotate on their own schedule and cannot be configured, and asymmetric
// keys and HMAC keys do not support rotation at all - counting either as a
// failure would report a finding the user cannot act on.
func (c *KMSChecks) CheckKeyRotation(ctx context.Context) (CheckResult, error) {
	const control, name = "CIS-4.6", "Customer-Managed KMS Key Rotation"
	frameworks := map[string]string{"CIS-AWS": "4.6", "SOC2": "CC6.3", "PCI-DSS": "3.6.1", "HIPAA": "164.312(a)(2)(iv)"}

	fail := func(msg string) CheckResult {
		return CheckResult{
			Control: control, Name: name, Status: "ERROR",
			Evidence:   msg,
			Severity:   "MEDIUM",
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: frameworks,
		}
	}
	if c.client == nil {
		return fail("KMS client not configured"), nil
	}

	var withoutRotation []string
	inScope := 0
	var marker *string
	for page := 0; page < maxKeyPages; page++ {
		out, err := c.client.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return fail(fmt.Sprintf("Unable to list KMS keys: %v", err)), nil
		}
		for _, k := range out.Keys {
			id := aws.ToString(k.KeyId)
			desc, err := c.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err != nil || desc.KeyMetadata == nil {
				// One unreadable key must not decide the control either way.
				continue
			}
			md := desc.KeyMetadata
			if md.KeyManager != kmstypes.KeyManagerTypeCustomer {
				continue // AWS-managed keys rotate on their own schedule
			}
			if md.KeySpec != kmstypes.KeySpecSymmetricDefault {
				continue // asymmetric and HMAC keys cannot be rotated
			}
			if md.KeyState != kmstypes.KeyStateEnabled {
				continue // a disabled or pending-deletion key is not in scope
			}
			inScope++
			rot, err := c.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
			if err != nil {
				continue
			}
			if !rot.KeyRotationEnabled {
				label := id
				if aws.ToString(md.Description) != "" {
					label = fmt.Sprintf("%s (%s)", id, aws.ToString(md.Description))
				}
				withoutRotation = append(withoutRotation, label)
			}
		}
		if !out.Truncated || out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}

	if len(withoutRotation) > 0 {
		shown := withoutRotation
		if len(shown) > 5 {
			shown = shown[:5]
		}
		return CheckResult{
			Control: control, Name: name, Status: "FAIL",
			Severity: "MEDIUM",
			Evidence: fmt.Sprintf("%d of %d customer-managed symmetric KMS key(s) do not have automatic rotation enabled: %v",
				len(withoutRotation), inScope, shown),
			Remediation:       "Enable automatic rotation on each customer-managed symmetric key",
			RemediationDetail: fmt.Sprintf("aws kms enable-key-rotation --key-id %s", withoutRotation[0]),
			ScreenshotGuide:   "KMS -> Customer managed keys -> select a key -> Key rotation -> Screenshot showing rotation enabled",
			ConsoleURL:        "https://console.aws.amazon.com/kms/home#/kms/keys",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        frameworks,
		}, nil
	}

	evidence := fmt.Sprintf("All %d customer-managed symmetric KMS key(s) have automatic rotation enabled", inScope)
	if inScope == 0 {
		evidence = "No customer-managed symmetric KMS keys exist in this region"
	}
	return CheckResult{
		Control: control, Name: name, Status: "PASS",
		Evidence:   evidence,
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: frameworks,
	}, nil
}
