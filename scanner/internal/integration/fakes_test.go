// Package integration drives the vulnerability evidence feature end to end in
// the Community edition: a faked Inspector API through the real collector and
// the real control adapter.
//
// Its second job is a runtime guard on the edition split.
// check-edition-split.py asserts that the paid capabilities are absent from
// this tree by reading the source; this asserts it by running the adapter and
// looking at what comes out, which is the claim that actually matters.
package integration

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func ptr[T any](v T) *T { return &v }

type fakeInspector struct {
	status   inspectortypes.Status
	coverage []inspectortypes.CoveredResource
	covErr   error
	// findings is served if anything ever asks. Nothing in this edition should.
	findings  []inspectortypes.Finding
	findCalls int
}

func (f fakeInspector) BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput,
	...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	status := f.status
	if status == "" {
		status = inspectortypes.StatusEnabled
	}
	return &inspector2.BatchGetAccountStatusOutput{
		Accounts: []inspectortypes.AccountState{{
			AccountId: ptr("111122223333"),
			State:     &inspectortypes.State{Status: status},
			ResourceState: &inspectortypes.ResourceState{
				Ec2:    &inspectortypes.State{Status: status},
				Ecr:    &inspectortypes.State{Status: status},
				Lambda: &inspectortypes.State{Status: status},
			},
		}},
	}, nil
}

func (f fakeInspector) ListCoverage(context.Context, *inspector2.ListCoverageInput,
	...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error) {
	if f.covErr != nil {
		return nil, f.covErr
	}
	return &inspector2.ListCoverageOutput{CoveredResources: f.coverage}, nil
}

func (f *fakeInspector) ListFindings(context.Context, *inspector2.ListFindingsInput,
	...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	f.findCalls++
	return &inspector2.ListFindingsOutput{Findings: f.findings}, nil
}

type fakeEC2 struct{ ids []string }

func (f fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput,
	...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	inst := make([]ec2types.Instance, 0, len(f.ids))
	for _, id := range f.ids {
		inst = append(inst, ec2types.Instance{
			InstanceId: ptr(id),
			State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		})
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: inst}},
	}, nil
}

type fakeLambda struct{}

func (fakeLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput,
	...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{}, nil
}

type fakeECR struct{}

func (fakeECR) DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput,
	...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return &ecr.DescribeRepositoriesOutput{}, nil
}

func covered(id, resourceType, status, reason string, scanned time.Time) inspectortypes.CoveredResource {
	r := inspectortypes.CoveredResource{
		ResourceId:   ptr(id),
		ResourceType: inspectortypes.CoverageResourceType(resourceType),
		ScanStatus: &inspectortypes.ScanStatus{
			StatusCode: inspectortypes.ScanStatusCode(status),
			Reason:     inspectortypes.ScanStatusReason(reason),
		},
	}
	if !scanned.IsZero() {
		r.LastScannedAt = ptr(scanned)
	}
	return r
}

func awsFinding(id, instanceID, severity string, first time.Time) inspectortypes.Finding {
	return inspectortypes.Finding{
		FindingArn: ptr("arn:aws:inspector2:us-east-1:111122223333:finding/" + id),
		Title:      ptr(id),
		Severity:   inspectortypes.Severity(severity),
		FirstObservedAt: func() *time.Time {
			if first.IsZero() {
				return nil
			}
			return ptr(first)
		}(),
		FixAvailable: inspectortypes.FixAvailableYes,
		Resources: []inspectortypes.Resource{{
			Id: ptr(instanceID), Type: inspectortypes.ResourceTypeAwsEc2Instance,
		}},
		PackageVulnerabilityDetails: &inspectortypes.PackageVulnerabilityDetails{
			VulnerabilityId: ptr(id),
		},
	}
}
