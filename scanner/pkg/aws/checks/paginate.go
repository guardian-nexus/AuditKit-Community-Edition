package checks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// The helpers below read every page of a list call and return the usual output
// type with the items of all pages merged, so a call site changes in one place
// and its code reading users.Users or functions.Functions stays as it was.
//
// Each of these calls used to be made once. AWS returns one page - 100 IAM
// users, roles or policies, 50 Lambda functions, 100 RDS instances, 50 alarms,
// and only 10 SSM managed instances or parameters by default - so an account
// past the first page was evaluated on a subset, and a control could pass with
// user 101 never looked at.

func listAllUsers(ctx context.Context, client iam.ListUsersAPIClient, in *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	out := &iam.ListUsersOutput{}
	for p := iam.NewListUsersPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Users = append(out.Users, page.Users...)
	}
	return out, nil
}

func listAllRoles(ctx context.Context, client iam.ListRolesAPIClient, in *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
	out := &iam.ListRolesOutput{}
	for p := iam.NewListRolesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Roles = append(out.Roles, page.Roles...)
	}
	return out, nil
}

func listAllPolicies(ctx context.Context, client iam.ListPoliciesAPIClient, in *iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
	out := &iam.ListPoliciesOutput{}
	for p := iam.NewListPoliciesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Policies = append(out.Policies, page.Policies...)
	}
	return out, nil
}

func listAllFunctions(ctx context.Context, client lambda.ListFunctionsAPIClient, in *lambda.ListFunctionsInput) (*lambda.ListFunctionsOutput, error) {
	out := &lambda.ListFunctionsOutput{}
	for p := lambda.NewListFunctionsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Functions = append(out.Functions, page.Functions...)
	}
	return out, nil
}

func describeAllInstanceInformation(ctx context.Context, client ssm.DescribeInstanceInformationAPIClient, in *ssm.DescribeInstanceInformationInput) (*ssm.DescribeInstanceInformationOutput, error) {
	out := &ssm.DescribeInstanceInformationOutput{}
	for p := ssm.NewDescribeInstanceInformationPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.InstanceInformationList = append(out.InstanceInformationList, page.InstanceInformationList...)
	}
	return out, nil
}

func describeAllParameters(ctx context.Context, client ssm.DescribeParametersAPIClient, in *ssm.DescribeParametersInput) (*ssm.DescribeParametersOutput, error) {
	out := &ssm.DescribeParametersOutput{}
	for p := ssm.NewDescribeParametersPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Parameters = append(out.Parameters, page.Parameters...)
	}
	return out, nil
}

func describeAllDBInstances(ctx context.Context, client rds.DescribeDBInstancesAPIClient, in *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
	out := &rds.DescribeDBInstancesOutput{}
	for p := rds.NewDescribeDBInstancesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.DBInstances = append(out.DBInstances, page.DBInstances...)
	}
	return out, nil
}

func describeAllAlarms(ctx context.Context, client cloudwatch.DescribeAlarmsAPIClient, in *cloudwatch.DescribeAlarmsInput) (*cloudwatch.DescribeAlarmsOutput, error) {
	out := &cloudwatch.DescribeAlarmsOutput{}
	for p := cloudwatch.NewDescribeAlarmsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.MetricAlarms = append(out.MetricAlarms, page.MetricAlarms...)
		out.CompositeAlarms = append(out.CompositeAlarms, page.CompositeAlarms...)
	}
	return out, nil
}
