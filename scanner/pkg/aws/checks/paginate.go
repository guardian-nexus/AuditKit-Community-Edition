package checks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
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
//
// The same went for SNS topics, ECR repositories, DynamoDB tables, KMS keys,
// Auto Scaling groups, REST APIs, Organizations policies and accounts,
// ElastiCache clusters and SageMaker resources, which all truncate in an
// account of ordinary size, and for the calls below them whose page size AWS
// does not document. Organizations may return an empty page that still
// carries a NextToken; the paginators loop on the token, not the page length.
//
// Every helper takes the input the call site already built, so a page size or
// filter set there still applies.

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

func listAllTopics(ctx context.Context, client sns.ListTopicsAPIClient, in *sns.ListTopicsInput) (*sns.ListTopicsOutput, error) {
	out := &sns.ListTopicsOutput{}
	for p := sns.NewListTopicsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Topics = append(out.Topics, page.Topics...)
	}
	return out, nil
}

func describeAllRepositories(ctx context.Context, client ecr.DescribeRepositoriesAPIClient, in *ecr.DescribeRepositoriesInput) (*ecr.DescribeRepositoriesOutput, error) {
	out := &ecr.DescribeRepositoriesOutput{}
	for p := ecr.NewDescribeRepositoriesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Repositories = append(out.Repositories, page.Repositories...)
	}
	return out, nil
}

func listAllTaskDefinitionFamilies(ctx context.Context, client ecs.ListTaskDefinitionFamiliesAPIClient, in *ecs.ListTaskDefinitionFamiliesInput) (*ecs.ListTaskDefinitionFamiliesOutput, error) {
	out := &ecs.ListTaskDefinitionFamiliesOutput{}
	for p := ecs.NewListTaskDefinitionFamiliesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Families = append(out.Families, page.Families...)
	}
	return out, nil
}

func listAllTables(ctx context.Context, client dynamodb.ListTablesAPIClient, in *dynamodb.ListTablesInput) (*dynamodb.ListTablesOutput, error) {
	out := &dynamodb.ListTablesOutput{}
	for p := dynamodb.NewListTablesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.TableNames = append(out.TableNames, page.TableNames...)
	}
	return out, nil
}

func listAllKeys(ctx context.Context, client kms.ListKeysAPIClient, in *kms.ListKeysInput) (*kms.ListKeysOutput, error) {
	out := &kms.ListKeysOutput{}
	for p := kms.NewListKeysPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Keys = append(out.Keys, page.Keys...)
	}
	return out, nil
}

func describeAllAutoScalingGroups(ctx context.Context, client autoscaling.DescribeAutoScalingGroupsAPIClient, in *autoscaling.DescribeAutoScalingGroupsInput) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	out := &autoscaling.DescribeAutoScalingGroupsOutput{}
	for p := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.AutoScalingGroups = append(out.AutoScalingGroups, page.AutoScalingGroups...)
	}
	return out, nil
}

func getAllRestApis(ctx context.Context, client apigateway.GetRestApisAPIClient, in *apigateway.GetRestApisInput) (*apigateway.GetRestApisOutput, error) {
	out := &apigateway.GetRestApisOutput{}
	for p := apigateway.NewGetRestApisPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, page.Items...)
	}
	return out, nil
}

func listAllOrgPolicies(ctx context.Context, client organizations.ListPoliciesAPIClient, in *organizations.ListPoliciesInput) (*organizations.ListPoliciesOutput, error) {
	out := &organizations.ListPoliciesOutput{}
	for p := organizations.NewListPoliciesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Policies = append(out.Policies, page.Policies...)
	}
	return out, nil
}

func listAllAccounts(ctx context.Context, client organizations.ListAccountsAPIClient, in *organizations.ListAccountsInput) (*organizations.ListAccountsOutput, error) {
	out := &organizations.ListAccountsOutput{}
	for p := organizations.NewListAccountsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Accounts = append(out.Accounts, page.Accounts...)
	}
	return out, nil
}

func describeAllCacheClusters(ctx context.Context, client elasticache.DescribeCacheClustersAPIClient, in *elasticache.DescribeCacheClustersInput) (*elasticache.DescribeCacheClustersOutput, error) {
	out := &elasticache.DescribeCacheClustersOutput{}
	for p := elasticache.NewDescribeCacheClustersPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.CacheClusters = append(out.CacheClusters, page.CacheClusters...)
	}
	return out, nil
}

func listAllEndpoints(ctx context.Context, client sagemaker.ListEndpointsAPIClient, in *sagemaker.ListEndpointsInput) (*sagemaker.ListEndpointsOutput, error) {
	out := &sagemaker.ListEndpointsOutput{}
	for p := sagemaker.NewListEndpointsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Endpoints = append(out.Endpoints, page.Endpoints...)
	}
	return out, nil
}

func listAllTrainingJobs(ctx context.Context, client sagemaker.ListTrainingJobsAPIClient, in *sagemaker.ListTrainingJobsInput) (*sagemaker.ListTrainingJobsOutput, error) {
	out := &sagemaker.ListTrainingJobsOutput{}
	for p := sagemaker.NewListTrainingJobsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.TrainingJobSummaries = append(out.TrainingJobSummaries, page.TrainingJobSummaries...)
	}
	return out, nil
}

func listAllNotebookInstances(ctx context.Context, client sagemaker.ListNotebookInstancesAPIClient, in *sagemaker.ListNotebookInstancesInput) (*sagemaker.ListNotebookInstancesOutput, error) {
	out := &sagemaker.ListNotebookInstancesOutput{}
	for p := sagemaker.NewListNotebookInstancesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.NotebookInstances = append(out.NotebookInstances, page.NotebookInstances...)
	}
	return out, nil
}

func listAllTrails(ctx context.Context, client cloudtrail.ListTrailsAPIClient, in *cloudtrail.ListTrailsInput) (*cloudtrail.ListTrailsOutput, error) {
	out := &cloudtrail.ListTrailsOutput{}
	for p := cloudtrail.NewListTrailsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Trails = append(out.Trails, page.Trails...)
	}
	return out, nil
}

func listAllSecrets(ctx context.Context, client secretsmanager.ListSecretsAPIClient, in *secretsmanager.ListSecretsInput) (*secretsmanager.ListSecretsOutput, error) {
	out := &secretsmanager.ListSecretsOutput{}
	for p := secretsmanager.NewListSecretsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.SecretList = append(out.SecretList, page.SecretList...)
	}
	return out, nil
}

func listAllBackupVaults(ctx context.Context, client backup.ListBackupVaultsAPIClient, in *backup.ListBackupVaultsInput) (*backup.ListBackupVaultsOutput, error) {
	out := &backup.ListBackupVaultsOutput{}
	for p := backup.NewListBackupVaultsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.BackupVaultList = append(out.BackupVaultList, page.BackupVaultList...)
	}
	return out, nil
}

func listAllBackupPlans(ctx context.Context, client backup.ListBackupPlansAPIClient, in *backup.ListBackupPlansInput) (*backup.ListBackupPlansOutput, error) {
	out := &backup.ListBackupPlansOutput{}
	for p := backup.NewListBackupPlansPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.BackupPlansList = append(out.BackupPlansList, page.BackupPlansList...)
	}
	return out, nil
}

func listAllFirewalls(ctx context.Context, client networkfirewall.ListFirewallsAPIClient, in *networkfirewall.ListFirewallsInput) (*networkfirewall.ListFirewallsOutput, error) {
	out := &networkfirewall.ListFirewallsOutput{}
	for p := networkfirewall.NewListFirewallsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Firewalls = append(out.Firewalls, page.Firewalls...)
	}
	return out, nil
}

func listAllFirewallPolicies(ctx context.Context, client networkfirewall.ListFirewallPoliciesAPIClient, in *networkfirewall.ListFirewallPoliciesInput) (*networkfirewall.ListFirewallPoliciesOutput, error) {
	out := &networkfirewall.ListFirewallPoliciesOutput{}
	for p := networkfirewall.NewListFirewallPoliciesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.FirewallPolicies = append(out.FirewallPolicies, page.FirewallPolicies...)
	}
	return out, nil
}

func describeAllConfigRules(ctx context.Context, client configservice.DescribeConfigRulesAPIClient, in *configservice.DescribeConfigRulesInput) (*configservice.DescribeConfigRulesOutput, error) {
	out := &configservice.DescribeConfigRulesOutput{}
	for p := configservice.NewDescribeConfigRulesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.ConfigRules = append(out.ConfigRules, page.ConfigRules...)
	}
	return out, nil
}

func describeAllComplianceByConfigRule(ctx context.Context, client configservice.DescribeComplianceByConfigRuleAPIClient, in *configservice.DescribeComplianceByConfigRuleInput) (*configservice.DescribeComplianceByConfigRuleOutput, error) {
	out := &configservice.DescribeComplianceByConfigRuleOutput{}
	for p := configservice.NewDescribeComplianceByConfigRulePaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.ComplianceByConfigRules = append(out.ComplianceByConfigRules, page.ComplianceByConfigRules...)
	}
	return out, nil
}

func describeAllStandards(ctx context.Context, client securityhub.DescribeStandardsAPIClient, in *securityhub.DescribeStandardsInput) (*securityhub.DescribeStandardsOutput, error) {
	out := &securityhub.DescribeStandardsOutput{}
	for p := securityhub.NewDescribeStandardsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Standards = append(out.Standards, page.Standards...)
	}
	return out, nil
}

func describeAllPatchGroups(ctx context.Context, client ssm.DescribePatchGroupsAPIClient, in *ssm.DescribePatchGroupsInput) (*ssm.DescribePatchGroupsOutput, error) {
	out := &ssm.DescribePatchGroupsOutput{}
	for p := ssm.NewDescribePatchGroupsPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.Mappings = append(out.Mappings, page.Mappings...)
	}
	return out, nil
}

func describeAllPatchBaselines(ctx context.Context, client ssm.DescribePatchBaselinesAPIClient, in *ssm.DescribePatchBaselinesInput) (*ssm.DescribePatchBaselinesOutput, error) {
	out := &ssm.DescribePatchBaselinesOutput{}
	for p := ssm.NewDescribePatchBaselinesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.BaselineIdentities = append(out.BaselineIdentities, page.BaselineIdentities...)
	}
	return out, nil
}

func listAllCertificates(ctx context.Context, client acm.ListCertificatesAPIClient, in *acm.ListCertificatesInput) (*acm.ListCertificatesOutput, error) {
	out := &acm.ListCertificatesOutput{}
	for p := acm.NewListCertificatesPaginator(client, in); p.HasMorePages(); {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out.CertificateSummaryList = append(out.CertificateSummaryList, page.CertificateSummaryList...)
	}
	return out, nil
}

// DescribeInstancePatchStates requires InstanceIds and accepts at most 50 per
// call, while the caller passes every managed instance. Each batch of 50 is
// paged in turn and the states of all batches are merged.
const maxPatchStateInstances = 50

func describeAllInstancePatchStates(ctx context.Context, client ssm.DescribeInstancePatchStatesAPIClient, in *ssm.DescribeInstancePatchStatesInput) (*ssm.DescribeInstancePatchStatesOutput, error) {
	out := &ssm.DescribeInstancePatchStatesOutput{}
	ids := in.InstanceIds
	for start := 0; start < len(ids); start += maxPatchStateInstances {
		end := min(start+maxPatchStateInstances, len(ids))
		batch := *in
		batch.InstanceIds = ids[start:end]
		for p := ssm.NewDescribeInstancePatchStatesPaginator(client, &batch); p.HasMorePages(); {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			out.InstancePatchStates = append(out.InstancePatchStates, page.InstancePatchStates...)
		}
	}
	return out, nil
}
