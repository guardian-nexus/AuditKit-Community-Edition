package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/guardian-nexus/auditkit/scanner/pkg/aws/checks"
)

type AWSScanner struct {
	cfg                 aws.Config
	s3Client            *s3.Client
	iamClient           *iam.Client
	ec2Client           *ec2.Client
	ctClient            *cloudtrail.Client
	stsClient           *sts.Client
	configClient        *configservice.Client
	gdClient            *guardduty.Client
	shClient            *securityhub.Client
	rdsClient           *rds.Client
	cwClient            *cloudwatch.Client
	snsClient           *sns.Client
	ssmClient           *ssm.Client
	asClient            *autoscaling.Client
	orgClient           *organizations.Client
	inspector2Client    *inspector2.Client
	backupClient        *backup.Client
	kmsClient           *kms.Client
	lambdaClient        *lambda.Client
	ecsClient           *ecs.Client
	eksClient           *eks.Client
	macieClient         *macie2.Client
	nfwClient           *networkfirewall.Client
	route53Client       *route53.Client
	accessAnalyzerClient *accessanalyzer.Client
	sqsClient            *sqs.Client
	apigwClient          *apigateway.Client
	apigwv2Client        *apigatewayv2.Client
	beanstalkClient      *elasticbeanstalk.Client
	secretsManagerClient *secretsmanager.Client
	ecrClient            *ecr.Client
	dynamodbClient       *dynamodb.Client
	cloudFormationClient *cloudformation.Client
	acmClient            *acm.Client
	// New services (January 2026)
	sagemakerClient   *sagemaker.Client
	redshiftClient    *redshift.Client
	elasticacheClient *elasticache.Client
	opensearchClient  *opensearch.Client
}

type ScanResult struct {
	Control           string
	Status            string
	Evidence          string
	Remediation       string
	RemediationDetail string
	Severity          string
	ScreenshotGuide   string
	ConsoleURL        string
	Frameworks        map[string]string
}

func NewScanner(profile string) (*AWSScanner, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	return NewScannerWithConfig(cfg)
}

// NewScannerWithConfig creates an AWS scanner with a pre-configured aws.Config
// This is useful for cross-account scanning with assumed role credentials
func NewScannerWithConfig(cfg aws.Config) (*AWSScanner, error) {
	return &AWSScanner{
		cfg:                  cfg,
		s3Client:             s3.NewFromConfig(cfg),
		iamClient:            iam.NewFromConfig(cfg),
		ec2Client:            ec2.NewFromConfig(cfg),
		ctClient:             cloudtrail.NewFromConfig(cfg),
		stsClient:            sts.NewFromConfig(cfg),
		configClient:         configservice.NewFromConfig(cfg),
		gdClient:             guardduty.NewFromConfig(cfg),
		shClient:             securityhub.NewFromConfig(cfg),
		rdsClient:            rds.NewFromConfig(cfg),
		cwClient:             cloudwatch.NewFromConfig(cfg),
		snsClient:            sns.NewFromConfig(cfg),
		ssmClient:            ssm.NewFromConfig(cfg),
		asClient:             autoscaling.NewFromConfig(cfg),
		orgClient:            organizations.NewFromConfig(cfg),
		inspector2Client:     inspector2.NewFromConfig(cfg),
		backupClient:         backup.NewFromConfig(cfg),
		kmsClient:            kms.NewFromConfig(cfg),
		lambdaClient:         lambda.NewFromConfig(cfg),
		ecsClient:            ecs.NewFromConfig(cfg),
		eksClient:            eks.NewFromConfig(cfg),
		macieClient:          macie2.NewFromConfig(cfg),
		nfwClient:            networkfirewall.NewFromConfig(cfg),
		route53Client:        route53.NewFromConfig(cfg),
		accessAnalyzerClient: accessanalyzer.NewFromConfig(cfg),
		sqsClient:            sqs.NewFromConfig(cfg),
		apigwClient:          apigateway.NewFromConfig(cfg),
		apigwv2Client:        apigatewayv2.NewFromConfig(cfg),
		beanstalkClient:      elasticbeanstalk.NewFromConfig(cfg),
		secretsManagerClient: secretsmanager.NewFromConfig(cfg),
		ecrClient:            ecr.NewFromConfig(cfg),
		dynamodbClient:       dynamodb.NewFromConfig(cfg),
		cloudFormationClient: cloudformation.NewFromConfig(cfg),
		acmClient:            acm.NewFromConfig(cfg),
		// New services (January 2026)
		sagemakerClient:   sagemaker.NewFromConfig(cfg),
		redshiftClient:    redshift.NewFromConfig(cfg),
		elasticacheClient: elasticache.NewFromConfig(cfg),
		opensearchClient:  opensearch.NewFromConfig(cfg),
	}, nil
}

func (s *AWSScanner) GetAccountID(ctx context.Context) string {
	identity, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "unknown"
	}
	return *identity.Account
}

func (s *AWSScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]ScanResult, error) {
	_, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if verbose {
			fmt.Println("Error: Not connected to AWS. Please configure AWS credentials.")
		}
		return nil, fmt.Errorf("AWS connection failed: %v", err)
	}
	
	var results []ScanResult
	framework = strings.ToLower(framework)
	
	switch framework {
	case "soc2":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	case "pci", "pci-dss":
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	case "cmmc":
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
	case "cis", "cis-aws":
		results = append(results, s.runCISChecks(ctx, verbose)...)
	case "all":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
		results = append(results, s.runCISChecks(ctx, verbose)...)
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

func (s *AWSScanner) runCISChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	if verbose {
		fmt.Println("Running CIS AWS Foundations Benchmark (v1.4 & 3.0)")
		fmt.Println("Using existing checks with CIS control mappings...")
		fmt.Println("")
	}
	
	// Run existing AWS check modules - they return results with Frameworks map
	checkModules := []checks.Check{
		checks.NewIAMChecks(s.iamClient),
		checks.NewS3Checks(s.s3Client),
		checks.NewEC2Checks(s.ec2Client),
		checks.NewCloudTrailChecks(s.ctClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewRDSChecks(s.rdsClient),
		checks.NewVPCChecks(s.ec2Client),
		checks.NewNetworkFirewallChecks(s.nfwClient, s.ec2Client),
		checks.NewLambdaChecks(s.lambdaClient),
		checks.NewECSChecks(s.ecsClient),
		checks.NewEKSChecks(s.eksClient),
		checks.NewRoute53Checks(s.route53Client),
		checks.NewAccessAnalyzerChecks(s.accessAnalyzerClient, s.cfg.Region),
		checks.NewSecurityServicesChecks(s.gdClient, s.macieClient, s.shClient, s.inspector2Client),
		checks.NewMonitoringChecks(s.cwClient, s.snsClient, s.shClient), // Add monitoring checks (CIS 4.16)
		checks.NewCISManualChecks(), // Add manual CIS controls (Section 4)
		// Section 10 - Additional Services
		checks.NewSSMChecks(s.ssmClient),                                // CIS 10.1-10.3
		checks.NewBeanstalkChecks(s.beanstalkClient),                    // CIS 10.4-10.6
		checks.NewAPIGatewayChecks(s.apigwClient, s.apigwv2Client),      // CIS 10.7-10.9
		checks.NewBackupVaultChecks(s.backupClient),                     // CIS 10.10-10.12
		checks.NewMessagingChecks(s.snsClient, s.sqsClient),             // CIS 10.13-10.15
		// Sections 11-18 - Extended Coverage for 100%
		checks.NewOrganizationsAdvancedChecks(s.orgClient, s.ctClient),  // CIS 11.1-11.4
		checks.NewSecretsManagerChecks(s.secretsManagerClient),          // CIS 12.1-12.3
		checks.NewECRChecks(s.ecrClient),                                // CIS 13.1-13.3
		checks.NewDynamoDBChecks(s.dynamodbClient),                      // CIS 14.1-14.3
		checks.NewCloudFormationChecks(s.cloudFormationClient),          // CIS 15.1-15.2
		checks.NewACMChecks(s.acmClient),                                // CIS 16.1-16.2
		checks.NewIAMExtendedChecks(s.iamClient),                        // CIS 17.1-17.2
		checks.NewAuroraChecks(s.rdsClient),                             // CIS 18.1
		// Sections 19-22 - Data Analytics & ML Services (January 2026)
		checks.NewSageMakerChecks(s.sagemakerClient),                    // CIS 19.1-19.6
		checks.NewRedshiftChecks(s.redshiftClient),                      // CIS 20.1-20.7
		checks.NewElastiCacheChecks(s.elasticacheClient),                // CIS 21.1-21.5
		checks.NewOpenSearchChecks(s.opensearchClient),                  // CIS 22.1-22.6
	}
	
	// Track which CIS sections we're covering
	sectionCounts := make(map[string]int)
	
	for _, check := range checkModules {
		if verbose {
			fmt.Printf("  Running %s...\n", check.Name())
		}
		
		checkResults, checkErr := check.Run(ctx)
		if checkErr != nil && verbose {
			fmt.Printf("    Warning: %v\n", checkErr)
		}
		
		for _, cr := range checkResults {
			// Check if this control has CIS-AWS mapping in Frameworks
			if cr.Frameworks != nil && cr.Frameworks["CIS-AWS"] != "" {
				cisControls := cr.Frameworks["CIS-AWS"]
				
				// Enhance control name with CIS numbers
				enhancedName := fmt.Sprintf("[CIS AWS %s] %s", cisControls, cr.Name)
				
				// Track section coverage (extract first digit from control number)
				if len(cisControls) > 0 {
					section := string(cisControls[0])
					switch section {
					case "1":
						sectionCounts["Identity and Access Management"]++
					case "2":
						sectionCounts["Storage"]++
					case "3":
						sectionCounts["Logging"]++
					case "4":
						sectionCounts["Monitoring"]++
					case "5":
						sectionCounts["Networking"]++
					case "6":
						sectionCounts["Lambda"]++
					case "7":
						sectionCounts["ECS"]++
					case "8":
						sectionCounts["EKS"]++
					case "9":
						sectionCounts["Security Services"]++
					default:
						// Handle multi-digit sections (10-18)
						if len(cisControls) >= 2 {
							switch cisControls[0:2] {
							case "10":
								sectionCounts["Additional Services"]++
							case "11":
								sectionCounts["Organizations"]++
							case "12":
								sectionCounts["Secrets Manager"]++
							case "13":
								sectionCounts["ECR"]++
							case "14":
								sectionCounts["DynamoDB"]++
							case "15":
								sectionCounts["CloudFormation"]++
							case "16":
								sectionCounts["ACM"]++
							case "17":
								sectionCounts["IAM Extended"]++
							case "18":
								sectionCounts["Aurora"]++
							case "19":
								sectionCounts["SageMaker"]++
							case "20":
								sectionCounts["Redshift"]++
							case "21":
								sectionCounts["ElastiCache"]++
							case "22":
								sectionCounts["OpenSearch"]++
							}
						}
					}
				}
				
				results = append(results, ScanResult{
					Control:           enhancedName,
					Status:            cr.Status,
					Evidence:          cr.Evidence,
					Remediation:       cr.Remediation,
					RemediationDetail: cr.RemediationDetail,
					Severity:          cr.Severity,
					ScreenshotGuide:   cr.ScreenshotGuide,
					ConsoleURL:        cr.ConsoleURL,
					Frameworks:        cr.Frameworks,
				})
			}
		}
	}
	
	if verbose {
		fmt.Printf("\nCIS AWS scan complete: %d controls tested\n", len(results))
		if len(sectionCounts) > 0 {
			fmt.Println("\nSection Coverage:")
			for section, count := range sectionCounts {
				fmt.Printf("  %s: %d controls\n", section, count)
			}
		}
		fmt.Println("\nNote: CIS Benchmark v1.4 and v3.0 has ~60 combined total controls")
		fmt.Println("This scan covers controls automatable via AWS API")
		fmt.Println("")
		fmt.Println("Missing controls require:")
		fmt.Println("  • Manual review of organizational policies")
		fmt.Println("  • Documentation of operational procedures")
	}
	
	return results
}

func (s *AWSScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	if verbose {
		fmt.Println("Running CMMC Level 1 (17 practices) - Open Source")
		fmt.Println("")
		fmt.Println("⚠️  IMPORTANT DISCLAIMER:")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("This scanner tests technical controls that can be automated.")
		fmt.Println("")
		fmt.Println("CMMC Level 1 requires 17 practices. Many controls require")
		fmt.Println("organizational documentation and policies that cannot be")
		fmt.Println("verified through automated scanning.")
		fmt.Println("")
		fmt.Println("A high automated check score does NOT mean you are CMMC")
		fmt.Println("compliant. This is a technical assessment tool, not a")
		fmt.Println("compliance certification.")
		fmt.Println("")
		fmt.Println("You still need to document policies, training, incident")
		fmt.Println("response procedures, and other organizational controls.")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("")
	}
	
	// ONLY Level 1 (17 practices)
	level1 := checks.NewAWSCMMCLevel1Checks(s.iamClient, s.s3Client, s.ec2Client, s.ctClient)
	results1, _ := level1.Run(ctx)
	for _, cr := range results1 {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	
	if verbose {
		fmt.Printf("\nCMMC Level 1 scan complete: %d controls tested\n", len(results))
		fmt.Println("")
		fmt.Println("🔓 UNLOCK CMMC LEVEL 2:")
		fmt.Println("  • 110 additional Level 2 practices for CUI")
		fmt.Println("  • Required for DoD contractors handling CUI")
		fmt.Println("  • Complete evidence collection guides")
		fmt.Println("  • November 10, 2025 deadline compliance")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro for full CMMC Level 2")
	}
	
	return results
}

func (s *AWSScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	// Initialize SOC2 checks
	soc2Checks := []checks.Check{
		// CC1 & CC2: Control Environment & Communication
		checks.NewCC1Checks(s.iamClient, s.orgClient, s.ssmClient),
		checks.NewCC2Checks(s.snsClient, s.ssmClient, s.iamClient),

		// CC3, CC4, CC5: Risk Assessment, Monitoring, Control Activities
		checks.NewCC3Checks(s.gdClient, s.shClient, s.inspector2Client),
		checks.NewCC4Checks(s.cwClient, s.configClient),
		checks.NewCC5Checks(s.backupClient, s.kmsClient),

		// CC6, CC7, CC8, CC9: Access Controls, Operations, Change Mgmt, Risk Mitigation
		checks.NewCC6Checks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient),
		checks.NewCC7Checks(s.ctClient, s.ssmClient, s.lambdaClient),
		checks.NewCC8Checks(s.lambdaClient, s.ec2Client),
		checks.NewCC9Checks(s.rdsClient, s.s3Client),

		// Also run traditional checks for backward compatibility
		checks.NewS3Checks(s.s3Client),
		checks.NewIAMChecks(s.iamClient),
		checks.NewEC2Checks(s.ec2Client),
		checks.NewCloudTrailChecks(s.ctClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewGuardDutyChecks(s.gdClient),
		checks.NewRDSChecks(s.rdsClient),
		checks.NewVPCChecks(s.ec2Client),

		// CIS AWS Benchmark v1.5.0+ comprehensive coverage
		checks.NewCISManualChecks(),                                                                   // CIS 4.1-4.15
		checks.NewAccessAnalyzerChecks(s.accessAnalyzerClient, s.cfg.Region),                          // CIS 1.8
		checks.NewRoute53Checks(s.route53Client),                                                      // CIS 5.19
		checks.NewSSMChecks(s.ssmClient),                                                              // CIS 10.1-10.3
		checks.NewBeanstalkChecks(s.beanstalkClient),                                                  // CIS 10.4-10.6
		checks.NewAPIGatewayChecks(s.apigwClient, s.apigwv2Client),                                    // CIS 10.7-10.9
		checks.NewBackupVaultChecks(s.backupClient),                                                   // CIS 10.10-10.12
		checks.NewMessagingChecks(s.snsClient, s.sqsClient),                                           // CIS 10.13-10.15
		checks.NewOrganizationsAdvancedChecks(s.orgClient, s.ctClient),                                // CIS 11.1-11.4
		checks.NewSecretsManagerChecks(s.secretsManagerClient),                                        // CIS 12.1-12.3
		checks.NewECRChecks(s.ecrClient),                                                              // CIS 13.1-13.3
		checks.NewDynamoDBChecks(s.dynamodbClient),                                                    // CIS 14.1-14.3
		checks.NewCloudFormationChecks(s.cloudFormationClient),                                        // CIS 15.1-15.2
		checks.NewACMChecks(s.acmClient),                                                              // CIS 16.1-16.2
		checks.NewIAMExtendedChecks(s.iamClient),                                                      // CIS 17.1-17.2
		checks.NewAuroraChecks(s.rdsClient),                                                           // CIS 18.1
		checks.NewLambdaChecks(s.lambdaClient),                                                        // Lambda best practices
		checks.NewECSChecks(s.ecsClient),                                                              // ECS best practices
		checks.NewEKSChecks(s.eksClient),                                                              // EKS best practices
		checks.NewNetworkFirewallChecks(s.nfwClient, s.ec2Client),                                     // Network Firewall
		checks.NewSecurityServicesChecks(s.gdClient, s.macieClient, s.shClient, s.inspector2Client),   // Additional security
		// Data Analytics & ML Services (January 2026)
		checks.NewSageMakerChecks(s.sagemakerClient),                                                  // SageMaker ML security
		checks.NewRedshiftChecks(s.redshiftClient),                                                    // Redshift data warehouse
		checks.NewElastiCacheChecks(s.elasticacheClient),                                              // ElastiCache/Redis
		checks.NewOpenSearchChecks(s.opensearchClient),                                                // OpenSearch/Elasticsearch
	}
	
	for _, check := range soc2Checks {
		if verbose {
			fmt.Printf("  Running %s ...\n", check.Name())
		}
		
		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("    Warning in %s: %v\n", check.Name(), err)
		}
		
		// Convert CheckResult to ScanResult
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          cr.Severity,
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}
	
	return results
}

func (s *AWSScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult
	
	// Check if pci_dss.go exists, if not fall back to basic checks with PCI mappings
	pciChecks := checks.NewPCIDSSChecks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient, s.configClient)
	
	if verbose {
		fmt.Printf("  Running PCI-DSS v4.0 requirements...\n")
	}
	
	checkResults, err := pciChecks.Run(ctx)
	if err != nil && verbose {
		fmt.Printf("    Warning in PCI-DSS checks: %v\n", err)
	}
	
	// Convert CheckResult to ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	
	// Also run basic checks but filter for PCI relevance
	basicChecks := []checks.Check{
		checks.NewIAMChecks(s.iamClient),      // For password policy, MFA, key rotation
		checks.NewS3Checks(s.s3Client),        // For encryption requirements
		checks.NewEC2Checks(s.ec2Client),      // For network segmentation
		checks.NewCloudTrailChecks(s.ctClient), // For logging requirements
	}
	
	for _, check := range basicChecks {
		checkResults, _ := check.Run(ctx)
		for _, cr := range checkResults {
			// Only include if it has PCI mapping
			if cr.Frameworks != nil && cr.Frameworks["PCI-DSS"] != "" {
				results = append(results, ScanResult{
					Control:           cr.Control,
					Status:            cr.Status,
					Evidence:          cr.Evidence,
					Remediation:       cr.Remediation,
					RemediationDetail: cr.RemediationDetail,
					Severity:          cr.Severity,
					ScreenshotGuide:   cr.ScreenshotGuide,
					ConsoleURL:        cr.ConsoleURL,
					Frameworks:        cr.Frameworks,
				})
			}
		}
	}
	
	return results
}
