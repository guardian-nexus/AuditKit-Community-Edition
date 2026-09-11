package aws

import (
	"context"
	"fmt"
	"github.com/guardian-nexus/auditkit/scanner/pkg/mappings"
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
	"github.com/aws/aws-sdk-go-v2/service/efs"
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
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/guardian-nexus/auditkit/scanner/pkg/aws/checks"
	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/awsinspector"
)

type AWSScanner struct {
	cfg             aws.Config
	s3Client        *s3.Client
	s3controlClient *s3control.Client
	// moduleResults memoises one check module's results for the duration of a
	// single ScanServices call. With -framework all the SOC2, PCI and CIS suites
	// share most modules, which previously ran (and hit the AWS API) three times.
	moduleResults        map[string][]checks.CheckResult
	iamClient            *iam.Client
	ec2Client            *ec2.Client
	ctClient             *cloudtrail.Client
	stsClient            *sts.Client
	configClient         *configservice.Client
	gdClient             *guardduty.Client
	shClient             *securityhub.Client
	rdsClient            *rds.Client
	efsClient            *efs.Client
	cwClient             *cloudwatch.Client
	snsClient            *sns.Client
	ssmClient            *ssm.Client
	asClient             *autoscaling.Client
	orgClient            *organizations.Client
	inspector2Client     *inspector2.Client
	backupClient         *backup.Client
	kmsClient            *kms.Client
	lambdaClient         *lambda.Client
	ecsClient            *ecs.Client
	eksClient            *eks.Client
	macieClient          *macie2.Client
	nfwClient            *networkfirewall.Client
	route53Client        *route53.Client
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
	Name              string
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
	// Only name a profile when one was actually asked for.
	//
	// The -profile flag defaults to "default", and passing that explicitly
	// selects the SDK's strict shared-config path: without a ~/.aws/config the
	// load fails outright with "failed to get shared config profile, default",
	// and environment credentials do not rescue it. That is exactly the shape of
	// every CI runner and container, so each CI/CD recipe on the site, and the
	// Docker example, could never have worked.
	//
	// With no profile named, the SDK's normal chain still reads the [default]
	// profile when one exists, and otherwise falls through to environment
	// variables, the container credential provider and the instance role.
	opts := []func(*config.LoadOptions) error{}
	if p := strings.TrimSpace(profile); p != "" && p != "default" {
		opts = append(opts, config.WithSharedConfigProfile(p))
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), opts...)
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
		s3controlClient:      s3control.NewFromConfig(cfg),
		iamClient:            iam.NewFromConfig(cfg),
		ec2Client:            ec2.NewFromConfig(cfg),
		ctClient:             cloudtrail.NewFromConfig(cfg),
		stsClient:            sts.NewFromConfig(cfg),
		configClient:         configservice.NewFromConfig(cfg),
		gdClient:             guardduty.NewFromConfig(cfg),
		shClient:             securityhub.NewFromConfig(cfg),
		rdsClient:            rds.NewFromConfig(cfg),
		efsClient:            efs.NewFromConfig(cfg),
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
	s.moduleResults = make(map[string][]checks.CheckResult)

	switch framework {
	case "soc2":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	case "pci", "pci-dss":
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	case "cmmc":
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
	case "cis", "cis-aws":
		results = append(results, s.runCISChecks(ctx, verbose)...)
	case "all",
		// Derived frameworks are reported through the crosswalk, which can
		// map any suite's findings. Falling through to the SOC2 suite alone
		// meant an 800-53, ISO or HIPAA scan never saw the PCI, CMMC or CIS
		// checks that map onto it.
		"800-53", "nist800-53", "nist-800-53", "iso27001", "iso-27001", "gdpr", "nist-csf", "csf", "hipaa", "fedramp-low", "fedramp-moderate", "fedramp-high":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
		results = append(results, s.runCISChecks(ctx, verbose)...)
		// The suites overlap, so the same finding arrives once per suite.
		results = dedupeIdenticalResults(results)
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

func (s *AWSScanner) runCISChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		cisEd, _ := mappings.EditionFor("CIS-AWS")
		fmt.Println("Running " + cisEd.Describe())
		fmt.Println("Using existing checks with CIS control mappings...")
		fmt.Println("")
	}

	// Run existing AWS check modules - they return results with Frameworks map
	checkModules := []checks.Check{
		checks.NewPCIDSSChecks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient, s.configClient),
		checks.NewIAMAdvancedChecks(s.iamClient),
		checks.NewIAMChecks(s.iamClient),
		checks.NewS3Checks(s.s3Client, s.s3controlClient, s.stsClient),
		checks.NewEC2Checks(s.ec2Client),
		checks.NewCloudTrailChecks(s.ctClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewRDSChecks(s.rdsClient),
		checks.NewVPCChecks(s.ec2Client),
		checks.NewEFSChecks(s.efsClient), // CIS AWS Foundations v7.0.0 3.3.1
		checks.NewKMSChecks(s.kmsClient), // CIS AWS Foundations v7.0.0 4.6
		checks.NewNetworkFirewallChecks(s.nfwClient, s.ec2Client),
		checks.NewLambdaChecks(s.lambdaClient),
		checks.NewECSChecks(s.ecsClient),
		checks.NewEKSChecks(s.eksClient),
		checks.NewRoute53Checks(s.route53Client),
		checks.NewAccessAnalyzerChecks(s.accessAnalyzerClient, s.cfg.Region),
		checks.NewSecurityServicesChecks(s.gdClient, s.macieClient, s.shClient, s.inspector2Client),
		checks.NewMonitoringChecks(s.cwClient, s.snsClient, s.shClient), // Add monitoring checks (CIS 4.16)
		checks.NewCISManualChecks(),                                     // Add manual CIS controls (Section 4)
		// Section 10 - Additional Services
		checks.NewSSMChecks(s.ssmClient),                           // CIS 10.1-10.3
		checks.NewBeanstalkChecks(s.beanstalkClient),               // CIS 10.4-10.6
		checks.NewAPIGatewayChecks(s.apigwClient, s.apigwv2Client), // CIS 10.7-10.9
		checks.NewBackupVaultChecks(s.backupClient),                // CIS 10.10-10.12
		checks.NewMessagingChecks(s.snsClient, s.sqsClient),        // CIS 10.13-10.15
		// Sections 11-18 - Extended Coverage for 100%
		checks.NewOrganizationsAdvancedChecks(s.orgClient, s.ctClient), // CIS 11.1-11.4
		checks.NewSecretsManagerChecks(s.secretsManagerClient),         // CIS 12.1-12.3
		checks.NewECRChecks(s.ecrClient),                               // CIS 13.1-13.3
		checks.NewDynamoDBChecks(s.dynamodbClient),                     // CIS 14.1-14.3
		checks.NewCloudFormationChecks(s.cloudFormationClient),         // CIS 15.1-15.2
		checks.NewACMChecks(s.acmClient),                               // CIS 16.1-16.2
		checks.NewIAMExtendedChecks(s.iamClient),                       // CIS 17.1-17.2
		checks.NewAuroraChecks(s.rdsClient),                            // CIS 18.1
		// Sections 19-22 - Data Analytics & ML Services (January 2026)
		checks.NewSageMakerChecks(s.sagemakerClient),     // CIS 19.1-19.6
		checks.NewRedshiftChecks(s.redshiftClient),       // CIS 20.1-20.7
		checks.NewElastiCacheChecks(s.elasticacheClient), // CIS 21.1-21.5
		checks.NewOpenSearchChecks(s.opensearchClient),   // CIS 22.1-22.6
	}

	// Track which CIS sections we're covering
	sectionCounts := make(map[string]int)

	for _, check := range checkModules {
		if verbose {
			fmt.Printf("  Running %s...\n", check.Name())
		}

		checkResults, checkErr := s.runCheckModule(ctx, check)
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
		// The old line quoted a control total for a benchmark version nobody
		// had read. State what this scan covers; the registry states the edition.
		fmt.Println("\nThis scan covers the CIS controls automatable via the AWS API")
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
		fmt.Println("Running CMMC Level 1 - Open Source (the level defines 17 practices)")
		fmt.Println("")
		fmt.Println("IMPORTANT DISCLAIMER:")
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
			Name:              cr.Name,
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
		fmt.Println("UNLOCK CMMC LEVEL 2:")
		fmt.Println("  • All 110 CMMC Level 2 practices for CUI")
		fmt.Println("  • Required for DoW contractors handling CUI")
		fmt.Println("  • Complete evidence collection guides")
		fmt.Println("  • November 10, 2025 deadline compliance")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro for full CMMC Level 2")
	}

	// Vulnerability scan coverage, read from Inspector rather than asked for as
	// a document. Answers RA.L2-3.11.2 with real PASS/FAIL.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitCMMC)...)

	return results
}

// runVulnCoverage builds the vulnerability coverage check for one framework and
// converts its results. emit keeps the CMMC and PCI passes from each reporting
// the other's control, which would double-count it on a scan of all frameworks.
func (s *AWSScanner) runVulnCoverage(ctx context.Context, emit checks.Emit) []ScanResult {
	vc := checks.NewVulnCoverageChecks(awsinspector.Clients{
		Inspector: s.inspector2Client,
		EC2:       s.ec2Client,
		Lambda:    s.lambdaClient,
		ECR:       s.ecrClient,
	}, s.GetAccountID(ctx), emit)

	crs, err := vc.Run(ctx)
	if err != nil {
		return nil
	}
	out := make([]ScanResult, 0, len(crs))
	for _, cr := range crs {
		out = append(out, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
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
	return out
}

func (s *AWSScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	// Initialize SOC2 checks
	soc2Checks := []checks.Check{
		// CC1 & CC2: Control Environment & Communication
		checks.NewMonitoringChecks(s.cwClient, s.snsClient, s.shClient),
		checks.NewCC1Checks(s.iamClient, s.orgClient, s.ssmClient),
		checks.NewKMSChecks(s.kmsClient), // claims SOC2 and PCI; must run in those scans
		checks.NewEFSChecks(s.efsClient), // claims SOC2 and PCI; must run in those scans
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
		checks.NewAvailabilityConfidentialityChecks(s.s3Client, s.rdsClient),

		// Advanced IAM and systems coverage. These suites were written but never
		// constructed, so their controls (CC6.4-CC6.6, CC7.1, A1.1) never ran.
		checks.NewIAMAdvancedChecks(s.iamClient),
		checks.NewSystemsChecks(s.ssmClient, s.asClient),

		// Also run traditional checks for backward compatibility
		checks.NewS3Checks(s.s3Client, s.s3controlClient, s.stsClient),
		checks.NewIAMChecks(s.iamClient),
		checks.NewEC2Checks(s.ec2Client),
		checks.NewCloudTrailChecks(s.ctClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewGuardDutyChecks(s.gdClient),
		checks.NewRDSChecks(s.rdsClient),
		checks.NewVPCChecks(s.ec2Client),

		// CIS AWS Benchmark coverage. The edition lives in pkg/mappings; this
		// comment claimed v1.5.0+ while the scan banner said something else.
		checks.NewCISManualChecks(), // CIS 4.1-4.15
		checks.NewAccessAnalyzerChecks(s.accessAnalyzerClient, s.cfg.Region),                        // CIS 1.8
		checks.NewRoute53Checks(s.route53Client),                                                    // CIS 5.19
		checks.NewSSMChecks(s.ssmClient),                                                            // CIS 10.1-10.3
		checks.NewBeanstalkChecks(s.beanstalkClient),                                                // CIS 10.4-10.6
		checks.NewAPIGatewayChecks(s.apigwClient, s.apigwv2Client),                                  // CIS 10.7-10.9
		checks.NewBackupVaultChecks(s.backupClient),                                                 // CIS 10.10-10.12
		checks.NewMessagingChecks(s.snsClient, s.sqsClient),                                         // CIS 10.13-10.15
		checks.NewOrganizationsAdvancedChecks(s.orgClient, s.ctClient),                              // CIS 11.1-11.4
		checks.NewSecretsManagerChecks(s.secretsManagerClient),                                      // CIS 12.1-12.3
		checks.NewECRChecks(s.ecrClient),                                                            // CIS 13.1-13.3
		checks.NewDynamoDBChecks(s.dynamodbClient),                                                  // CIS 14.1-14.3
		checks.NewCloudFormationChecks(s.cloudFormationClient),                                      // CIS 15.1-15.2
		checks.NewACMChecks(s.acmClient),                                                            // CIS 16.1-16.2
		checks.NewIAMExtendedChecks(s.iamClient),                                                    // CIS 17.1-17.2
		checks.NewAuroraChecks(s.rdsClient),                                                         // CIS 18.1
		checks.NewLambdaChecks(s.lambdaClient),                                                      // Lambda best practices
		checks.NewECSChecks(s.ecsClient),                                                            // ECS best practices
		checks.NewEKSChecks(s.eksClient),                                                            // EKS best practices
		checks.NewNetworkFirewallChecks(s.nfwClient, s.ec2Client),                                   // Network Firewall
		checks.NewSecurityServicesChecks(s.gdClient, s.macieClient, s.shClient, s.inspector2Client), // Additional security
		// Data Analytics & ML Services (January 2026)
		checks.NewSageMakerChecks(s.sagemakerClient),     // SageMaker ML security
		checks.NewRedshiftChecks(s.redshiftClient),       // Redshift data warehouse
		checks.NewElastiCacheChecks(s.elasticacheClient), // ElastiCache/Redis
		checks.NewOpenSearchChecks(s.opensearchClient),   // OpenSearch/Elasticsearch
	}

	for _, check := range soc2Checks {
		if verbose {
			fmt.Printf("  Running %s ...\n", check.Name())
		}

		checkResults, err := s.runCheckModule(ctx, check)
		if err != nil && verbose {
			fmt.Printf("    Warning in %s: %v\n", check.Name(), err)
		}

		// Convert CheckResult to ScanResult
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Name:              cr.Name,
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
		fmt.Printf("  Running PCI-DSS v4.0.1 requirements...\n")
	}

	checkResults, err := pciChecks.Run(ctx)
	if err != nil && verbose {
		fmt.Printf("    Warning in PCI-DSS checks: %v\n", err)
	}

	// Convert CheckResult to ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
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
		checks.NewVPCChecks(s.ec2Client),
		checks.NewSecurityServicesChecks(s.gdClient, s.macieClient, s.shClient, s.inspector2Client),
		checks.NewSecretsManagerChecks(s.secretsManagerClient),
		checks.NewSageMakerChecks(s.sagemakerClient),
		checks.NewSSMChecks(s.ssmClient),
		checks.NewRoute53Checks(s.route53Client),
		checks.NewRedshiftChecks(s.redshiftClient),
		checks.NewOrganizationsAdvancedChecks(s.orgClient, s.ctClient),
		checks.NewOpenSearchChecks(s.opensearchClient),
		checks.NewNetworkFirewallChecks(s.nfwClient, s.ec2Client),
		checks.NewMonitoringChecks(s.cwClient, s.snsClient, s.shClient),
		checks.NewMessagingChecks(s.snsClient, s.sqsClient),
		checks.NewLambdaChecks(s.lambdaClient),
		checks.NewIAMExtendedChecks(s.iamClient),
		checks.NewElastiCacheChecks(s.elasticacheClient),
		checks.NewEKSChecks(s.eksClient),
		checks.NewECSChecks(s.ecsClient),
		checks.NewECRChecks(s.ecrClient),
		checks.NewDynamoDBChecks(s.dynamodbClient),
		checks.NewConfigChecks(s.configClient),
		checks.NewCloudFormationChecks(s.cloudFormationClient),
		checks.NewCISManualChecks(),
		checks.NewBeanstalkChecks(s.beanstalkClient),
		checks.NewBackupVaultChecks(s.backupClient),
		checks.NewAuroraChecks(s.rdsClient),
		checks.NewAccessAnalyzerChecks(s.accessAnalyzerClient, s.cfg.Region),
		checks.NewAPIGatewayChecks(s.apigwClient, s.apigwv2Client),
		checks.NewACMChecks(s.acmClient),
		checks.NewIAMChecks(s.iamClient),                               // For password policy, MFA, key rotation
		checks.NewKMSChecks(s.kmsClient),                               // claims SOC2 and PCI; must run in those scans
		checks.NewEFSChecks(s.efsClient),                               // claims SOC2 and PCI; must run in those scans
		checks.NewS3Checks(s.s3Client, s.s3controlClient, s.stsClient), // For encryption requirements
		checks.NewEC2Checks(s.ec2Client),                               // For network segmentation
		checks.NewCloudTrailChecks(s.ctClient),                         // For logging requirements
		// RDS carries PCI 3.5.1 (stored account data encrypted) and 1.4.2 (no
		// direct public access). Without it a PCI scan reported no RDS evidence
		// at all, though the mappings for it already existed.
		checks.NewRDSChecks(s.rdsClient),
	}

	for _, check := range basicChecks {
		checkResults, _ := s.runCheckModule(ctx, check)
		for _, cr := range checkResults {
			// Only include if it has PCI mapping
			if cr.Frameworks != nil && cr.Frameworks["PCI-DSS"] != "" {
				results = append(results, ScanResult{
					Control:           cr.Control,
					Name:              cr.Name,
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

	// PCI-DSS 11.3.1 wants scans quarterly across every in-scope system, which
	// "Inspector is enabled" never established.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitPCI)...)

	return results
}

// runCheckModule executes a check module once per scan, reusing its results if
// another framework suite in the same run already ran it.
func (s *AWSScanner) runCheckModule(ctx context.Context, check checks.Check) ([]checks.CheckResult, error) {
	if s.moduleResults == nil {
		s.moduleResults = make(map[string][]checks.CheckResult)
	}
	if cached, ok := s.moduleResults[check.Name()]; ok {
		return cached, nil
	}
	results, err := check.Run(ctx)
	if err != nil {
		// Caching a partial result and replaying it as success would hide the
		// failure from every later framework suite in the same run.
		return results, err
	}
	s.moduleResults[check.Name()] = results
	return results, nil
}

// dedupeIdenticalResults removes results that are the same finding reported by
// more than one framework suite. It keys on control, status and evidence, so
// genuinely distinct findings that share a control ID (several resources failing
// the same criterion) are preserved.
func dedupeIdenticalResults(results []ScanResult) []ScanResult {
	seen := make(map[string]bool, len(results))
	deduped := make([]ScanResult, 0, len(results))

	for _, result := range results {
		key := result.Control + "\x00" + result.Status + "\x00" + result.Evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, result)
	}

	return deduped
}
