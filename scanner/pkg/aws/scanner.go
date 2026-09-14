package aws

import (
	"context"
	"fmt"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
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
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/aws/checks"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/vuln/awsinspector"
)

type AWSScanner struct {
	// Cached result of runSuites, so the shared suite list runs once per scan.
	suiteCache  []ScanResult
	suiteCached bool

	cfg                  aws.Config
	s3Client             *s3.Client
	s3controlClient      *s3control.Client
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
	if verbose {
		cisEd, _ := mappings.EditionFor("CIS-AWS")
		fmt.Println("Running " + cisEd.Describe())
		fmt.Println("")
	}

	// Every suite, once. This path used to construct its own copy of the suite
	// list, run it, and then call runSuites as well, so a cis-aws scan ran
	// every check twice and reported every row twice. The CIS filter, and the
	// recommendation number a row is displayed under, both live at the report
	// layer, which reads them from the Frameworks map.
	var results []ScanResult
	results = append(results, s.runSuites(ctx, verbose)...)

	if verbose {
		fmt.Println("")
		fmt.Println("This scan covers the CIS controls automatable via the AWS API")
		fmt.Println("")
		fmt.Println("Missing controls require:")
		fmt.Println("  - Manual review of organizational policies")
		fmt.Println("  - Documentation of operational procedures")
	}

	return results
}

func (s *AWSScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Println("Running CMMC - all 110 practices reported, the technical ones measured")
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

	// Every suite, once. The Level 1 suite is in allSuites; constructing and
	// running it here as well reported each of its practices twice and counted
	// each FAIL twice. Appended onto a fresh slice so the rows added below do
	// not land in runSuites' cached backing array.
	var results []ScanResult
	results = append(results, s.runSuites(ctx, verbose)...)

	// Vulnerability scan coverage, read from Inspector rather than asked for as
	// a document. Answers RA.L2-3.11.2 with real PASS/FAIL.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitCMMC)...)

	// Every practice nothing above reported, reported as a manual requirement.
	// This runs after the suites so it sees every practice a suite answered,
	// including one answered only through a non-CMMC suite's tag; run before
	// them it reported those practices twice, once unanswered and once answered.
	// A CMMC report's denominator is the benchmark's 110, not the subset this
	// provider can automate, or a reader cannot tell an absent practice from a
	// satisfied one.
	results = append(results, s.reportRemainingCMMCPractices(ctx, results)...)

	if verbose {
		fmt.Printf("\nCMMC scan complete: all %d practices reported\n", mappings.CMMCPracticeCount)
		fmt.Println("")
		fmt.Println("WHAT AUDITKIT PRO ADDS:")
		fmt.Println("  - More of the 110 practices measured rather than asked for")
		fmt.Println("  - Evidence packages an assessor can read directly")
		fmt.Println("  - Multi-account scanning and continuous monitoring")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro")
	}

	return results
}

// reportRemainingCMMCPractices fills in the practices the suites above did not
// name. The covered set is computed from the results just produced rather than
// kept by hand, so adding an automated check for a practice removes it from
// here automatically instead of leaving it reported twice.
func (s *AWSScanner) reportRemainingCMMCPractices(ctx context.Context, reported []ScanResult) []ScanResult {
	covered := map[string]bool{}
	for _, r := range reported {
		covered[r.Control] = true
		// A tag may name more than one practice. None do today, but a
		// single-key read would silently report both of them again.
		for _, id := range strings.Split(r.Frameworks["CMMC"], ",") {
			if id = strings.TrimSpace(id); id != "" {
				covered[id] = true
			}
		}
	}
	var out []ScanResult
	rows, _ := checks.NewCMMCPracticeReport(covered).Run(ctx)
	for _, cr := range rows {
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

// allSuites is every check suite this provider has, constructed once.
//
// Each framework path used to hand-pick its own subset, so a suite claiming a
// framework ran only if somebody had remembered to add it to that path. The PCI
// suite answers CIS 3.1.1 - S3 buckets denying HTTP - and never ran on a CIS
// scan; the CC8 and CC9 suites answer four CA.L2 practices and never ran on a
// CMMC scan. Neither omission was visible in the output.
//
// The framework filter belongs at the report layer, where
// controlMatchesFramework already applies it - including to the results that
// carry no Frameworks field and match through their control id in the
// framework's catalog, which an in-scan filter on tag presence drops.
func (s *AWSScanner) allSuites(ctx context.Context) []checks.Check {
	return []checks.Check{
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
		checks.NewAWSCMMCLevel1Checks(s.iamClient, s.s3Client, s.ec2Client, s.ctClient),
		checks.NewPCIDSSChecks(s.iamClient, s.ec2Client, s.s3Client, s.ctClient, s.configClient),
	}
}

// runSuites runs every suite and converts the results. Shared by the framework
// paths so none of them can quietly run a different set.
func (s *AWSScanner) runSuites(ctx context.Context, verbose bool) []ScanResult {
	// Run once per scan. The framework paths share this list, so a scan
	// that calls several of them would otherwise re-run every suite.
	if s.suiteCached {
		return append([]ScanResult(nil), s.suiteCache...)
	}
	var results []ScanResult
	for _, check := range s.allSuites(ctx) {
		if verbose {
			fmt.Printf("   Running %s...\n", check.Name())
		}
		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("     Warning in %s: %v\n", check.Name(), err)
		}
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Name:              cr.Name,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          severityOf(cr),
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}
	s.suiteCache, s.suiteCached = results, true
	return append([]ScanResult(nil), results...)
}

// severityOf reads a result's severity from whichever field the suite filled.
// The AWS and Azure suites mostly set Severity; a few set only Priority.Level,
// and the framework paths that used to run those suites directly read that
// field. Now that every suite reaches the report through runSuites, a blank
// here would drop a HIGH finding to LOW at the report layer.
func severityOf(cr checks.CheckResult) string {
	if cr.Severity != "" {
		return cr.Severity
	}
	return cr.Priority.Level
}
func (s *AWSScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	// Initialize SOC2 checks

	results = append(results, s.runSuites(ctx, verbose)...)

	return results
}

func (s *AWSScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Printf("  Running PCI-DSS v4.0.1 requirements...\n")
	}

	// Every suite, once. The PCI-DSS suite is in allSuites; constructing and
	// running it here as well reported each of its rows twice. Appended onto a
	// fresh slice so the row added below does not land in runSuites' cached
	// backing array.
	var results []ScanResult
	results = append(results, s.runSuites(ctx, verbose)...)

	// PCI-DSS 11.3.1 wants scans quarterly across every in-scope system, which
	// "Inspector is enabled" never established.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitPCI)...)

	return results
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
