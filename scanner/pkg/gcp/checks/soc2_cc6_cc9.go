package checks

import (
	"context"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/sqladmin/v1"
)

// CC6: Logical and Physical Access Controls (9 criteria)
// CC7: System Operations (5 criteria)
// CC8: Change Management (1 criterion)
// CC9: Risk Mitigation (2 criteria)

// GCPCC6Checks wraps the actual service checks for CC6 (Access Controls)
type GCPCC6Checks struct {
	storageClient  *storage.Client
	iamClient      *admin.IamClient
	computeService *compute.Service
	sqlService     *sqladmin.Service
	projectID      string
}

func NewGCPCC6Checks(storageClient *storage.Client, iamClient *admin.IamClient, computeService *compute.Service, sqlService *sqladmin.Service, projectID string) *GCPCC6Checks {
	return &GCPCC6Checks{
		storageClient:  storageClient,
		iamClient:      iamClient,
		computeService: computeService,
		sqlService:     sqlService,
		projectID:      projectID,
	}
}

func (c *GCPCC6Checks) Name() string {
	return "GCP SOC2 CC6 Access Controls"
}

func (c *GCPCC6Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// CC6.1: Logical Access - Call IAM checks
	iamChecker := NewIAMChecks(c.iamClient, c.projectID)
	iamResults, _ := iamChecker.Run(ctx)
	results = append(results, iamResults...)

	// CC6.2: Network Security - Call Storage and Network checks
	storageChecker := NewStorageChecks(c.storageClient, c.projectID)
	storageResults := storageChecker.CheckBucketPublicAccess(ctx)
	results = append(results, storageResults...)

	networkChecker := NewNetworkChecks(c.computeService, c.projectID)
	networkResults, _ := networkChecker.Run(ctx)
	results = append(results, networkResults...)

	// CC6.3: Data Encryption - Call Storage encryption checks
	encryptionResults := storageChecker.CheckBucketEncryption(ctx)
	results = append(results, encryptionResults...)

	// CC6.6: Authentication - Covered by IAM MFA checks (already included above)

	// CC6.7: Password/Key Management - Call KMS checks
	// Note: This requires KMS client which we don't have in this wrapper
	// The individual service checks cover this

	return results, nil
}

// GCPCC7Checks wraps the actual service checks for CC7 (System Operations)
type GCPCC7Checks struct {
	loggingClient  *logging.ConfigClient
	computeService *compute.Service
	projectID      string
}

func NewGCPCC7Checks(loggingClient *logging.ConfigClient, computeService *compute.Service, projectID string) *GCPCC7Checks {
	return &GCPCC7Checks{
		loggingClient:  loggingClient,
		computeService: computeService,
		projectID:      projectID,
	}
}

func (c *GCPCC7Checks) Name() string {
	return "GCP SOC2 CC7 System Operations"
}

func (c *GCPCC7Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// CC7.1: Security Monitoring - Call Logging checks
	loggingChecker := NewLoggingChecks(c.loggingClient, c.projectID)
	loggingResults, _ := loggingChecker.Run(ctx)
	results = append(results, loggingResults...)

	// CC7.2: Incident Detection - Covered by logging checks above

	// CC7.3: Performance Monitoring
	computeChecker := NewComputeChecks(c.computeService, c.projectID)
	computeResults := computeChecker.CheckOSPatchManagement(ctx)
	results = append(results, computeResults...)

	return results, nil
}

// GCPCC8Checks for Change Management
type GCPCC8Checks struct {
	projectID string
}

func NewGCPCC8Checks(projectID string) *GCPCC8Checks {
	return &GCPCC8Checks{projectID: projectID}
}

func (c *GCPCC8Checks) Name() string {
	return "GCP SOC2 CC8 Change Management"
}

func (c *GCPCC8Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC8.1: Change Management Process
	results = append(results, CheckResult{
		Control:         "CC8.1",
		Name:            "Change Management Process",
		Status:          "INFO",
		Evidence:        "Manual review required: Document change management process for infrastructure changes",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Implement change management process with approval workflows",
		ScreenshotGuide: "Provide change management documentation and approval records",
		Frameworks: map[string]string{
			"SOC2": "CC8.1",
		},
	})

	return results, nil
}

// GCPCC9Checks for Risk Mitigation
type GCPCC9Checks struct {
	storageClient *storage.Client
	sqlService    *sqladmin.Service
	projectID     string
}

func NewGCPCC9Checks(storageClient *storage.Client, sqlService *sqladmin.Service, projectID string) *GCPCC9Checks {
	return &GCPCC9Checks{
		storageClient: storageClient,
		sqlService:    sqlService,
		projectID:     projectID,
	}
}

func (c *GCPCC9Checks) Name() string {
	return "GCP SOC2 CC9 Risk Mitigation"
}

func (c *GCPCC9Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// CC9.1: Risk Mitigation Activities
	results = append(results, CheckResult{
		Control:         "CC9.1",
		Name:            "Risk Mitigation Activities",
		Status:          "INFO",
		Evidence:        "Manual review required: Document risk mitigation and treatment plans",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Implement and document risk mitigation activities",
		ScreenshotGuide: "Provide evidence of risk mitigation activities and outcomes",
		Frameworks: map[string]string{
			"SOC2": "CC9.1",
		},
	})

	// CC9.2: Vendor Management - Call SQL and Storage backup checks
	storageChecker := NewStorageChecks(c.storageClient, c.projectID)
	versioningResults := storageChecker.CheckBucketVersioning(ctx)
	results = append(results, versioningResults...)

	sqlChecker := NewSQLChecks(c.sqlService, c.projectID)
	backupResults := sqlChecker.CheckBackupEnabled(ctx)
	results = append(results, backupResults...)

	return results, nil
}
