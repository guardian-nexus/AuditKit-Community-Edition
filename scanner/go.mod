module github.com/guardian-nexus/auditkit/scanner

go 1.24.0

toolchain go1.24.7

require (
	// Azure SDK
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.19.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.12.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor v0.11.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage v1.8.1
	// AWS SDK v2
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.31.8
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.59.1
	github.com/aws/aws-sdk-go-v2/service/backup v1.47.4
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.53.4
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.50.1
	github.com/aws/aws-sdk-go-v2/service/configservice v1.58.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.253.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.64.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.47.5
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.44.4
	github.com/aws/aws-sdk-go-v2/service/kms v1.45.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.77.4
	github.com/aws/aws-sdk-go-v2/service/organizations v1.45.1
	github.com/aws/aws-sdk-go-v2/service/rds v1.107.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.88.1
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.64.2
	github.com/aws/aws-sdk-go-v2/service/sns v1.38.3
	github.com/aws/aws-sdk-go-v2/service/ssm v1.64.4
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.4

	// Report generation
	github.com/jung-kurt/gofpdf v1.16.2
)

require (
	// Azure indirect dependencies
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.5.0 // indirect
	// AWS indirect dependencies
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.8.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.4 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

require (
	cloud.google.com/go/iam v1.5.3
	cloud.google.com/go/kms v1.23.2
	cloud.google.com/go/logging v1.13.0
	cloud.google.com/go/storage v1.57.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity v0.14.0
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.44.7
	github.com/aws/aws-sdk-go-v2/service/acm v1.37.8
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.35.8
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.32.8
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.68.1
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.52.2
	github.com/aws/aws-sdk-go-v2/service/ecr v1.51.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.65.4
	github.com/aws/aws-sdk-go-v2/service/eks v1.74.5
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.51.9
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.33.9
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.50.0
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.57.3
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.57.1
	github.com/aws/aws-sdk-go-v2/service/redshift v1.61.5
	github.com/aws/aws-sdk-go-v2/service/route53 v1.58.5
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.229.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.39.9
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.11
	github.com/microsoftgraph/msgraph-sdk-go v1.87.0
	google.golang.org/api v0.252.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cel.dev/expr v0.24.0 // indirect
	cloud.google.com/go v0.121.6 // indirect
	cloud.google.com/go/auth v0.17.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/longrunning v0.6.7 // indirect
	cloud.google.com/go/monitoring v1.24.2 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.29.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.53.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.53.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.11 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.32.4 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v4 v4.1.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/microsoft/kiota-abstractions-go v1.9.3 // indirect
	github.com/microsoft/kiota-authentication-azure-go v1.3.1 // indirect
	github.com/microsoft/kiota-http-go v1.5.4 // indirect
	github.com/microsoft/kiota-serialization-form-go v1.1.2 // indirect
	github.com/microsoft/kiota-serialization-json-go v1.1.2 // indirect
	github.com/microsoft/kiota-serialization-multipart-go v1.1.2 // indirect
	github.com/microsoft/kiota-serialization-text-go v1.1.3 // indirect
	github.com/microsoftgraph/msgraph-sdk-go-core v1.4.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/std-uritemplate/std-uritemplate/go/v2 v2.0.3 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.36.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	golang.org/x/oauth2 v0.31.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/time v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251002232023-7c0ddcbb5797 // indirect
	google.golang.org/grpc v1.75.1 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
