# CI/CD Integration

Automate compliance checks in your CI/CD pipelines to catch security misconfigurations before they reach production.

## Table of Contents

- [Overview](#overview)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [AWS CodePipeline](#aws-codepipeline)
- [Azure DevOps](#azure-devops)
- [Cloud Build (GCP)](#cloud-build-gcp)
- [Failing Builds on Compliance Issues](#failing-builds-on-compliance-issues)
- [Multi-Cloud Pipelines](#multi-cloud-pipelines)

---

## Overview

AuditKit can run in CI/CD pipelines to:
- **Prevent regressions** - Catch new compliance failures before deployment
- **Automate security checks** - Run compliance scans on every commit or PR
- **Track compliance over time** - Store JSON reports as build artifacts
- **Block deployments** - Fail builds when critical controls fail
- **Generate audit trails** - Archive compliance reports for auditors

**Key Features:**
- JSON output for programmatic parsing (`-format json`)
- Exit codes (0 = pass, 1 = fail) for pipeline decisions
- Lightweight binaries (~50-80MB) run in Docker containers
- Provider-specific scanners for faster CI/CD builds

---

## GitHub Actions

### AWS Compliance Check (SOC2)

```yaml
name: AWS SOC2 Compliance Check

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2am UTC

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Download AuditKit
        run: |
          curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-linux-amd64.tar.gz && tar -xzf auditkit-linux-amd64.tar.gz && mv auditkit-linux-amd64 auditkit
          chmod +x auditkit

      - name: Run SOC2 compliance scan
        run: |
          ./auditkit scan -provider aws -framework soc2 -format json -output soc2-results.json

      - name: Check compliance score
        run: |
          SCORE=$(jq -r '.score.percentage' soc2-results.json)
          echo "Compliance Score: $SCORE%"
          if (( $(echo "$SCORE < 80" | bc -l) )); then
            echo "FAIL:Compliance score below 80% threshold"
            exit 1
          fi
          echo "PASS:Compliance score meets threshold"

      - name: Upload compliance report
        uses: actions/upload-artifact@v3
        with:
          name: soc2-compliance-report
          path: soc2-results.json
```

### Multi-Cloud Compliance Check

```yaml
name: Multi-Cloud Compliance

on: [push, pull_request]

jobs:
  aws-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - name: Run AWS scan
        run: |
          curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-aws-linux-amd64.tar.gz && tar -xzf auditkit-aws-linux-amd64.tar.gz && mv auditkit-aws-linux-amd64 auditkit-aws
          chmod +x auditkit-aws
          ./auditkit-aws scan -framework soc2 -format json -output aws-soc2.json
      - uses: actions/upload-artifact@v3
        with:
          name: aws-compliance
          path: aws-soc2.json

  azure-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - name: Run Azure scan
        run: |
          curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-azure-linux-amd64.tar.gz && tar -xzf auditkit-azure-linux-amd64.tar.gz && mv auditkit-azure-linux-amd64 auditkit-azure
          chmod +x auditkit-azure
          ./auditkit-azure scan -framework soc2 -format json -output azure-soc2.json
      - uses: actions/upload-artifact@v3
        with:
          name: azure-compliance
          path: azure-soc2.json

  gcp-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_CREDENTIALS }}
      - name: Run GCP scan
        run: |
          curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-gcp-linux-amd64.tar.gz && tar -xzf auditkit-gcp-linux-amd64.tar.gz && mv auditkit-gcp-linux-amd64 auditkit-gcp
          chmod +x auditkit-gcp
          ./auditkit-gcp scan -framework soc2 -format json -output gcp-soc2.json
      - uses: actions/upload-artifact@v3
        with:
          name: gcp-compliance
          path: gcp-soc2.json
```

---

## GitLab CI

### AWS PCI-DSS Compliance

```yaml
# .gitlab-ci.yml
stages:
  - compliance

aws-pci-scan:
  stage: compliance
  image: ubuntu:22.04
  before_script:
    - apt-get update && apt-get install -y curl jq
    - curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-linux-amd64.tar.gz && tar -xzf auditkit-linux-amd64.tar.gz && mv auditkit-linux-amd64 auditkit
    - chmod +x auditkit
  script:
    - ./auditkit scan -provider aws -framework pci -format json -output pci-results.json
    - |
      CRITICAL_FAILURES=$(jq '[.results[] | select(.status=="FAIL" and .severity=="CRITICAL")] | length' pci-results.json)
      if [ "$CRITICAL_FAILURES" -gt 0 ]; then
        echo "FAIL:Found $CRITICAL_FAILURES CRITICAL failures"
        exit 1
      fi
  artifacts:
    paths:
      - pci-results.json
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

### Azure CMMC Compliance

```yaml
# .gitlab-ci.yml
azure-cmmc-scan:
  stage: compliance
  image: mcr.microsoft.com/azure-cli
  before_script:
    - az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
    - curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-azure-linux-amd64.tar.gz && tar -xzf auditkit-azure-linux-amd64.tar.gz && mv auditkit-azure-linux-amd64 auditkit-azure
    - chmod +x auditkit-azure
  script:
    - ./auditkit-azure scan -framework cmmc -format json -output cmmc-results.json
  artifacts:
    paths:
      - cmmc-results.json
    reports:
      junit: cmmc-results.json
```

---

## Jenkins

### AWS SOC2 Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        AWS_REGION = 'us-east-1'
    }

    stages {
        stage('Download AuditKit') {
            steps {
                sh '''
                    curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-aws-linux-amd64.tar.gz && tar -xzf auditkit-aws-linux-amd64.tar.gz && mv auditkit-aws-linux-amd64 auditkit-aws
                    chmod +x auditkit-aws
                '''
            }
        }

        stage('AWS Compliance Scan') {
            steps {
                withCredentials([
                    string(credentialsId: 'aws-access-key-id', variable: 'AWS_ACCESS_KEY_ID'),
                    string(credentialsId: 'aws-secret-access-key', variable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    sh './auditkit-aws scan -framework soc2 -format json -output soc2-results.json'
                }
            }
        }

        stage('Check Compliance') {
            steps {
                script {
                    def results = readJSON file: 'soc2-results.json'
                    def score = results.score.percentage

                    echo "Compliance Score: ${score}%"

                    if (score < 80) {
                        error("Compliance score ${score}% is below 80% threshold")
                    }
                }
            }
        }

        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'soc2-results.json', fingerprint: true
            }
        }
    }

    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'soc2-results.json',
                reportName: 'SOC2 Compliance Report'
            ])
        }
    }
}
```

### Multi-Cloud Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Parallel Compliance Scans') {
            parallel {
                stage('AWS') {
                    steps {
                        sh '''
                            curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-aws-linux-amd64.tar.gz && tar -xzf auditkit-aws-linux-amd64.tar.gz && mv auditkit-aws-linux-amd64 auditkit-aws
                            chmod +x auditkit-aws
                            ./auditkit-aws scan -framework soc2 -format json -output aws-soc2.json
                        '''
                    }
                }

                stage('Azure') {
                    steps {
                        sh '''
                            curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-azure-linux-amd64.tar.gz && tar -xzf auditkit-azure-linux-amd64.tar.gz && mv auditkit-azure-linux-amd64 auditkit-azure
                            chmod +x auditkit-azure
                            az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
                            ./auditkit-azure scan -framework soc2 -format json -output azure-soc2.json
                        '''
                    }
                }

                stage('GCP') {
                    steps {
                        sh '''
                            curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-gcp-linux-amd64.tar.gz && tar -xzf auditkit-gcp-linux-amd64.tar.gz && mv auditkit-gcp-linux-amd64 auditkit-gcp
                            chmod +x auditkit-gcp
                            gcloud auth activate-service-account --key-file=$GCP_CREDENTIALS
                            ./auditkit-gcp scan -framework soc2 -format json -output gcp-soc2.json
                        '''
                    }
                }
            }
        }

        stage('Aggregate Results') {
            steps {
                script {
                    def awsScore = readJSON(file: 'aws-soc2.json').score.percentage
                    def azureScore = readJSON(file: 'azure-soc2.json').score.percentage
                    def gcpScore = readJSON(file: 'gcp-soc2.json').score.percentage

                    echo "AWS Score: ${awsScore}%"
                    echo "Azure Score: ${azureScore}%"
                    echo "GCP Score: ${gcpScore}%"

                    def avgScore = (awsScore + azureScore + gcpScore) / 3
                    echo "Average Multi-Cloud Score: ${avgScore}%"

                    if (avgScore < 75) {
                        error("Multi-cloud compliance score below threshold")
                    }
                }
            }
        }
    }
}
```

---

## AWS CodePipeline

### CodeBuild buildspec.yml

```yaml
# buildspec.yml
version: 0.2

phases:
  install:
    commands:
      - echo "Installing AuditKit..."
      - curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-aws-linux-amd64.tar.gz && tar -xzf auditkit-aws-linux-amd64.tar.gz && mv auditkit-aws-linux-amd64 auditkit-aws
      - chmod +x auditkit-aws

  build:
    commands:
      - echo "Running SOC2 compliance scan..."
      - ./auditkit-aws scan -framework soc2 -format json -output soc2-results.json

  post_build:
    commands:
      - |
        SCORE=$(jq -r '.score.percentage' soc2-results.json)
        echo "Compliance Score: $SCORE%"
        if [ $(echo "$SCORE < 80" | bc) -eq 1 ]; then
          echo "Compliance score below 80% threshold"
          exit 1
        fi

artifacts:
  files:
    - soc2-results.json
  name: compliance-report

reports:
  compliance:
    files:
      - soc2-results.json
    file-format: JSON
```

---

## Azure DevOps

### Azure Pipeline YAML

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: AzureCLI@2
    displayName: 'Azure Login'
    inputs:
      azureSubscription: '$(AzureServiceConnection)'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: 'az account show'

  - script: |
      curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-azure-linux-amd64.tar.gz && tar -xzf auditkit-azure-linux-amd64.tar.gz && mv auditkit-azure-linux-amd64 auditkit-azure
      chmod +x auditkit-azure
    displayName: 'Download AuditKit'

  - script: |
      ./auditkit-azure scan -framework soc2 -format json -output soc2-results.json
    displayName: 'Run SOC2 Compliance Scan'

  - task: PublishBuildArtifacts@1
    displayName: 'Publish Compliance Report'
    inputs:
      PathtoPublish: 'soc2-results.json'
      ArtifactName: 'compliance-report'

  - script: |
      SCORE=$(jq -r '.score.percentage' soc2-results.json)
      echo "Compliance Score: $SCORE%"
      if (( $(echo "$SCORE < 80" | bc -l) )); then
        echo "##vso[task.logissue type=error]Compliance score below 80%"
        exit 1
      fi
    displayName: 'Validate Compliance Score'
```

---

## Cloud Build (GCP)

### cloudbuild.yaml

```yaml
# cloudbuild.yaml
steps:
  # Download AuditKit
  - name: 'ubuntu'
    args:
      - 'bash'
      - '-c'
      - |
        curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-gcp-linux-amd64.tar.gz && tar -xzf auditkit-gcp-linux-amd64.tar.gz && mv auditkit-gcp-linux-amd64 auditkit-gcp
        chmod +x auditkit-gcp

  # Run GCP SOC2 scan
  - name: 'ubuntu'
    env:
      - 'GOOGLE_CLOUD_PROJECT=$PROJECT_ID'
    args:
      - 'bash'
      - '-c'
      - './auditkit-gcp scan -framework soc2 -format json -output soc2-results.json'

  # Check compliance score
  - name: 'gcr.io/cloud-builders/jq'
    args:
      - '-r'
      - '.score.percentage'
      - 'soc2-results.json'

artifacts:
  objects:
    location: 'gs://${PROJECT_ID}_cloudbuild/compliance-reports'
    paths:
      - 'soc2-results.json'

timeout: '600s'
```

---

## Failing Builds on Compliance Issues

### Fail on Any Critical Failures

```bash
#!/bin/bash
# fail-on-critical.sh

CRITICAL_FAILURES=$(jq '[.results[] | select(.status=="FAIL" and .severity=="CRITICAL")] | length' results.json)

if [ "$CRITICAL_FAILURES" -gt 0 ]; then
  echo "FAIL:Found $CRITICAL_FAILURES CRITICAL compliance failures:"
  jq -r '.results[] | select(.status=="FAIL" and .severity=="CRITICAL") | "\(.control_id): \(.name)"' results.json
  exit 1
fi

echo "PASS:No critical compliance failures"
```

### Fail on Score Below Threshold

```bash
#!/bin/bash
# fail-on-score.sh

THRESHOLD=80
SCORE=$(jq -r '.score.percentage' results.json)

echo "Compliance Score: $SCORE%"

if (( $(echo "$SCORE < $THRESHOLD" | bc -l) )); then
  echo "FAIL:Compliance score $SCORE% is below threshold $THRESHOLD%"
  exit 1
fi

echo "PASS:Compliance score meets threshold"
```

### Fail on Specific Controls

```bash
#!/bin/bash
# fail-on-controls.sh

# Fail if specific high-priority controls fail
REQUIRED_CONTROLS=(
  "CC6.1"  # Encryption at rest
  "CC6.6"  # MFA for privileged users
  "CC7.2"  # Audit logging enabled
)

FAILED=false

for CONTROL in "${REQUIRED_CONTROLS[@]}"; do
  STATUS=$(jq -r ".results[] | select(.control_id==\"$CONTROL\") | .status" results.json)

  if [ "$STATUS" == "FAIL" ]; then
    echo "FAIL:Required control $CONTROL failed"
    FAILED=true
  fi
done

if [ "$FAILED" = true ]; then
  exit 1
fi

echo "PASS:All required controls passed"
```

---

## Multi-Cloud Pipelines

### Parallel Multi-Cloud Scan (GitHub Actions)

```yaml
name: Multi-Cloud Compliance

on: [push]

jobs:
  compliance-matrix:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        provider: [aws, azure, gcp]
        framework: [soc2, pci, cmmc]
    steps:
      - uses: actions/checkout@v3

      - name: Setup credentials
        run: |
          if [ "${{ matrix.provider }}" == "aws" ]; then
            echo "AWS_ACCESS_KEY_ID=${{ secrets.AWS_ACCESS_KEY_ID }}" >> $GITHUB_ENV
            echo "AWS_SECRET_ACCESS_KEY=${{ secrets.AWS_SECRET_ACCESS_KEY }}" >> $GITHUB_ENV
          elif [ "${{ matrix.provider }}" == "azure" ]; then
            az login --service-principal -u ${{ secrets.AZURE_CLIENT_ID }} -p ${{ secrets.AZURE_CLIENT_SECRET }} --tenant ${{ secrets.AZURE_TENANT_ID }}
          elif [ "${{ matrix.provider }}" == "gcp" ]; then
            echo "${{ secrets.GCP_CREDENTIALS }}" > gcp-key.json
            gcloud auth activate-service-account --key-file=gcp-key.json
          fi

      - name: Run compliance scan
        run: |
          curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-${{ matrix.provider }}-linux-amd64.tar.gz && tar -xzf auditkit-${{ matrix.provider }}-linux-amd64.tar.gz && mv auditkit-${{ matrix.provider }}-linux-amd64 auditkit
          chmod +x auditkit
          ./auditkit scan -framework ${{ matrix.framework }} -format json -output ${{ matrix.provider }}-${{ matrix.framework }}.json

      - uses: actions/upload-artifact@v3
        with:
          name: ${{ matrix.provider }}-${{ matrix.framework }}
          path: ${{ matrix.provider }}-${{ matrix.framework }}.json
```

---

## Docker Integration

### Dockerfile for CI/CD

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    bc \
    && rm -rf /var/lib/apt/lists/*

# Download AuditKit (choose provider-specific or universal)
RUN curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-linux-amd64.tar.gz && \
    tar -xzf auditkit-linux-amd64.tar.gz && mv auditkit-linux-amd64 /usr/local/bin/auditkit && \
    chmod +x /usr/local/bin/auditkit

# Optionally download provider-specific scanners
RUN curl -LO https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/latest/download/auditkit-aws-linux-amd64.tar.gz && \
    tar -xzf auditkit-aws-linux-amd64.tar.gz && mv auditkit-aws-linux-amd64 /usr/local/bin/auditkit-aws && \
    chmod +x /usr/local/bin/auditkit-aws

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/auditkit"]
```

### Using Docker in CI/CD

```bash
# Build Docker image
docker build -t auditkit:latest .

# Run compliance scan in container
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -v $(pwd):/workspace \
  auditkit:latest scan -provider aws -framework soc2 -format json -output /workspace/results.json
```

---

## Best Practices

1. **Use provider-specific scanners** - 30% smaller binaries = faster CI/CD builds
2. **Cache binaries** - Download once, reuse across pipeline steps
3. **Run scans in parallel** - Scan AWS, Azure, GCP simultaneously
4. **Store JSON artifacts** - Archive compliance reports for audit trails
5. **Fail fast** - Check critical controls first, exit immediately on failures
6. **Schedule regular scans** - Daily/weekly cron jobs catch drift
7. **Use read-only credentials** - AuditKit never modifies cloud resources
8. **Version pin binaries** - Use specific release URLs for reproducible builds

---

## Troubleshooting

### Permission Errors

If scans fail with permission errors:

```bash
# AWS - Use read-only IAM policy
aws iam attach-user-policy --user-name ci-user --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# Azure - Assign Reader + Security Reader roles
az role assignment create --assignee <service-principal-id> --role "Security Reader"

# GCP - Grant Viewer + Security Reviewer roles
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:ci-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

### Binary Download Failures

If binary downloads fail in CI/CD:

```bash
# Use GitHub API for latest release
LATEST_URL=$(curl -s https://api.github.com/repos/guardian-nexus/AuditKit-Community-Edition/releases/latest | jq -r '.assets[] | select(.name=="auditkit-linux-amd64.tar.gz") | .browser_download_url')
curl -L $LATEST_URL -o auditkit-linux-amd64.tar.gz
tar -xzf auditkit-linux-amd64.tar.gz && mv auditkit-linux-amd64 auditkit
```

### JSON Parsing Errors

If `jq` is not available:

```bash
# Install jq in pipeline
apt-get update && apt-get install -y jq   # Ubuntu/Debian
yum install -y jq                         # CentOS/RHEL
apk add jq                                # Alpine
```

---

## Example Output

### Successful Build

```
PASS:AWS SOC2 Compliance Scan Complete
   Score: 87.5% (56/64 checks passed)
   Critical Failures: 0
   High Failures: 3
   Medium Failures: 5

PASS:Compliance score meets 80% threshold
PASS:No critical failures detected
```

### Failed Build

```
FAIL:AWS SOC2 Compliance Scan Complete
   Score: 68.8% (44/64 checks passed)
   Critical Failures: 2
   High Failures: 12
   Medium Failures: 6

FAIL:CRITICAL: CC6.1 - Encryption at rest not enabled on S3 buckets
FAIL:CRITICAL: CC6.6 - MFA not enforced for IAM users with console access

FAIL:Compliance score 68.8% below 80% threshold
FAIL:Build failed due to compliance issues
```

---

## Additional Resources

- [AuditKit CLI Reference](../docs/cli-reference.md)
- [Getting Started](../docs/getting-started.md)
- [Cloud Provider Setup](../docs/setup/)
- [Sample Reports](./reports/)
