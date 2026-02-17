# Installation Guide

Complete installation instructions for AuditKit.

---

## System Requirements

**Operating Systems:**
- Linux (any modern distribution)
- macOS (10.15 Catalina or newer)
- Windows (10/11 or Server 2016+)

**Requirements:**
- Go 1.19 or newer (for building from source)
- Cloud CLI tools (AWS CLI, Azure CLI, or gcloud CLI)
- Read-only cloud credentials
- Internet connection (for downloading and scanning)

**Disk Space:**
- Binary: ~15 MB
- Source code: ~50 MB
- Scan results: ~1-10 MB per scan

---

## Installation Methods

### Option 1: Download Pre-Built Binary (Recommended)

**Fastest and easiest method**

#### Linux

```bash
# Download latest release
wget https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/download/v0.7.0/auditkit-linux-amd64

# Make executable
chmod +x auditkit-linux-amd64

# Move to PATH
sudo mv auditkit-linux-amd64 /usr/local/bin/auditkit

# Verify installation
auditkit version
```

#### macOS

```bash
# Download latest release
curl -L https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/download/v0.7.0/auditkit-darwin-amd64 -o auditkit

# Make executable
chmod +x auditkit

# Move to PATH
sudo mv auditkit /usr/local/bin/

# If you get security warning on first run:
# System Preferences > Security & Privacy > Allow

# Verify installation
auditkit version
```

#### Windows

```powershell
# Download from GitHub Releases page
# https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/download/v0.7.0/auditkit-windows-amd64.exe

# Rename to auditkit.exe
Rename-Item auditkit-windows-amd64.exe auditkit.exe

# Add to PATH or run from current directory
.\auditkit.exe version
```

---

### Option 2: Build from Source

**For developers or custom builds**

#### Prerequisites

```bash
# Install Go 1.19 or newer
# Download from: https://go.dev/dl/

# Verify Go installation
go version  # Should show 1.19 or higher
```

#### Clone and Build

```bash
# Clone repository
git clone https://github.com/guardian-nexus/AuditKit-Community-Edition
cd AuditKit-Community-Edition/scanner

# Build binary
go build ./cmd/auditkit

# Binary is now at: ./auditkit

# Optional: Move to PATH
sudo mv auditkit /usr/local/bin/

# Verify installation
auditkit version
```

#### Build for Different Platforms

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o auditkit-linux ./cmd/auditkit

# macOS (amd64)
GOOS=darwin GOARCH=amd64 go build -o auditkit-macos ./cmd/auditkit

# macOS (arm64 - M1/M2)
GOOS=darwin GOARCH=arm64 go build -o auditkit-macos-arm64 ./cmd/auditkit

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o auditkit.exe ./cmd/auditkit
```

---

### Option 3: Go Install

**For Go users**

```bash
# Install directly from GitHub
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest

# Binary installed to: $GOPATH/bin/auditkit

# Add GOPATH/bin to PATH if needed
export PATH=$PATH:$(go env GOPATH)/bin

# Verify installation
auditkit version
```

---

## Installing Cloud CLI Tools

AuditKit requires cloud CLI tools for authentication.

### AWS CLI

**Linux/macOS:**
```bash
# Option 1: Using package manager
# macOS
brew install awscli

# Ubuntu/Debian
sudo apt-get install awscli

# Option 2: Using pip
pip3 install awscli

# Verify installation
aws --version
```

**Windows:**
```powershell
# Download installer from:
# https://aws.amazon.com/cli/

# Or using Chocolatey
choco install awscli

# Verify installation
aws --version
```

**[AWS Setup Guide →](./setup/aws.md)**

### Azure CLI

**Linux/macOS:**
```bash
# macOS
brew install azure-cli

# Ubuntu/Debian
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Verify installation
az --version
```

**Windows:**
```powershell
# Download installer from:
# https://docs.microsoft.com/cli/azure/install-azure-cli-windows

# Or using Chocolatey
choco install azure-cli

# Verify installation
az --version
```

**[Azure Setup Guide →](./setup/azure.md)**

### Google Cloud SDK

**Linux/macOS:**
```bash
# macOS
brew install google-cloud-sdk

# Linux - using snap
sudo snap install google-cloud-cli --classic

# Or download from:
# https://cloud.google.com/sdk/docs/install

# Verify installation
gcloud --version
```

**Windows:**
```powershell
# Download installer from:
# https://cloud.google.com/sdk/docs/install

# Or using Chocolatey
choco install gcloudsdk

# Verify installation
gcloud --version
```

**[GCP Setup Guide →](./setup/gcp.md)**

---

## Verifying Installation

### Check AuditKit Version

```bash
auditkit version
```

**Expected output:**
```
AuditKit v0.8.1
Built: 2026-02-03
```

### Check Cloud CLI Tools

```bash
# AWS
aws --version

# Azure
az --version

# GCP
gcloud --version
```

### Run Test Scan

```bash
# Test AWS (requires configured credentials)
auditkit scan -provider aws -framework soc2

# Test Azure (requires login)
auditkit scan -provider azure -framework soc2

# Test GCP (requires auth)
auditkit scan -provider gcp -framework soc2
```

---

## Configuration

### Setting Up Cloud Credentials

**AWS:**
```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region
```

**Azure:**
```bash
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

**GCP:**
```bash
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-project-id
```

**[Detailed setup guides →](./setup/)**

---

## Updating AuditKit

### Check for Updates

```bash
auditkit update
```

### Update Binary Installation

```bash
# Download new version
wget https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/download/v0.X.X/auditkit-linux-amd64

# Replace old binary
chmod +x auditkit-linux-amd64
sudo mv auditkit-linux-amd64 /usr/local/bin/auditkit

# Verify new version
auditkit version
```

### Update Source Installation

```bash
cd auditkit
git pull origin main
cd scanner
go build ./cmd/auditkit
sudo mv auditkit /usr/local/bin/
```

### Update Go Install

```bash
go install github.com/guardian-nexus/auditkit/scanner/cmd/auditkit@latest
```

---

## Troubleshooting Installation

### "Command not found: auditkit"

**Cause:** Binary not in PATH

**Solution:**
```bash
# Find where binary is located
which auditkit

# If not found, add to PATH
export PATH=$PATH:/path/to/auditkit/directory

# Or move to standard location
sudo mv auditkit /usr/local/bin/
```

### "Permission denied" when running auditkit

**Cause:** Binary not executable

**Solution:**
```bash
chmod +x auditkit
```

### macOS "cannot be opened because the developer cannot be verified"

**Cause:** macOS Gatekeeper security

**Solution:**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine auditkit

# Or: System Preferences > Security & Privacy > Allow
```

### Build errors with Go

**Cause:** Go version too old or dependencies missing

**Solution:**
```bash
# Update Go to 1.19 or newer
go version

# Clean build cache
go clean -cache -modcache

# Rebuild
go build ./cmd/auditkit
```

### "Cannot connect to AWS/Azure/GCP"

**Cause:** Cloud CLI not installed or not configured

**Solution:**
```bash
# Install cloud CLI tools (see above)
# Configure credentials (see setup guides)

# Test cloud CLI directly
aws sts get-caller-identity  # AWS
az account show              # Azure
gcloud projects list         # GCP
```

---

## Uninstalling AuditKit

### Remove Binary

```bash
# Find installation location
which auditkit

# Remove binary
sudo rm /usr/local/bin/auditkit
```

### Remove Source Installation

```bash
# Remove cloned repository
rm -rf ~/auditkit

# Remove Go binary (if installed via go install)
rm $(go env GOPATH)/bin/auditkit
```

### Clean Up Scan Results

```bash
# Remove scan history (if you want to)
rm -rf ~/.auditkit/
```

---

## Advanced Installation

### Installing in Air-Gapped Environment

**For environments without internet access:**

1. Download binary on internet-connected machine:
```bash
wget https://github.com/guardian-nexus/AuditKit-Community-Edition/releases/download/v0.7.0/auditkit-linux-amd64
```

2. Transfer to air-gapped machine via USB/secure transfer

3. Install normally:
```bash
chmod +x auditkit-linux-amd64
sudo mv auditkit-linux-amd64 /usr/local/bin/auditkit
```

**Note:** Cloud CLI tools must also be installed offline

### Installing for Multiple Users

**System-wide installation:**

```bash
# Install to /usr/local/bin (all users can access)
sudo cp auditkit /usr/local/bin/
sudo chmod 755 /usr/local/bin/auditkit

# Verify all users can run
su - otheruser -c "auditkit version"
```

### Custom Installation Directory

```bash
# Install to custom location
mkdir -p ~/tools
cp auditkit ~/tools/

# Add to PATH in shell profile
echo 'export PATH=$PATH:$HOME/tools' >> ~/.bashrc
source ~/.bashrc

# Verify
auditkit version
```

---

## Pro Version Installation

**For AuditKit customers:**

1. **[Sign up for trial →](https://auditkit.io/pro/)**
2. Receive `.lic` license file via email
3. Download Pro binary from customer portal
4. Save your license file and run:

```bash
# Install Pro binary (note: different binary name)
chmod +x auditkit-pro
sudo mv auditkit-pro /usr/local/bin/auditkit-pro

# Save license file (received after purchase/trial signup)
mkdir -p ~/.auditkit-pro
cp ~/Downloads/license.lic ~/.auditkit-pro/license.lic

# Activation is automatic on first run — no separate command needed
auditkit-pro version  # Shows "Pro" edition

# Run Pro scans
auditkit-pro scan -provider aws -framework cmmc-l2
```

**Note:** Pro version uses `auditkit-pro` command, not `auditkit`

**Legacy method (deprecated):** The old `export AUDITKIT_PRO_LICENSE=AKP-...` environment variable still works but is deprecated in favor of the `.lic` file.

**[Pro feature details →](./pricing.md)**

---

## Next Steps

- **[Run your first scan →](./getting-started.md)**
- **[Setup cloud credentials →](./setup/)**
- **[CLI Reference →](./cli-reference.md)**
- **[Examples →](./examples/)**
