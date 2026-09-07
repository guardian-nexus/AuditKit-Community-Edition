# AuditKit Scanner - Multi-Cloud Compliance Tool
# Hybrid Build: Multi-cloud + Provider-specific binaries

VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
LDFLAGS := -ldflags="-s -w -X main.CurrentVersion=$(VERSION)"

.PHONY: help build build-all build-aws build-gcp build-azure build-full test scan scan-soc2 scan-pci clean sizes

help:
	@echo "AuditKit Build System"
	@echo ""
	@echo "Build Commands:"
	@echo "  make build-all    - Build all variants (multi-cloud + provider-specific)"
	@echo "  make build-aws    - Build AWS-only binary (~80-100MB)"
	@echo "  make build-gcp    - Build GCP-only binary (~40-60MB)"
	@echo "  make build-azure  - Build Azure-only binary (~60-80MB)"
	@echo "  make build-full   - Build multi-cloud binary (~260MB)"
	@echo "  make build        - Quick build (AWS-only for testing)"
	@echo ""
	@echo "Test Commands:"
	@echo "  make test         - Run tests"
	@echo "  make scan         - Test AWS scan (CMMC)"
	@echo "  make scan-soc2    - Test AWS scan (SOC2)"
	@echo "  make scan-pci     - Test AWS scan (PCI-DSS)"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make sizes        - Show binary sizes"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run linter"

# Hybrid build: All variants
build-all: build-full build-aws build-gcp build-azure
	@echo ""
	@echo "✅ Hybrid build complete! Binary sizes:"
	@ls -lh auditkit auditkit-aws auditkit-gcp auditkit-azure 2>/dev/null | awk '{print "  " $$9 ": " $$5}'
	@echo ""
	@echo "Usage:"
	@echo "  ./auditkit        - Multi-cloud scanner (all providers)"
	@echo "  ./auditkit-aws    - AWS-only scanner (smaller, faster)"
	@echo "  ./auditkit-gcp    - GCP-only scanner"
	@echo "  ./auditkit-azure  - Azure-only scanner"

# Multi-cloud binary (full feature set)
build-full:
	@echo "Building multi-cloud binary (auditkit)..."
	@go build $(LDFLAGS) -o auditkit ./cmd/auditkit

# AWS-only binary
build-aws:
	@echo "Building AWS-only binary (auditkit-aws)..."
	@go build $(LDFLAGS) -o auditkit-aws ./cmd/auditkit-aws

# GCP-only binary
build-gcp:
	@echo "Building GCP-only binary (auditkit-gcp)..."
	@go build $(LDFLAGS) -o auditkit-gcp ./cmd/auditkit-gcp

# Azure-only binary
build-azure:
	@echo "Building Azure-only binary (auditkit-azure)..."
	@go build $(LDFLAGS) -o auditkit-azure ./cmd/auditkit-azure

# Quick build (AWS-only for testing)
build: build-aws

test:
	@go test ./... -v

scan: build
	@./auditkit scan -provider aws -framework cmmc -verbose

scan-soc2: build
	@./auditkit scan -provider aws -framework soc2 -verbose

scan-pci: build
	@./auditkit scan -provider aws -framework pci -verbose

clean:
	@echo "Cleaning build artifacts..."
	@rm -f auditkit auditkit-aws auditkit-gcp auditkit-azure *.pdf *.html *.json
	@echo "✅ Cleaned"

sizes:
	@echo "Binary sizes:"
	@ls -lh auditkit* 2>/dev/null | awk '{print "  " $$9 ": " $$5}' || echo "  No binaries found. Run 'make build-all' first."

fmt:
	@echo "Formatting code..."
	@goimports -w .
	@go mod tidy

lint:
	@echo "Running linter..."
	@golangci-lint run
