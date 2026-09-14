# AuditKit Scanner - Multi-Cloud Compliance Tool
# Hybrid Build: Multi-cloud + Provider-specific binaries

VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
LDFLAGS := -ldflags="-s -w -X main.CurrentVersion=$(VERSION)"

.PHONY: help build test scan scan-soc2 scan-pci clean sizes fmt lint

help:
	@echo "AuditKit Build System"
	@echo ""
	@echo "Build Commands:"
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

# One binary, every provider. The single-cloud variants were dropped for
# v1.0: they printed the scanner's rows raw, with none of the report layer.
build:
	@echo "Building auditkit..."
	@go build $(LDFLAGS) -o auditkit ./cmd/auditkit

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
	@rm -f auditkit *.pdf *.html *.json
	@echo "✅ Cleaned"

sizes:
	@echo "Binary sizes:"
	@ls -lh auditkit* 2>/dev/null | awk '{print "  " $$9 ": " $$5}' || echo "  No binaries found. Run 'make build' first."

fmt:
	@echo "Formatting code..."
	@goimports -w .
	@go mod tidy

lint:
	@echo "Running linter..."
	@golangci-lint run
