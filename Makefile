GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0

.PHONY: help lint fmt

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

lint: ## Lint the Go files
	$(GOLANGCI) run

fmt: ## Format the Go files
	$(GOLANGCI) fmt
