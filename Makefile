BIN := snapwitness
GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
RUMDL := uvx rumdl@0.2.78

.DEFAULT_GOAL := help

.PHONY: help build test bench lint fmt clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the snapwitness binary into the repo root
	CGO_ENABLED=0 go build -o $(BIN) ./cmd/snapwitness

test: ## Run all tests with the race detector
	go test -race ./...

bench: ## Run the benchmarks
	go test -run '^$$' -bench . ./...

lint: ## Lint the Go and Markdown files
	$(GOLANGCI) run
	$(RUMDL) check .

fmt: ## Format the Go and Markdown files
	$(GOLANGCI) fmt
	$(RUMDL) fmt .

clean: ## Remove the built binary
	rm -f $(BIN)
