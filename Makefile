BIN := snapwitness
GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
SH := demo/demo.sh
SHFMT := go run mvdan.cc/sh/v3/cmd/shfmt@v3.14.1
RUMDL := uvx rumdl@0.2.78

.DEFAULT_GOAL := help

.PHONY: help build test bench cover lint fmt demo clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the snapwitness binary into the repo root
	CGO_ENABLED=0 go build -o $(BIN) ./cmd/snapwitness

test: ## Run all tests with the race detector
	go test -race ./...

bench: ## Run the benchmarks
	go test -run '^$$' -bench . ./...

cover: ## Write coverage.out and print the coverage of each function
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint: ## Lint the Go, shell and Markdown files
	$(GOLANGCI) run
	shellcheck $(SH)
	$(SHFMT) -d $(SH)
	$(RUMDL) check .

fmt: ## Format the Go, shell and Markdown files
	$(GOLANGCI) fmt
	$(SHFMT) -w $(SH)
	$(RUMDL) fmt .

demo: ## Run the 5-case demo with real restic and litewitness (DEMO_CLEAN=1 deletes its files afterwards)
	./demo/demo.sh

clean: ## Remove the built binary and the demo work files
	rm -rf demo/.work demo/.bin $(BIN)
