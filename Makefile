.DEFAULT_GOAL := help

.PHONY: help test

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

test: ## Run unit + integration tests with coverage
	DATABASE_URL="sqlite://$(CURDIR)/db_v2.sqlite3" cargo llvm-cov --workspace --exclude s3software --summary-only
