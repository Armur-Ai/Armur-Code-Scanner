# Armur Code Scanner — Improvement Roadmap

A comprehensive checklist of tasks to evolve Armur Code Scanner into a production-grade,
widely-adopted open-source security scanning platform. Tasks are grouped by pillar and
ordered by priority within each sprint.

---

## Sprint 1 — Foundation (Make it Trustworthy)

### 1.1 Test Suite
- [ ] Create `testdata/` directory with vulnerable code fixtures for each supported language
  - [ ] `testdata/go/` — Go files with known vulnerabilities (SQL injection, hardcoded secrets, etc.)
  - [ ] `testdata/python/` — Python files with known vulnerabilities
  - [ ] `testdata/js/` — JavaScript/TypeScript files with known vulnerabilities
- [ ] Write unit tests for every tool wrapper in `internal/tools/`
  - [ ] Mock `exec.Command` to avoid requiring tools installed in CI
  - [ ] Test happy path (tool runs, results parsed correctly)
  - [ ] Test failure path (tool not found, tool exits non-zero, malformed output)
- [ ] Write unit tests for result merging/aggregation (`internal/tasks/tasks.go`)
- [ ] Write unit tests for CWE mapping logic
- [ ] Write unit tests for language detection logic
- [ ] Write integration tests for the full scan pipeline using `testdata/` fixtures
- [ ] Write API handler tests (`internal/api/handlers.go`)
- [ ] Add test coverage reporting (`go test -cover ./...`)
- [ ] Enforce minimum 70% test coverage in CI
- [ ] Add `go test ./...` to `Makefile`

### 1.2 Error Propagation
- [ ] Audit all occurrences of `results, _ := RunTool()` and replace with proper error handling
- [ ] Add `Errors []ScanError` field to the scan result response payload
  - [ ] Each `ScanError` should include: tool name, error message, exit code
- [ ] Surface tool-not-found errors to the user (e.g., "gosec not found in PATH")
- [ ] Ensure a single tool failure never silently nulls out its section of results
- [ ] Add error context to all `log.Printf` / `log.Println` calls (include repo URL, tool name, task ID)
- [ ] Remove all bare `panic()` calls; replace with graceful error returns

### 1.3 Input Validation & Security Hardening
- [ ] Validate Git URLs before cloning
  - [ ] Allowlist `https://` scheme only (block `file://`, `ssh://`, `git://`)
  - [ ] Block private/internal IP ranges in resolved hostnames
- [ ] Add file size limit for `/api/v1/scan/file` uploads (e.g., 50MB max)
- [ ] Sanitize all directory path inputs to prevent path traversal attacks
- [ ] Add rate limiting middleware to all API endpoints (e.g., 10 scans/min per IP)
- [ ] Validate `task_id` format before Redis lookups (UUID format check)
- [ ] Add request body size limit to the Gin server

### 1.4 Structured Logging
- [ ] Replace all `fmt.Println` / `log.Println` with a structured logger (`zerolog` or `zap`)
- [ ] Remove all debug `fmt.Println` statements from production code paths
- [ ] Add log levels: DEBUG, INFO, WARN, ERROR
- [ ] Add `--verbose` / `-v` flag to CLI for debug output
- [ ] Include contextual fields in all log entries: `task_id`, `tool`, `repo_url`, `duration_ms`
- [ ] Add request/response logging middleware to the API server

### 1.5 API Authentication
- [ ] Implement API key authentication middleware
  - [ ] Generate API key on server start (or via config)
  - [ ] Require `Authorization: Bearer <key>` header on all endpoints
  - [ ] Return `401 Unauthorized` for missing/invalid keys
- [ ] Add API key to CLI config (`armur config set api-key <key>`)
- [ ] Document authentication in README and Swagger spec

---

## Sprint 2 — Performance & Architecture

### 2.1 Parallel Tool Execution
- [ ] Refactor `RunSimpleScan()` to execute tools concurrently using goroutines + `sync.WaitGroup`
- [ ] Refactor `RunAdvancedScans()` similarly
- [ ] Use a result channel to collect tool outputs safely
- [ ] Add a configurable concurrency limit (env var: `MAX_TOOL_CONCURRENCY`, default: 5)
- [ ] Add per-tool timeout (env var: `TOOL_TIMEOUT_SECONDS`, default: 300)
- [ ] Benchmark before/after to document speedup

### 2.2 Diff / Incremental Scanning
- [ ] Add `--diff <base-ref>` flag to `armur scan` (e.g., `--diff HEAD~1`, `--diff main`)
- [ ] Implement git diff logic to extract list of changed files
- [ ] Pass changed-files list to tool wrappers; skip unchanged files
- [ ] Add `changed_files_only` field to the scan API request body
- [ ] Document diff scanning in README

### 2.3 Plugin System for Custom Tools
- [ ] Define plugin interface spec in `.armur.yml`:
  ```yaml
  plugins:
    - name: my-tool
      command: my-tool --json {target}
      output-format: json
      language: go
  ```
- [ ] Implement plugin loader that reads `.armur.yml` from the scanned repo root
- [ ] Implement generic tool runner that executes plugin command and parses JSON output
- [ ] Add plugin result category `custom_tool` in aggregated results
- [ ] Document plugin system with examples in docs

### 2.4 Project-Level Configuration File
- [ ] Support `.armur.yml` in the scanned repository root
- [ ] Config options to support:
  - [ ] `exclude` — glob patterns for files/dirs to skip
  - [ ] `tools.enabled` — explicit tool allowlist
  - [ ] `tools.disabled` — explicit tool blocklist
  - [ ] `severity-threshold` — minimum severity to report (info/low/medium/high/critical)
  - [ ] `fail-on-findings` — exit code 1 if findings exceed threshold (for CI use)
- [ ] Document all config options in README and docs

### 2.5 Smaller Docker Image
- [ ] Refactor `Dockerfile` to use multi-stage builds
- [ ] Create language-specific image variants:
  - [ ] `armur:go` — Go tools only
  - [ ] `armur:python` — Python tools only
  - [ ] `armur:js` — JavaScript/TypeScript tools only
  - [ ] `armur:full` — all tools (current behavior)
- [ ] Publish image variants to Docker Hub with size documentation
- [ ] Use `alpine` base where possible to reduce layer sizes
- [ ] Document image variant selection in README

### 2.6 Code Quality Cleanup
- [ ] Split `utils.go` (758 lines) into focused modules:
  - [ ] `format.go` — result formatting and table rendering
  - [ ] `history.go` — scan history management
  - [ ] `output.go` — JSON/text output helpers
- [ ] Standardize tool wrapper function signatures across all 18 tool files
- [ ] Remove hardcoded paths (e.g., `/armur/repos`); move to config/env vars
- [ ] Fix all `golangci-lint` warnings on the codebase itself

---

## Sprint 3 — Integrations & Adoption

### 3.1 SARIF Output Format
- [ ] Implement SARIF 2.1.0 output format for scan results
- [ ] Add `--format sarif` flag to `armur scan` CLI command
- [ ] Add `format=sarif` query param to API status endpoint
- [ ] Map all existing CWE/finding data to SARIF `result`, `rule`, `location` objects
- [ ] Validate output against SARIF schema
- [ ] Add SARIF output example to README
- [ ] Document GitHub Code Scanning upload workflow

### 3.2 GitHub Actions Integration
- [ ] Create `armur-ai/armur-scan-action` GitHub Action repository
- [ ] Implement action with inputs:
  - [ ] `target` — path to scan (default: `.`)
  - [ ] `fail-on-severity` — minimum severity to fail the workflow
  - [ ] `output-format` — `sarif`, `json`, or `table`
  - [ ] `languages` — comma-separated language filter
- [ ] Upload SARIF to GitHub Code Scanning via `github/codeql-action/upload-sarif`
- [ ] Add PR comment with finding summary using GitHub API
- [ ] Publish to GitHub Actions Marketplace
- [ ] Add usage example to main README

### 3.3 Pre-commit Hook Support
- [ ] Create `.pre-commit-hooks.yaml` in repo root
- [ ] Implement fast pre-commit scan (staged files only, skip slow tools)
- [ ] Document setup in README:
  ```yaml
  repos:
    - repo: https://github.com/armur-ai/armur-scanner
      hooks:
        - id: armur-scan
  ```
- [ ] Add `--staged-only` flag to CLI for pre-commit use case

### 3.4 Webhook Notifications
- [ ] Add `webhook_url` field to scan request payload
- [ ] POST scan results to webhook URL on task completion
- [ ] Include HMAC signature header for webhook verification
- [ ] Add retry logic for failed webhook deliveries (3 retries, exponential backoff)
- [ ] Document webhook payload schema

### 3.5 GitLab CI Integration
- [ ] Create GitLab CI template (`.gitlab-ci.yml` snippet)
- [ ] Map SARIF output to GitLab SAST report format
- [ ] Document GitLab Security Dashboard integration
- [ ] Add GitLab template to docs

---

## Sprint 4 — Language Expansion

### 4.1 Rust Support
- [ ] Add `cargo-audit` integration (dependency vulnerability scanning)
- [ ] Add `cargo-geiger` integration (unsafe code detection)
- [ ] Add `clippy` integration (linting and common mistakes)
- [ ] Add Rust file extension detection (`*.rs`, `Cargo.toml`)
- [ ] Add Rust to language detection logic
- [ ] Add Rust fixtures to `testdata/`
- [ ] Document Rust support in README

### 4.2 Java / Kotlin Support
- [ ] Add `SpotBugs` integration (bug pattern detection)
- [ ] Add `PMD` integration (code quality)
- [ ] Add `OWASP Dependency-Check` integration (SCA for Java)
- [ ] Add Java/Kotlin file extension detection
- [ ] Add Java/Kotlin to language detection logic
- [ ] Add Java/Kotlin fixtures to `testdata/`
- [ ] Document Java/Kotlin support in README

### 4.3 Ruby Support
- [ ] Add `Brakeman` integration (Rails security scanner)
- [ ] Add `bundler-audit` integration (gem vulnerability scanning)
- [ ] Add Ruby file extension detection (`*.rb`, `Gemfile`)
- [ ] Add Ruby fixtures to `testdata/`

### 4.4 PHP Support
- [ ] Add `PHPCS` with security sniffs integration
- [ ] Add `Psalm` integration (static analysis)
- [ ] Add PHP file extension detection (`*.php`)
- [ ] Add PHP fixtures to `testdata/`

### 4.5 C / C++ Support
- [ ] Add `cppcheck` integration
- [ ] Add `Flawfinder` integration (security-focused C/C++ scanner)
- [ ] Add C/C++ file extension detection
- [ ] Add C/C++ fixtures to `testdata/`

### 4.6 Infrastructure / IaC Expansion
- [ ] Add `hadolint` integration (Dockerfile linting)
- [ ] Add `tfsec` integration (Terraform security)
- [ ] Add `kics` integration (multi-IaC platform)
- [ ] Add `kube-linter` integration (Kubernetes manifest validation)
- [ ] Add `kube-score` integration (Kubernetes best practices)
- [ ] Detect IaC file types automatically (`*.tf`, `Dockerfile`, `*.yaml` with k8s markers)

### 4.7 Solidity / Web3 Support
- [ ] Add `Slither` integration (Solidity static analyzer)
- [ ] Add `Mythril` integration (symbolic execution for smart contracts)
- [ ] Add Solidity file extension detection (`*.sol`)
- [ ] Add Solidity fixtures to `testdata/`

---

## Sprint 5 — CLI Polish & UX

### 5.1 Embedded Server Mode
- [ ] Add `armur serve` command that starts the API server locally
- [ ] Auto-detect if a server is already running before starting a new one
- [ ] Support `armur scan .` without any prior setup (auto-start server if needed)
- [ ] Add `--no-server` flag for users managing the server themselves

### 5.2 Real-Time Streaming Output
- [ ] Stream tool progress to CLI as scan runs (server-sent events or polling)
- [ ] Show which tools are currently running with a live spinner per tool
- [ ] Show elapsed time per tool
- [ ] Display a live finding counter that updates as results come in

### 5.3 Improved Scan Summary
- [ ] Display a summary card at end of scan:
  ```
  ┌─────────────────────────────────────────┐
  │           Scan Complete                 │
  ├──────────┬──────────┬──────────┬────────┤
  │ Critical │   High   │  Medium  │  Low   │
  │    3     │    12    │    27    │   41   │
  └──────────┴──────────┴──────────┴────────┘
  ```
- [ ] Add `--fail-on-severity <level>` flag (non-zero exit code if findings found)
- [ ] Add severity filter flag `--min-severity <level>` to suppress noise

### 5.4 Scan History Improvements
- [ ] Replace JSON file history with SQLite (`~/.armur/history.db`)
- [ ] `armur history` — list past scans with timestamps, targets, finding counts
- [ ] `armur history show <id>` — show full results of a past scan
- [ ] `armur compare <scan-id-1> <scan-id-2>` — diff two scan results (new/fixed findings)
- [ ] `armur history clear` — wipe local history

### 5.5 Command Naming & UX Fixes
- [ ] Rename `scan-i` to `scan --interactive` (or make interactive the default with no args)
- [ ] Add `armur init` command to create `.armur.yml` in current directory with sane defaults
- [ ] Add `armur doctor` command to check which tools are installed and working
- [ ] Add shell completion support (`armur completion bash/zsh/fish/powershell`)
- [ ] Add `--watch` mode to re-scan on file changes (development workflow)

### 5.6 Report Generation
- [ ] Add `armur report --format html --task <id>` — generate standalone HTML report
  - [ ] Include severity distribution chart
  - [ ] Include CWE category breakdown
  - [ ] Include file-by-file findings
  - [ ] Make it self-contained (no external dependencies)
- [ ] Add `armur report --format pdf` — PDF version of the HTML report
- [ ] Add `armur report --format csv` — spreadsheet-friendly export

---

## Sprint 6 — Observability & Operations

### 6.1 Prometheus Metrics
- [ ] Add `/metrics` endpoint exposing Prometheus metrics
- [ ] Track: scan duration histogram (per tool and total)
- [ ] Track: queue depth (pending tasks)
- [ ] Track: error rate per tool
- [ ] Track: active worker count
- [ ] Track: total scans completed/failed
- [ ] Add Grafana dashboard JSON to `docs/grafana/`

### 6.2 Health Check Endpoint
- [ ] Add `GET /health` endpoint
  - [ ] Check Redis connectivity
  - [ ] Check worker availability
  - [ ] Return structured JSON: `{ "status": "ok", "redis": "ok", "workers": 3 }`
- [ ] Add `GET /ready` endpoint for Kubernetes readiness probes

### 6.3 OpenTelemetry Tracing
- [ ] Add OpenTelemetry instrumentation to the scan pipeline
- [ ] Trace spans for: API request → task enqueue → worker pickup → each tool → result store
- [ ] Export to OTLP (compatible with Jaeger, Tempo, Datadog, etc.)
- [ ] Add `OTEL_EXPORTER_OTLP_ENDPOINT` env var support

---

## Sprint 7 — Community & Open Source Health

### 7.1 CI/CD for the Repo Itself
- [ ] Add `.github/workflows/test.yml` — run `go test ./...` on every PR
- [ ] Add `.github/workflows/lint.yml` — run `golangci-lint` on every PR
- [ ] Add `.github/workflows/docker.yml` — build and push Docker image on merge to main
- [ ] Add `.github/workflows/release.yml` — create GitHub Release with binaries on tag push
- [ ] Add `.github/workflows/security.yml` — run Armur on itself (dogfood)

### 7.2 Cross-Platform Releases
- [ ] Add `goreleaser` configuration
- [ ] Build binaries for: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`
- [ ] Publish to GitHub Releases on every semver tag
- [ ] Add Homebrew formula (`brew install armur-ai/tap/armur`)
- [ ] Add `install.sh` one-liner script

### 7.3 Versioning & Changelog
- [ ] Add semantic versioning (`MAJOR.MINOR.PATCH`)
- [ ] Embed version string in binary (`ldflags -X main.version`)
- [ ] Add `armur version` command
- [ ] Create `CHANGELOG.md` following Keep a Changelog format
- [ ] Automate changelog generation from conventional commits

### 7.4 Issue & PR Templates
- [ ] Add `.github/ISSUE_TEMPLATE/bug_report.md`
- [ ] Add `.github/ISSUE_TEMPLATE/feature_request.md`
- [ ] Add `.github/ISSUE_TEMPLATE/new_tool_request.md`
- [ ] Add `.github/PULL_REQUEST_TEMPLATE.md` with checklist (tests, docs, changelog)
- [ ] Add `.github/SECURITY.md` for responsible disclosure process

### 7.5 Contributing Guide
- [ ] Add `CONTRIBUTING.md` with:
  - [ ] How to set up dev environment without Docker
  - [ ] How to add a new tool integration (step-by-step with example)
  - [ ] How to add a new language
  - [ ] Code style and conventions
  - [ ] How to run tests
  - [ ] PR review process

### 7.6 README Improvements
- [ ] Add build status badge (GitHub Actions)
- [ ] Add test coverage badge (Codecov or similar)
- [ ] Add Go Report Card badge
- [ ] Add Docker pulls badge
- [ ] Add license badge
- [ ] Add a demo GIF/video showing CLI in action
- [ ] Add "Supported Languages" table with tool counts per language
- [ ] Add "Quick Start" section that works in under 60 seconds

### 7.7 Documentation Site
- [ ] Add "Getting Started" guide (5-minute quickstart)
- [ ] Add "Tool Reference" page documenting every integrated tool
- [ ] Add "CI/CD Integration" guides (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- [ ] Add "Configuration Reference" (all `.armur.yml` options)
- [ ] Add "Plugin Development" guide
- [ ] Add "API Reference" (expand current Swagger docs)
- [ ] Deploy docs site to GitHub Pages or Vercel

---

## Backlog / Future Ideas

- [ ] VS Code extension — show findings inline as you code
- [ ] JetBrains plugin — IntelliJ/GoLand/PyCharm integration
- [ ] Web dashboard UI — visualize scan history, trends, team findings
- [ ] Multi-repo scanning — scan all repos in a GitHub org
- [ ] GitHub App — auto-scan PRs and post review comments with findings
- [ ] Findings suppression — `// armur:ignore CWE-89` inline comments
- [ ] SBOM generation — produce CycloneDX or SPDX SBOM as part of advanced scan
- [ ] Policy-as-code — define custom security policies in `.armur.yml`
- [ ] Team/org features — shared scan history, role-based access
- [ ] LLM-powered fix suggestions — suggest code fixes for each finding

---

*Last updated: February 2026*
*Based on full codebase analysis — see analysis notes for context on each item.*
