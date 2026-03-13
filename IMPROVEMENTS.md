# Armur Code Scanner — Improvement Roadmap

A comprehensive checklist of tasks to evolve Armur Code Scanner into a production-grade,
widely-adopted open-source security scanning platform. Tasks are grouped by pillar and
ordered by priority within each sprint.

---

## Sprint 1 — Foundation (Make it Trustworthy)

### 1.1 Test Suite
- [x] Create `testdata/` directory with vulnerable code fixtures for each supported language
  - [x] `testdata/go/` — Go files with known vulnerabilities (SQL injection, hardcoded secrets, etc.)
  - [x] `testdata/python/` — Python files with known vulnerabilities
  - [x] `testdata/js/` — JavaScript/TypeScript files with known vulnerabilities
- [x] Write unit tests for every tool wrapper in `internal/tools/`
  - [x] Mock `exec.Command` to avoid requiring tools installed in CI
  - [x] Test happy path (tool runs, results parsed correctly)
  - [x] Test failure path (tool not found, tool exits non-zero, malformed output)
- [x] Write unit tests for result merging/aggregation (`internal/tasks/tasks.go`)
- [x] Write unit tests for CWE mapping logic
- [x] Write unit tests for language detection logic
- [x] Write integration tests for the full scan pipeline using `testdata/` fixtures
- [x] Write API handler tests (`internal/api/handlers.go`)
- [x] Add test coverage reporting (`go test -cover ./...`)
- [x] Enforce minimum 70% test coverage in CI
- [x] Add `go test ./...` to `Makefile`

### 1.2 Error Propagation
- [x] Audit all occurrences of `results, _ := RunTool()` and replace with proper error handling
- [x] Add `Errors []ScanError` field to the scan result response payload
  - [x] Each `ScanError` should include: tool name, error message, exit code
- [x] Surface tool-not-found errors to the user (e.g., "gosec not found in PATH")
- [x] Ensure a single tool failure never silently nulls out its section of results
- [x] Add error context to all `log.Printf` / `log.Println` calls (include repo URL, tool name, task ID)
- [x] Remove all bare `panic()` calls; replace with graceful error returns

### 1.3 Input Validation & Security Hardening
- [x] Validate Git URLs before cloning
  - [x] Allowlist `https://` scheme only (block `file://`, `ssh://`, `git://`)
  - [x] Block private/internal IP ranges in resolved hostnames
- [x] Add file size limit for `/api/v1/scan/file` uploads (e.g., 50MB max)
- [x] Sanitize all directory path inputs to prevent path traversal attacks
- [x] Add rate limiting middleware to all API endpoints (e.g., 10 scans/min per IP)
- [x] Validate `task_id` format before Redis lookups (UUID format check)
- [x] Add request body size limit to the Gin server

### 1.4 Structured Logging
- [x] Replace all `fmt.Println` / `log.Println` with a structured logger (`zerolog` or `zap`)
- [x] Remove all debug `fmt.Println` statements from production code paths
- [x] Add log levels: DEBUG, INFO, WARN, ERROR
- [x] Add `--verbose` / `-v` flag to CLI for debug output
- [x] Include contextual fields in all log entries: `task_id`, `tool`, `repo_url`, `duration_ms`
- [x] Add request/response logging middleware to the API server

### 1.5 API Authentication
- [x] Implement API key authentication middleware
  - [x] Generate API key on server start (or via config)
  - [x] Require `Authorization: Bearer <key>` header on all endpoints
  - [x] Return `401 Unauthorized` for missing/invalid keys
- [x] Add API key to CLI config (`armur config set api-key <key>`)
- [ ] Document authentication in README and Swagger spec

---

## Sprint 2 — Performance & Architecture

### 2.1 Parallel Tool Execution
- [x] Refactor `RunSimpleScan()` to execute tools concurrently using goroutines + `sync.WaitGroup`
- [x] Refactor `RunAdvancedScans()` similarly
- [x] Use a result channel to collect tool outputs safely
- [x] Add a configurable concurrency limit (env var: `MAX_TOOL_CONCURRENCY`, default: 5)
- [x] Add per-tool timeout (env var: `TOOL_TIMEOUT_SECONDS`, default: 300)
- [ ] Benchmark before/after to document speedup

### 2.2 Diff / Incremental Scanning
- [x] Add `--diff <base-ref>` flag to `armur scan` (e.g., `--diff HEAD~1`, `--diff main`)
- [x] Implement git diff logic to extract list of changed files
- [x] Pass changed-files list to tool wrappers; skip unchanged files
- [x] Add `changed_files_only` field to the scan API request body
- [ ] Document diff scanning in README

### 2.3 Plugin System for Custom Tools
- [x] Define plugin interface spec in `.armur.yml`:
  ```yaml
  plugins:
    - name: my-tool
      command: my-tool --json {target}
      output-format: json
      language: go
  ```
- [x] Implement plugin loader that reads `.armur.yml` from the scanned repo root
- [x] Implement generic tool runner that executes plugin command and parses JSON output
- [x] Add plugin result category `custom_tool` in aggregated results
- [ ] Document plugin system with examples in docs

### 2.4 Project-Level Configuration File
- [x] Support `.armur.yml` in the scanned repository root
- [x] Config options to support:
  - [x] `exclude` — glob patterns for files/dirs to skip
  - [x] `tools.enabled` — explicit tool allowlist
  - [x] `tools.disabled` — explicit tool blocklist
  - [x] `severity-threshold` — minimum severity to report (info/low/medium/high/critical)
  - [x] `fail-on-findings` — exit code 1 if findings exceed threshold (for CI use)
- [ ] Document all config options in README and docs

### 2.5 Smaller Docker Image
- [x] Refactor `Dockerfile` to use multi-stage builds
- [x] Create language-specific image variants:
  - [x] `armur:go` — Go tools only
  - [x] `armur:python` — Python tools only
  - [x] `armur:js` — JavaScript/TypeScript tools only
  - [x] `armur:full` — all tools (current behavior)
- [ ] Publish image variants to Docker Hub with size documentation
- [x] Use `alpine` base where possible to reduce layer sizes
- [ ] Document image variant selection in README

### 2.6 Code Quality Cleanup
- [x] Split `utils.go` (758 lines) into focused modules:
  - [x] `format.go` — result formatting and table rendering
  - [x] `report.go` — OWASP/SANS report generation
- [ ] Standardize tool wrapper function signatures across all 18 tool files
- [x] Remove hardcoded paths (e.g., `/armur/repos`); move to config/env vars
- [ ] Fix all `golangci-lint` warnings on the codebase itself

---

## Sprint 3 — Integrations & Adoption

### 3.1 SARIF Output Format
- [x] Implement SARIF 2.1.0 output format for scan results
- [x] Add `--format sarif` flag to `armur scan` CLI command
- [x] Add `format=sarif` query param to API status endpoint
- [x] Map all existing CWE/finding data to SARIF `result`, `rule`, `location` objects
- [ ] Validate output against SARIF schema
- [ ] Add SARIF output example to README
- [ ] Document GitHub Code Scanning upload workflow

### 3.2 GitHub Actions Integration
- [x] Create `armur-ai/armur-scan-action` GitHub Action repository
- [x] Implement action with inputs:
  - [x] `target` — path to scan (default: `.`)
  - [x] `fail-on-severity` — minimum severity to fail the workflow
  - [x] `output-format` — `sarif`, `json`, or `table`
  - [x] `languages` — comma-separated language filter
- [x] Upload SARIF to GitHub Code Scanning via `github/codeql-action/upload-sarif`
- [ ] Add PR comment with finding summary using GitHub API
- [ ] Publish to GitHub Actions Marketplace
- [ ] Add usage example to main README

### 3.3 Pre-commit Hook Support
- [x] Create `.pre-commit-hooks.yaml` in repo root
- [x] Implement fast pre-commit scan (staged files only, skip slow tools)
- [ ] Document setup in README:
  ```yaml
  repos:
    - repo: https://github.com/armur-ai/armur-scanner
      hooks:
        - id: armur-scan
  ```
- [x] Add `--staged-only` flag to CLI for pre-commit use case

### 3.4 Webhook Notifications
- [x] Add `webhook_url` field to scan request payload
- [x] POST scan results to webhook URL on task completion
- [x] Include HMAC signature header for webhook verification
- [x] Add retry logic for failed webhook deliveries (3 retries, exponential backoff)
- [ ] Document webhook payload schema

### 3.5 GitLab CI Integration
- [x] Create GitLab CI template (`.gitlab-ci.yml` snippet)
- [x] Map SARIF output to GitLab SAST report format
- [x] Document GitLab Security Dashboard integration
- [x] Add GitLab template to docs

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

## Sprint 8 — `armur run`: Flagship TUI Command

The primary user-facing goal: a single entry point that replaces `scan`, `scan-i`, and all manual flags.
Running `armur run` with no arguments opens a beautiful full-screen TUI that walks the user through
everything and shows live progress as the scan executes.

### 8.1 `armur run` Wizard (Multi-Step Setup Form)

The first thing the user sees — a guided setup before the scan begins.

- [ ] Add `armur run` as a new top-level Cobra command (additive; does not replace `scan`)
- [ ] Implement a multi-step `charmbracelet/huh` form wizard:
  - [ ] **Step 1 — Target**: auto-fill current directory if it is a git repo; three options:
    - Current directory (pre-selected when inside a git repo, shown as `./`)
    - Enter a local path (file or directory picker)
    - Enter a remote git repository URL
  - [ ] **Step 2 — Scan depth**: "Quick" (simple tool suite, ~30s) vs "Deep" (full advanced suite, ~2–3m)
  - [ ] **Step 3 — Language** (skip if auto-detected with >80% confidence): dropdown with Go, Python, JavaScript/TypeScript, Auto-detect
  - [ ] **Step 4 — Output**: Text (default), JSON, SARIF — plus toggle "Save report to file"
  - [ ] **Step 5 — Confirmation screen**: show summary of choices before scan begins; buttons: "Start Scan" / "Go Back" / "Cancel"
- [ ] Pressing Ctrl+C at any wizard step exits cleanly with "Scan cancelled."
- [ ] Persist last-used wizard choices to `~/.armur/last_run.json` and pre-fill them on the next `armur run`
- [ ] Read `.armur.yml` from current directory (if present) to further pre-fill defaults

### 8.2 Live Scan Dashboard (Bubbletea Full-Screen TUI)

After the wizard, transition to a full-screen Bubbletea model that shows real-time scan progress.

- [ ] Create `cli/internal/tui/` package for all Bubbletea models and messages
- [ ] Implement `ScanDashboard` Bubbletea model with the following terminal layout:
  ```
  ╔══════════════════════════════════════════════════════╗
  ║  ARMUR  ·  Scanning: ./my-project  ·  Deep scan     ║
  ╠══════════════════════════════════════════════════════╣
  ║  Tool              Progress          Status  Found  ║
  ║  ──────────────────────────────────────────────────  ║
  ║  semgrep           [██████████] 100%  ✓ Done    14  ║
  ║  gosec             [████░░░░░░]  42%  ⟳ Running  3  ║
  ║  golint            [░░░░░░░░░░]   0%  ○ Queued   -  ║
  ║  staticcheck       [░░░░░░░░░░]   0%  ○ Queued   -  ║
  ║  gocyclo           [░░░░░░░░░░]   0%  ○ Queued   -  ║
  ║  trufflehog        [░░░░░░░░░░]   0%  ○ Queued   -  ║
  ╠══════════════════════════════════════════════════════╣
  ║  Critical: 0  High: 3  Medium: 8  Low: 6  Info: 0  ║
  ║  Elapsed: 0:23                           [q] Quit  ║
  ╚══════════════════════════════════════════════════════╝
  ```
- [ ] Use `github.com/charmbracelet/bubbles/progress` for per-tool progress bars
- [ ] Use `github.com/charmbracelet/bubbles/spinner` for the currently-running tool indicator
- [ ] Each tool row updates in real time: name, progress bar, status icon, finding count
  - Status icons: `○` queued · `⟳` running · `✓` done · `✗` failed · `⚠` skipped (tool not installed)
- [ ] Severity counter row in the footer updates as findings arrive
- [ ] Elapsed time counter ticks every second
- [ ] Press `q` or Ctrl+C to cancel the scan mid-run (sends cancel to server, cleans up, exits)
- [ ] Press `p` to pause live updates (freeze screen to read without stopping the scan)
- [ ] Degrade gracefully: if terminal is too narrow, collapse to a single-line spinner + counts

### 8.3 Post-Scan Results Browser (Interactive Viewer)

After scan completion, transition directly to a two-pane interactive results browser without leaving the TUI.

- [ ] Implement `ResultsBrowser` Bubbletea model with:
  - **Left pane** — scrollable finding list, sorted by severity desc
  - **Right pane** — detail view of the currently selected finding
- [ ] Finding list row: `[SEV]  file/path.go:42  rule-id  Short message truncated...`
- [ ] Severity badges color-coded with lipgloss: `[CRIT]` · `[HIGH]` · `[MED]` · `[LOW]` · `[INFO]`
- [ ] Keyboard navigation:
  - `↑`/`↓` or `j`/`k` — move through the findings list
  - `Enter` — expand/collapse the right-pane detail view
  - `f` — toggle filter sidebar (multi-select: severity, category, file glob, tool)
  - `s` — cycle sort order: severity desc → file → tool → line number
  - `/` — inline search: filter by substring across file path and message
  - `e` — export current filtered view (JSON or text, prompts for filename)
  - `r` — open report submenu (generate HTML / CSV / Markdown)
  - `q` — quit to shell
- [ ] Right-pane detail view shows:
  - File path + line number (highlighted)
  - Rule ID and CWE (if available) as badges
  - Full finding message
  - 5-line code snippet with the offending line highlighted (read from local file if available)
  - Tool name that reported it
  - Remediation hint (if the tool provides one)
- [ ] Summary bar above the list: `17 findings · Critical 1  High 5  Medium 8  Low 3 · Showing: all`
- [ ] Filter sidebar: checkbox groups for each dimension; updates list in real time as filters change

### 8.4 Post-Scan Summary Card (Static Output After TUI Exits)

When the user quits the TUI, print a compact lipgloss-styled summary card to stdout that remains visible in the terminal history.

- [ ] Print a bordered summary card using `charmbracelet/lipgloss`:
  ```
  ┌────────────────────────────────────────────────┐
  │  Scan Complete — ./my-project (Go, Deep)       │
  │  Duration: 1m 43s  ·  Tools: 5 ok, 0 failed   │
  ├──────────┬──────────┬──────────┬───────────────┤
  │ Critical │   High   │  Medium  │  Low / Info   │
  │    1     │    5     │    8     │     3 / 7     │
  └──────────┴──────────┴──────────┴───────────────┘
  Task ID:  abc-123-def
  Report:   ~/.armur/reports/abc-123-def.json
  Run 'armur history show abc-123-def' to view again.
  ```
- [ ] Severity counts colored (red / yellow / green) using lipgloss
- [ ] Print only if there were findings; if zero findings: print a green "✓ No issues found." card instead
- [ ] If `--fail-on-severity` was set and threshold exceeded: print exit code warning before exiting with code 1

---

## Sprint 9 — Streaming Architecture (Server-Side Events)

To power the live TUI dashboard in Sprint 8, the server must push real-time per-tool progress events
to the CLI as the scan executes rather than waiting until everything is done.

### 9.1 Server-Sent Events (SSE) Endpoint

- [ ] Add `GET /api/v1/scan/stream/:task_id` SSE endpoint to the Gin router (`internal/api/routes.go`)
- [ ] Define the event schema (newline-delimited JSON in SSE `data:` field):
  ```json
  { "event": "tool_started",    "tool": "gosec",  "ts": 1700000001 }
  { "event": "tool_progress",   "tool": "gosec",  "pct": 42, "ts": 1700000003 }
  { "event": "tool_completed",  "tool": "gosec",  "findings": 3, "duration_ms": 4200 }
  { "event": "tool_failed",     "tool": "gosec",  "error": "exit status 1" }
  { "event": "tool_skipped",    "tool": "golint", "reason": "binary not found in PATH" }
  { "event": "scan_completed",  "total_findings": 17, "duration_ms": 103000 }
  ```
- [ ] Worker writes events to a per-task buffered channel stored in a registry (`sync.Map`)
- [ ] SSE handler reads from that channel and writes `data: <json>\n\n` to the response stream
- [ ] Set correct SSE headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`
- [ ] Handle client disconnect (context cancellation) by closing the read loop gracefully
- [ ] Store the last 50 events per task in Redis so late-connecting clients can replay missed events
- [ ] Add 30-second keepalive comment (`: ping\n\n`) to prevent proxy timeouts

### 9.2 Worker Progress Instrumentation

- [ ] Define `ProgressReporter` interface in `internal/tasks/progress.go`:
  ```go
  type ProgressReporter interface {
      Started(tool string)
      Progress(tool string, pct int)
      Completed(tool string, findingCount int, d time.Duration)
      Failed(tool string, err error)
      Skipped(tool string, reason string)
  }
  ```
- [ ] Implement `ChannelReporter` that sends events to the per-task channel
- [ ] Thread `ProgressReporter` into `RunSimpleScan`, `RunAdvancedScans`, and every tool wrapper
- [ ] Call `Started` immediately before `exec.Command`, `Completed`/`Failed` immediately after
- [ ] For tools that print progress to stdout (semgrep JSON streaming, trivy), parse their output line-by-line and emit `Progress` events with estimated `pct` based on lines processed
- [ ] Emit `Skipped` when a tool binary is not found in PATH (currently silently errors)

### 9.3 CLI SSE Client

- [ ] Implement `cli/internal/sse/client.go`:
  - `Connect(url, taskID string) (<-chan Event, error)` — opens SSE connection, returns event channel
  - Parses `data:` lines, unmarshals JSON into `Event` struct
  - Sends events to a channel that the Bubbletea program reads via `tea.Program.Send()`
- [ ] Run SSE client in a goroutine spawned when the TUI dashboard starts
- [ ] Implement reconnect with exponential backoff: retry after 1s, 2s, 4s, then fall back to 2s polling
- [ ] On `scan_completed` event: send a `ScanDoneMsg` to Bubbletea to trigger transition to ResultsBrowser
- [ ] On connection failure: show "⚠ Live updates unavailable — polling every 2s" in the dashboard footer

---

## Sprint 10 — Core Engine Overhaul

### 10.1 Parallel Tool Execution

All language-specific tools read the same directory independently; there is no reason to run them
sequentially. Parallelizing cuts scan time by 3–5x for a typical Go project.

- [ ] Refactor `RunSimpleScan` and `RunAdvancedScans` to a concurrent pattern:
  ```go
  type toolResult struct {
      tool    string
      results map[string]interface{}
      err     error
  }
  results := make(chan toolResult, len(tools))
  var wg sync.WaitGroup
  for _, t := range activeTools {
      wg.Add(1)
      go func(t toolRunner) {
          defer wg.Done()
          r, err := t.Run(ctx, dirPath)
          results <- toolResult{t.Name(), r, err}
      }(t)
  }
  wg.Wait()
  close(results)
  ```
- [ ] Use a semaphore (`chan struct{}`) to cap concurrent tool goroutines to `MAX_TOOL_CONCURRENCY`
- [ ] Wrap each tool `exec.Command` in a `context.WithTimeout(ctx, TOOL_TIMEOUT)` so hung tools are killed
- [ ] Merge results from the channel after all goroutines finish (order-independent)
- [ ] Benchmark scan time before and after for a medium Go repo; document in `docs/benchmarks.md`

### 10.2 Unified `Finding` Type

Replace all `map[string]interface{}` result flowing through the pipeline with a concrete typed struct.
This eliminates hundreds of fragile type assertions scattered across `tasks.go`, `scan.go`, and `utils.go`.

- [ ] Define `internal/models/finding.go`:
  ```go
  type Severity string
  const (
      SeverityCritical Severity = "CRITICAL"
      SeverityHigh     Severity = "HIGH"
      SeverityMedium   Severity = "MEDIUM"
      SeverityLow      Severity = "LOW"
      SeverityInfo     Severity = "INFO"
  )

  type Finding struct {
      ID          string   `json:"id"`              // SHA256 fingerprint (computed)
      Tool        string   `json:"tool"`
      Category    string   `json:"category"`        // security_issues | antipatterns_bugs | etc.
      File        string   `json:"file"`
      Line        int      `json:"line"`
      EndLine     int      `json:"end_line,omitempty"`
      Column      int      `json:"column,omitempty"`
      RuleID      string   `json:"rule_id,omitempty"`
      CWE         string   `json:"cwe,omitempty"`
      OWASP       string   `json:"owasp,omitempty"`
      Severity    Severity `json:"severity"`
      Message     string   `json:"message"`
      Snippet     string   `json:"snippet,omitempty"`      // 3-5 lines of code context
      Remediation string   `json:"remediation,omitempty"` // fix suggestion if tool provides one
  }
  ```
- [ ] Update every tool wrapper in `internal/tools/` to return `([]Finding, error)` instead of `(map[string]interface{}, error)`
- [ ] Update `RunSimpleScan` / `RunAdvancedScans` to aggregate `[]Finding`
- [ ] Update API response serialization to use `[]Finding`
- [ ] Update all CLI display functions (`utils.go`, `scan.go`) to use `Finding` fields directly
- [ ] Write unit tests asserting each tool wrapper's output shape

### 10.3 Finding Fingerprinting & Deduplication

Multiple tools often report the same issue (e.g. gosec and semgrep both flag the same SQL injection).
Deduplicate before surfacing results to avoid noise.

- [ ] Compute `Finding.ID` as `hex(SHA256(tool + "|" + file + "|" + strconv.Itoa(line) + "|" + ruleID + "|" + message[:64]))`
- [ ] After merging all tool results, group by `(file, line, cwe)`:
  - If two findings share the same `file + line + CWE`, keep the one with more fields populated (prefer remediation hints)
  - Record the de-duplicated finding's ID in the surviving finding's `DuplicateOf []string` field
- [ ] Add deduplication metadata to scan result: `"meta": { "raw_count": 34, "after_dedup": 17, "dupes_removed": 17 }`
- [ ] Write unit tests for deduplication with synthetic overlapping inputs

### 10.4 Severity Normalization

Each tool uses different severity representations. Normalize all of them to the canonical `Severity` enum at parse time inside each tool wrapper so the rest of the pipeline never needs to handle raw severity strings.

- [ ] Create `internal/tools/severity.go` with `Normalize(raw string) Severity`
- [ ] Add tool-specific normalization rules:
  - `gosec`: `"HIGH"/"MEDIUM"/"LOW"` → direct mapping
  - `bandit`: `"HIGH"/"MEDIUM"/"LOW"` → direct mapping
  - `semgrep`: `"ERROR"` → High, `"WARNING"` → Medium, `"INFO"` → Info
  - `eslint`: numeric `2` → High, `1` → Medium, `0` → Info
  - `trufflehog`: all findings → Critical (credentials are always critical)
  - `gocyclo`: complexity > 20 → High, > 10 → Medium, else Low
  - `checkov`: `"FAILED"` → Medium by default; specific check IDs mapped to higher severity
  - `trivy`: `"CRITICAL"/"HIGH"/"MEDIUM"/"LOW"/"UNKNOWN"` → direct mapping
  - `osv-scanner`: use ecosystem CVSS score bands: ≥9.0 → Critical, ≥7.0 → High, ≥4.0 → Medium, else Low
- [ ] Write unit tests for every normalization branch

### 10.5 Scan Cancellation

- [ ] Add `DELETE /api/v1/scan/:task_id` endpoint to cancel an in-progress scan
- [ ] Store a `context.CancelFunc` per task in a registry (`sync.Map`) keyed by task ID
- [ ] Cancel endpoint calls the stored `CancelFunc`, which propagates through all tool goroutines via `context.WithCancel`
- [ ] On cancellation: kill running subprocess (if any), clean up temp directories, store `"status": "cancelled"` in Redis
- [ ] CLI: pressing `q` in the scan dashboard calls the cancel endpoint before exiting

---

## Sprint 11 — Smart Scanning & Zero-Config UX

The goal: `armur run` in any project directory just works with no flags or prior setup required.

### 11.1 Auto-Detect Everything from Context

- [ ] On `armur run` with no args, walk up from `cwd` to find the nearest `.git` directory and use that as the scan root
- [ ] Auto-detect language from file extension frequency (`.go` files dominant → Go, etc.)
- [ ] If a single language is detected with high confidence, skip the language wizard step and show "Language: Go (auto-detected)" in the confirmation
- [ ] Handle multi-language repos: if two or more languages are detected, offer "Scan all" or let user pick one from a checkbox list
- [ ] Auto-detect `.armur.yml` in the repo root and pre-fill all wizard fields from it

### 11.2 `.armur.yml` Project Config File

Full support for a repo-level config that controls scan behavior without any CLI flags.

- [ ] Define and document the `.armur.yml` schema:
  ```yaml
  scan:
    depth: quick              # quick | deep
    language: go              # override auto-detection; omit for auto
    severity-threshold: medium  # minimum severity to include in output
    fail-on-findings: true    # exit with code 1 if any findings at threshold or above

  exclude:
    - vendor/
    - "**/*_test.go"
    - testdata/
    - "*.pb.go"

  tools:
    disabled:
      - gocyclo               # skip this tool
    timeout: 120              # per-tool timeout in seconds (overrides env var)

  output:
    format: text              # text | json | sarif
    save-to: ./reports/       # directory to auto-save reports after each scan

  plugins:
    - name: my-custom-linter
      command: "my-linter --json {target}"
      output-format: json
      language: go
  ```
- [ ] Server reads `.armur.yml` from the cloned/local repo root when executing tasks
- [ ] CLI reads `.armur.yml` from cwd to pre-fill wizard defaults
- [ ] Config file values are overridden by explicit CLI flags (flag > config > default)

### 11.3 `armur init` Command

- [ ] `armur init` runs a short guided huh form and writes `.armur.yml` to the current directory
- [ ] Wizard fields: preferred depth, language override (or auto), severity threshold, paths to exclude
- [ ] Output file includes inline YAML comments explaining every field
- [ ] If `.armur.yml` already exists: prompt "Overwrite existing config? (y/N)"

### 11.4 Diff / Incremental Scanning

- [ ] Add `--diff <base-ref>` flag to both `armur run` and `armur scan`
- [ ] Wizard Step 2.5 (shown only in "Quick" mode): optional "Only scan files changed since [git ref]" input
- [ ] Server: after cloning, run `git diff --name-only <base-ref>` to get the changed file list
- [ ] Pass changed file list into each tool wrapper; wrappers that support file-level targeting use it
- [ ] Tools that cannot target individual files (trufflehog, checkov) scan the full repo regardless
- [ ] Add diff metadata to scan result: `"diff_mode": true, "base_ref": "HEAD~1", "files_scanned": 12`
- [ ] `--staged-only` flag: pass only git-staged files (for pre-commit use case)

---

## Sprint 12 — `armur doctor` & CLI Completeness

### 12.1 `armur doctor` Command

A self-diagnosis command that checks all prerequisites and reports what is working and what is missing.

- [ ] Implement `armur doctor` command
- [ ] Checks performed:
  - [ ] API server reachable at configured URL (GET `/health`, show version)
  - [ ] Redis reachable (server reports Redis status in `/health` response)
  - [ ] Docker running (if Docker-based deployment is configured)
  - [ ] For each of the 18 bundled tools: binary exists in PATH + print installed version
  - [ ] API key configured and accepted (authenticated request to `/api/v1/status/ping`)
  - [ ] `.armur.yml` present in cwd (informational only)
- [ ] Output format (lipgloss-styled):
  ```
  armur doctor
  ──────────────────────────────────────────────
  ✓  API server    http://localhost:4500  (v1.2.0)
  ✓  Redis         redis://localhost:6379  (pong)
  ✓  API key       configured
  ──────────────────────────────────────────────
  ✓  semgrep       1.45.0
  ✓  gosec         2.18.2
  ✗  gocyclo       NOT FOUND
                   → go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
  ✓  bandit        1.7.5
  ⚠  pylint        3.0.1  (latest: 3.1.0)
  ──────────────────────────────────────────────
  1 tool missing. Fix the issues above to enable full scanning.
  ```
- [ ] Color-code: green ✓ / red ✗ / yellow ⚠
- [ ] Exit code 0 if server is reachable and all tools found; exit code 1 if anything critical is missing

### 12.2 SQLite-Backed Scan History

Replace the current JSON file history with a SQLite database for reliable querying and pagination.

- [ ] Add `modernc.org/sqlite` dependency (pure Go, no CGo required)
- [ ] Initialize `~/.armur/history.db` on first run with schema:
  ```sql
  CREATE TABLE IF NOT EXISTS scans (
      id           TEXT PRIMARY KEY,
      target       TEXT NOT NULL,
      language     TEXT,
      mode         TEXT,
      started_at   DATETIME,
      finished_at  DATETIME,
      status       TEXT,
      critical     INTEGER DEFAULT 0,
      high         INTEGER DEFAULT 0,
      medium       INTEGER DEFAULT 0,
      low          INTEGER DEFAULT 0,
      info         INTEGER DEFAULT 0,
      report_path  TEXT
  );
  ```
- [ ] `armur history` — list last 20 scans in a lipgloss-styled table (newest first)
- [ ] `armur history --all` — list all scans with pagination (`--page`, `--limit` flags)
- [ ] `armur history show <id>` — re-display full results from the saved JSON report file
- [ ] `armur history clear` — wipe all rows (ask "Clear all scan history? (y/N)" first)
- [ ] `armur compare <id1> <id2>` — diff two scans; show:
  - New findings (in id2 but not id1) highlighted in red
  - Fixed findings (in id1 but not id2) highlighted in green
  - Unchanged findings (in both) in grey
- [ ] Auto-save full scan results JSON to `~/.armur/reports/<task-id>.json` after every completed scan
- [ ] Insert a history row after every scan (success or failure)

### 12.3 Shell Completions

- [ ] Add `armur completion bash` — print Bash completion script
- [ ] Add `armur completion zsh` — print Zsh completion script
- [ ] Add `armur completion fish` — print Fish completion script
- [ ] Add `armur completion powershell` — print PowerShell completion script
- [ ] `armur history show <TAB>` — complete from scan IDs stored in local history DB
- [ ] Document how to install completions for each shell in README

### 12.4 `--watch` Mode

- [ ] Add `--watch` flag to `armur run` / `armur scan`
- [ ] On file change in the scanned directory (using `fsnotify`), re-run the last scan config automatically
- [ ] In watch mode: use compact output (single-line per re-scan, not full-screen TUI)
  - e.g. `[14:32:01] File changed: main.go — re-scanning...`
  - e.g. `[14:32:34] Done. 2 new findings, 0 fixed. (high: 1, medium: 1)`
- [ ] Debounce: ignore file changes within 3 seconds of a scan start to avoid re-scan storms
- [ ] Exit watch mode cleanly on Ctrl+C

### 12.5 `armur version` Command

- [ ] Add `armur version` command
- [ ] Embed at build time via `ldflags`: version tag, git commit hash, build date
- [ ] Output:
  ```
  armur v1.2.0 (commit abc1234, built 2026-03-05)
  ```
- [ ] `armur version --check` — fetch latest release from GitHub Releases API and compare; print upgrade hint if behind

---

## Sprint 13 — Result Display & Report Generation

### 13.1 Rich Terminal Output (Redesigned Display Layer)

The current display is scattered across `scan.go` and `utils.go` with fragile manual column widths.
Centralize and redesign.

- [ ] Create `cli/internal/display/` package with clean public API:
  - `RenderFindingsTable(findings []Finding, opts RenderOpts) string`
  - `RenderSummaryCard(meta ScanMeta) string`
  - `RenderToolErrors(errs []ScanError) string`
- [ ] `RenderFindingsTable`:
  - [ ] Auto-detect terminal width via `golang.org/x/term` and adjust column widths dynamically
  - [ ] Group findings by category; print a bold lipgloss-styled category header before each group
  - [ ] Severity column: render as a colored lipgloss badge `[HIGH]` not raw text
  - [ ] Truncate long file paths from the left (`...internal/pkg/utils/foo.go`) not from the right
  - [ ] Alternate row background shading for readability in long lists
  - [ ] Show finding count per category in the group header: `Security Issues (14)`
- [ ] `RenderSummaryCard`: lipgloss-bordered card with severity counts (from Sprint 8.4)
- [ ] `RenderToolErrors`: yellow warning block listing tool failures at the end of output

### 13.2 HTML Report Generation

- [ ] `armur report html --task <id>` — generate a standalone, self-contained HTML file
- [ ] Report sections:
  - [ ] Header: scan target, date, duration, tool versions used
  - [ ] Executive summary: severity counts + inline SVG donut chart (no JS)
  - [ ] CWE category breakdown table with finding counts
  - [ ] Per-file findings: grouped by file, each finding as a `<details>` collapsible row
  - [ ] Tool errors section: list of skipped/failed tools
  - [ ] Methodology section: one-line description of each tool run
- [ ] All CSS inlined in `<style>` block; no external CDN references; no JavaScript required
- [ ] Write to `~/.armur/reports/<task-id>.html`; print path after generation

### 13.3 CSV & Markdown Report Generation

- [ ] `armur report csv --task <id>` — CSV with columns: ID, Tool, File, Line, Severity, CWE, OWASP, Message
- [ ] `armur report markdown --task <id>` — GFM table of findings (ready to paste into a GitHub comment)
- [ ] Both accept `--output <path>` to override the default save location

### 13.4 CI-Friendly Exit Codes & Flags

- [ ] `--fail-on-severity <level>` flag for `armur run` and `armur scan`:
  - If any finding at or above the given severity level is found: exit code 1
  - Valid levels: `critical`, `high`, `medium`, `low` (default: disabled)
- [ ] `--min-severity <level>` flag: suppress display of findings below the given level
- [ ] `--quiet` / `-q` flag: suppress all output except the summary card and exit code
- [ ] Add a GitHub Actions workflow snippet to README showing a CI step that fails on HIGH findings

---

## Sprint 14 — API & Protocol Improvements

### 14.1 Typed API Response Model

Replace all `map[string]interface{}` response bodies with concrete Go structs so the API is
self-documenting, testable, and generates accurate OpenAPI schemas.

- [ ] Define typed structs in `internal/api/types.go`:
  - `ScanSubmitResponse { TaskID string; QueuedAt time.Time }`
  - `ScanStatusResponse { TaskID, Status string; StartedAt, FinishedAt *time.Time; Findings []Finding; Errors []ScanError; Meta ScanMeta }`
  - `ScanMeta { Language, Mode string; ToolsRun []string; Duration time.Duration; DedupStats DedupStats }`
- [ ] Update all handler functions to use these types (eliminates all `map[string]interface{}` in handlers)
- [ ] Add response validation in handler tests
- [ ] Regenerate OpenAPI spec from struct tags

### 14.2 Batch Scanning API

- [ ] `POST /api/v1/scan/batch` — accepts `[{ "repo_url": "...", "language": "go", "mode": "quick" }, ...]`
- [ ] Enqueues each as an independent Asynq task; returns `{ "batch_id": "...", "task_ids": ["...", "..."] }`
- [ ] `GET /api/v1/scan/batch/:batch_id` — returns aggregated status: how many done/pending/failed, merged finding totals
- [ ] CLI: `armur run --batch repos.txt` — reads newline-delimited repo URLs, submits as a batch, shows per-repo progress in a list view in the TUI

### 14.3 Webhook Notifications

- [ ] Add `webhook_url` + `webhook_secret` optional fields to the scan request body
- [ ] On task completion: POST the full `ScanStatusResponse` JSON to `webhook_url`
- [ ] Sign the payload: `X-Armur-Signature: sha256=<hmac-sha256(webhook_secret, body)>`
- [ ] Retry logic: 3 attempts, exponential backoff (1s → 4s → 16s), then give up and log
- [ ] Log each delivery attempt outcome (success/failure/timeout) in the structured logger

### 14.4 Request Correlation IDs

- [ ] Add `X-Request-ID` Gin middleware: if header is absent, generate a UUID v4; if present, use caller's value
- [ ] Include `request_id` in every log entry within that request's lifecycle
- [ ] Return `X-Request-ID` in every response header
- [ ] Store `request_id` in Asynq task metadata so it flows through to worker log entries

---

## Sprint 15 — Embedded Server & Zero-Infrastructure Mode

Currently using `armur` requires Docker, Redis, and a separately running server. For local developer
use, the CLI should be able to start everything it needs without any external services.

### 15.1 `armur serve` Command

- [ ] Add `armur serve` as a top-level command that starts the Go HTTP server in the foreground
- [ ] Accept `--port` flag (default: 4500) and `--redis-url` flag
- [ ] On start: print `Armur server listening at http://localhost:4500 (press Ctrl+C to stop)`
- [ ] Graceful shutdown on SIGINT/SIGTERM: drain in-flight Asynq tasks (with timeout), close Redis, exit

### 15.2 Embedded Redis for Local Use

- [ ] Evaluate and integrate `github.com/alicebob/miniredis` (in-process Redis-compatible server) for local mode
- [ ] When `armur run` detects no external Redis and the user confirms local mode: start miniredis in-process
- [ ] Local mode uses miniredis; production/Docker mode uses real Redis — controlled by `ARMUR_LOCAL=true` env var or `--local` flag

### 15.3 Auto-Server in `armur run`

- [ ] Before submitting a scan task, check if the configured API URL responds to `/health`
- [ ] If unreachable and `--no-server` is not set: prompt "No server found. Start a local server? (Y/n)"
- [ ] If confirmed: launch `armur serve` as a managed subprocess (store PID), wait for `/health` to respond (timeout 10s), then proceed with the scan
- [ ] On scan completion: print "Local server still running (PID 12345). Stop it with: armur serve stop"
- [ ] `armur serve stop` — send SIGTERM to the stored PID, wait for clean exit

### 15.4 In-Process Scan Mode (No Server at All)

- [ ] Add `--in-process` flag to `armur run` — runs the scan pipeline directly in the CLI process, no HTTP round-trip
- [ ] The CLI imports the server's `internal/tasks` package and calls `RunSimpleScan` / `RunAdvancedScans` directly
- [ ] Progress events emitted via the same `ProgressReporter` interface; TUI receives them through a local channel instead of SSE
- [ ] This enables `armur run --in-process` to work with zero external dependencies (no Docker, no Redis, no server)
- [ ] Requires the scan tools themselves to be installed on the host machine (show `armur doctor` output if any are missing)

---

## Backlog / Future Ideas

- [ ] VS Code extension — show findings inline as you code with CodeLens
- [ ] JetBrains plugin — IntelliJ/GoLand/PyCharm integration with inline annotations
- [ ] Web dashboard UI — visualize scan history, trends, team findings with charts
- [ ] Multi-repo scanning — scan all repos in a GitHub org with `armur run --batch`
- [ ] GitHub App — auto-scan PRs and post review comments with findings inline
- [ ] Findings suppression — `// armur:ignore CWE-89` inline comments in source code
- [ ] SBOM generation — produce CycloneDX or SPDX SBOM as part of advanced scan
- [ ] Policy-as-code — define custom security policies in `.armur.yml` with custom fail conditions
- [ ] Team/org features — shared scan history, role-based access, org-level dashboards
- [ ] LLM-powered fix suggestions — `armur fix <finding-id>` uses Claude API to suggest a code patch
- [ ] `armur explain <finding-id>` — plain-English explanation of a finding with exploit scenario and fix
- [ ] Finding trend charts — `armur trends` shows finding counts over time per category (sparklines in terminal using `github.com/guptarohit/asciigraph`)
- [ ] `armur audit` mode — scheduled recurring scans via embedded cron, alerting on new findings via webhook
- [ ] Secrets rotation helper — when trufflehog finds a leaked secret, `armur secrets rotate` guides revocation

---

*Last updated: March 2026*
*Sprints 1–7: original roadmap. Sprints 8–15: CLI/TUI overhaul and core engine improvements added March 2026.*

---

## Sprint 16 — Language Expansion: Tier 1 (Java · Kotlin · C# · Rust)

These four languages represent the highest-demand enterprise environments. Each gets SAST, SCA,
and quality analysis coverage using the best-in-class open source tools for that ecosystem.

### 16.1 Java & Kotlin

- [ ] **SpotBugs** integration (static bytecode analysis, 400+ bug patterns)
  - Run: `spotbugs -textui -xml:withMessages -output results.xml <classes-dir>`
  - Parse XML output; map to `Finding.Category` by bug pattern category (SECURITY, CORRECTNESS, etc.)
  - Require a pre-compiled `.class` directory or run Maven/Gradle compile step first
- [ ] **PMD** integration (code quality, 300+ rules including security)
  - Run: `pmd check -d <src> -R rulesets/java/quickstart.xml -f json`
  - Parse `violations` array; map `rule` to `RuleID`, `priority` to `Severity`
- [ ] **OWASP Dependency-Check** (SCA for Maven/Gradle/Ivy)
  - Run: `dependency-check.sh --scan <dir> --format JSON --out <outdir>`
  - Parse `vulnerabilities` in each `dependency`; map CVE IDs and CVSS scores to `Finding`
- [ ] **Error Prone** integration (Google's compile-time bug checker for Java)
  - Invoke via Gradle/Maven plugin; parse annotation-processor diagnostic output
- [ ] **semgrep** Java rules — already runs on auto config; add explicit `--config=p/java` and `--config=p/kotlin`
- [ ] Language detection: add `.java`, `.kt`, `.kts`, `pom.xml`, `build.gradle`, `build.gradle.kts` to language detector
- [ ] Add `testdata/java/` and `testdata/kotlin/` with known-vulnerable sample files
- [ ] Document Java/Kotlin support in README with setup instructions (JDK version requirement)

### 16.2 C# and .NET

- [ ] **Security Code Scan** integration (Roslyn-based SAST for C#/VB.NET)
  - Run as a dotnet tool: `dotnet-scs --project <csproj> --export-sarif-file results.sarif`
  - Parse SARIF output using the shared SARIF parser (from Sprint 3.1)
- [ ] **Puma Scan** Community Edition integration (OWASP-mapped C# security scanner)
  - Run: `puma-scan -solution <sln> -j results.json`
- [ ] **dotnet-retire** integration (detect retired/vulnerable NuGet packages)
  - Run: `retire --js --path <dir> --outputformat json`
  - Map CVE IDs to SCA findings
- [ ] **Semgrep** C# rules: add `--config=p/csharp` to the semgrep invocation for .NET repos
- [ ] **Roslynator CLI** integration (200+ Roslyn analyzers for code quality)
  - Run: `roslynator analyze <sln> --output results.xml`
- [ ] Language detection: add `.cs`, `.vb`, `.csproj`, `.sln`, `*.nuspec`, `packages.config`, `packages.lock.json`
- [ ] Add `testdata/csharp/` with known-vulnerable C# sample files
- [ ] NuGet SCA: parse `packages.config` and `<PackageReference>` in `.csproj` files; query OSV/NVD for CVEs

### 16.3 Rust

- [ ] **cargo-audit** integration (official Rust advisory database SCA)
  - Run: `cargo audit --json`; parse `vulnerabilities.list` array
  - Map advisory IDs (RUSTSEC-*), CVSS scores, and patched versions to `Finding`
- [ ] **cargo-deny** integration (license compliance + SCA + bans for Rust)
  - Run: `cargo deny check --format json`
  - Parse `deny`, `advisories`, `licenses` sections
  - Emit license findings to a new `license_violation` category
- [ ] **cargo-geiger** integration (unsafe code detection)
  - Run: `cargo geiger --output-format Json`
  - Map `unsafe` counts per crate to findings with severity proportional to count
- [ ] **Clippy** integration (official Rust linter with security-relevant lints)
  - Run: `cargo clippy --message-format json -- -W clippy::all`
  - Parse JSON diagnostic stream; map `lint` names containing "security"/"correctness" to relevant categories
- [ ] **Semgrep** Rust rules: add `--config=p/rust` to semgrep invocation for Rust repos
- [ ] Language detection: add `.rs`, `Cargo.toml`, `Cargo.lock`
- [ ] Add `testdata/rust/` with known-vulnerable Rust sample files (unsafe blocks, outdated deps)

---

## Sprint 17 — Language Expansion: Tier 2 (PHP · Ruby · Swift · Shell)

### 17.1 PHP

- [ ] **PHPCS + Security Sniffs** integration
  - Run: `phpcs --standard=Security --report=json <dir>`
  - Parse `files` map; map each `message` to a finding
- [ ] **Psalm** integration (static analysis for PHP, security-focused mode)
  - Run: `psalm --output-format=json --taint-analysis <dir>`
  - Parse `issues` array; taint-analysis results map to `security_issues` category
- [ ] **PHP Security Checker** (symfony/security-checker or local-php-security-checker)
  - Run: `local-php-security-checker --format=json`
  - Parses `composer.lock`; maps CVE advisories to SCA findings
- [ ] **Exakat** integration (PHP static analyzer with security rules)
  - Run: `exakat project -p myproject -r <dir> -format json`
- [ ] Language detection: add `.php`, `composer.json`, `composer.lock`
- [ ] Add `testdata/php/` with SQL injection, eval injection, file include vulnerability samples

### 17.2 Ruby

- [ ] **Brakeman** integration (Rails security scanner — best-in-class for Ruby web apps)
  - Run: `brakeman -o /dev/stdout -f json <dir>`
  - Parse `warnings` array; map `warning_type` to `RuleID`, `confidence` to `Severity`
  - Map to OWASP categories using Brakeman's built-in OWASP tags
- [ ] **bundler-audit** integration (SCA for RubyGems)
  - Run: `bundle-audit check --json`
  - Parse advisory list; map to SCA findings with CVE IDs and patched versions
- [ ] **RuboCop** with security rules (`rubocop-rails-security`, `rubocop-ast` security cops)
  - Run: `rubocop --format json --only Security <dir>`
  - Parse `offenses` in each `file`
- [ ] Language detection: add `.rb`, `Gemfile`, `Gemfile.lock`, `Rakefile`, `.gemspec`
- [ ] Add `testdata/ruby/` with known-vulnerable Rails patterns (mass assignment, CSRF, open redirect)

### 17.3 Swift

- [ ] **SwiftLint** with security rules integration
  - Run: `swiftlint lint --reporter json <dir>`
  - Parse violations; filter for security-relevant rule identifiers
- [ ] **Periphery** integration (dead code detection for Swift/Xcode projects)
  - Run: `periphery scan --format json`
  - Map unused declarations to `dead_code` category
- [ ] **semgrep** Swift rules: add `--config=p/swift` for Swift repos
- [ ] Language detection: add `.swift`, `Package.swift`, `Package.resolved`, `.xcodeproj/`
- [ ] Add `testdata/swift/` with insecure data storage, missing encryption samples

### 17.4 Shell / Bash / PowerShell

- [ ] **ShellCheck** integration (shell script static analysis — covers bash, sh, dash, ksh)
  - Run: `shellcheck --format=json <file>`
  - Parse `comments` array; map `level` (error/warning/info/style) to `Severity`
  - Detect shell files by shebang (`#!/bin/bash`, `#!/bin/sh`) and `.sh`, `.bash` extensions
- [ ] **bashate** integration (style and error checking for bash scripts)
  - Run: `bashate --max-line-length 120 <file>` — parse stdout for violations
- [ ] **PSScriptAnalyzer** integration (PowerShell security linter)
  - Run: `pwsh -Command "Invoke-ScriptAnalyzer -Path <dir> -Recurse -OutputFormat Json"`
  - Parse JSON; map `RuleName` patterns containing "Security" or "Injection" to findings
- [ ] Detect `.ps1`, `.psm1`, `.psd1` as PowerShell; `.sh`, `.bash`, `.zsh` as Shell
- [ ] Add `testdata/shell/` with command injection, eval misuse, insecure temp file patterns

---

## Sprint 18 — Language Expansion: Tier 3 (Scala · Elixir · Dart · Go Extras)

### 18.1 Scala

- [ ] **Scalafix** integration (refactoring and linting framework for Scala)
  - Run: `scalafix --rules=DisableSyntax,LeakingImplicitClassVal <dir>`
  - Parse diagnostic output
- [ ] **WartRemover** integration (flexible Scala code linting)
  - Invoke as sbt plugin; parse warning output for security-relevant warts
- [ ] **semgrep** Scala rules: add `--config=p/scala`
- [ ] Language detection: add `.scala`, `build.sbt`, `project/build.properties`

### 18.2 Elixir

- [ ] **Sobelow** integration (security-focused analysis for Phoenix Framework apps)
  - Run: `sobelow --format json --skip <dir>`
  - Parse `findings` array; map `type` to `RuleID`, `confidence` to `Severity`
- [ ] **Credo** integration (code consistency and quality for Elixir)
  - Run: `mix credo --format json`
  - Parse `issues`; filter for security-relevant checks (e.g., `Credo.Check.Warning.UnsafeExec`)
- [ ] Language detection: add `.ex`, `.exs`, `mix.exs`, `mix.lock`
- [ ] Add `testdata/elixir/` with SQL injection and command injection Phoenix samples

### 18.3 Dart / Flutter

- [ ] **dart analyze** integration (official Dart static analysis)
  - Run: `dart analyze --format=machine <dir>`
  - Parse machine-readable output; map `ERROR`/`WARNING`/`INFO` to severity
- [ ] **dependency_validator** integration (unused/missing Dart dependencies)
  - Run: `dart run dependency_validator`
- [ ] **pubspec_lock_checker** — parse `pubspec.lock`; query OSV for vulnerable pub packages
- [ ] Language detection: add `.dart`, `pubspec.yaml`, `pubspec.lock`

### 18.4 Additional Go Analysis Tools

- [ ] **govulncheck** integration (official Go vulnerability database, Go team at Google)
  - Run: `govulncheck -json ./...`
  - Parse `finding` entries with `osv_id` and `trace`; map to SCA findings
  - Govulncheck does call graph analysis — only flags vulnerabilities that are actually *reachable* in the code (massive false positive reduction vs. osv-scanner)
- [ ] **errcheck** integration (checks for unchecked errors in Go)
  - Run: `errcheck -json ./...`
  - Map to `antipatterns_bugs` category with HIGH severity (unchecked errors = common security bug source)
- [ ] **ineffassign** integration (detect ineffectual assignments)
  - Run: `ineffassign ./...`
  - Map to `dead_code` category
- [ ] **shadow** (`go vet -shadow`) integration — detect shadowed variables

---

## Sprint 19 — Web3 / Blockchain: Comprehensive Smart Contract Security

Web3 codebases have unique and critical vulnerabilities. Armur should be the go-to scanner for
smart contract security, covering all major chains.

### 19.1 Solidity (EVM Chains: Ethereum, Polygon, BNB, Avalanche, etc.)

- [ ] **Slither** integration (best open-source Solidity static analyzer, 80+ detectors)
  - Run: `slither <dir> --json results.json`
  - Parse `detector_results`; map `impact` (High/Medium/Low/Informational) and `confidence` to severity
  - Map Slither detector IDs to CWE numbers where available
  - Enable all built-in detectors; add `--exclude-informational` for quiet mode
- [ ] **Mythril** integration (symbolic execution and formal verification for EVM)
  - Run: `myth analyze --solv <version> --execution-timeout 120 --output json <file>`
  - Parse `issues` array; map `severity` and `swc-id` (SWC = Smart Contract Weakness Classification)
  - SWC IDs map to CWE equivalents — add SWC → CWE mapping table
- [ ] **Semgrep** Solidity rules: add `--config=p/solidity`
- [ ] **solhint** integration (Solidity linter with security plugins)
  - Run: `solhint --formatter json 'contracts/**/*.sol'`
  - Parse violations; map `ruleId` to `RuleID`
- [ ] Add `SWC` (Smart Contract Weakness Classification) ID support as a new `Finding.SWC` field
- [ ] Language detection: add `.sol`, `hardhat.config.js`, `truffle-config.js`, `foundry.toml`
- [ ] Add `testdata/solidity/` with reentrancy, integer overflow, access control, tx.origin samples
- [ ] Document gas optimization findings separately from security findings (new category: `gas_optimization`)

### 19.2 Vyper

- [ ] **Slither** Vyper support: `slither <file>.vy --json results.json` (Slither supports Vyper natively)
- [ ] **vyper compiler** security warnings: parse stderr of `vyper -f abi <file>` for security diagnostics
- [ ] Language detection: add `.vy`, `vyper.json`

### 19.3 Move (Aptos / Sui)

- [ ] **move-analyzer** integration (official Move language server with diagnostics)
  - Run: `move-analyzer` in LSP mode; extract diagnostics for static findings
- [ ] **Semgrep** Move rules (community rules for Move smart contracts)
- [ ] Language detection: add `.move`, `Move.toml`, `Move.lock`
- [ ] Add `testdata/move/` with overflow, capability misuse, and resource leak examples

### 19.4 Cairo (StarkNet)

- [ ] **Amarna** integration (static analyzer for Cairo 1.x smart contracts)
  - Run: `amarna <file>.cairo -j results.json`
  - Parse `results`; map `category` to finding category
- [ ] Language detection: add `.cairo`, `Scarb.toml`

### 19.5 Rust WASM (WebAssembly Smart Contracts)

- [ ] Treat `.wasm` target Rust (ink!, CosmWasm) as smart contract context
- [ ] Run cargo-audit + cargo-geiger in addition to standard Rust tools
- [ ] Add `testdata/wasm-contracts/` with ink! (Polkadot) and CosmWasm (Cosmos) examples
- [ ] Flag `unsafe` blocks with CRITICAL severity in smart contract Rust (unlike regular Rust)

---

## Sprint 20 — IaC Deep: Cloud Providers (Terraform · CloudFormation · CDK · Pulumi · Bicep)

### 20.1 Terraform

- [ ] **tfsec** integration (purpose-built Terraform security scanner)
  - Run: `tfsec <dir> --format json`
  - Parse `results`; map `severity`, `rule_id`, provider (aws/azure/gcp/kubernetes) to findings
  - Map tfsec rule IDs to CWE/NIST control IDs where available
- [ ] **Checkov** Terraform rules (already have Checkov; add `--framework terraform` explicitly)
  - Ensure Checkov is invoked with `--framework terraform` for `.tf` directories
- [ ] **terrascan** integration (multi-cloud IaC scanner)
  - Run: `terrascan scan -i terraform -d <dir> -o json`
  - Parse `results.violations`; use as cross-validation with tfsec
- [ ] **infracost** integration (cloud cost policy violations — catch misconfigured expensive resources)
  - Run: `infracost breakdown --path <dir> --format json`
  - Map resources exceeding policy thresholds to a new `cost_risk` finding category
- [ ] Terraform language detection: `.tf`, `.tfvars`, `terraform.lock.hcl`, `*.tf.json`
- [ ] Add `testdata/terraform/` with S3 bucket public access, unencrypted RDS, wide security groups

### 20.2 AWS CloudFormation

- [ ] **cfn-lint** integration (official AWS CloudFormation linter)
  - Run: `cfn-lint <template> --format json`
  - Parse `matches`; map `rule.id`, `rule.severity` to findings
- [ ] **cfn-nag** integration (CloudFormation security linter with 80+ rules)
  - Run: `cfn_nag_scan --input-path <template> --output-format json`
  - Parse `failure_count` and `violations`; map `id` and `message` to findings
- [ ] **Checkov** CloudFormation: add `--framework cloudformation` for YAML/JSON templates
- [ ] CloudFormation detection: `*.template`, `*.template.yaml`, `*.template.json`, `cloudformation/` directories

### 20.3 AWS CDK

- [ ] **cdk-nag** integration (security and compliance checks for AWS CDK constructs)
  - Invoke via CDK App synthesis; parse `cdk.out/` for cdk-nag warning annotations
  - Run: `cdk synth 2>&1 | parse cdk-nag annotations`
- [ ] CDK detection: `cdk.json`, `cdk.out/`, TypeScript/Python CDK app patterns

### 20.4 Pulumi

- [ ] **Checkov** Pulumi: add `--framework pulumi` for Pulumi YAML programs
- [ ] **pulumi-policy** integration: run against Pulumi CrossGuard policy packs
- [ ] Pulumi detection: `Pulumi.yaml`, `Pulumi.<stack>.yaml`

### 20.5 Azure ARM Templates & Bicep

- [ ] **arm-ttk** integration (official Azure Resource Manager template test toolkit)
  - Run: `Test-AzTemplate -TemplatePath <dir>` via PowerShell; parse JSON output
- [ ] **PSRule.Rules.Azure** integration (comprehensive Azure security benchmark rules)
  - Run: `Invoke-PSRule -InputPath <dir> -Module PSRule.Rules.Azure -OutputFormat Json`
  - Parse rule failures; map to finding with CIS Azure Benchmark control IDs
- [ ] **Checkov** ARM: add `--framework arm` for ARM template JSON files
- [ ] Azure detection: `azuredeploy.json`, `*.parameters.json`, `*.bicep`, `.bicepparam`

### 20.6 GCP Deployment Manager & Config Connector

- [ ] **Checkov** GCP support: add `--framework googledeploymentmanager`
- [ ] Detect GCP Deployment Manager templates: `*.jinja`, `*.jinja.schema`, `config.yaml`
- [ ] Detect Config Connector YAML files (kind: SQLInstance, StorageBucket, etc.)

---

## Sprint 21 — IaC Deep: Kubernetes, Containers & Configuration Management

### 21.1 Kubernetes Manifests

- [ ] **kube-linter** integration (StackRox/RedHat — focuses on security and correctness)
  - Run: `kube-linter lint <dir> --format json`
  - Parse `Reports`; map `Check`, `Diagnostic.Message` to findings with Kubernetes context
- [ ] **kube-score** integration (structured scoring of Kubernetes workloads)
  - Run: `kube-score score <manifests> -o json`
  - Parse `object_meta` + `checks`; map failing checks to findings
- [ ] **kubesec** integration (risk score for Kubernetes resources)
  - Run: `kubesec scan <file>` — parse `scoring.advise` and `scoring.critical` arrays
- [ ] **Polaris** integration (Fairwinds governance for Kubernetes — 40+ checks)
  - Run: `polaris audit --audit-path <dir> --format json`
  - Parse `Results`; map `category` to finding category
- [ ] **Checkov** Kubernetes: add `--framework kubernetes` for YAML with Kubernetes markers
- [ ] Kubernetes detection: YAML files containing `apiVersion:` + `kind:` patterns; `k8s/`, `manifests/`, `deploy/` directories

### 21.2 Helm Charts

- [ ] **helm lint** integration (official Helm linter)
  - Run: `helm lint <chart-dir> --strict`; parse stderr warnings to findings
- [ ] **Checkov** Helm: add `--framework helm` for Helm chart directories (`Chart.yaml` present)
- [ ] **nova** integration (find outdated Helm chart versions and deprecated APIs)
  - Run: `nova find --format json`; map outdated charts to `sca` findings
- [ ] Helm detection: `Chart.yaml`, `values.yaml`, `templates/*.yaml` directory structure

### 21.3 Docker Compose

- [ ] **Checkov** Docker Compose: add `--framework docker_compose` for `docker-compose.yml` files
- [ ] Custom checks: privileged containers, host network mode, writable root filesystem, missing health checks
- [ ] Detection: `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`

### 21.4 Ansible

- [ ] **ansible-lint** integration (best-practice enforcement and security rules for Ansible)
  - Run: `ansible-lint <playbook> --format pep8 -R` — parse output for violations
  - Add `--profile=security` to focus on security-relevant rules
- [ ] **ansible-later** integration (additional Ansible review standards)
- [ ] Detection: `.yml` files containing `hosts:`, `tasks:`, `roles:` patterns; `playbooks/` directory

### 21.5 Puppet & Chef

- [ ] **puppet-lint** with security rules:
  - Run: `puppet-lint --log-format "%{path}:%{line}:%{kind}:%{message}" <dir>`
- [ ] **cookstyle** (Chef Infra cookbook linter, RuboCop-based):
  - Run: `cookstyle --format json <cookbook-dir>`
- [ ] Detection: `.pp` files for Puppet; `metadata.rb`, `recipes/` for Chef

### 21.6 Hadolint (Dockerfile)

- [ ] **hadolint** integration (Dockerfile linter — best Dockerfile security tool available)
  - Run: `hadolint --format json <Dockerfile>`
  - Parse array of violations; map `code` (DL/SC rule IDs) and `level` to findings
  - DL codes are Dockerfile-specific; SC codes are ShellCheck from RUN commands
  - Map relevant rule IDs to CIS Docker Benchmark controls
- [ ] Multi-stage Dockerfile support: analyze each stage independently
- [ ] Detection: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- [ ] Add `testdata/docker/` with: running as root, COPY --chown missing, ADD from URL, secrets in ENV

---

## Sprint 22 — Container Image Security

Beyond scanning the *source code* of containers, Armur should also scan *built images* and running containers.

### 22.1 Docker Image Vulnerability Scanning

- [ ] **Trivy image** mode integration (already have `trivy fs` — add `trivy image`)
  - Run: `trivy image --format json <image:tag>`
  - Scan: OS packages, language packages, misconfigurations, secrets in layers
  - Parse `Results` from image scan; merge with filesystem scan results
- [ ] **Grype** integration (Anchore's vulnerability scanner — excellent accuracy, fast)
  - Run: `grype <image:tag> -o json`
  - Parse `matches`; map `vulnerability.id`, `vulnerability.severity`, `relatedVulnerabilities` to findings
  - Grype cross-references NVD + GitHub Advisory + OSV + RHSA + DSA databases
- [ ] Image scanning mode: `armur run --image <image:tag>` triggers image scan pipeline
- [ ] Parse `PURL` (Package URL) from Grype output for standardized package identification
- [ ] Map `FixedInVersion` to remediation hint: "Upgrade to <package>@<fixed-version>"

### 22.2 Image Layer Analysis

- [ ] Layer-by-layer secret detection: use `docker save <image> | tar -x` and scan each layer's filesystem tar for secrets
- [ ] Detect secrets that were `ADD`ed and then `rm`-ed (they persist in lower layers)
- [ ] Build history analysis: `docker history --no-trunc <image>` — flag ENV instructions with credential patterns
- [ ] Large layer detection: flag layers > 100MB (bloat indicator) as informational findings

### 22.3 Base Image Security Assessment

- [ ] EOL/EOS base image detection: maintain a list of EOL dates for common base images (ubuntu:18.04, debian:buster, centos:7, etc.)
- [ ] Known-CVE count for base image: query Trivy/Grype for the base image's vulnerability count before application packages
- [ ] Recommend alternatives: if `ubuntu:22.04` has N CVEs, suggest `ubuntu:22.04-minimal` or `debian:bookworm-slim`
- [ ] Distroless recommendation: flag full OS base images when a distroless equivalent exists (`gcr.io/distroless/static`)
- [ ] CIS Docker Benchmark checks: privileged ports, user namespace, AppArmor/seccomp profiles

### 22.4 SBOM Extraction from Images

- [ ] **Trivy SBOM** mode: `trivy image --format cyclonedx <image:tag>` — extract CycloneDX SBOM from image
- [ ] **Syft** integration (Anchore's SBOM generator — best-in-class for images)
  - Run: `syft <image:tag> -o cyclonedx-json`
  - Parse SBOM; cross-reference with Grype for vulnerability enrichment
- [ ] Store extracted SBOMs alongside scan results in `~/.armur/sboms/<task-id>.cdx.json`

---

## Sprint 23 — Secrets Detection: Comprehensive & Deep

The current trufflehog3 integration scans only the working tree. This sprint makes secrets detection
deep, validated, and actionable.

### 23.1 Git History Scanning

- [ ] **Gitleaks** integration (fast, accurate secrets scanner with excellent rule coverage)
  - Run: `gitleaks detect --source <dir> --report-format json --report-path results.json`
  - For git history mode: `gitleaks detect --source <dir> --log-opts="--all" --report-format json`
  - Parse `findings`; map `RuleID`, `Description`, `Secret`, `Commit`, `Author`, `Date`, `File`, `Line` to `Finding`
  - Gitleaks rules cover 150+ secret types including: AWS, GCP, Azure, GitHub, Stripe, Slack, Twilio, etc.
- [ ] **Trufflehog v3** upgrade: switch from `trufflehog3` to the newer `trufflehog` CLI (v3.x):
  - Run: `trufflehog filesystem --json --no-verification <dir>`
  - For git history: `trufflehog git file://<dir> --json --since-commit HEAD~100`
- [ ] Add `--scan-history` flag to `armur run` and API: when true, scan full git history (slow but thorough)
- [ ] When history scanning: deduplicate secrets found in both current tree and history; annotate with earliest commit date

### 23.2 Secret Validation

- [ ] For detected secrets, optionally validate if they are still active (opt-in via `.armur.yml: secrets.validate: true`):
  - **AWS Access Keys**: call `sts:GetCallerIdentity` — if 200: mark as ACTIVE (critical), if 403: mark as INVALID
  - **GitHub Personal Access Tokens**: call `GET /user` — if 200: mark as ACTIVE
  - **Stripe API Keys**: call `GET /v1/charges?limit=1` — if 200: mark as ACTIVE
  - **Slack Bot Tokens**: call `auth.test` — if `ok: true`: mark as ACTIVE
  - **Generic JWT**: decode and check expiry claim without signature verification
- [ ] Add `Finding.SecretStatus` field: `"active"` | `"expired"` | `"invalid"` | `"unvalidated"`
- [ ] Mark validated active secrets as `SeverityCritical`; unvalidated secrets as `SeverityHigh`

### 23.3 Git Blame Integration

- [ ] For each detected secret: run `git blame -L <line>,<line> <file>` to get commit hash, author, date
- [ ] Populate `Finding.BlameCommit`, `Finding.BlameAuthor`, `Finding.BlameDate` fields
- [ ] Display in CLI: "Introduced by: jane@example.com in commit abc1234 on 2025-01-15"
- [ ] Include git blame data in HTML reports for accountability tracking

### 23.4 Custom Secret Patterns & Allowlists

- [ ] `.armur.yml` secrets configuration:
  ```yaml
  secrets:
    validate: false           # set true to test if found secrets are still active
    scan-history: false       # set true to scan full git history
    custom-patterns:
      - name: "Internal API Key"
        regex: "INTERNAL_[A-Z0-9]{32}"
        severity: critical
    allowlist:
      - path: "testdata/**"   # ignore secrets in test fixtures
      - regex: "example_key_.*"  # ignore obviously fake keys
      - commit: "abc1234"     # ignore a specific commit (already rotated)
  ```
- [ ] Load and apply custom patterns during gitleaks/trufflehog execution (via gitleaks custom config)
- [ ] Allowlist entries suppress findings without removing them from the raw count (audit trail preserved)

### 23.5 Entropy-Based Detection

- [ ] Implement high-entropy string detection as a standalone pass (complement to rule-based detection):
  - Scan all string literals in source code
  - Compute Shannon entropy; flag strings with entropy > 4.5 and length > 20 as potential secrets
  - Apply a dictionary filter (skip strings that are mostly English words)
- [ ] Rate-limit entropy findings: max 50 per file to avoid alert fatigue
- [ ] Present entropy findings with lower confidence: `Finding.Confidence = "low"`

---

## Sprint 24 — Software Composition Analysis: All Ecosystems

Expand SCA coverage from the current (Go modules + generic OSV) to every major package ecosystem.
Goal: comprehensive dependency vulnerability detection regardless of language.

### 24.1 Package Ecosystem Coverage Matrix

For each ecosystem: detect the manifest/lockfile, parse direct + transitive dependencies, query OSV API for CVEs.

- [ ] **npm / Yarn / pnpm** (JavaScript/TypeScript):
  - Detect: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - Run: `npm audit --json` or `osv-scanner --lockfile=package-lock.json:npm`
  - Parse: vulnerability ID, package name, installed version, patched version, CVSS
- [ ] **pip / Poetry / Pipenv / PDM / uv** (Python):
  - Detect: `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pdm.lock`, `uv.lock`, `pyproject.toml`
  - Run: `osv-scanner --lockfile=requirements.txt:pip`; also `pip-audit --format json`
  - Add `pip-audit` integration (Google's official Python auditing tool)
- [ ] **Go modules** (already have osv-scanner + govulncheck — improve):
  - Detect: `go.mod`, `go.sum`
  - Run both govulncheck (reachability-aware) and osv-scanner (all deps including non-reachable)
  - Display reachability status in findings: "reachable: yes | no | unknown"
- [ ] **Cargo** (Rust):
  - Detect: `Cargo.toml`, `Cargo.lock`
  - Run: `cargo audit --json` (already planned in Sprint 16.3)
- [ ] **Maven / Gradle** (Java/Kotlin/Scala):
  - Detect: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`
  - Run: `mvn dependency:tree -DoutputType=dot` + osv-scanner; or OWASP Dependency-Check
- [ ] **RubyGems** (Ruby):
  - Detect: `Gemfile.lock`
  - Run: `bundle-audit check --json` (already in Sprint 17.2)
- [ ] **Composer** (PHP):
  - Detect: `composer.lock`
  - Run: `local-php-security-checker --format=json` (already in Sprint 17.1)
- [ ] **NuGet** (C#/.NET):
  - Detect: `packages.config`, `packages.lock.json`, `*.csproj` with `<PackageReference>`
  - Run: `dotnet list package --vulnerable --include-transitive --format json`
- [ ] **CocoaPods** (iOS/macOS):
  - Detect: `Podfile.lock`
  - Run: `osv-scanner --lockfile=Podfile.lock:cocoapods`
- [ ] **Swift Package Manager**:
  - Detect: `Package.resolved`
  - Run: `osv-scanner --lockfile=Package.resolved:swift`
- [ ] **pub** (Dart/Flutter):
  - Detect: `pubspec.lock`
  - Run: `dart pub audit` (official Dart advisory checking)
- [ ] **Hex** (Elixir):
  - Detect: `mix.lock`
  - Run: `mix hex.audit` — parse output for vulnerable packages
- [ ] **Conan** (C/C++):
  - Detect: `conanfile.txt`, `conanfile.py`, `conan.lock`
  - Query OSV API with package names and versions
- [ ] **sbt** (Scala):
  - Detect: `build.sbt`, `project/plugins.sbt`
  - Run: `sbt dependencyUpdates` + OSV API query

### 24.2 OSV API Integration (Unified Vulnerability Database)

- [ ] Implement a shared `internal/sca/osv.go` OSV API client:
  - `BatchQuery(pkgs []Package) ([]Vulnerability, error)` — uses OSV `/v1/querybatch` endpoint
  - Cache results in Redis for 1 hour to avoid redundant API calls
  - Rate-limit: max 100 packages per batch request
- [ ] Map OSV vulnerability severities using CVSS v3 base score: ≥9.0 → Critical, ≥7.0 → High, ≥4.0 → Medium, <4.0 → Low
- [ ] Enrich each SCA finding with: CVE IDs, GHSA IDs, PURL, affected version range, fixed version, CVSS score, summary

---

## Sprint 25 — SBOM Generation & License Compliance

### 25.1 SBOM Generation (CycloneDX + SPDX)

- [ ] **CycloneDX** SBOM generation for all supported ecosystems:
  - Use `cdxgen` (CycloneDX Generator — supports 20+ ecosystems):
    - Run: `cdxgen -t <type> -o sbom.json <dir>`
  - Output: `~/.armur/sboms/<task-id>.cdx.json`
  - Include all direct + transitive dependencies with PURLs
- [ ] **SPDX** SBOM generation:
  - Use `spdx-sbom-generator` or Trivy SPDX mode: `trivy fs --format spdx-json <dir>`
  - Output: `~/.armur/sboms/<task-id>.spdx.json`
- [ ] `armur sbom <target> --format cyclonedx|spdx` CLI command
- [ ] SBOM content includes: component name, version, PURL, license, supplier, checksum
- [ ] NTIA Minimum Elements compliance check: verify SBOM contains all required NTIA fields; report gaps
- [ ] **Dependency-Track** export: `armur sbom upload --dt-url <url> --project-id <id>` — push SBOM to a Dependency-Track instance

### 25.2 License Detection & Compliance

- [ ] **licensee** integration (GitHub's license detection tool — identifies SPDX license IDs)
  - Run: `licensee detect <dir> --json`; extract license expressions per file/package
- [ ] **FOSSA-style license policy** in `.armur.yml`:
  ```yaml
  licenses:
    allowed:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
    denied:
      - GPL-3.0-only       # copyleft — incompatible with proprietary products
      - AGPL-3.0-only      # network copyleft
      - SSPL-1.0           # server-side copyleft
    notice-required:
      - MPL-2.0            # weak copyleft — require attribution notice
  ```
- [ ] Flag each dependency with a denied license as a `license_violation` finding (severity: HIGH for copyleft)
- [ ] License compatibility matrix: detect GPL contamination — if any transitive dep is GPL, the entire dependency tree is tainted
- [ ] `armur licenses <target>` CLI command: print a table of all dependencies with their detected licenses
- [ ] Generate an attribution notice file (`NOTICES.txt`) for all permissive-license dependencies

---

## Sprint 26 — Supply Chain Security

### 26.1 Dependency Confusion Detection

Dependency confusion attacks substitute a private package with a malicious public one by registering
the private package name on the public registry with a higher version number.

- [ ] Detect private package name patterns in manifests:
  - Scope packages (`@company/pkg`) in npm that also exist on the public registry
  - Internal PyPI package names that appear on public PyPI with a newer version
  - Go module paths that use internal domains but resolve via public GOPROXY
- [ ] For each internal package: check if the same name exists on the public registry (npm API, PyPI API)
- [ ] If found with a higher version on public registry: flag as `CRITICAL` dependency confusion risk
- [ ] Recommend mitigation: use `--registry` flags, npm `.npmrc` scope-to-registry mappings, or Artifactory

### 26.2 Typosquatting Detection

- [ ] Maintain a list of top-1000 most-downloaded packages per ecosystem (npm, PyPI, RubyGems, crates.io)
- [ ] For each dependency in the scanned manifest: compute Levenshtein distance against the top-1000 list
- [ ] If distance == 1 and the package is not in the top-1000: flag as potential typosquat (severity: MEDIUM)
- [ ] False positive reduction: only flag packages with <1,000 total downloads or <1 year old on the registry

### 26.3 Dependency Version Pinning Analysis

- [ ] Analyze lockfiles and manifests for version constraint security:
  - Flag semver ranges (`^1.0.0`, `~1.0.0`, `>=1.0.0`) as `INFO` — prefer exact pins for reproducibility
  - Flag unpinned indirect dependencies (manifest has `^1.0.0` but no lockfile committed)
  - Flag missing lockfile: manifest has dependencies but no lockfile in the repo
- [ ] **Renovate / Dependabot config detection**: check if automated dependency update tooling is configured; if not, flag as `INFO`

### 26.4 Package Provenance & Signing

- [ ] **npm provenance** check: for npm packages, verify `provenance` attestation via npm CLI (`npm audit signatures`)
- [ ] **Sigstore/cosign** verification for Go modules: use `cosign verify-blob` for signed modules
- [ ] **PyPI Trusted Publishers** check: verify if critical PyPI packages use Trusted Publisher attestations
- [ ] Flag packages published from unverified sources as `INFO` findings

### 26.5 Abandoned & Unmaintained Package Detection

- [ ] For each dependency: query the package registry API for:
  - Last release date (flag if > 2 years with no release)
  - Number of maintainers (flag if sole maintainer and account shows no recent activity)
  - Repository archived on GitHub (flag as abandoned)
- [ ] Severity mapping: actively abandoned + has known CVEs → HIGH; just abandoned → LOW; sole maintainer → INFO

---

## Sprint 27 — Compliance Framework Mapping

Map every finding to every relevant compliance control so security teams can generate compliance evidence
directly from scan results.

### 27.1 OWASP Top 10 (2021)

- [ ] Build complete OWASP Top 10 2021 mapping table in `internal/compliance/owasp_top10.go`:
  - A01 Broken Access Control → findings from: semgrep auth rules, gosec G401+, checkov IAM rules
  - A02 Cryptographic Failures → findings from: gosec G401/G402/G501, semgrep crypto, bandit B323
  - A03 Injection → findings from: gosec G201, bandit B608, semgrep sql/injection, semgrep commandinjection
  - A04 Insecure Design → findings from: architecture-level checkov rules, missing security headers
  - A05 Security Misconfiguration → findings from: checkov, tfsec, hadolint, kube-linter
  - A06 Vulnerable Components → all SCA findings (trivy, osv-scanner, cargo-audit, etc.)
  - A07 Auth & Session Mgmt → findings from: gosec G101, semgrep session rules, jwt analysis
  - A08 Software & Data Integrity → supply chain findings (Sprint 26), SBOM gap findings
  - A09 Logging & Monitoring Failures → findings from: semgrep logging rules, missing audit log patterns
  - A10 SSRF → findings from: semgrep ssrf rules, bandit B310
- [ ] Add `Finding.OWASP2021` field (e.g., `"A03:2021"`)
- [ ] `armur report owasp --task <id>` — generate OWASP Top 10 compliance report showing coverage per category

### 27.2 CWE Top 25 (2024)

- [ ] Build CWE Top 25 2024 mapping in `internal/compliance/cwe_top25.go`
- [ ] Map all tool rule IDs to CWE IDs (most tools already emit CWEs — collect and normalize)
- [ ] `armur report cwe --task <id>` — print CWE Top 25 coverage matrix

### 27.3 PCI-DSS v4.0

- [ ] Build PCI-DSS requirement → finding category mapping:
  - Req 6.2 (bespoke software security): all SAST findings
  - Req 6.3 (security vulnerabilities identified and addressed): all SCA findings
  - Req 6.3.3 (patches applied): outdated dependency SCA findings
  - Req 8.3 (strong authentication): JWT/OAuth misconfiguration findings
  - Req 10 (log and monitor): logging/monitoring gap findings
- [ ] `armur report pci --task <id>` — PCI-DSS compliance gap report with remediation guidance

### 27.4 HIPAA Technical Safeguards

- [ ] Map findings to HIPAA §164.312 technical safeguard requirements:
  - §164.312(a)(2)(iv) Encryption and Decryption → crypto findings
  - §164.312(c)(2) Authentication → auth findings
  - §164.312(d) Person or Entity Authentication → JWT/auth misconfiguration
  - §164.312(e)(2)(ii) Encryption in transit → TLS/HTTPS misconfiguration findings
- [ ] `armur report hipaa --task <id>` — HIPAA technical safeguard gap report

### 27.5 NIST SP 800-53 & SOC 2

- [ ] Build NIST SP 800-53 Rev 5 control → finding mapping for the most relevant controls (SA-11, SI-3, SC-28, IA-5, etc.)
- [ ] Build SOC 2 Trust Service Criteria → finding mapping (CC6.1, CC6.6, CC6.8, CC7.1, CC8.1)
- [ ] `armur report nist --task <id>` and `armur report soc2 --task <id>` compliance reports

---

## Sprint 28 — Advanced Static Analysis (Taint Tracking & Data Flow)

Most tools in Armur today are pattern-based. This sprint adds semantic analysis that tracks data
across call boundaries — the class of analysis that CodeQL and Semgrep Pro are known for.

### 28.1 Semgrep Pro Taint Mode Integration

- [ ] Upgrade semgrep invocation to use `--config=p/default` and explicitly add taint rules:
  - `--config=p/sql-injection` (taint: user input → SQL query builder)
  - `--config=p/xss` (taint: user input → HTML output)
  - `--config=p/command-injection` (taint: user input → os.exec / subprocess)
  - `--config=p/path-traversal` (taint: user input → file path operations)
  - `--config=p/ssrf` (taint: user input → HTTP client URL)
- [ ] Enable `interfile: true` in semgrep config to get cross-file taint analysis
- [ ] Parse `taint_trace` field from semgrep JSON output when present; add to `Finding.TaintTrace []TraceStep`
- [ ] Display taint trace in the TUI detail view and HTML report: "Source → [3 intermediate steps] → Sink"

### 28.2 Go Race Condition Detection

- [ ] Integrate `go test -race ./...` as an optional scan step (requires test suite present):
  - Run with `-count=1 -timeout 120s`; parse race detector output
  - Map each detected race to a `race_condition` finding category with CRITICAL severity
- [ ] Integrate `golangci-lint` with `govet` (includes `-copylocks`, `-loopclosure` analyzers)
- [ ] **Go deadcode** integration: extend `godeadcode` to flag unreachable exported functions separately

### 28.3 Integer & Arithmetic Safety

- [ ] Semgrep rules for integer overflow patterns:
  - `int(float64)` conversions without bounds checking
  - Unchecked `strconv.Atoi` used in size/offset calculations
  - Loop bounds from user input without validation
- [ ] For C/C++ (Sprint 17 prerequisite): cppcheck `--enable=warning` covers integer overflows
- [ ] For Rust: clippy `clippy::arithmetic-side-effects` lint integration

### 28.4 Type Confusion & Unsafe Deserialization

- [ ] Semgrep rules for unsafe deserialization:
  - Python: `pickle.loads(user_input)`, `yaml.load()` without Loader
  - Java: `ObjectInputStream` from user-controlled streams
  - PHP: `unserialize($user_input)`
  - JavaScript: `eval(userInput)`, `Function(userInput)()`
- [ ] Bandit rules B301-B302 (pickle, yaml.load) already partially covered; ensure they are emitted

---

## Sprint 29 — API Security Analysis

### 29.1 OpenAPI / Swagger Spec Security Analysis

- [ ] Detect OpenAPI specs: `openapi.yaml`, `openapi.json`, `swagger.yaml`, `swagger.json`, `api-docs.json`
- [ ] Implement `internal/tools/openapi.go` — parse spec and run security checks:
  - [ ] Missing `security` on individual operations (endpoint has no auth requirement defined)
  - [ ] Missing global `securitySchemes` definition
  - [ ] HTTP scheme used instead of HTTPS in `servers[].url`
  - [ ] Parameters with `in: query` or `in: header` missing `maxLength` or `pattern` (injection risk)
  - [ ] Response schemas missing for 4xx/5xx codes (information disclosure risk)
  - [ ] `additionalProperties: true` on request body schemas (mass assignment risk)
  - [ ] Deprecated API versions still listed without deprecation notice header
- [ ] Use `go-openapi/loads` library to parse spec; implement checks as functions

### 29.2 GraphQL Schema Security Analysis

- [ ] Detect GraphQL schemas: `schema.graphql`, `*.graphql`, `schema.gql`
- [ ] Implement `internal/tools/graphql.go` — parse schema and run security checks:
  - [ ] Introspection type `__schema` present (should be disabled in production)
  - [ ] Missing depth limit annotation or directive (`@complexity`, `@depth`)
  - [ ] Mutation fields without auth directives (unauthenticated data modification)
  - [ ] Subscription fields (potential DoS via long-lived connections)
  - [ ] Batch query support without rate limiting (N+1 / DoS risk)
- [ ] Use `github.com/vektah/gqlparser/v2` to parse GraphQL schema

### 29.3 JWT Implementation Analysis

- [ ] Detect JWT usage patterns across all supported languages:
  - Go: `github.com/golang-jwt/jwt`, `github.com/dgrijalva/jwt-go`
  - Python: `PyJWT`, `python-jose`
  - JavaScript: `jsonwebtoken`, `jose`
- [ ] Check for insecure patterns:
  - `alg: "none"` acceptance (algorithm confusion attack)
  - HMAC secret derived from public key or short constant
  - Missing `exp` (expiry) claim verification
  - Missing `aud` (audience) claim verification
  - `RS256` keys with bit length < 2048
- [ ] Implement as a semgrep rule pack in `configs/semgrep/jwt-security.yaml`

### 29.4 OAuth 2.0 & OIDC Misconfiguration

- [ ] Detect OAuth client implementations and check for:
  - Missing PKCE (`code_challenge` parameter) in public clients
  - `response_type=token` (implicit flow — deprecated and insecure)
  - Redirect URI wildcard (`*`) or insufficient validation
  - Client secret committed to source code (detected by secrets scanner, but add specific OAuth context)
- [ ] Add OIDC-specific checks: missing `nonce` validation, ID token not verified

---

## Sprint 30 — AI / LLM-Powered Enhancements

### 30.1 `armur explain` — Plain-English Finding Explanation

- [ ] `armur explain <finding-id>` CLI command
- [ ] Uses the Claude API (`claude-sonnet-4-6`) to generate a targeted explanation:
  - **What it is**: one sentence description of the vulnerability class
  - **Why it matters**: real-world impact and exploitability
  - **Attack scenario**: short realistic attack walkthrough for this specific code context
  - **How to fix**: concrete code change recommendation
- [ ] Include the finding's code snippet and file context in the prompt for specificity
- [ ] Stream the response to the terminal in real-time (SSE from Claude API)
- [ ] Cache explanations locally in SQLite (`~/.armur/history.db`) — reuse for same finding ID
- [ ] `armur explain --all --severity high` — bulk explain all HIGH findings in the last scan

### 30.2 `armur fix` — AI-Generated Code Patches

- [ ] `armur fix <finding-id>` CLI command
- [ ] Read the affected file from disk, extract ±10 lines of context around the finding's line
- [ ] Send to Claude API: `Given this vulnerability in <language>, generate a minimal code patch that fixes only the reported issue without changing functionality`
- [ ] Display the diff in the terminal (colored unified diff format using `github.com/pmezard/go-difflib`)
- [ ] `armur fix --apply <finding-id>` — apply the patch directly to the file (with backup to `<file>.armur.bak`)
- [ ] `armur fix --pr <finding-id>` — apply the patch, stage the change, and create a draft GitHub PR
- [ ] Batch mode: `armur fix --all --severity critical --apply` — apply AI fixes for all CRITICAL findings (requires explicit confirmation)

### 30.3 False Positive Reduction via LLM

- [ ] After a scan completes, run MEDIUM-severity findings through an LLM filter:
  - Input: finding details + 15 lines of code context
  - Prompt: "Is this a genuine security finding or a false positive? Rate confidence 0-100."
  - Findings with LLM confidence < 40: mark as `low_confidence`, hide by default (show with `--show-low-confidence`)
- [ ] Track false positive rates per tool over time; surface "this tool has 40% FP rate for this rule"
- [ ] Configurable: `armur.yml: ai.false-positive-filter: true` (default: false — requires API key)

### 30.4 Vulnerability Chaining Detection

- [ ] Detect cases where multiple LOW/MEDIUM findings together form a higher-risk attack chain:
  - Example: SSRF (MEDIUM) + credentials in env var (MEDIUM) → Remote credential theft (HIGH/CRITICAL)
  - Example: Path traversal (MEDIUM) + file read in same function → file disclosure (HIGH)
- [ ] Implement a rule engine in `internal/analysis/chains.go` with hand-crafted chaining rules
- [ ] LLM augmentation: send clusters of findings from the same file to Claude for chain analysis
- [ ] Display chains as a separate `vulnerability_chain` category in results

### 30.5 Natural Language Scan Configuration

- [ ] `armur run --ask "scan only for SQL injection and hardcoded credentials"` flag
- [ ] Parse the natural language instruction with Claude API → convert to a structured `.armur.yml` fragment
- [ ] Apply the generated config for the current scan run only (do not persist)

---

## Sprint 31 — Rules Marketplace & Customization

### 31.1 Community Rules Registry

- [ ] Create `github.com/armur-ai/armur-rules` repository — official community rules repo
- [ ] Structure: `rules/<language>/<category>/<rule-name>.yaml` (Semgrep rule format)
- [ ] Rules index at `rules/index.json`: `{ "packs": [{ "name": "go-security", "version": "1.2.0", "rules": 24, "languages": ["go"] }] }`
- [ ] Automated PR-based contribution workflow with CI testing

### 31.2 `armur rules` CLI Subcommands

- [ ] `armur rules list` — browse available rule packs from the registry (paginated table output)
- [ ] `armur rules search <keyword>` — search rules by keyword, language, or CWE
- [ ] `armur rules install <pack-name>` — download and install a rule pack to `~/.armur/rules/<pack-name>/`
- [ ] `armur rules update` — update all installed rule packs to latest versions
- [ ] `armur rules remove <pack-name>` — uninstall a rule pack
- [ ] `.armur.yml` integration:
  ```yaml
  rules:
    community:
      - go-security@1.2.0
      - python-owasp@2.0.1
    local:
      - ./my-custom-rules/
  ```

### 31.3 Custom Rule Authoring Tools

- [ ] `armur rules create` — interactive wizard to scaffold a new Semgrep rule:
  - Ask: target language, vulnerability category, example vulnerable code snippet
  - Generate a starter `.yaml` rule file with the correct Semgrep schema
- [ ] `armur rules test <rule-file>` — test a custom rule against `testdata/` fixtures:
  - Run semgrep with the rule against good and bad code samples
  - Report: true positives, false positives, false negatives
- [ ] `armur rules validate <rule-file>` — validate rule YAML schema and check for common mistakes

### 31.4 Import Rules from External Sources

- [ ] `armur rules import --from semgrep-registry <rule-id>` — fetch and adapt a Semgrep registry rule
- [ ] `armur rules import --from snyk <vuln-id>` — convert a Snyk rule template to Armur format
- [ ] Rule versioning: each installed rule pack has a version; `armur rules update` shows changelog

---

## Sprint 32 — IDE & Editor Integrations

### 32.1 Language Server Protocol (LSP) Server

- [ ] Implement `armur lsp` command — start Armur as an LSP server
  - Protocol: JSON-RPC over stdio (standard LSP transport)
  - Capabilities: `textDocument/diagnostic`, `textDocument/codeAction`, `workspace/diagnostic`
- [ ] On `textDocument/didSave`: trigger an `--in-process` scan of the saved file; return diagnostics
- [ ] Diagnostics mapped to LSP `Diagnostic` objects: range, severity, code (rule ID), message, source ("armur")
- [ ] Code actions: `armur.fix` action — returns a `WorkspaceEdit` with the LLM-generated patch
- [ ] Debounce: wait 500ms after last keystroke before re-scanning
- [ ] Configure scan timeout in LSP mode (default: 30s) to avoid blocking the editor

### 32.2 VS Code Extension

- [ ] Create `armur-ai/armur-vscode` extension repository
- [ ] Extension bootstraps: downloads the `armur` binary if not found in PATH; or uses `armur lsp` via the installed CLI
- [ ] Show findings as inline squiggle diagnostics in the Problems panel
- [ ] CodeLens: show "⚠ 2 security issues" above affected functions
- [ ] Hover tooltip: show finding summary when hovering over a highlighted line
- [ ] Quick Fix: "Fix with Armur AI" code action that calls `armur fix` and applies the patch
- [ ] Sidebar panel: filterable list of all findings in the workspace
- [ ] Command Palette: "Armur: Scan Workspace", "Armur: Clear Findings", "Armur: Explain Finding"
- [ ] Publish to VS Code Marketplace

### 32.3 Neovim Plugin

- [ ] Create `armur-ai/armur.nvim` repository (Lua plugin for Neovim ≥ 0.9)
- [ ] Integrate with `nvim-lspconfig` as a custom LSP client pointing to `armur lsp`
- [ ] Show findings as LSP diagnostics (virtual text + signs)
- [ ] `:ArmurFix` command — apply AI fix for finding under cursor
- [ ] `:ArmurExplain` command — explain finding under cursor in a floating window
- [ ] Telescope picker: `:ArmurFindings` — fuzzy-search all findings

### 32.4 JetBrains Plugin

- [ ] Create `armur-ai/armur-jetbrains` plugin (supports IntelliJ, GoLand, PyCharm, WebStorm)
- [ ] Run `armur` as an external tool; parse JSON output for findings
- [ ] Show findings as inspection warnings in the editor gutter
- [ ] Quick fix action: "Apply Armur AI Fix"
- [ ] Tool window panel: findings list with filter and sort
- [ ] Publish to JetBrains Marketplace

---

## Sprint 33 — Team & Organization Features

### 33.1 Multi-User API with RBAC

- [ ] Add user model to the server: `User { ID, Email, Role, APIKey, CreatedAt }`
- [ ] Roles: `admin` (full access), `editor` (run scans, manage findings), `viewer` (read-only)
- [ ] Admin API endpoints: `POST /api/v1/admin/users`, `DELETE /api/v1/admin/users/:id`, `PATCH /api/v1/admin/users/:id/role`
- [ ] API keys scoped to users: each user has their own API key for CLI authentication
- [ ] Findings are tagged with the user who submitted the scan

### 33.2 Finding Assignment & Workflow

- [ ] Add `PATCH /api/v1/findings/:id` endpoint:
  - `assignee_email` — assign to a team member
  - `status` — `open` | `in_progress` | `resolved` | `suppressed` | `accepted_risk`
  - `comment` — free text note
- [ ] `armur finding assign <id> --to user@example.com` CLI command
- [ ] `armur finding status <id> --set resolved` CLI command
- [ ] Webhook notification when a finding is assigned

### 33.3 Finding Suppression Management

- [ ] Inline suppression in source code: `// armur:ignore <rule-id> -- reason -- until:2026-12-31`
- [ ] Global suppression via `.armur.yml`:
  ```yaml
  suppress:
    - rule: "gosec.G401"
      path: "internal/crypto/legacy.go"
      reason: "Legacy code, scheduled for removal in Q2 2026"
      expires: "2026-06-01"
      approved-by: "jane@example.com"
  ```
- [ ] `armur suppress <finding-id>` interactive CLI: prompts for reason, expiry, approver
- [ ] Suppression audit trail: log who suppressed what, when, with what reason
- [ ] Expired suppressions automatically reactivate the finding on next scan
- [ ] `armur suppressions list` — show all active suppressions with expiry dates

### 33.4 SSO Integration

- [ ] OIDC provider support (Google, GitHub, Okta, Auth0):
  - Config: `ARMUR_OIDC_ISSUER`, `ARMUR_OIDC_CLIENT_ID`, `ARMUR_OIDC_CLIENT_SECRET`
  - Exchange OIDC ID token for Armur API key on first login
- [ ] SAML 2.0 IdP integration for enterprise (Okta SAML, Azure AD SAML)
- [ ] `armur login --oidc` CLI command: opens browser for OIDC flow, stores token in `~/.armur/credentials`

### 33.5 Organization-Level Audit Log

- [ ] Every scan submission, finding suppression, user creation, and role change creates an audit log entry
- [ ] `GET /api/v1/admin/audit-log` endpoint (admin-only): paginated audit log
- [ ] `armur audit-log --since 2026-01-01` CLI command to query the log
- [ ] Audit log entries include: timestamp, actor (user ID + email), action, resource ID, IP address

---

## Sprint 34 — Advanced Reporting & Analytics

### 34.1 Security Posture Score

- [ ] Compute a 0–100 security posture score for each scanned repo:
  ```
  score = 100
         - (critical_count × 20)
         - (high_count × 10)
         - (medium_count × 3)
         - (low_count × 0.5)
         + bonus_for_zero_critical × 10
  score = max(0, min(100, score))  // clamp to [0, 100]
  ```
- [ ] Add letter grade: A (90-100), B (75-89), C (60-74), D (40-59), F (<40)
- [ ] Display posture score prominently in the TUI summary card and HTML report header
- [ ] Track score over time in SQLite history: `posture_score` column in `scans` table
- [ ] `armur score <target>` quick command — print only the score + grade, no findings

### 34.2 Finding Trend Charts (Terminal + HTML)

- [ ] **Terminal sparklines**: use `github.com/guptarohit/asciigraph` to render finding count over time
  - `armur trends --repo <path>` — show per-category trend over last 10 scans
  - `armur trends --severity high` — show HIGH finding count trend
- [ ] **HTML report charts**: inline SVG line charts of finding count over time (per severity)
- [ ] **Heatmap**: HTML report shows a file-level heatmap (which files have the most findings)

### 34.3 Mean Time to Remediation (MTTR)

- [ ] When a finding from a previous scan is absent in the new scan → mark it as "resolved" in history
- [ ] Compute MTTR per category: average days between finding first detected and resolved
- [ ] `armur mttr --last 90d` — print MTTR table by category and severity
- [ ] Include MTTR in executive PDF report

### 34.4 Developer Accountability Report

- [ ] Using git blame data (from Sprint 23.3): attribute each finding to the developer who introduced the code
- [ ] Per-developer summary: total open findings, critical count, MTTR
- [ ] `armur report team --task <id>` — generate per-developer breakdown
- [ ] This data is opt-in (`armur.yml: reporting.blame: true`) — off by default for privacy

### 34.5 Risk Priority Score per Finding

- [ ] Compute a risk priority score for each finding beyond just severity:
  ```
  risk = base_cvss_score
       × reachability_multiplier  (1.5 if reachable, 1.0 if unknown, 0.5 if unreachable)
       × exposure_multiplier      (1.3 if internet-facing endpoint, 1.0 if internal)
       × fixability_factor        (1.0 if patch available, 0.8 if workaround only)
  ```
- [ ] Add `Finding.RiskScore float64` field
- [ ] Default sort in the TUI results browser: by `RiskScore` desc (not raw severity)
- [ ] `armur report risk --task <id>` — output findings sorted by risk score with score column

### 34.6 Executive PDF Report

- [ ] `armur report pdf --task <id>` — generate a multi-page PDF executive report
- [ ] Report pages:
  1. Cover: target, date, posture score, grade
  2. Executive Summary: key metrics, highest-risk findings, trend vs previous scan
  3. Severity breakdown (pie chart)
  4. Compliance framework coverage (OWASP, PCI, HIPAA traffic-light matrix)
  5. Top 10 findings by risk score (detail for each)
  6. SCA: dependency vulnerability summary
  7. Secrets: secrets detected (redacted values)
  8. Remediation roadmap: prioritized action list
- [ ] Use `github.com/signintech/gopdf` or `maroto` library for PDF generation (no external dependencies)
- [ ] `armur report pdf --schedule weekly --email ciso@example.com` — scheduled PDF delivery

---

## Sprint 35 — Performance at Scale (Monorepos · Caching · Distributed Scanning)

### 35.1 Monorepo Support

- [ ] **Service detection**: detect services/modules within a monorepo by finding multiple `go.mod`, `package.json`, `pom.xml`, `pyproject.toml` files
- [ ] **Per-service scanning**: scan each detected service independently in parallel; merge results with per-service labels
- [ ] `armur run --monorepo` flag: explicitly enable monorepo mode with per-service breakdown in TUI
- [ ] `armur run --service <name>` flag: scan only a specific named service within a monorepo
- [ ] Result grouping in TUI: top-level tabs by service name; summary card shows per-service severity counts

### 35.2 Scan Result Caching

- [ ] **File-level caching**: compute SHA256 hash of each source file before scanning
  - If a file's hash matches a cache entry (stored in Redis), reuse cached tool results for that file
  - Only re-run tools on files that have changed since the last scan
  - Cache key: `cache:<repo-url>:<file-path>:<sha256>:<tool>`
- [ ] **Tool result caching**: cache the full tool output keyed by `(tool_version + dir_hash)`; TTL: 24h
- [ ] Cache invalidation: clear cache for a repo when any file in the repo changes
- [ ] Cache hit rate reported in scan metadata: `"cache": { "hit_rate": 0.73, "files_from_cache": 147 }`
- [ ] `armur cache clear` CLI command — flush all cached results

### 35.3 Distributed Scanning (Multiple Workers)

- [ ] Asynq already supports multiple workers — document and test multi-worker deployment
- [ ] Add worker-aware task distribution: large repos split into sub-tasks (one per tool or one per service) for parallel execution across workers
- [ ] Worker health reporting: each worker registers itself in Redis with heartbeat TTL; `GET /api/v1/workers` endpoint lists active workers
- [ ] Priority queues: add `critical`, `default`, `low` Asynq queues; API key tier determines which queue tasks land in
- [ ] Worker auto-scaling hints: `/metrics` endpoint (Sprint 6.1) exposes queue depth; publish Kubernetes HPA custom metrics example

### 35.4 Large Repo Optimizations

- [ ] Shallow clone by default: `git clone --depth=1` for repository scans (already fast; make explicit)
- [ ] Sparse checkout for monorepos: only check out the specific service directory when `--service` is specified
- [ ] File count limit with warning: if repo has > 50,000 files, warn and offer to scan only the top-level `--depth 3` directories
- [ ] Memory limit for tool execution: set `ulimit -v` (virtual memory cap) per tool subprocess to prevent OOM on oversized repos
- [ ] Incremental cache warm-up: on first scan, build file hash cache; subsequent scans are 5–10x faster

### 35.5 Scan Queue Priority & Scheduling

- [ ] `POST /api/v1/scan/repo` accepts optional `priority: critical|high|normal|low` field
- [ ] Priority maps to Asynq queue: critical → immediately dequeued, low → background
- [ ] `scheduled_at` field: schedule a scan for a future time (e.g., nightly at 02:00)
- [ ] Recurring scan schedule: `cron: "0 2 * * *"` field in scan request — re-enqueues task on the given cron schedule
- [ ] `armur schedule add <target> --cron "0 2 * * *"` CLI command for recurring scans

---

## Backlog / Future Ideas

- [ ] GitHub App — auto-scan PRs and post inline review comments with findings
- [ ] Findings suppression inline comments: `// armur:ignore CWE-89 -- false positive in test helper`
- [ ] Policy-as-code — define complex custom security policies using CEL (Common Expression Language) in `.armur.yml`
- [ ] `armur audit` mode — scheduled recurring scans via embedded cron, alerting on new findings via webhook
- [ ] Secrets rotation helper — when a leak is found, `armur secrets rotate` guides revocation across all known services
- [ ] DAST integration — trigger OWASP ZAP or Nuclei scans after SAST scan completes (for running services)
- [ ] Binary analysis mode — scan compiled binaries for known vulnerable embedded libraries using Grype
- [ ] Mobile app scanning — Android APK analysis (MobSF integration), iOS IPA analysis
- [ ] Fuzzing orchestration — integrate with go-fuzz / AFL++ / libFuzzer; suggest fuzz targets based on SAST findings
- [ ] LLM-powered threat modeling — generate a STRIDE threat model from the codebase architecture
- [ ] `armur bench <tool>` — benchmark a specific tool's performance on a target and suggest config tuning
- [ ] Finding deduplication across multiple scans — deduplicate findings across all historical scans for a repo, not just within a single scan
- [ ] Org-level finding database — centralized finding database across all repos in an organization with org-wide suppression management
- [ ] `armur import --from sonarqube|snyk|codeql` — import findings from other tools and normalize to Armur format
- [ ] Signed scan attestations — sign scan result JSON with a private key; `armur verify <result.json>` for tamper evidence in CI pipelines

---

*Last updated: March 2026*
*Sprints 1–7: original roadmap. Sprints 8–15: CLI/TUI overhaul and core engine. Sprints 16–35: world-class scanner expansion added March 2026.*

---

## Sprint 36 — MCP Server: Native AI Assistant Integration

The Model Context Protocol (MCP) is how AI coding assistants (Claude Code, Cursor, Windsurf, Claude
Desktop) call external tools. Armur as an MCP server means every developer using an AI assistant
gets Armur's scanning capabilities built directly into their coding workflow — zero extra steps.
This is the highest-leverage distribution play available right now.

### 36.1 Core MCP Server Implementation

- [ ] Add `armur mcp` command — starts Armur as an MCP server over stdio (standard Claude Code transport)
- [ ] Use `github.com/mark3labs/mcp-go` as the MCP SDK (or implement the JSON-RPC 2.0 protocol directly)
- [ ] Implement MCP `initialize` handshake: declare server name `armur`, version, and capabilities
- [ ] Implement the following **MCP Tools** (functions Claude can call):

  **Scanning tools:**
  - `armur_scan_path` — scan a local file or directory
    - Input: `{ "path": string, "depth": "quick"|"deep" (optional) }`
    - Output: `{ "task_id": string, "findings": Finding[], "summary": ScanSummary }`
    - Runs in-process (no server required) for lowest latency
  - `armur_scan_code` — scan a code snippet without touching the filesystem (for inline use)
    - Input: `{ "code": string, "language": string, "filename": string (optional) }`
    - Output: `{ "findings": Finding[], "summary": ScanSummary }`
    - Writes to temp file, runs semgrep + language tools, returns findings, deletes temp file
  - `armur_scan_git_history` — scan git history for leaked secrets
    - Input: `{ "path": string, "depth": "full"|"recent" }` (`"recent"` = last 100 commits)
    - Output: `{ "findings": Finding[] }`

  **Finding intelligence tools:**
  - `armur_explain_finding` — explain a specific finding in plain English with attack scenario
    - Input: `{ "finding_id": string }` or `{ "finding": Finding }` (inline finding object)
    - Output: `{ "explanation": string, "attack_scenario": string, "remediation": string }`
  - `armur_fix_finding` — generate a code patch for a finding
    - Input: `{ "finding_id": string, "code_context": string (10 lines around the issue) }`
    - Output: `{ "patch": string (unified diff format), "explanation": string }`
  - `armur_check_dependency` — check if a specific package version has known vulnerabilities
    - Input: `{ "package": string, "version": string, "ecosystem": "npm"|"pip"|"go"|"cargo"|... }`
    - Output: `{ "vulnerabilities": Vulnerability[], "safe": bool, "fix_version": string }`

  **History & status tools:**
  - `armur_get_history` — get recent scan history for a path
    - Input: `{ "path": string (optional), "limit": int (default: 5) }`
    - Output: `{ "scans": ScanSummary[] }`
  - `armur_get_posture_score` — get the security posture score for a path
    - Input: `{ "path": string }`
    - Output: `{ "score": int, "grade": string, "breakdown": SeverityBreakdown }`

- [ ] Implement MCP **Resources** (data Claude can read without calling a tool):
  - `armur://findings/latest` — findings from the most recent scan of cwd
  - `armur://posture` — current posture score for cwd
  - `armur://history` — last 10 scan summaries
- [ ] Implement MCP **Prompts** (reusable prompt templates Claude can invoke):
  - `security_review` — "Review the following code for security vulnerabilities using Armur"
  - `fix_vulnerabilities` — "Fix all HIGH and CRITICAL vulnerabilities found by Armur in this file"
  - `explain_findings` — "Explain the Armur findings in this scan in developer-friendly language"

### 36.2 Claude Code Integration

- [ ] Write `docs/integrations/claude-code.md` with step-by-step setup:
  ```json
  // Add to ~/.claude/settings.json (or use: claude mcp add armur -- armur mcp)
  {
    "mcpServers": {
      "armur": {
        "command": "armur",
        "args": ["mcp"],
        "env": { "ARMUR_API_KEY": "<your-key>" }
      }
    }
  }
  ```
- [ ] One-liner setup command: `armur setup claude-code` — writes the MCP config automatically to the correct Claude Code settings file
- [ ] Verify the integration: `armur setup claude-code --verify` — starts the MCP server, sends a test tool call, confirms it responds correctly
- [ ] Generate a `CLAUDE.md` snippet users can add to their project:
  ```markdown
  ## Security Policy
  This project uses Armur for security scanning. Before suggesting code changes:
  1. Use `armur_scan_code` to check new code for vulnerabilities
  2. Use `armur_check_dependency` before suggesting new package additions
  3. Address any HIGH or CRITICAL findings before finalizing suggestions
  4. Use `armur_explain_finding` if a finding needs clarification
  ```
- [ ] `armur setup claude-code --add-project-md` — appends the above snippet to `CLAUDE.md` in cwd

### 36.3 Cursor Integration

- [ ] Write `docs/integrations/cursor.md` — Cursor supports MCP via the same `~/.cursor/mcp.json` config format
- [ ] `armur setup cursor` — writes MCP config to `~/.cursor/mcp.json`
- [ ] Cursor-specific prompt template: "When writing code, automatically check for security issues using Armur tools"
- [ ] Test the Cursor integration end-to-end; document known limitations (Cursor MCP differences)

### 36.4 Windsurf Integration

- [ ] Write `docs/integrations/windsurf.md`
- [ ] `armur setup windsurf` — writes config to Windsurf's MCP config path
- [ ] Test and document Windsurf-specific behavior

### 36.5 Claude Desktop Integration

- [ ] Write `docs/integrations/claude-desktop.md`
- [ ] `armur setup claude-desktop` — writes to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or equivalent on Windows/Linux
- [ ] Desktop-specific use case: scan repos you're reviewing without an editor open

### 36.6 MCP Server Performance & Reliability

- [ ] `armur_scan_path` must complete in < 5 seconds for `depth: "quick"` on a typical project (use in-process mode)
- [ ] `armur_scan_code` must complete in < 2 seconds for a single file (semgrep only, no heavy tools)
- [ ] MCP server logs errors to stderr (visible in Claude Code's MCP debug output)
- [ ] Graceful error handling: if a tool is not installed, return a helpful error message instead of crashing
- [ ] Add integration tests that start the MCP server and call each tool via the MCP protocol

---

## Sprint 37 — Zero-Friction Distribution (Every Platform, One Command)

A tool is only as good as how easy it is to install. Every developer should be able to go from
"I heard about Armur" to running their first scan in under 60 seconds, on any platform.

### 37.1 Homebrew (macOS & Linux — Primary Channel)

- [ ] Create `armur-ai/homebrew-tap` GitHub repository
- [ ] Write `Formula/armur.rb` Homebrew formula:
  - Downloads pre-built binary from GitHub Releases based on OS and arch
  - Installs to `/opt/homebrew/bin/armur` (Apple Silicon) or `/usr/local/bin/armur` (Intel)
  - Includes shell completion setup in the formula's `caveats` section
- [ ] Test formula installation on macOS (arm64 + x86_64) and Linux (x86_64)
- [ ] Publish: `brew install armur-ai/tap/armur`
- [ ] Submit to Homebrew Core (after meeting minimum formula requirements: 75+ stars, stable release)
- [ ] `armur update` self-update: `brew upgrade armur` under the hood when installed via Homebrew

### 37.2 npm Global Package (JavaScript/TypeScript Developer Channel)

- [ ] Create `packages/armur-cli` npm package:
  - `package.json` with `bin: { "armur": "bin/armur.js" }`
  - `postinstall` script: detect OS/arch, download the correct Go binary from GitHub Releases, place in `node_modules/.bin/`
  - Inspired by how `esbuild`, `turbo`, and `@biomejs/biome` distribute native binaries via npm
- [ ] Publish to npm: `npm install -g @armur/cli` or `npx @armur/cli scan .` (no install needed)
- [ ] `npx @armur/cli scan .` must work with zero prior setup — downloads binary, runs scan, exits
- [ ] Auto-detect and run without the Docker server when invoked via npx (always use `--in-process`)

### 37.3 pip Package (Python Developer Channel)

- [ ] Create `packages/armur` pip package:
  - `pyproject.toml` with `scripts = { "armur" = "armur.cli:main" }`
  - `__init__.py` `main()`: detect OS/arch, download binary, exec it (similar to the npm approach)
- [ ] Publish to PyPI: `pip install armur` or `pipx install armur`
- [ ] `pipx install armur` is the recommended approach (isolated environment, global `armur` command)

### 37.4 Windows (winget + Scoop + MSI)

- [ ] Submit to `winget-pkgs` (Windows Package Manager): `winget install Armur.Armur`
- [ ] Create Scoop manifest in `armur-ai/scoop-bucket`: `scoop install armur`
- [ ] Build `.msi` installer using `go-msi` for users who prefer GUI install
- [ ] Windows-specific: ensure all tool integrations work on Windows (use WSL for Linux-only tools)
- [ ] Test the complete CLI TUI experience on Windows Terminal

### 37.5 Docker (Zero-Install Path for Any Platform)

- [ ] `docker run --rm -v $(pwd):/scan armur/scanner scan /scan` — scan cwd without any installation
- [ ] Publish to Docker Hub as `armur/scanner:latest` and `armur/scanner:v<version>`
- [ ] Docker image includes all 18 tools pre-installed (current behavior in the full image)
- [ ] Provide a convenience shell alias in the docs:
  ```bash
  alias armur='docker run --rm -v $(pwd):/scan armur/scanner'
  ```
- [ ] `armur/scanner:slim` — image with only the CLI tools (no server, no Redis) for local use

### 37.6 `curl | sh` Universal Installer

- [ ] Host `install.armur.ai/install.sh` — detects OS/arch, downloads the correct binary, installs to `/usr/local/bin/`
  ```bash
  curl -fsSL https://install.armur.ai | sh
  ```
- [ ] The install script:
  1. Detects OS: `linux`, `darwin`, `windows`
  2. Detects arch: `amd64`, `arm64`
  3. Fetches latest release tag from GitHub API
  4. Downloads the binary and checksum file
  5. Verifies SHA256 checksum
  6. Installs to `/usr/local/bin/` (or `$HOME/.local/bin` if no root)
  7. Prints "armur installed! Run 'armur run' to get started."
- [ ] PowerShell equivalent for Windows: `irm install.armur.ai/install.ps1 | iex`
- [ ] All downloads are over HTTPS; checksums are verified before installation

### 37.7 `armur update` Self-Update Command

- [ ] `armur update` — checks GitHub Releases API for a newer version and self-updates
- [ ] Atomically replaces the current binary (download to temp path, rename over existing)
- [ ] `armur update --check` — print latest version without updating
- [ ] Show update hint at the end of `armur run` output when a newer version is available (at most once per day)

### 37.8 goreleaser Cross-Platform Release Pipeline

- [ ] `.goreleaser.yml` configuration:
  - Builds: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`
  - Archives: `.tar.gz` for Unix, `.zip` for Windows
  - Checksums: `SHA256SUMS` file signed with Cosign
  - Homebrew tap: auto-updates `armur-ai/homebrew-tap` formula on release
  - Docker: builds and pushes `armur/scanner` image on release
  - Changelog: generated from conventional commits
- [ ] Release workflow: `git tag v1.0.0 && git push --tags` → goreleaser does everything else
- [ ] Sign release binaries with Cosign for provenance attestation

---

## Sprint 38 — GitHub Native: App, Actions & Security Tab

GitHub is where most open source and enterprise code lives. Deep GitHub integration is the
highest-leverage adoption channel for reaching developers who haven't discovered Armur yet.

### 38.1 GitHub App (Zero-Config Org-Wide Scanning)

- [ ] Create `Armur Security` GitHub App at `github.com/apps/armur-security`
- [ ] App permissions:
  - Read: Contents, Pull Requests, Code scanning alerts, Checks
  - Write: Checks, Code scanning alerts, Pull Request review comments, Statuses
- [ ] Webhook events subscribed: `push`, `pull_request` (opened, synchronize, reopened), `installation`
- [ ] On `pull_request` event: automatically scan the PR's changed files (diff mode)
  - Enqueue a scan task with `--diff <base-sha>` and the PR's head commit
  - Report results via GitHub Checks API (creates a check run on the PR)
  - Upload SARIF to GitHub Code Scanning API (`/code-scanning/sarifs`)
  - Post inline review comments on the PR diff for each finding (one comment per finding, grouped by file)
- [ ] On `push` to default branch: scan full repo (background, non-blocking)
- [ ] Check run report format:
  ```
  Armur Security  ·  15 findings
  ──────────────────────────────
  ✗ Critical: 1   ✗ High: 4   ⚠ Medium: 7   · Low: 3
  View full report →
  ```
- [ ] PR comment summary (posted by the App bot):
  ```
  ## Armur Security Scan
  Found **15 findings** in the changed files.
  | Severity | Count |
  |----------|-------|
  | 🔴 Critical | 1 |
  | 🟠 High | 4 |
  | 🟡 Medium | 7 |
  | 🟢 Low | 3 |
  [View full results](https://github.com/owner/repo/security/code-scanning)
  ```
- [ ] Re-scan when a PR is updated (push to the PR branch)
- [ ] Respect `.armur.yml` from the repository for scan config
- [ ] App installation page: one-click install for an entire organization (covers all repos)

### 38.2 GitHub Actions (Polished, Composable Action)

- [ ] Create `armur-ai/armur-action` GitHub Action (replaces the basic one from Sprint 3.2)
- [ ] Action inputs:
  ```yaml
  - uses: armur-ai/armur-action@v1
    with:
      path: '.'                    # directory to scan (default: repo root)
      depth: 'quick'               # quick | deep
      fail-on-severity: 'high'     # fail workflow if findings at this level or above
      min-severity: 'medium'       # suppress findings below this level in output
      output-format: 'sarif'       # sarif | json | table
      upload-sarif: true           # upload SARIF to GitHub Security tab
      comment-on-pr: true          # post findings summary as PR comment
      armur-version: 'latest'      # pin to a specific armur version
  ```
- [ ] Action outputs: `findings-count`, `critical-count`, `high-count`, `sarif-path`, `report-path`
- [ ] Automatically upload SARIF via `github/codeql-action/upload-sarif@v3`
- [ ] Auto-detect push vs PR and run appropriate mode (full scan vs diff scan)
- [ ] Publish to GitHub Actions Marketplace with verified badge
- [ ] Add badge to README: `[![Armur Scan](https://github.com/<owner>/<repo>/actions/workflows/armur.yml/badge.svg)](https://github.com/<owner>/<repo>/actions/workflows/armur.yml)`
- [ ] Include starter workflows for common patterns:
  - `armur-pr-scan.yml` — scan PRs and fail on HIGH findings
  - `armur-nightly.yml` — full deep scan nightly, notify via Slack
  - `armur-release-gate.yml` — block releases if CRITICAL findings exist

### 38.3 GitHub Security Tab (Code Scanning Integration)

- [ ] SARIF output fully conformant with GitHub's Code Scanning SARIF requirements:
  - `$schema`: `https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json`
  - `runs[].tool.driver.name`: "Armur"
  - `runs[].tool.driver.rules[]`: one rule per unique finding type with `helpUri` linking to docs
  - `results[].locations[].physicalLocation.artifactLocation.uriBaseId`: `%SRCROOT%`
  - `results[].fingerprints`: for finding stability across scans (prevents duplicate alerts)
- [ ] Each SARIF rule includes a `help` markdown block with remediation guidance
- [ ] Finding level → SARIF level: Critical/High → `error`, Medium → `warning`, Low → `note`
- [ ] Findings show as inline annotations on the Files Changed tab in GitHub PRs

### 38.4 GitHub Codespaces Integration

- [ ] Add Armur to the `devcontainer.json` feature registry:
  ```json
  "features": {
    "ghcr.io/armur-ai/features/armur:1": {}
  }
  ```
- [ ] The devcontainer feature installs the `armur` binary in the container
- [ ] Write `docs/integrations/codespaces.md`
- [ ] Provide a `.devcontainer/devcontainer.json` template that includes Armur + the VS Code extension
- [ ] When Armur is in the devcontainer, `armur run .` works with `--in-process` automatically (no Docker/Redis needed)

### 38.5 GitHub Marketplace Listing

- [ ] Submit both the GitHub App and the GitHub Action to GitHub Marketplace
- [ ] Write compelling marketplace listing descriptions with screenshots
- [ ] Add demo video showing PR scan workflow (GIF embedded in marketplace listing)

---

## Sprint 39 — VS Code / Cursor / AI Editor Ecosystem

### 39.1 VS Code Extension — Polished Distribution

Building on Sprint 32.2 (which covers core functionality), this sprint focuses on distribution,
onboarding, and making the extension the #1 security extension on the marketplace.

- [ ] Extension ID: `armur-ai.armur-security` — reserve this on the VS Code Marketplace
- [ ] Extension categories: `Linters`, `Other` — and tag: `security`, `scanner`, `SAST`, `DevSecOps`
- [ ] **Onboarding flow** (first install):
  - Welcome walkthrough: 3-screen carousel explaining what Armur does
  - Check if `armur` binary is installed; if not, offer one-click install (downloads binary)
  - Check server config; if no server: offer "Use local mode" (sets `--in-process`)
  - Run a 10-second quick scan of the open workspace on first activation
  - Show "Found X findings in your project" notification with "View All" button
- [ ] **Status bar item**: `$(shield) Armur: 3 🔴 12 🟠` — shows finding count, click to open panel
- [ ] **Explorer tree view**: "Armur Security" sidebar panel showing findings grouped by file
- [ ] **Problems panel integration**: all findings appear in VS Code's Problems panel with correct severity icons
- [ ] **Auto-scan on save**: configurable (default: off; opt-in in settings)
- [ ] **Scan on open**: run a background scan when a workspace is opened (configurable)
- [ ] Extension settings:
  ```json
  "armur.scanDepth": "quick",
  "armur.scanOnSave": false,
  "armur.scanOnOpen": true,
  "armur.minSeverity": "medium",
  "armur.binaryPath": "armur",
  "armur.serverUrl": "http://localhost:4500",
  "armur.useLocalMode": true
  ```
- [ ] `.vscode/extensions.json` recommendation: when a `.armur.yml` is present, VS Code prompts "Install Armur Security extension?"

### 39.2 Cursor-Specific Integration

- [ ] The VS Code extension works in Cursor without modification (Cursor is VS Code-based)
- [ ] Add Cursor-specific MCP integration: when the extension detects it is running in Cursor, automatically set up the Armur MCP server config in Cursor's settings
- [ ] Write `docs/integrations/cursor.md` focused on the combined extension + MCP experience
- [ ] Cursor badge: "Works with Cursor" on the extension marketplace listing

### 39.3 VS Code Web Extension (github.dev & Codespaces)

- [ ] Refactor the extension to support the VS Code Web Extension API (restricted environment)
- [ ] In web extension mode: use the Armur Cloud API instead of a local binary
- [ ] Show findings from the last scan (read-only) when no scan can be run
- [ ] Works in `github.dev`, Codespaces, and VS Code for the Web

### 39.4 `.vscode/` Project Templates

- [ ] Provide `armur init --vscode` to scaffold `.vscode/` config:
  - `.vscode/extensions.json`: recommends `armur-ai.armur-security`
  - `.vscode/settings.json`: sets `armur.scanOnOpen: true`, `armur.minSeverity: "medium"`
  - `.vscode/tasks.json`: adds "Armur: Scan Workspace" as a task
- [ ] When a project has `.armur.yml` and no `.vscode/extensions.json`, offer to create one

---

## Sprint 40 — CI/CD Ecosystem Breadth

One GitHub Action is not enough. Every developer uses a different CI system. Armur needs a
first-class native integration in every major CI/CD platform.

### 40.1 GitLab CI/CD

- [ ] Create `armur-ai/armur-gitlab-ci` repository with a GitLab CI include template:
  ```yaml
  # In your .gitlab-ci.yml:
  include:
    - project: 'armur-ai/armur-gitlab-ci'
      ref: 'v1'
      file: '/templates/armur-scan.yml'
  ```
- [ ] Template supports: MR scanning (diff mode), nightly full scans, SAST report artifact upload
- [ ] Map SARIF output to GitLab SAST JSON report format for the Security Dashboard
- [ ] Submit to GitLab's CI/CD catalog (official marketplace for CI templates)

### 40.2 CircleCI Orb

- [ ] Create and publish `armur-ai/armur` CircleCI Orb to the Orb Registry
- [ ] Orb jobs: `armur/scan`, `armur/scan-and-report`
- [ ] Orb executors: `armur/default` (uses `armur/scanner` Docker image)
- [ ] Usage:
  ```yaml
  orbs:
    armur: armur-ai/armur@1.0.0
  jobs:
    security-scan:
      executor: armur/default
      steps:
        - armur/scan:
            fail-on-severity: high
  ```

### 40.3 Jenkins Plugin

- [ ] Create `armur-jenkins-plugin` (Java, Maven-based Jenkins plugin)
- [ ] Post-build step: "Armur Security Scan" — runs scan, publishes findings as a build artifact
- [ ] Build status: fail build if findings exceed threshold (configurable)
- [ ] Finding trend graph in Jenkins job dashboard (using Jenkins Plot Plugin)
- [ ] Publish to Jenkins Plugin Index

### 40.4 Azure DevOps Extension

- [ ] Create `armur-security` Azure DevOps extension in the Visual Studio Marketplace
- [ ] Pipeline task: `ArmurScan@1`
  ```yaml
  - task: ArmurScan@1
    inputs:
      scanPath: '$(Build.SourcesDirectory)'
      failOnSeverity: 'high'
      uploadSarif: true
  ```
- [ ] Uploads SARIF to Azure DevOps Code Scanning (if enabled in the project)
- [ ] Publish to Azure DevOps Marketplace

### 40.5 Bitbucket Pipelines

- [ ] Create `armur-ai/armur-pipe` Bitbucket Pipe:
  ```yaml
  - pipe: armur-ai/armur-pipe:1.0.0
    variables:
      FAIL_ON_SEVERITY: 'high'
      MIN_SEVERITY: 'medium'
  ```
- [ ] Publish to Bitbucket Pipes catalog

### 40.6 Additional CI Platforms

- [ ] **Drone CI** (`.drone.yml` plugin): `armur-ai/drone-armur` plugin image
- [ ] **Argo Workflows**: `WorkflowTemplate` YAML for running Armur as a workflow step
- [ ] **Tekton**: `Task` definition for running Armur in Tekton Pipelines
- [ ] **Dagger** module: `armur-ai/dagger-armur` — composable Armur scan in Dagger pipelines
- [ ] For each: provide a ready-to-use config snippet in `docs/ci/`

### 40.7 Pre-commit Hook (Language-Agnostic)

- [ ] Create `.pre-commit-hooks.yaml` in the root repo:
  ```yaml
  - id: armur-scan
    name: Armur Security Scan
    language: system
    entry: armur scan --staged-only --fail-on-severity medium
    pass_filenames: false
    types: [text]
  ```
- [ ] For JS projects: `armur-ai/husky-armur` — Husky configuration for npm projects:
  ```json
  { "hooks": { "pre-commit": "armur scan --staged-only --fail-on-severity high" } }
  ```
- [ ] `armur setup pre-commit` — interactively configures the pre-commit hook for the current project (detects husky vs pre-commit framework vs plain git hooks)

---

## Sprint 41 — Slack, Teams & Issue Tracker Integrations

When a critical vulnerability is found at 2am in a nightly scan, the right person needs to know
immediately — in the tool they use for communication, not in a dashboard they rarely visit.

### 41.1 Slack Integration

- [ ] Create `Armur Security` Slack App at `api.slack.com/apps`
- [ ] **Incoming webhook notifications**: when a scan completes with findings above threshold, POST to a configured Slack webhook:
  ```
  🛡 Armur Security Alert
  ━━━━━━━━━━━━━━━━━━━━━
  Repo: github.com/acme/api
  Branch: main  ·  Scan: deep
  ━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔴 Critical  1   (new: 1)
  🟠 High      5   (new: 2)
  🟡 Medium    12
  ━━━━━━━━━━━━━━━━━━━━━━━━━
  [View findings]  [Assign]  [Suppress]
  ```
- [ ] Interactive buttons in Slack message: "View findings" → links to results, "Assign" → opens assignee picker in Slack, "Suppress" → mark as accepted risk
- [ ] `/armur scan <url>` Slack slash command: trigger a scan from Slack; bot replies with results in a thread
- [ ] `/armur status <task-id>` — check scan status from Slack
- [ ] Configurable notification thresholds: only notify for CRITICAL, or CRITICAL+HIGH, etc.
- [ ] Configuration: `armur config slack --webhook-url <url> --channel #security --notify-on critical`

### 41.2 Microsoft Teams Integration

- [ ] Adaptive Card notification for Microsoft Teams (same trigger conditions as Slack)
- [ ] Teams Connector webhook: post scan results as a rich card
- [ ] Teams bot: `@Armur scan <url>` — trigger a scan from a Teams channel
- [ ] Configuration: `armur config teams --webhook-url <url>`

### 41.3 Jira Integration

- [ ] When a scan finds HIGH or CRITICAL findings, auto-create Jira issues:
  - One Jira issue per finding (or one issue per scan with all findings as sub-tasks)
  - Issue type: "Security Bug"
  - Fields: Summary = finding message, Description = full finding detail + remediation, Priority = mapped from severity, Labels = ["security", "armur", tool-name]
  - Link to the affected file/line in the Jira description
- [ ] `armur config jira --url <jira-url> --project <key> --token <pat>` — configure Jira connection
- [ ] `armur jira sync --task <scan-id>` — manually sync findings to Jira
- [ ] Deduplication: don't create a Jira issue for a finding that already has an open issue (match by finding fingerprint)
- [ ] Auto-close Jira issues when findings are resolved in subsequent scans

### 41.4 Linear Integration

- [ ] Auto-create Linear issues for findings (same logic as Jira):
  - Use Linear's GraphQL API
  - Map finding severity to Linear priority (Urgent/High/Medium/Low)
  - Add label "security" automatically
- [ ] `armur config linear --token <token> --team <team-id>` — configure Linear connection
- [ ] `armur linear sync --task <scan-id>` — sync findings to Linear

### 41.5 GitHub Issues Auto-Creation

- [ ] `armur config github-issues --repo <owner/repo> --token <pat>` — configure GitHub Issues sink
- [ ] On scan completion: create one GitHub Issue per CRITICAL/HIGH finding:
  - Title: `[Armur] <severity>: <short-message> in <file>`
  - Label: `security`, `armur`, `<severity>`
  - Body: full finding detail, code snippet, remediation, link to PR if applicable
- [ ] `armur github sync --task <scan-id>` — manual sync

### 41.6 PagerDuty Alerting

- [ ] Trigger PagerDuty incidents for CRITICAL findings in production repos
- [ ] `armur config pagerduty --service-key <key> --trigger-on critical` — configuration
- [ ] Include finding details in the PagerDuty incident description
- [ ] Auto-resolve PagerDuty incident when the finding is fixed in a subsequent scan

---

## Sprint 42 — Security Posture Badges & Social Proof

Badges are a viral mechanism. Every GitHub README with an Armur badge is an ad for Armur.

### 42.1 Dynamic Security Score Badge

- [ ] Host a badge service at `badge.armur.ai`:
  - `GET https://badge.armur.ai/<owner>/<repo>.svg` → SVG badge with current posture score
  - Badge styles: flat, flat-square, plastic (same as shields.io)
  - Colors: green (A/B), yellow (C), orange (D), red (F)
- [ ] Badge content: `armur | A · 94` (grade + score) or `armur | 0 critical` (zero critical variant)
- [ ] Badge is updated after every scan of the repo (GitHub App triggers the update)
- [ ] `armur badge generate` — prints the Markdown and HTML for embedding the badge in README
- [ ] Generate badges for the most common formats:
  ```markdown
  <!-- Standard -->
  [![Armur Security Score](https://badge.armur.ai/owner/repo.svg)](https://armur.ai/scan/owner/repo)
  <!-- Zero-critical variant -->
  [![Zero Critical Findings](https://badge.armur.ai/owner/repo/critical.svg)](https://armur.ai/scan/owner/repo)
  ```

### 42.2 Public Scan Results Page

- [ ] Host `armur.ai/scan/<owner>/<repo>` — public findings summary page for open source repos
- [ ] Page shows: posture grade, severity breakdown, top 10 findings (by risk score), trend over last 30 scans
- [ ] Social sharing: "Share this scan" → Twitter/X, LinkedIn, Bluesky with pre-written message + badge
- [ ] "Verify" button: lets a repo maintainer claim the scan and add their own notes
- [ ] Embed widget: `<iframe src="https://armur.ai/embed/<owner>/<repo>">` — security summary card embeddable in project websites

### 42.3 Armur Security Leaderboard

- [ ] Public leaderboard at `armur.ai/leaderboard` showing top-100 most secure open source repos
- [ ] Ranked by: posture score, zero-critical streak (consecutive scans with zero critical findings), MTTR
- [ ] Weekly "Most Improved" section: repos that improved their score the most in the last 7 days
- [ ] Opt-in for open source repos: scan with `armur run --public` to appear on the leaderboard
- [ ] Share your rank: "This repo is #47 in the Armur Security Leaderboard 🛡" — shareable card

### 42.4 README Security Section Generator

- [ ] `armur readme generate` — generates a "Security" section for the project README:
  ```markdown
  ## Security

  This project uses [Armur](https://armur.ai) for automated security scanning.

  [![Armur Security Score](https://badge.armur.ai/owner/repo.svg)](https://armur.ai/scan/owner/repo)

  To run a security scan locally:
  \`\`\`bash
  armur run .
  \`\`\`

  Found a vulnerability? Please see our [security policy](SECURITY.md).
  ```
- [ ] `armur readme update` — automatically inserts or updates the Security section in the existing README

---

## Sprint 43 — Armur Cloud (Hosted SaaS)

Some users will not want to run their own server. Armur Cloud removes all infrastructure friction
and adds team collaboration features that are impractical to self-host.

### 43.1 Cloud Infrastructure

- [ ] Deploy the Armur server to a managed cloud environment (Fly.io or Railway for simplicity):
  - API server: horizontally scalable (stateless Gin server)
  - Workers: Asynq workers (scalable independently from API)
  - Redis: managed Redis instance
  - Storage: object storage (S3-compatible) for scan results and SBOMs
- [ ] Custom domain: `api.armur.ai`
- [ ] Status page: `status.armur.ai` (Uptime monitoring with public status)
- [ ] Multi-region: at minimum US and EU (for GDPR compliance)

### 43.2 Web Dashboard

- [ ] Build `app.armur.ai` — the Armur Cloud web dashboard
- [ ] Pages:
  - **Dashboard**: recent scans, posture score trend, critical findings requiring attention
  - **Scans**: list of all scans with status, date, target, finding counts; trigger new scan
  - **Findings**: unified findings table across all repos with filter/sort/search
  - **Repositories**: list of connected repositories with their current posture score
  - **Reports**: generate and download reports for any past scan
  - **Settings**: API keys, team members, notification config, `.armur.yml` editor
- [ ] Built with: Next.js + Tailwind CSS (or equivalent — keep the stack simple)
- [ ] Real-time scan progress via WebSocket (same SSE events as the CLI TUI)
- [ ] Mobile-responsive design

### 43.3 GitHub / GitLab OAuth Login

- [ ] GitHub OAuth: "Sign in with GitHub" — scopes: `user:email`, `read:org`, `repo` (for private repo scanning)
- [ ] GitLab OAuth: "Sign in with GitLab"
- [ ] On first login: show connected repositories (via GitHub API); offer one-click scan for any repo
- [ ] Auto-install the GitHub App when the user first connects a repository

### 43.4 Cloud API

- [ ] Cloud API at `api.armur.ai` — same REST API as the self-hosted server, fully backward compatible
- [ ] API key per user (generated on signup)
- [ ] CLI works with Armur Cloud by setting: `armur config api-url https://api.armur.ai`
- [ ] `armur login` command: opens browser for OAuth, stores token, automatically sets API URL to cloud

### 43.5 Pricing Tiers

- [ ] **Free tier**: 10 scans/month, public repos only, community tools only, results retained 7 days
- [ ] **Pro tier** ($0/month for open source, $15/month for private repos): unlimited scans, all tools, results retained 90 days, Slack/email notifications, 1 user
- [ ] **Team tier** ($49/month): everything in Pro + 5 users, RBAC, Jira/Linear integration, 1-year retention
- [ ] **Enterprise**: custom pricing, SSO, self-hosted option, SLA, dedicated support
- [ ] Open source projects: free Pro tier (verified via GitHub stars + license check)

---

## Sprint 44 — Developer Onboarding & First-Run Experience

The first 5 minutes with Armur determine whether a developer uses it again. This sprint focuses
entirely on making those first 5 minutes remarkable.

### 44.1 `armur quickstart` Interactive Onboarding

- [ ] `armur quickstart` — runs the first time `armur` is installed (also accessible anytime)
- [ ] Steps:
  1. "Welcome to Armur! Let's get you set up in 2 minutes."
  2. Run `armur doctor` inline — show which tools are installed
  3. Detect if the current directory is a git repo; offer to scan it immediately
  4. Run a 30-second quick scan with a beautiful live TUI progress display
  5. Show the summary card with findings
  6. Ask: "Set up automatic scanning on git push? (Y/n)"
  7. If yes: run `armur setup pre-commit` automatically
  8. "You're all set! Here's what to do next:" + 3 actionable next steps
- [ ] On first scan: open the interactive results browser so users see the TUI experience immediately
- [ ] After quickstart: create `~/.armur/profile.json` marking onboarding as complete (skip on subsequent runs)

### 44.2 `armur tutorial` Interactive Learning Mode

- [ ] `armur tutorial` — walkthrough that teaches how to use Armur with a practice repo
- [ ] Downloads a sample vulnerable repo (`armur-ai/juice-shop-go` or similar)
- [ ] Guided steps:
  1. "Let's run a quick scan." → `armur run . --depth quick` with annotations
  2. "Here's a SQL injection. Let's understand it." → `armur explain <id>`
  3. "Let's fix it with AI." → `armur fix <id>`
  4. "Now let's check our dependencies." → `armur run . --sca-only`
  5. "Set up CI." → `armur setup github-actions`
- [ ] Each step waits for the user to complete the action (or press Enter to skip)
- [ ] Completion message: "You've completed the Armur tutorial! 🎉" + share result card

### 44.3 MOTD & Contextual Tips

- [ ] After each scan, show one contextual tip related to the findings:
  - If secrets found: "Tip: Run `armur scan --history` to check your git history for leaked secrets"
  - If SCA findings: "Tip: Set up `armur setup pre-commit` to catch vulnerable deps before pushing"
  - If zero findings: "✓ Clean scan! Add `armur scan --depth deep` to your nightly CI for thorough coverage"
- [ ] Tips shown at most once per day; dismissible; opt-out in settings

### 44.4 `armur setup` Command Family

A unified setup wizard for every integration, so developers never have to read docs to connect things.

- [ ] `armur setup` — interactive menu listing all available integrations:
  ```
  armur setup
  ──────────────────────────────
  What would you like to set up?

  > Claude Code (MCP integration)
    VS Code extension
    GitHub Actions
    GitLab CI
    Pre-commit hook
    Slack notifications
    Jira integration
    Custom server
  ```
- [ ] `armur setup github-actions` — detects GitHub repo, generates `.github/workflows/armur.yml`, commits it
- [ ] `armur setup gitlab-ci` — adds include block to `.gitlab-ci.yml`
- [ ] `armur setup pre-commit` — adds Armur hook to `.pre-commit-config.yaml` or creates one
- [ ] `armur setup slack` — prompts for webhook URL, sends a test message, saves config
- [ ] `armur setup jira` — prompts for Jira URL + token, tests connection, saves config
- [ ] Each setup command ends with: "✓ Set up complete. Test it with: <command>"

---

## Sprint 45 — Community, Content & Growth Flywheel

Tools become category leaders not just from features, but from community, content, and
making contributors successful. This sprint builds the ecosystem around Armur.

### 45.1 armur.ai Website

- [ ] Landing page at `armur.ai`:
  - Hero: animated terminal demo showing `armur run .` in action (asciinema embed or GIF)
  - "Scan any codebase in 30 seconds" headline
  - Language/IaC coverage grid (all supported tools + ecosystems with icons)
  - Comparison table: Armur vs Semgrep vs SonarQube vs Snyk (open source features)
  - Live demo: paste a code snippet, get instant findings (powered by `armur_scan_code` MCP tool / Cloud API)
  - Testimonials from real users / contributor quotes
  - "Get started" CTA: `brew install armur-ai/tap/armur`
- [ ] Pricing page at `armur.ai/pricing` (maps to Sprint 43.5 tiers)
- [ ] Blog at `armur.ai/blog` — technical content driving SEO

### 45.2 Documentation Site

- [ ] Deploy docs at `docs.armur.ai` (using Docusaurus or Nextra — React-based, great SEO)
- [ ] Sections:
  - **Getting Started** (5-minute quickstart — must work end-to-end in one terminal session)
  - **CLI Reference** (every command, every flag, every config option)
  - **Tool Reference** (what each of the 18+ tools does, what it detects, version requirements)
  - **Language Support** (per-language tool coverage matrix)
  - **IaC Support** (per-IaC platform coverage matrix)
  - **Configuration** (`.armur.yml` full reference)
  - **CI/CD Integrations** (GitHub Actions, GitLab, CircleCI, Jenkins, etc.)
  - **MCP Integration** (Claude Code, Cursor, Windsurf, Claude Desktop)
  - **API Reference** (OpenAPI spec rendered with Scalar or Redoc)
  - **Rules Marketplace** (how to install, create, and share rules)
  - **Contributing** (how to add a new tool, new language, new compliance rule)
- [ ] Search: Algolia DocSearch (free for open source)
- [ ] Versioned docs: separate docs for each major CLI version

### 45.3 Demo Content

- [ ] **asciinema demo**: record a 90-second terminal demo of `armur run .` on a real vulnerable repo — embed on landing page and README
- [ ] **YouTube channel**: `youtube.com/@armur-ai`
  - Video 1: "Find security vulnerabilities in your code in 30 seconds" (5 min quickstart)
  - Video 2: "Armur + Claude Code: AI-powered security scanning" (MCP integration demo)
  - Video 3: "How to add Armur to your GitHub Actions CI pipeline" (3 min tutorial)
  - Video 4: "Scanning a vulnerable Node.js app with Armur" (real-world demo)
- [ ] **Dev.to & Hashnode**: write introductory articles with embedded demos; cross-post
- [ ] **Product Hunt launch**: submit when v1.0.0 ships; prepare launch assets (logo, screenshots, tagline)

### 45.4 Discord Community

- [ ] Create Armur Discord server at `discord.gg/armur`
- [ ] Channels: `#announcements`, `#help`, `#showcase` (share your scan results), `#rules-marketplace`, `#contributors`, `#general`
- [ ] Discord bot (`@Armur Bot`): `/scan <github-url>` triggers a scan from within Discord; posts results in thread
- [ ] Weekly "Security of the Week" post: scan a popular open source repo, share interesting findings in `#showcase`
- [ ] Contributor office hours: weekly 30-minute voice call for contributors to ask questions

### 45.5 Contributor Program

- [ ] `CONTRIBUTING.md` with a step-by-step guide: add a new tool, add a new language, add a compliance rule
- [ ] "Good First Issues" tagged in GitHub Issues for newcomers
- [ ] **Bounty program**: defined bounties for specific contributions:
  - New tool integration (complete with tests + testdata): $50–200 depending on complexity
  - New language support (full suite): $200–500
  - New compliance framework mapping: $100–300
  - Bug with reproduction case + fix: $25–100
- [ ] **Security Hall of Fame**: contributors who report vulnerabilities in Armur itself
- [ ] Contributor recognition: GitHub Sponsors profile, contributor badge in Discord, mention in release notes
- [ ] `SECURITY.md` with responsible disclosure policy and contact email

### 45.6 "Scan Open Source" Program

- [ ] `armur.ai/open-source` — program that scans popular open source projects monthly and publishes results publicly (with maintainer notification)
- [ ] Reports published as blog posts: "Security analysis of the top 100 Go projects"
- [ ] Responsible disclosure: findings shared privately with maintainers 30 days before publishing
- [ ] This generates high-quality SEO content, press coverage, and demonstrates Armur's capabilities at scale
- [ ] Partner with CNCF, Apache Foundation, and similar orgs for responsible scanning of their projects

---

*Last updated: March 2026*
*Sprints 1–7: original roadmap. Sprints 8–15: CLI/TUI overhaul and core engine. Sprints 16–35: world-class scanner expansion. Sprints 36–45: distribution, adoption, and community flywheel — added March 2026.*

---

## Sprint 46 — Privacy Mode, Local LLM & Air-Gapped Enterprise Support

The AI features in Sprint 30 (`armur explain`, `armur fix`, false-positive reduction) all require
sending code to the Claude API. Any company with a data classification policy — banks, governments,
healthcare, defense — will block this immediately. This sprint makes every AI feature work entirely
on-device with no external calls, using locally-running LLMs via Ollama.

### 46.1 Ollama Integration (Local LLM Backend)

- [ ] Add `internal/llm/` package with a provider interface:
  ```go
  type LLMProvider interface {
      Complete(ctx context.Context, prompt string) (string, error)
      Stream(ctx context.Context, prompt string) (<-chan string, error)
  }
  ```
- [ ] Implement `AnthropicProvider` — wraps existing Claude API calls (current behavior)
- [ ] Implement `OllamaProvider` — calls the Ollama local API (`http://localhost:11434/api/generate`):
  - Auto-detect if Ollama is running: `GET http://localhost:11434/api/tags`
  - Default model: `deepseek-coder-v2` (best for code security tasks; alternatives: `codellama`, `mistral`, `llama3.1`)
  - Configurable via `ARMUR_LLM_MODEL` env var or `.armur.yml: ai.model: deepseek-coder-v2`
  - Stream token output to the terminal in real time
- [ ] Implement `OpenAICompatibleProvider` — any OpenAI-compatible API endpoint (LM Studio, vLLM, Together.ai, Groq)
  - Config: `ARMUR_LLM_BASE_URL`, `ARMUR_LLM_API_KEY`, `ARMUR_LLM_MODEL`
- [ ] Provider selection order: explicit config → env var `ARMUR_LLM_PROVIDER` → auto-detect (Ollama if running, else Claude API if key set, else error)
- [ ] `armur config ai --provider ollama --model deepseek-coder-v2` — configure AI provider interactively

### 46.2 `--offline` Mode

- [ ] `--offline` global flag: when set, Armur makes zero external network calls
  - No Claude API calls
  - No OSV API queries (use local vulnerability database cache if available)
  - No badge server pings
  - No telemetry (already off by default; this makes it explicit)
  - Scan still runs fully; only AI features and online lookups are disabled
- [ ] `.armur.yml: offline: true` — project-level offline enforcement
- [ ] `ARMUR_OFFLINE=true` env var — enforcement for CI environments without outbound internet
- [ ] `armur explain` and `armur fix` in offline mode: use Ollama if running; otherwise print actionable error "Install Ollama or set ARMUR_LLM_BASE_URL for offline AI assistance"

### 46.3 Local Vulnerability Database Cache

- [ ] `armur db update` — download the OSV vulnerability database to `~/.armur/vuln-db/` (SQLite)
  - Downloads all OSV advisories for Go, npm, PyPI, crates.io, Maven, RubyGems, etc.
  - Database size: ~300MB for all ecosystems; supports incremental updates
- [ ] `armur db update --ecosystem go,npm` — update only specific ecosystems
- [ ] SCA checks in `--offline` mode use the local DB instead of the OSV API
- [ ] Show DB freshness warning if local DB is > 24h old when running SCA scans
- [ ] Auto-update DB in the background (daily, configurable) when online

### 46.4 Air-Gapped Deployment Guide

- [ ] Document `docs/deployment/air-gapped.md`:
  - How to bundle Armur + all 18 tools + local vuln DB into an offline package
  - How to run the server with no outbound access
  - How to use `armur db update --offline <db-tarball.tar.gz>` to import a pre-downloaded DB
  - How to configure Ollama in air-gapped mode (download models separately, load from file)
- [ ] `armur package air-gap --output armur-offline-bundle.tar.gz` — create a self-contained offline bundle:
  - Armur binary (all platforms)
  - Snapshot of the vuln DB
  - All tool binaries (for the current platform)
  - Docker image tarball
  - Offline install script

### 46.5 Privacy & Telemetry Policy

- [ ] Zero telemetry by default — Armur never phones home
- [ ] Document explicitly in README: "Armur does not collect usage data, scan results, or any code. Everything runs locally unless you explicitly configure Armur Cloud."
- [ ] `--privacy-audit` flag: print a list of every network call that *would* be made during a scan (for enterprise review teams to approve)
- [ ] Code never sent to AI provider when using `armur_scan_code` MCP tool without explicit user consent (warn and require confirmation the first time)

---

## Sprint 47 — OpenSSF Scorecard, CISA KEV & Security Hygiene Metrics

### 47.1 OpenSSF Scorecard Integration

The OpenSSF Scorecard assesses project-level security hygiene — things no SAST/SCA tool checks:
branch protection, signed releases, dependency update automation, CI security, etc. It is
increasingly required by enterprise security procurement and SLSA compliance.

- [ ] **Scorecard CLI** integration: `scorecard --repo <url> --format json`
  - Run against the repository URL (not the local directory)
  - Parse `checks` array: each check has a `name`, `score` (0-10), and `reason`
  - Map checks with score < 5 to findings in a new `security_hygiene` category:
    - `Branch-Protection` score < 5 → HIGH: "Default branch has no protection rules"
    - `Signed-Releases` score < 5 → MEDIUM: "Releases are not cryptographically signed"
    - `Dependency-Update-Tool` score < 5 → MEDIUM: "No automated dependency updates configured (Dependabot/Renovate)"
    - `Token-Permissions` score < 5 → HIGH: "GitHub Actions workflows use excessive token permissions"
    - `Dangerous-Workflow` score < 1 → CRITICAL: "Dangerous CI workflow patterns detected (script injection, untrusted checkout)"
    - `Maintained` score < 1 → INFO: "Project appears unmaintained (no activity in 90 days)"
    - `Pinned-Dependencies` score < 5 → MEDIUM: "CI workflow dependencies are not pinned to commit hashes"
    - `Security-Policy` score < 5 → LOW: "No SECURITY.md or security policy found"
    - `Fuzzing` score < 5 → INFO: "No fuzzing integration found"
    - `SAST` score < 5 → INFO: "No SAST tool detected in CI (but you're using Armur, so fix this!)"
- [ ] Scorecard findings appear in the main results browser under a "Security Hygiene" tab
- [ ] `armur scorecard <repo-url>` — run Scorecard check standalone; print scored checklist
- [ ] Include Scorecard score in the posture score calculation: `final_score = 0.7 × finding_score + 0.3 × scorecard_score`

### 47.2 CISA KEV (Known Exploited Vulnerabilities) Enrichment

The CISA KEV catalog lists CVEs that are being **actively exploited in the wild right now**.
A KEV match is far more urgent than a theoretical CVE with a high CVSS score.

- [ ] Fetch CISA KEV catalog: `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - Cache locally in `~/.armur/cisa-kev.json`; refresh every 6 hours (or daily in offline mode)
  - Catalog contains ~1,200 CVEs (growing) with due dates and affected products
- [ ] During SCA scanning: check every detected CVE against the KEV catalog
  - If match found: upgrade severity to `CRITICAL` regardless of CVSS score
  - Add `Finding.InCISAKEV = true` field
  - Add `Finding.CISADueDate` — the remediation due date CISA recommends for federal agencies
  - Message: "⚠ ACTIVELY EXPLOITED — This CVE is in the CISA Known Exploited Vulnerabilities catalog. Treat as P0."
- [ ] Display KEV findings with a special `[KEV]` badge in the TUI and HTML report
- [ ] `armur db update --kev` — force-refresh the KEV catalog immediately

### 47.3 EPSS (Exploit Prediction Scoring System) Integration

EPSS is a probability score (0–100%) predicting how likely a CVE is to be exploited in the next 30 days. It complements CVSS which measures impact but not likelihood.

- [ ] Fetch EPSS scores from the FIRST.org API: `GET https://api.first.org/data/1.0/epss?cve=CVE-XXXX`
- [ ] Add `Finding.EPSSScore float64` (0.0–1.0) to SCA findings
- [ ] Use EPSS in risk score calculation (Sprint 34.5): `risk = cvss_score × (1 + epss_score) × reachability_multiplier`
- [ ] Display EPSS as a percentage in the results table: "EPSS: 73% (high exploitation probability)"
- [ ] Sort SCA findings by EPSS score by default (highest exploitation probability first)

### 47.4 SLSA Compliance Checking

SLSA (Supply-chain Levels for Software Artifacts) is a framework for supply chain integrity.

- [ ] Check SLSA Level 1 requirements for the scanned repository:
  - Scripted build (CI system detected) → ✓
  - Provenance generated (goreleaser with cosign signing detected) → ✓
  - Signed commits (GPG/SSH commit signing) → check `.gitconfig` or GitHub commit signature status
- [ ] Check SLSA Level 2: hosted build platform + authenticated provenance
- [ ] Report SLSA level achieved and gaps to reach next level
- [ ] `armur slsa --repo <url>` — dedicated SLSA assessment command
- [ ] Include SLSA level in the executive PDF report (Sprint 34.6)

---

## Sprint 48 — DAST: Dynamic Application Security Testing

SAST finds vulnerabilities in code. DAST confirms they are actually exploitable at runtime.
The combination — showing a finding is BOTH in the code AND reachable via HTTP — is uniquely
powerful and something no current open-source tool does end-to-end.

### 48.1 OWASP ZAP Integration (Full-Featured DAST)

- [ ] **ZAP Baseline Scan** integration: passive spider + passive scan (safe, no active attacks)
  - Run: `docker run -t owasp/zap2docker-stable zap-baseline.py -t <url> -J results.json`
  - Parse: `site[].alerts[]` — map `risk` (High/Medium/Low/Informational) and `cweid` to findings
  - Baseline scan is fast (~2 min) and safe to run against production
- [ ] **ZAP Full Scan** integration: active scan (only for non-production targets — add explicit warning)
  - Run: `zap-full-scan.py -t <url> -J results.json`
  - Flag each active scan finding with `Finding.DynamicConfidence = "confirmed"` (vs SAST's `"static"`)
- [ ] `armur scan --url <http://localhost:8080>` — trigger DAST scan against a running service
- [ ] `armur scan --url <url> --depth quick` → ZAP baseline; `--depth deep` → ZAP full scan
- [ ] DAST findings land in the same results pipeline as SAST/SCA findings
- [ ] New `Finding.Source` field: `"sast"` | `"dast"` | `"sca"` | `"secrets"` | `"iac"` | `"hygiene"`

### 48.2 Nuclei Integration (Fast Template-Based DAST)

- [ ] **Nuclei** integration (ProjectDiscovery's vulnerability scanner — 9,000+ templates)
  - Run: `nuclei -u <url> -j -severity medium,high,critical -o results.json`
  - Parse `info.severity`, `templateID`, `matched-at`, `extracted-results` from each finding
  - Nuclei templates cover: CVE exploitation, exposed panels, misconfigurations, exposed credentials
  - Much faster than ZAP for known CVE checks (seconds vs minutes)
- [ ] `armur scan --url <url> --dast-engine nuclei` — use Nuclei instead of ZAP
- [ ] Combine both: `--dast-engine both` — run Nuclei first (fast), then ZAP baseline (thorough)

### 48.3 SAST + DAST Correlation (Unique Feature)

The real power: linking a SAST finding (line of code) to a DAST finding (HTTP endpoint) that confirms the same vulnerability is reachable.

- [ ] After both SAST and DAST scans complete: run a correlation pass
  - Match SAST SQL injection findings against DAST SQL injection findings by endpoint
  - Match SAST XSS findings against DAST XSS findings by endpoint
  - When a match is found: create a `CorrelatedFinding` with both `SASTFinding` and `DASTFinding`
  - `CorrelatedFinding.Severity` → always CRITICAL (confirmed exploitable in running code)
- [ ] Display correlated findings with a `[CONFIRMED]` badge in the TUI: "SQL Injection in user.go:42 — confirmed exploitable at POST /api/users"
- [ ] Correlated findings prioritized at the top of all result views
- [ ] Include correlated findings section in the HTML and PDF reports

### 48.4 DAST in CI/CD

- [ ] `armur scan --url <url>` works in CI: deploys the app to a temporary environment, runs DAST, tears down
- [ ] GitHub Action input: `dast-url` — if provided, runs DAST scan against this URL after SAST
- [ ] Document the pattern: build → deploy to staging → `armur scan --url https://staging.example.com` → fail CI if findings
- [ ] ZAP Authentication: support form-based login config for scanning authenticated endpoints:
  ```yaml
  dast:
    target: "http://localhost:8080"
    auth:
      type: form
      login-url: "/login"
      username-field: "email"
      password-field: "password"
      credentials:
        username: "${DAST_USER}"
        password: "${DAST_PASS}"
  ```

---

## Sprint 49 — Mobile Application Security (Android & iOS)

Mobile apps represent a massive and under-secured attack surface. There are almost no
good open-source mobile security scanners with a modern CLI. Armur owning this space is achievable.

### 49.1 MobSF Integration (Android + iOS Static Analysis)

- [ ] **MobSF** (Mobile Security Framework) integration — the gold standard for mobile SAST:
  - Run MobSF as a Docker container: `docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf`
  - Upload APK/IPA via MobSF REST API: `POST /api/v1/upload`
  - Trigger scan: `POST /api/v1/scan`; poll for completion
  - Download JSON report: `POST /api/v1/report_json`
  - Parse findings from `android_api_analysis`, `manifest_analysis`, `binary_analysis`, `code_analysis`
- [ ] `armur scan --apk <file.apk>` — scan Android APK
- [ ] `armur scan --ipa <file.ipa>` — scan iOS IPA
- [ ] New finding categories for mobile:
  - `mobile_manifest` — insecure AndroidManifest.xml / Info.plist settings
  - `mobile_data_storage` — insecure local data storage (SharedPreferences, SQLite, external storage)
  - `mobile_network` — insecure network communications (cleartext, missing certificate pinning)
  - `mobile_crypto` — weak cryptography (MD5, SHA1, ECB mode, hardcoded keys)
  - `mobile_code` — code vulnerabilities (eval, reflection, dynamic code loading)
  - `mobile_permissions` — dangerous permission requests without justification

### 49.2 Android-Specific Tools

- [ ] **apkleaks** integration (extract hardcoded secrets from APKs):
  - Run: `apkleaks -f <file.apk> -o results.json`
  - Parse findings; map to `secret_detection` category
- [ ] **jadx** decompilation (for source-level analysis of APKs):
  - Decompile: `jadx -d <output-dir> <file.apk>`
  - Run Semgrep on the decompiled Java/Kotlin source
  - Run all applicable Java/Kotlin SAST tools on the decompiled code
- [ ] **androguard** integration (Android malware detection and reverse engineering):
  - Run: `androguard analyze -i <file.apk> --json`
  - Check for: dynamic code loading, reflection abuse, root detection bypass patterns

### 49.3 iOS-Specific Tools

- [ ] **objection** runtime analysis support — document how to use Armur findings with Objection for runtime validation
- [ ] **ipatool** — extract IPA from App Store for scanning (with appropriate auth)
- [ ] Binary analysis: extract strings from IPA binaries for hardcoded secrets
- [ ] Entitlements analysis: parse the `.entitlements` file; flag dangerous entitlements (com.apple.developer.icloud-container-environment, get-task-allow)

### 49.4 Certificate Pinning & Network Security Analysis

- [ ] Parse `network_security_config.xml` (Android) — flag missing or overly broad certificate pinning
- [ ] Parse `NSAppTransportSecurity` dict in `Info.plist` (iOS) — flag `NSAllowsArbitraryLoads: true`
- [ ] Detect HTTP URLs hardcoded in mobile app code (as opposed to HTTPS)
- [ ] Flag self-signed certificate acceptance patterns in network code

### 49.5 Mobile CI Integration

- [ ] GitHub Action: detect APK/IPA in the repo or build artifacts; automatically run mobile scan
- [ ] `armur scan <dir>` auto-detection: if `.apk` or `.ipa` files are found in the directory, offer to run mobile scan
- [ ] `armur report mobile --task <id>` — generate a mobile-specific OWASP MASVS (Mobile Application Security Verification Standard) compliance report

---

## Sprint 50 — Security Regression Prevention, Verified Fixes & SLA Enforcement

Security fixes that silently reappear are a major enterprise pain point. This sprint makes Armur
into an active security guardian — not just a reporter — by verifying fixes, preventing regressions,
and enforcing remediation timelines.

### 50.1 Verified Fix Workflow

When `armur fix --apply <id>` applies a patch, automatically re-scan to confirm the fix worked.

- [ ] After `armur fix --apply <finding-id>`:
  1. Apply the patch to the file
  2. Immediately re-scan only the patched file (`armur scan --file <path> --in-process`)
  3. Check if the original finding is gone
  4. Check if the patch introduced any new findings
  5. Report result:
     - ✓ "Finding resolved. No new issues introduced." → delete the original finding from history
     - ✗ "Finding still present. The patch may be incomplete." → show the re-scan result
     - ⚠ "Finding resolved but 1 new issue introduced." → show the new finding
- [ ] Add `--verify` flag to `armur fix --apply --verify` to make verification explicit
- [ ] Verified fixes are marked with `Finding.Status = "verified_fixed"` in the history DB

### 50.2 Security Regression Detection

A regression is when a previously-fixed finding reappears in a new scan.

- [ ] On each scan completion: compare findings against the previous scan for the same target
  - New findings (in current scan, not in previous): mark as `NEW` (shown in red in the TUI)
  - Regressed findings (fixed in a previous scan, back in current): mark as `REGRESSED` (shown in purple)
  - Resolved findings (in previous scan, not in current): mark as `FIXED` (shown in green)
  - Persistent findings (in both): mark as `OPEN`
- [ ] Regression findings are automatically promoted one severity level (a regressed MEDIUM becomes HIGH — regression implies the team ignored a fix)
- [ ] CI integration: `--fail-on-regression` flag — fail the CI build if any previously-fixed finding reappears
- [ ] `armur compare --regression <task-id>` — show only regressed findings between two scans

### 50.3 "Never Allow" Rules (Hard Security Gates)

Some vulnerabilities must never appear in a codebase — ever. Armur should enforce this as a
hard gate, distinct from severity thresholds.

- [ ] `.armur.yml` `never-allow` configuration:
  ```yaml
  never-allow:
    - rule: "gosec.G401"      # MD5 usage — never acceptable
      message: "MD5 is cryptographically broken. Use SHA-256 or better."
    - cwe: "CWE-89"           # SQL injection — never acceptable
    - category: "secret_detection"  # hardcoded secrets — never acceptable
    - tool: "trufflehog"      # any trufflehog finding
  ```
- [ ] If a `never-allow` finding is detected: exit code 2 (distinct from the normal exit code 1 for threshold violations)
- [ ] In CI: `never-allow` violations block merge regardless of PR author permissions — this is a hard gate
- [ ] `armur never-allow add <rule-id>` — add a rule to the never-allow list interactively
- [ ] Display `never-allow` violations at the top of all results with a `[BLOCKED]` badge

### 50.4 SLA Tracking & Enforcement

Security findings have deadlines. Tracking whether teams meet them is essential for compliance.

- [ ] Define SLA policies in `.armur.yml` or via the web dashboard:
  ```yaml
  sla:
    critical: 1d      # 1 business day
    high: 7d          # 7 calendar days
    medium: 30d       # 30 calendar days
    low: 90d          # 90 calendar days
    info: 180d        # 6 months
  ```
- [ ] When a finding first appears: record `Finding.DetectedAt` timestamp in the history DB
- [ ] On each subsequent scan: compute `days_open = now - detected_at`; compare to SLA
- [ ] SLA breach: finding is past its deadline → mark as `SLA_BREACHED`, promote severity by one level
- [ ] SLA warning: finding is within 20% of its deadline → mark as `SLA_WARNING`
- [ ] `armur sla report` — print a table of all open findings with days remaining / days overdue
- [ ] SLA breach notifications: Slack/Teams/email alert when a finding enters SLA_BREACHED state
- [ ] SLA compliance rate: `armur sla stats` — "72% of HIGH findings were fixed within SLA in the last 90 days"
- [ ] Include SLA compliance rate in the executive PDF report (Sprint 34.6)

### 50.5 Security Debt Tracker

Security debt is the accumulation of known issues that have been deferred. Quantifying it helps
teams prioritize and helps management understand risk.

- [ ] Compute security debt score: `debt = Σ (severity_weight × days_open)` for all open findings
  - CRITICAL × 20 per day, HIGH × 10 per day, MEDIUM × 3 per day, LOW × 1 per day
- [ ] `armur debt` — print the current security debt score + trend (increasing/decreasing)
- [ ] Display security debt trend in the HTML report: sparkline of debt score over last 30 scans
- [ ] "Debt payoff planner": given the current team velocity (avg fixes per sprint), estimate how many sprints to reach zero critical debt
- [ ] Alert when security debt score increases by > 20% in a single week (sudden new vulnerabilities introduced)

---

*Last updated: March 2026*
*Sprints 1–7: original roadmap. Sprints 8–15: CLI/TUI overhaul and core engine. Sprints 16–35: world-class scanner expansion. Sprints 36–45: distribution, adoption, and community flywheel. Sprints 46–50: enterprise hardening, privacy, DAST, mobile, and security governance — added March 2026.*

---

## Sprint 51 — Documentation, README & CLI Reference

Documentation is a first-class product. A developer who can't figure out how to use a tool in
5 minutes will not use it. This sprint treats every doc as a user-facing feature and ensures
Armur's documentation is best-in-class — better than Semgrep's, better than Snyk's.

### 51.1 README Complete Rewrite

The current README is minimal. Rewrite it as the primary marketing and onboarding document.

- [ ] **Header section**:
  - Project logo (SVG, dark + light mode variants)
  - One-line tagline: "The open-source security scanner that covers everything — SAST, SCA, secrets, IaC, containers, and more."
  - Badge row: build status · test coverage · Go Report Card · Docker pulls · license · Armur score · latest release
  - Animated asciinema demo GIF embedded directly in the README (shows `armur run .` from zero to findings in 30 seconds)

- [ ] **Quick Start section** (works end-to-end in a single terminal session):
  ```bash
  # Install
  brew install armur-ai/tap/armur           # macOS/Linux
  # or: npm install -g @armur/cli           # via npm
  # or: curl -fsSL https://install.armur.ai | sh  # universal

  # Scan your project (no config needed)
  cd your-project
  armur run .

  # Scan a GitHub repository
  armur run https://github.com/org/repo

  # Check dependencies only
  armur run . --sca-only

  # Scan a Docker image
  armur scan --image nginx:latest
  ```

- [ ] **What Armur detects** — visual grid showing all categories with icons:
  | Category | Description | Example Tools |
  |----------|-------------|---------------|
  | SAST | Code vulnerabilities | semgrep, gosec, bandit, eslint |
  | SCA | Vulnerable dependencies | osv-scanner, govulncheck, cargo-audit |
  | Secrets | Hardcoded credentials | gitleaks, trufflehog |
  | IaC | Cloud misconfigs | tfsec, checkov, kube-linter |
  | Containers | Image vulnerabilities | trivy, grype |
  | DAST | Runtime exploitability | zap, nuclei |
  | Mobile | APK/IPA analysis | mobsf, apkleaks |

- [ ] **Language support matrix** — table of every supported language with tool names and coverage level (✓ full / ~ partial / planned):
  | Language | SAST | SCA | Secrets | Quality |
  |----------|------|-----|---------|---------|
  | Go | ✓ | ✓ | ✓ | ✓ |
  | Python | ✓ | ✓ | ✓ | ✓ |
  | ... etc |

- [ ] **Command reference summary** — all top-level commands in one table:
  | Command | Description |
  |---------|-------------|
  | `armur run [target]` | Scan with interactive TUI (recommended) |
  | `armur scan [target]` | Non-interactive scan |
  | `armur explain <id>` | AI explanation of a finding |
  | `armur fix <id>` | AI-generated code patch |
  | `armur doctor` | Check prerequisites |
  | `armur history` | Browse past scans |
  | `armur report <format>` | Generate reports |
  | `armur rules` | Manage detection rules |
  | `armur setup <integration>` | Configure integrations |
  | `armur serve` | Start local server |
  | `armur mcp` | Start MCP server for AI editors |

- [ ] **CI/CD integration snippets** — ready-to-paste code blocks for the 5 most common CI systems
- [ ] **How it works** — 4-step architecture diagram (ASCII art or SVG): Code → Tools → Results → Report
- [ ] **FAQ section** in the README (top 5 most-asked questions with short answers):
  - "Does Armur send my code anywhere?" → No. Everything runs locally by default.
  - "Do I need Docker?" → No. `armur run --in-process` works with zero infrastructure.
  - "How is Armur different from Semgrep/Snyk?" → One tool that covers all categories; MCP integration; better TUI.
  - "Can I use it in CI without a server?" → Yes. Use `armur scan --in-process`.
  - "Is it free?" → Yes. MIT license. Armur Cloud has a free tier for open source.
- [ ] **Contributing** and **License** sections at the bottom
- [ ] Keep README under 500 lines — use "Read the docs" links for detail rather than embedding everything

### 51.2 CLI Command Reference (In-Tool `--help` + Online Docs)

Every command and flag must be self-documenting inside the tool itself, not just in external docs.

- [ ] **Rich `--help` output for every command** — include:
  - Short description (one line)
  - Full description (2–3 sentences explaining when to use this command)
  - At least 3 usage examples with real-world scenarios
  - Flag descriptions that explain *why* you'd use the flag, not just what it does
  - Link to online docs at the bottom: `Docs: https://docs.armur.ai/cli/<command>`

  Example for `armur run`:
  ```
  armur run — Scan a target with the full interactive TUI experience

  Opens a multi-step wizard to configure your scan, then shows a live progress
  dashboard while tools run, and an interactive results browser when complete.
  This is the recommended entry point for all new users.

  Usage:
    armur run [target] [flags]

  Arguments:
    target    File, directory, or git URL to scan.
              Defaults to the current directory if omitted.

  Examples:
    armur run                          # scan current directory (auto-detects everything)
    armur run ./my-project             # scan a specific directory
    armur run https://github.com/org/repo  # scan a remote repository
    armur run . --depth deep           # deep scan with all tools
    armur run . --diff HEAD~1          # scan only files changed since last commit
    armur run . --sca-only             # dependency vulnerabilities only
    armur run . --fail-on-severity high  # exit 1 if any HIGH+ findings (for CI)

  Flags:
    -d, --depth string          Scan depth: quick (default) or deep
    -l, --language string       Override auto-detected language
        --diff string           Only scan files changed since this git ref
        --sca-only              Run SCA (dependency) tools only
        --dast-url string       Also run DAST scan against this URL
        --fail-on-severity      Exit 1 if findings at or above this level
        --min-severity string   Hide findings below this level in output
        --output string         Output format: text (default), json, sarif
        --save-report           Save report to ~/.armur/reports/
        --in-process            Run without a server (no Docker/Redis needed)
        --offline               Disable all external network calls
        --watch                 Re-scan on file changes

  Docs: https://docs.armur.ai/cli/run
  ```

- [ ] Apply the same rich `--help` treatment to all commands:
  - [ ] `armur scan` — non-interactive version with all flags documented + examples
  - [ ] `armur explain <id>` — with example output shown in --help
  - [ ] `armur fix <id>` — document --apply, --pr, --verify flags with examples
  - [ ] `armur doctor` — explain what each check does in --help
  - [ ] `armur history` / `armur history show` / `armur history clear`
  - [ ] `armur compare <id1> <id2>`
  - [ ] `armur report html|csv|markdown|pdf|sarif|owasp|pci|cwe`
  - [ ] `armur rules list|install|update|remove|create|test|validate`
  - [ ] `armur setup <integration>`
  - [ ] `armur serve` / `armur serve stop`
  - [ ] `armur mcp` — explain MCP protocol and link to integration guides
  - [ ] `armur config` — document every key with allowed values and defaults
  - [ ] `armur init` — explain every generated .armur.yml field
  - [ ] `armur sla report|stats`
  - [ ] `armur debt`
  - [ ] `armur scorecard`
  - [ ] `armur sbom`
  - [ ] `armur badge generate`
  - [ ] `armur version --check`

- [ ] **`armur help` interactive browser** — when `armur help` is run with no args, show a
  Bubbletea-powered searchable list of all commands with descriptions; press Enter to expand
  the full help for that command

### 51.3 docs.armur.ai — The Documentation Site

Full reference docs deployed at `docs.armur.ai`. Every page must be accurate, copyable, and searchable.

- [ ] **Getting Started** (5-minute quickstart):
  - [ ] Page 1: Installation (all methods: brew, npm, pip, curl, Docker, from source)
  - [ ] Page 2: First scan — `cd my-project && armur run .` with annotated screenshot of TUI output
  - [ ] Page 3: Understanding results — what each category means, what to fix first
  - [ ] Page 4: Setting up CI — paste-ready GitHub Actions snippet
  - [ ] Page 5: What's next — links to deeper topics

- [ ] **CLI Reference** (auto-generated from cobra's command tree + hand-written examples):
  - One page per top-level command
  - Each page: description, usage syntax, all flags with types/defaults, 5+ examples, related commands
  - Examples use real-world scenarios, not toy inputs
  - Include expected output (truncated) for each example

- [ ] **Configuration Reference** (`.armur.yml` full spec):
  - Every field documented with: type, default, description, example value, which sprint introduced it
  - Organized by section: `scan`, `tools`, `exclude`, `output`, `secrets`, `licenses`, `sla`, `never-allow`, `plugins`, `dast`, `ai`
  - Full annotated example `.armur.yml` at the top of the page
  - JSON Schema for `.armur.yml` published at `docs.armur.ai/schema/armur.json` (enables IDE autocompletion)

- [ ] **Tool Reference** — one page per integrated tool (18 initial + all additions):
  - Tool name, homepage, license, version requirement
  - What it detects (with example findings)
  - Which languages it supports
  - How Armur invokes it (the exact command)
  - How to install it manually (for non-Docker deployments)
  - Known limitations and false positive patterns
  - Link to the tool's own documentation

- [ ] **Language Support Guide** — one page per supported language:
  - Which tools run for this language in quick vs deep mode
  - Which SCA ecosystems are supported
  - Setup requirements (e.g. Java needs a JDK to compile before SpotBugs can run)
  - Example `.armur.yml` for this language
  - Sample findings from real projects in this language

- [ ] **IaC & Container Reference** — per-platform pages for Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, etc.

- [ ] **Integrations** — per-integration pages:
  - Claude Code (MCP), Cursor, Windsurf, Claude Desktop
  - VS Code extension
  - GitHub Actions, GitLab CI, CircleCI, Jenkins, Azure DevOps, Bitbucket
  - Slack, Teams, Jira, Linear
  - Pre-commit hook, Husky
  - Armur Cloud

- [ ] **API Reference** — rendered OpenAPI spec:
  - Use Scalar (modern, beautiful) or Redoc for rendering
  - Every endpoint documented with: description, request body, response schema, example cURL call, example response
  - Include authentication section with example API key setup

- [ ] **Architecture Guide** (for contributors and self-hosters):
  - System diagram: CLI → API server → Asynq worker → tool executors → Redis → result store
  - How a scan flows through the system end-to-end
  - How the MCP server works
  - How SSE streaming works
  - Data model: Finding, ScanTask, ScanResult

- [ ] **Deployment Guide**:
  - Docker Compose (quickest — current method)
  - Docker Compose in production (with reverse proxy, TLS, secrets management)
  - Kubernetes deployment with Helm chart
  - Air-gapped / offline deployment
  - High-availability setup (multiple workers, Redis Sentinel)
  - Environment variable reference (every `ARMUR_*` env var documented)

- [ ] **Security Model** page — how Armur handles code security itself:
  - What runs locally vs what goes to cloud
  - How API keys are stored
  - Network calls made during a scan (with `--offline` flag behavior)
  - How to run in fully air-gapped mode
  - Armur's own security posture (we dogfood our own scanner)

### 51.4 Cookbook — Common Workflows as Recipes

Short, copy-paste-ready guides for common real-world scenarios. Each recipe is one page.

- [ ] **Recipe: Secure a Node.js API before launch** — quick scan + SCA + secrets + DAST
- [ ] **Recipe: Add security to a Go microservice** — gosec + govulncheck + trivy in CI
- [ ] **Recipe: Scan a monorepo with 5 services** — `armur run --monorepo` walkthrough
- [ ] **Recipe: Block a PR with high security findings** — GitHub Actions gate setup
- [ ] **Recipe: Find leaked secrets in git history** — `armur scan --history` walkthrough
- [ ] **Recipe: Scan Terraform before `terraform apply`** — pre-apply security gate
- [ ] **Recipe: Audit your Docker image before pushing** — `armur scan --image` workflow
- [ ] **Recipe: Set up weekly security reports via Slack** — scheduled scan + Slack webhook
- [ ] **Recipe: Use Armur in Claude Code for secure coding** — MCP setup walkthrough
- [ ] **Recipe: Fix all CRITICAL findings with AI** — `armur fix --all --severity critical --apply`
- [ ] **Recipe: Migrate from Snyk to Armur** — Snyk → Armur workflow mapping
- [ ] **Recipe: Generate an SBOM for a compliance audit** — `armur sbom` + Dependency-Track
- [ ] **Recipe: Set up SLA enforcement for your team** — SLA config + Slack breach notifications
- [ ] **Recipe: Scan a smart contract before deployment** — Solidity + Slither + Mythril walkthrough

### 51.5 Migration Guides

Developers switching from other tools need a bridge. These guides show exactly how to map
their existing workflow to Armur.

- [ ] **Migrating from Semgrep**:
  - Comparison table: Semgrep concepts → Armur equivalents
  - How to import your existing Semgrep rules into Armur (`armur rules import --from semgrep`)
  - Feature coverage comparison (what Armur adds that Semgrep doesn't: SCA, secrets, IaC, TUI)
  - Side-by-side CLI comparison: `semgrep scan .` vs `armur run .`

- [ ] **Migrating from Snyk**:
  - Snyk vs Armur: what Snyk does that Armur covers, and vice versa
  - Mapping Snyk severity levels to Armur severity levels
  - How to reproduce Snyk's `snyk test` and `snyk code test` with Armur
  - Cost comparison: Snyk Enterprise ($) vs Armur (free + Armur Cloud)

- [ ] **Migrating from SonarQube**:
  - Mapping SonarQube quality gates → Armur `fail-on-severity` and `never-allow`
  - How to replicate SonarQube's language coverage with Armur
  - Self-hosted comparison: SonarQube (JVM + Elasticsearch) vs Armur (Go + Redis — much simpler)

- [ ] **Migrating from Trivy (standalone)**:
  - Trivy is already integrated inside Armur — show how `armur run .` supersedes `trivy fs .`
  - How Armur adds SAST + secrets + IaC on top of what Trivy provides

- [ ] **Migrating from Checkov**:
  - Checkov is already integrated inside Armur — show how `armur run .` supersedes `checkov -d .`
  - What Armur adds: SAST, SCA for application code, secrets, TUI, reports

### 51.6 Troubleshooting Guide

- [ ] **Common error messages** — every error Armur can print, with cause and fix:
  - "Connection refused: http://localhost:4500" → server not running, use --in-process
  - "Tool not found: gosec" → install instructions per OS
  - "Language detection failed" → how to specify --language manually
  - "Redis connection failed" → Redis not running, use embedded mode
  - "Scan timeout" → increase TOOL_TIMEOUT_SECONDS, or use --depth quick
  - "Permission denied cloning repository" → SSH key or token setup instructions

- [ ] **Performance troubleshooting**:
  - Scan taking > 5 minutes → which tools are slow and why, how to skip them
  - High memory usage → MAX_TOOL_CONCURRENCY tuning
  - Disk space issues → temp directory cleanup instructions

- [ ] **CI/CD troubleshooting**:
  - Why GitHub Actions fails on rate limits (solution: cache tool installations)
  - Why SARIF upload fails (common: file size limit, path issues)
  - Why the scan works locally but fails in CI (environment differences)

- [ ] **False positive management**:
  - How to identify false positives vs genuine findings
  - How to suppress with inline comments vs `.armur.yml` vs global suppression
  - How to report a false positive to the Armur team

### 51.7 CHANGELOG.md & Release Notes

- [ ] Create `CHANGELOG.md` at repo root following [Keep a Changelog](https://keepachangelog.com) format:
  ```markdown
  # Changelog

  All notable changes to Armur Code Scanner are documented here.
  Format: Keep a Changelog (https://keepachangelog.com)
  Versioning: Semantic Versioning (https://semver.org)

  ## [Unreleased]
  ### Added
  - ...

  ## [1.0.0] — 2026-XX-XX
  ### Added
  - Initial release with Go, Python, and JavaScript/TypeScript support
  - 18 integrated security tools
  - REST API + Asynq worker architecture
  ...
  ```
- [ ] Automate CHANGELOG generation from conventional commits using `git-cliff` or `release-please`
- [ ] Each GitHub Release includes:
  - What's new (bullet points from CHANGELOG)
  - Breaking changes (prominently highlighted)
  - Migration steps for breaking changes
  - SHA256 checksums for all binaries
  - Docker image digest

### 51.8 In-Code Documentation Standards

These apply to all code written going forward, ensuring future contributors understand the codebase.

- [ ] Every exported function in `internal/tools/` must have a godoc comment explaining:
  - What the tool does
  - What it returns
  - What errors it can return
  - Example: `// RunGosec runs the gosec static analyzer against the given directory and returns categorized security findings. Returns ErrToolNotFound if gosec is not installed.`
- [ ] Every tool wrapper file must have a package-level comment with:
  - Tool name and homepage URL
  - Version requirement (minimum version tested)
  - Installation instructions for the tool itself
- [ ] `internal/models/finding.go` — every field of the `Finding` struct must have an inline comment
- [ ] `internal/api/types.go` — every API request/response struct field must have a `json` tag + godoc comment (used for OpenAPI generation)
- [ ] Run `golint ./...` and `godoc ./...` in CI to enforce comment coverage
- [ ] Generate HTML godoc and publish to `pkg.go.dev/github.com/armur-ai/armur-codescanner`

---

*Last updated: March 2026*
*Sprints 1–7: original roadmap. Sprints 8–15: CLI/TUI overhaul and core engine. Sprints 16–35: world-class scanner expansion. Sprints 36–45: distribution, adoption, and community flywheel. Sprints 46–50: enterprise hardening, privacy, DAST, mobile, and security governance. Sprint 51: documentation, README, and CLI reference — added March 2026.*

---

## Sprint 52 — Fuzzing Integration (Go · Python · JavaScript)

Static analysis finds known patterns. Fuzzing finds unknown crashes, panics, and logic bugs that no
rule ever catches. All three integrations use the same tool-wrapper pattern — exec.Command + output
parsing — with no novel infrastructure required.

### 52.1 Go Native Fuzzing

- [ ] Implement `internal/tools/gofuzz.go`
- [ ] Detect fuzz-able functions: scan the repo for functions whose first arg is `*testing.F`; if none
  exist, scan for exported functions that accept `[]byte`, `string`, or `io.Reader` and auto-generate
  a stub fuzz harness in a temp directory
- [ ] Run: `go test -fuzz=Fuzz -fuzztime=60s ./...` (timeout configurable via `.armur.yml: fuzzing.timeout`)
- [ ] Parse panic output and crash artifacts from `testdata/fuzz/` — map each crash to a `Finding`
  with `Category = "crash"` and `Severity = CRITICAL`
- [ ] Save corpus to `~/.armur/fuzzing/<task-id>/corpus/` for replay
- [ ] Add `--fuzz` flag to `armur run` to append the fuzzing phase after static analysis

### 52.2 Python Fuzzing (Atheris)

- [ ] Implement `internal/tools/atheris.go`
- [ ] Run: `python -m atheris -runs=10000 fuzz_target.py` where `fuzz_target.py` is either an
  existing harness found in the repo or a generated one for detected entry functions
- [ ] Parse uncaught exceptions from stderr → map to findings
- [ ] Require `atheris` pip package; emit `armur doctor` warning if missing

### 52.3 JavaScript Fuzzing (jsfuzz)

- [ ] Implement `internal/tools/jsfuzz.go`
- [ ] Run: `jsfuzz fuzz_target.js --runs 5000`
- [ ] Parse crash output → findings
- [ ] Require `jsfuzz` npm package; emit `armur doctor` warning if missing

### 52.4 `armur fuzz` CLI Command

- [ ] `armur fuzz <target>` — dedicated fuzz command (runs all available fuzzers for the detected language)
- [ ] `armur fuzz replay <crash-file>` — reproduce a specific crash
- [ ] Display per-fuzzer status in the TUI dashboard using the same `ProgressReporter` interface (Sprint 9.2)
- [ ] `.armur.yml` fuzzing configuration:
  ```yaml
  fuzzing:
    timeout: 60         # per-fuzzer run time in seconds
    corpus-dir: .armur/corpus   # seed corpus location
    max-crashes: 10     # stop after N crashes to avoid noise
  ```

---

## Sprint 53 — Privacy & PII Compliance (GDPR · CCPA · LGPD)

All checks are pure Go pattern matching, ORM model parsing, and compliance mapping tables.
No external tools required — same implementation approach as the existing CWE/OWASP mapping logic.

### 53.1 PII Pattern Detection in Source Code

- [ ] Implement `internal/tools/piidetect.go` — scan all source files with regex patterns for:
  - Email addresses in string literals and log statements
  - SSN / national ID patterns (US, UK, EU formats)
  - Credit card numbers (pass Luhn check on matched strings)
  - Phone numbers (E.164 + common local formats)
  - Date of birth patterns in variable names and string literals
  - Passport / driver's licence patterns
  - GPS coordinates
- [ ] Flag PII found in: `log.Printf/Println` args, SQL query strings, HTTP response structs, test fixtures
- [ ] New finding category: `pii_exposure`
- [ ] Add `testdata/pii/` with deliberately leaky code samples per language

### 53.2 Database Schema PII Column Detection

- [ ] Parse ORM model files:
  - Go: GORM struct field names (`json:"email"`, `gorm:"column:ssn"`)
  - Python: Django model field names, SQLAlchemy column names
  - JavaScript/TypeScript: TypeORM, Sequelize, Mongoose schema keys
- [ ] Flag column names matching PII patterns: `email`, `phone`, `ssn`, `dob`, `passport`, `address`,
  `credit_card`, `ip_address`, `geolocation`
- [ ] Check for missing field-level encryption decorators on PII columns (e.g., missing `encrypted:true`)
- [ ] Finding message: `"PII column 'email' in User model is stored without encryption annotation"`

### 53.3 API Response PII Leak Detection

- [ ] Use the OpenAPI parser (Sprint 29.1) to scan response schemas for PII field names
- [ ] Flag response objects that return raw PII without masking (e.g., `ssn` returned in full)
- [ ] Flag API response examples in OpenAPI docs that contain real-looking PII values (regex match)
- [ ] Detect PII in GraphQL type definitions (Sprint 29.2 prerequisite)

### 53.4 Compliance Mapping & Reports

- [ ] Build `internal/compliance/gdpr.go` — GDPR Article → finding category mapping:
  - Art. 25 Data minimization → flag unnecessary PII collection patterns
  - Art. 32 Security of processing → forward to crypto/auth findings
  - Art. 17 Right to erasure → detect hard-delete vs soft-delete patterns where erasure is required
- [ ] Build `internal/compliance/ccpa.go` — CCPA mapping:
  - Right to Know → flag missing data inventory comments/annotations
  - Right to Delete → same erasure detection as GDPR Art. 17
- [ ] `armur report gdpr --task <id>` — GDPR gap report: list of PII findings mapped to Articles
- [ ] `armur report ccpa --task <id>` — CCPA compliance report
- [ ] Add `Finding.PrivacyRegulation []string` field (e.g., `["GDPR-Art25", "CCPA-1798.100"]`)

### 53.5 Consent & Retention Pattern Checks

- [ ] Detect missing consent collection patterns in web frameworks:
  - Flask/FastAPI: no consent middleware in route decorators for PII-collecting endpoints
  - Express: no consent cookie check before PII processing
- [ ] Flag hardcoded retention periods that may exceed legal maximums
  (e.g., `retentionDays := 3650` — 10 years is likely excessive for most PII types)
- [ ] `.armur.yml` PII configuration:
  ```yaml
  privacy:
    pii-detection: true
    regulations: [gdpr, ccpa]
    allowlist:
      - path: "testdata/**"   # ignore test fixtures
      - pattern: "example@example.com"  # obviously fake
  ```

---

## Sprint 54 — Cryptographic Health & Post-Quantum Readiness

All checks use Go's `crypto/x509` stdlib for certificate parsing, regex on config files for TLS
settings, and new Semgrep rules for algorithm detection. Zero new infrastructure required.

### 54.1 TLS Configuration File Analysis

- [ ] Implement `internal/tools/tlsconfig.go`
- [ ] Parse the following config files for TLS directives using regex (no full config parser needed):
  - `nginx.conf`, `nginx/*.conf`: `ssl_protocols`, `ssl_ciphers`, `ssl_session_timeout`,
    `add_header Strict-Transport-Security`
  - `apache2.conf`, `httpd.conf`, `*.conf`: `SSLProtocol`, `SSLCipherSuite`, `Header always set HSTS`
  - `haproxy.cfg`: `ssl-min-ver`, `ciphers`
  - `.env`, `config.yml`, `config.json`: any key containing `TLS_VERSION`, `SSL_PROTOCOLS`
- [ ] Findings:
  - `ssl_protocols TLSv1` or `TLSv1.1` present → HIGH
  - `SSLv2` or `SSLv3` present → CRITICAL
  - Weak ciphers (`RC4`, `3DES`, `NULL`, `EXPORT`, `DES`) → HIGH
  - Missing `Strict-Transport-Security` header → MEDIUM
  - Missing perfect forward secrecy ciphers (`ECDHE`, `DHE`) → MEDIUM
- [ ] New finding category: `crypto_config`

### 54.2 Cryptographic Algorithm Strength (Source Code)

- [ ] Add new Semgrep rules in `configs/semgrep/crypto-strength.yaml`:
  - RSA key generation with `bits < 2048` in Go, Python, Java, JavaScript
  - ECDSA with curves weaker than P-256 (`secp192r1`, `secp160r1`)
  - MD5 or SHA-1 used in signature contexts (not just hashing)
  - ECB mode block cipher usage in any language
  - Deterministic ECDSA without RFC 6979 (`k` value hardcoded or derived insecurely)
  - DH key exchange with group size < 2048 bits
- [ ] Extend existing `gosec` and `bandit` coverage to catch the above gaps
- [ ] Map all findings to relevant CWE: CWE-326 (Inadequate Encryption Strength), CWE-327 (Broken Algorithm)

### 54.3 Certificate File Analysis

- [ ] Implement `internal/tools/certcheck.go`
- [ ] Walk repo for `*.pem`, `*.crt`, `*.cer`, `*.der` files
- [ ] Parse each with Go's `crypto/x509` stdlib: no external library needed
- [ ] Check and flag:
  - Key length < 2048 bits (RSA) or weak curve (ECDSA) → HIGH
  - SHA-1 signature algorithm → HIGH
  - MD5 signature algorithm → CRITICAL
  - Certificate expiring in < 30 days → HIGH; < 7 days → CRITICAL
  - Self-signed certificate in a non-test path → MEDIUM
- [ ] `armur certs <target>` CLI command: certificate inventory table
- [ ] Export to `~/.armur/reports/<task-id>.certs.json`

### 54.4 Post-Quantum Algorithm Detection

- [ ] Add Semgrep rules to flag quantum-vulnerable algorithm usage with `INFO` severity:
  - RSA key exchange or signature (any key size — quantum-vulnerable regardless of bits)
  - ECDH / ECDSA usage
  - Classic DH key exchange
- [ ] Finding message includes migration guidance:
  - Key exchange: "Consider migrating to CRYSTALS-Kyber (ML-KEM, NIST FIPS 203)"
  - Signatures: "Consider migrating to CRYSTALS-Dilithium (ML-DSA, NIST FIPS 204) or SPHINCS+"
- [ ] `armur crypto <target>` dedicated command: runs all crypto checks and outputs a crypto health report
- [ ] `.armur.yml` crypto configuration:
  ```yaml
  crypto:
    min-rsa-bits: 2048
    min-ec-curve: P-256
    flag-quantum-vulnerable: true   # INFO-level findings for PQC migration
    check-cert-expiry: true
  ```

---

## Sprint 55 — Binary & Compiled Artifact Security

All integrations follow the standard tool-wrapper pattern. `checksec` is a widely available tool;
Go binary metadata extraction uses the standard `go` binary already on the PATH.

### 55.1 Binary Hardening Analysis (checksec)

- [ ] Implement `internal/tools/checksec.go`
- [ ] Walk repo for compiled binaries: ELF files (`*.elf`, `bin/`, `dist/`, files with ELF magic bytes),
  PE files (`*.exe`, `*.dll`), Mach-O files (macOS `*.dylib`, files in `bin/`)
- [ ] Run: `checksec --file=<binary> --format=json`
- [ ] Parse and flag missing mitigations:
  - NX (No-Execute) not set → HIGH
  - PIE/ASLR not enabled → MEDIUM
  - Stack canary missing → MEDIUM
  - RELRO partial (not full) → LOW
  - Debug symbols not stripped → INFO (production binaries should be stripped)
  - FORTIFY_SOURCE not enabled (for C/C++ binaries) → MEDIUM
- [ ] New finding category: `binary_hardening`
- [ ] `armur scan --binary <path>` scan mode — scan a single binary file

### 55.2 Hardcoded String Analysis in Binaries

- [ ] Implement Go equivalent of `strings`: scan binary file bytes for printable ASCII sequences ≥ 8 chars
- [ ] Apply secrets regex patterns (from Sprint 23) to extracted strings
- [ ] Detect API keys, connection strings, private key PEM headers embedded in compiled artifacts
- [ ] Flag: `"PRIVATE KEY"` PEM header found in binary → CRITICAL; AWS/GCP/Azure key patterns → CRITICAL
- [ ] Rate-limit to top 50 high-entropy matches per binary to avoid noise

### 55.3 Go Binary Dependency Extraction

- [ ] Run: `go version -m <binary>` — extracts embedded Go module list from any Go binary
- [ ] Parse module list; submit to OSV API (Sprint 24.2) for vulnerability lookup
- [ ] Flag vulnerable embedded modules the same as source-level SCA findings
- [ ] Useful for auditing third-party Go binaries you receive or vendor into your repo

### 55.4 SBOM from Compiled Artifacts

- [ ] Add `--binary` mode to `armur sbom` command (Sprint 25.1): `armur sbom --binary <path>`
- [ ] Use Syft binary mode: `syft <binary> -o cyclonedx-json`
- [ ] Merge binary-extracted SBOM with source-level SBOM; flag components that appear in the binary
  but are not declared in any manifest (potential dependency confusion or hidden dependency)
- [ ] Output: `~/.armur/sboms/<task-id>.binary.cdx.json`

---

## Sprint 56 — Threat Modeling from Code

Route detection uses Semgrep patterns against the top 5 frameworks — exactly the same mechanism
as existing SAST rules. Mermaid output is pure string generation. No novel infrastructure.

### 56.1 HTTP Route Detection via Semgrep

- [ ] Add Semgrep rule pack `configs/semgrep/routes/` with rules for each major framework:
  - Go (Gin): `router.GET`, `router.POST`, `r.Group`, `v1.Use` (middleware detection)
  - Go (Echo, Chi): equivalent route registration patterns
  - Python (Flask): `@app.route`, `@blueprint.route` decorators
  - Python (FastAPI): `@router.get`, `@router.post`, `@app.include_router`
  - JavaScript (Express): `app.get(`, `router.post(`, `app.use(`
- [ ] Each matched route emits: HTTP method, path pattern, handler function name, file + line
- [ ] Collect all routes into `internal/analysis/routes.go` as `[]RouteDefinition`

### 56.2 DFD Generation (Mermaid.js)

- [ ] Build `internal/analysis/threatmodel.go`:
  - Parse detected routes into nodes
  - Detect external service calls (HTTP clients, gRPC clients, DB calls) using Semgrep patterns
  - Detect middleware (auth, rate limiting, logging) from framework-specific patterns
  - Detect data stores (DB connection patterns, Redis, S3 client init)
- [ ] Generate Mermaid.js diagram from the collected nodes and edges:
  ```
  graph LR
    Internet --> AuthMiddleware
    AuthMiddleware --> POST_/api/users
    POST_/api/users --> UsersDB[(PostgreSQL)]
    POST_/api/users --> EmailService[SendGrid]
  ```
- [ ] Output: `~/.armur/reports/<task-id>.threat-model.md` (Mermaid fenced code block)
- [ ] `armur threatmodel <target>` dedicated command

### 56.3 STRIDE Analysis per Component

- [ ] For each detected entry point, run a STRIDE check:
  - **Spoofing**: is auth middleware present before this route?
  - **Tampering**: is input validation present (validator, binding)?
  - **Repudiation**: is request logging middleware present?
  - **Information Disclosure**: does the response include error details in production mode?
  - **DoS**: is rate limiting middleware present?
  - **Elevation of Privilege**: is authorization (role check) performed after authentication?
- [ ] Each failing STRIDE check becomes a finding: `Category = "threat_model"`, severity based on the
  STRIDE category (Spoofing → HIGH, DoS → MEDIUM, Repudiation → LOW, etc.)

### 56.4 Attack Surface Report

- [ ] `armur attack-surface <target>` command — enumerate and output:
  - All public endpoints with their HTTP methods and auth status
  - File upload endpoints (flag separately — high attack surface)
  - Admin/management endpoints (`/admin`, `/debug`, `/metrics`, `/health`)
  - WebSocket upgrade endpoints
  - Unauthenticated endpoints (no auth middleware detected)
- [ ] Output as a structured table in the terminal and as JSON in the report file

---

## Sprint 57 — Developer Security Gamification & Education

Pure Go + SQLite (already planned in Sprint 12) + existing charmbracelet/huh and lipgloss libraries.
No new dependencies required.

### 57.1 Developer Security Score (Git Blame Attribution)

- [ ] Implement `internal/analysis/blame.go`:
  - For each finding: run `git blame -L <line>,<line> -- <file>` to get commit hash + author email
  - Cache blame results by `(file, line)` tuple to avoid redundant git calls
- [ ] Store per-developer finding attribution in `~/.armur/history.db`:
  ```sql
  CREATE TABLE IF NOT EXISTS finding_blame (
      finding_id  TEXT,
      scan_id     TEXT,
      author      TEXT,
      commit_hash TEXT,
      introduced  DATETIME
  );
  ```
- [ ] `armur leaderboard` command: ranked table of contributors by security score
  - Score = 100 − (critical×20 + high×10 + medium×3 + low×0.5) + (fixed_findings × 5)
- [ ] Only enabled when `armur.yml: reporting.blame: true` (off by default for privacy)

### 57.2 `armur learn` Interactive Lessons

- [ ] Implement `armur learn <cwe-id>` command
- [ ] Lessons stored as YAML files in `~/.armur/lessons/<cwe-id>.yaml`:
  ```yaml
  cwe: CWE-89
  title: "SQL Injection"
  what: "..."
  why_it_matters: "..."
  attack_scenario: "..."
  vulnerable_example:
    language: go
    code: |
      query := "SELECT * FROM users WHERE id = " + userInput
  secure_example:
    language: go
    code: |
      query := "SELECT * FROM users WHERE id = ?"
      db.Query(query, userInput)
  quiz:
    - question: "Which of these is safe?"
      options: ["Option A", "Option B", "Option C"]
      answer: 1
  ```
- [ ] Initial lesson pack ships with Armur for top 10 CWEs; additional packs downloadable via
  `armur rules install lessons-pack`
- [ ] `armur learn` with no args: show a menu of available lessons filtered to CWEs found in the last scan

### 57.3 Fix Streak & Achievement Tracking

- [ ] Add `streak` and `achievements` tables to `~/.armur/history.db`
- [ ] Calculate fix streak: consecutive calendar days with at least one scan showing zero new HIGH+ findings
- [ ] Achievements (checked after every scan, awarded once):
  - "First Scan" — completed first successful scan
  - "Zero Critical" — first scan with no CRITICAL findings
  - "Clean Sweep" — first scan with zero findings of any severity
  - "Dependency Champion" — all SCA findings resolved
  - "Secret Hunter" — secrets category empty for 30 consecutive days
  - "Fix Streak 7" / "Fix Streak 30" — streak milestones
- [ ] Display earned achievements and current streak in `armur history` output header
- [ ] Print a small achievement notification after a scan when a new one is earned

### 57.4 Security Challenge Mode

- [ ] `armur challenge` command — scan a deliberately vulnerable code snippet (bundled with Armur)
- [ ] Three difficulty levels: easy (1 obvious vuln), medium (3 vulns), hard (5 vulns + a false positive)
- [ ] User is asked to predict how many findings Armur will report; the scan runs and compares
- [ ] Challenge results saved in history; `armur challenge --history` shows past attempts and scores

---

## Sprint 58 — Dependency Update Automation (Auto-Fix PRs)

Manifest parsing uses stdlib text manipulation; GitHub/GitLab PR creation uses `net/http` + JSON.
The `gh` CLI (already used for releases in Sprint 7) provides a fallback for GitHub.

### 58.1 Safe Dependency Bump Engine

- [ ] Implement `internal/depfix/bump.go`
- [ ] For each SCA finding that has a `patched_version` field: compute the minimal safe version bump
- [ ] Supported manifest formats (all parsed with Go stdlib + regex, no external parsers):
  - `go.mod` — use `golang.org/x/mod/modfile` (already in the Go module ecosystem)
  - `package.json` — stdlib `encoding/json`
  - `requirements.txt` — line-by-line text; update `package==version` → `package==patched`
  - `Cargo.toml` — TOML parsing (`pelletier/go-toml` — add dep)
  - `Gemfile.lock` — text replacement
  - `pom.xml` — XML parsing with `encoding/xml` stdlib
  - `pyproject.toml` — TOML parsing
- [ ] Safety check: only bump within the same major version (semver) unless `--allow-major` flag set
- [ ] `armur fix-deps --dry-run` — print what would change without writing to disk

### 58.2 GitHub Pull Request Creation

- [ ] `armur fix-deps --create-pr` — apply bumps, commit with `git`, push to a new branch, create PR
- [ ] Branch name: `armur/fix-deps-<date>` (e.g., `armur/fix-deps-2026-03-11`)
- [ ] Commit message: `fix(deps): patch N vulnerabilities (Armur auto-fix)`
- [ ] PR title: `fix(deps): patch N critical/high vulnerabilities`
- [ ] PR body template (Markdown table):
  ```markdown
  ## Security Dependency Updates (Armur)
  | Package | From | To | CVE | CVSS | Severity |
  |---------|------|----|-----|------|----------|
  | lodash  | 4.17.15 | 4.17.21 | CVE-2021-23337 | 7.2 | HIGH |
  ```
- [ ] Use GitHub REST API via `net/http`: `POST /repos/:owner/:repo/pulls`
- [ ] GitLab: `POST /projects/:id/merge_requests`
- [ ] API tokens read from `armur config`: `armur config set github-token <token>`

### 58.3 PR Policy Configuration

- [ ] `.armur.yml` dep-update policy:
  ```yaml
  dep-updates:
    auto-pr: false          # set true to auto-create PRs after each scan
    group-by: severity      # one PR for all, or one per severity tier
    max-open-prs: 5         # don't flood the repo
    skip-major-bumps: true  # only patch/minor version bumps
    assignees: []           # GitHub usernames to assign
    labels: ["security", "dependencies"]
  ```
- [ ] `armur fix-deps --schedule` — run on embedded cron (cron library already in go.mod: `robfig/cron`)

### 58.4 Pre-Bump Safety Scan

- [ ] Before creating the PR: run a quick in-process scan of the updated manifest to verify the bumped
  version does not introduce new vulnerabilities (query OSV API for the new version)
- [ ] If new vulns found in the bump target: skip that package and add a note to the PR body

---

## Sprint 59 — AI / LLM Application Security (OWASP LLM Top 10)

All checks implemented as Semgrep rule packs + a small Go wrapper. Same implementation pattern
as all existing SAST tool integrations.

### 59.1 LLM SDK Detection

- [ ] Implement `internal/tools/llmsecurity.go`
- [ ] Detect LLM SDK usage by scanning imports:
  - Go: `github.com/anthropics/anthropic-sdk-go`, `github.com/sashabaranov/go-openai`
  - Python: `import anthropic`, `import openai`, `from langchain`, `from llama_index`
  - JavaScript: `import Anthropic`, `require('openai')`, `from 'langchain'`
- [ ] If no LLM SDK detected: skip this tool entirely (zero false positives for non-AI codebases)

### 59.2 Prompt Injection Detection (LLM01)

- [ ] Semgrep rules in `configs/semgrep/llm-security/prompt-injection.yaml`:
  - Python: f-string or `.format()` with user input variable directly concatenated into a prompt
    variable that is then passed to an LLM client completion call
  - JavaScript: template literal with user input directly in a `messages` array passed to `.create()`
  - Go: `fmt.Sprintf` with user input inside a string passed to the Anthropic/OpenAI SDK
- [ ] Taint: source = HTTP request body / query param / form field; sink = LLM completion call argument
- [ ] Finding message: `"User input directly interpolated into LLM prompt — prompt injection risk (OWASP LLM01)"`

### 59.3 Insecure Output Handling (LLM02)

- [ ] Semgrep rules in `configs/semgrep/llm-security/output-handling.yaml`:
  - LLM response content passed directly to `eval()` / `exec()` / `subprocess.run()` → CRITICAL
  - LLM response rendered as raw HTML without `html.EscapeString()` or template auto-escaping → HIGH
  - LLM response used as a SQL query fragment → CRITICAL
  - LLM response written to a filesystem path without sanitization → HIGH

### 59.4 Excessive Agency Detection (LLM08)

- [ ] Detect tool/function definitions in agentic LLM code:
  - Python: `tools=[{"name": ..., "function": ...}]` or LangChain `Tool` definitions
  - TypeScript: `tools: [{type: "function", function: {...}}]` in OpenAI tool arrays
- [ ] Flag tool definitions that combine: filesystem write + network access + code execution in a single
  agent without human-in-the-loop confirmation logic
- [ ] Flag: database write tools (`INSERT`, `UPDATE`, `DELETE`) with no human approval step

### 59.5 OWASP LLM Top 10 Mapping & Report

- [ ] Build `internal/compliance/owasp_llm.go` mapping table:
  - LLM01 Prompt Injection → prompt injection findings
  - LLM02 Insecure Output Handling → output handling findings
  - LLM06 Sensitive Information Disclosure → PII in prompt context (cross-ref Sprint 53)
  - LLM08 Excessive Agency → agency detection findings
  - LLM09 Overreliance → missing fallback/error handling when LLM API fails
- [ ] Add `Finding.OWASPLLM string` field (e.g., `"LLM01:2025"`)
- [ ] `armur report llm --task <id>` — LLM security report
- [ ] `armur llm-security <target>` — dedicated scan mode that runs only LLM security checks

---

## Sprint 60 — Network & Protocol Configuration Security

All checks are regex/grep on config files (nginx, Apache, Istio YAML) or YAML parsing using
`gopkg.in/yaml.v3` which is already in go.mod. No external tools required.

### 60.1 TLS Configuration in Web Server Files

- [ ] Implement `internal/tools/netconfig.go`
- [ ] Walk repo for: `nginx.conf`, `nginx/*.conf`, `conf.d/*.conf`, `httpd.conf`, `apache2.conf`,
  `haproxy.cfg`, `traefik.yml`, `traefik.yaml`, `caddy`/`Caddyfile`
- [ ] Regex-based checks (no full config parser needed — targeting specific directive lines):
  - `ssl_protocols` containing `TLSv1` or `TLSv1.1` → HIGH
  - `SSLProtocol` containing `+TLSv1` or `+TLSv1.1` → HIGH
  - Cipher string containing `RC4`, `3DES`, `NULL`, `EXPORT`, `DES` → HIGH
  - No `ssl_session_tickets off` → MEDIUM (session ticket key rotation risk)
  - No `resolver` configured for OCSP stapling → INFO

### 60.2 HTTP Security Header Analysis

- [ ] Check web server and application configs for missing security headers:
  - `add_header X-Frame-Options` missing → MEDIUM
  - `add_header X-Content-Type-Options nosniff` missing → MEDIUM
  - `add_header Strict-Transport-Security` missing → HIGH (if TLS is configured)
  - `add_header Content-Security-Policy` missing → MEDIUM
  - `add_header Referrer-Policy` missing → LOW
  - `Content-Security-Policy` value containing `unsafe-eval` or `unsafe-inline` → HIGH
- [ ] Parse application-level header setting for Go (Gin middleware), Python (Flask/Django middleware),
  and Express (helmet.js usage) to check in-code header configuration

### 60.3 Istio / Service Mesh Security

- [ ] Parse Istio resource YAML files using `gopkg.in/yaml.v3` (already in go.mod):
  - `AuthorizationPolicy` with `action: ALLOW` and no `from` or `to` rules → CRITICAL
    (allows all traffic)
  - `PeerAuthentication` with `mtls.mode: DISABLE` or `mtls.mode: PERMISSIVE` → HIGH
  - `VirtualService` routing to HTTP (not HTTPS) backends → MEDIUM
- [ ] Detect Istio resources by `apiVersion: security.istio.io/v1` or `networking.istio.io/v1`

### 60.4 Protobuf / gRPC Security

- [ ] Implement `internal/tools/protocheck.go`
- [ ] Walk repo for `*.proto` files; parse with line-by-line text analysis (no full proto parser):
  - Service definitions with no auth comment / option annotation → INFO
  - Fields named `password`, `secret`, `token`, `api_key` without `(buf.validate.field).string.min_len` → MEDIUM
  - `stream` RPCs (potential DoS via long-lived connections without timeout options) → LOW
- [ ] Detect `*.proto` files and add proto language to `armur doctor` tool check list

### 60.5 Kubernetes Ingress & Network Policy

- [ ] Parse `Ingress` resources: flag HTTP (non-TLS) backends → MEDIUM
- [ ] Parse `NetworkPolicy` resources: flag absence of NetworkPolicy in a namespace → INFO
  (any pod can reach any other pod)
- [ ] Flag `NetworkPolicy` with `podSelector: {}` and no `policyTypes` (matches all pods) → MEDIUM
- [ ] Detect via `kind: Ingress` / `kind: NetworkPolicy` in YAML files

---

## Sprint 61 — Security Test Generation

Pure Go code generation using `text/template` stdlib. No external tools, no new dependencies.
The output is test files (.go, .py, .js) generated from templates and written with `os.WriteFile`.

### 61.1 Failing Test Generation from SAST Findings

- [ ] Implement `internal/testgen/generator.go`
- [ ] For each finding with a known exploit pattern, generate a test using language-specific templates:

  **SQL Injection (Go):**
  ```go
  func TestSQLInjection_<file>_<line>(t *testing.T) {
      payload := "' OR '1'='1"
      _, err := handler(payload)
      if err == nil {
          t.Fatal("expected error for SQL injection payload, got nil")
      }
  }
  ```

  **XSS (JavaScript/Jest):**
  ```js
  test('XSS: <file>:<line> should escape HTML', () => {
      const payload = '<script>alert(1)</script>';
      const result = renderFunction(payload);
      expect(result).not.toContain('<script>');
  });
  ```

  **Path Traversal (Python/pytest):**
  ```python
  def test_path_traversal_<file>_<line>():
      response = client.get('/file?path=../../../etc/passwd')
      assert response.status_code in (400, 403), "path traversal not blocked"
  ```

- [ ] Templates stored in `internal/testgen/templates/<language>/<category>.tmpl`
- [ ] `armur generate-tests --task <id> --language go` — output to `.armur/security-tests/`

### 61.2 PoC Payload Library

- [ ] `internal/testgen/payloads.go` — curated payload lists per vulnerability category:
  - SQL injection: 20 classic payloads (`' OR 1=1--`, `1; DROP TABLE users--`, etc.)
  - XSS: 15 payloads (`<img src=x onerror=alert(1)>`, `"><script>`, etc.)
  - Path traversal: 10 payloads (`../../../etc/passwd`, `..%2F..%2F`, etc.)
  - Command injection: 10 payloads (`; ls -la`, `| whoami`, `` `id` ``, etc.)
  - SSRF: internal IP ranges and metadata endpoint URLs
- [ ] Payloads saved to `~/.armur/reports/<task-id>/poc/<finding-id>.txt` for reference
- [ ] NOT automatically executed — displayed for manual verification only

### 61.3 Regression Test Suite Generation

- [ ] `armur generate-tests --regression --task <id>` — generate a security regression suite:
  - For each finding that was previously present and is now resolved: generate a test that asserts
    the fix holds (using the PoC payload against the fixed code path)
  - Tests written to `.armur/security-tests/regression_test.<ext>` in the repo
- [ ] Include in README a section: "Run `go test ./.armur/security-tests/...` to verify security fixes"

### 61.4 Fuzz Harness Generation

- [ ] For each function flagged as vulnerable to injection-type findings:
  - Go: generate a `FuzzXxx(f *testing.F)` harness with the PoC payloads as seed corpus entries
  - Python: generate an Atheris harness with seed corpus
- [ ] `armur generate-tests --fuzz --task <id>` — generate fuzz harnesses alongside unit tests
- [ ] Output to `.armur/security-tests/fuzz_<finding-id>_test.<ext>`

---

## Sprint 62 — Multi-Tenant Enterprise API (Org · RBAC · Audit Log)

Built on top of the existing Gin + Redis stack. OIDC via `coreos/go-oidc` (well-established Go library).
SAML and SCIM deliberately excluded — too complex and not needed for initial multi-tenant support.

### 62.1 Organization & Project Data Model

- [ ] Extend Redis schema with org and project namespaces:
  - `org:<org-id>:info` — org metadata (name, created_at, owner)
  - `org:<org-id>:projects` — set of project IDs
  - `project:<project-id>:info` — project metadata (name, repo_url, org_id)
  - `project:<project-id>:scans` — sorted set of scan IDs by timestamp
- [ ] API endpoints:
  - `POST /api/v1/orgs` — create org (returns `org_id`)
  - `GET /api/v1/orgs/:id` — get org info
  - `POST /api/v1/orgs/:id/projects` — create project
  - `GET /api/v1/orgs/:id/projects` — list projects
  - `GET /api/v1/orgs/:id/findings` — aggregate findings across all projects
  - `GET /api/v1/orgs/:id/posture` — org-wide posture score

### 62.2 Role-Based Access Control (RBAC)

- [ ] Roles: `org_admin`, `project_admin`, `developer`, `viewer`
- [ ] Store user roles in Redis: `user:<api-key>:role` → `org_admin`
- [ ] Add `RBACMiddleware` to Gin: reads API key from `Authorization` header, looks up role,
  enforces permissions per endpoint
- [ ] Permission matrix:
  - `org_admin`: all endpoints
  - `project_admin`: project scan + findings + suppressions; no user management
  - `developer`: trigger scans, view findings, create suppressions
  - `viewer`: GET endpoints only, no scan trigger

### 62.3 OIDC Single Sign-On

- [ ] Add `coreos/go-oidc` dependency
- [ ] Config: `ARMUR_OIDC_ISSUER`, `ARMUR_OIDC_CLIENT_ID`, `ARMUR_OIDC_CLIENT_SECRET` env vars
- [ ] `GET /api/v1/auth/oidc/login` — redirect to IdP (Google, Okta, GitHub, Auth0)
- [ ] `GET /api/v1/auth/oidc/callback` — exchange code for tokens, create/update user record,
  return Armur API key
- [ ] `armur login --oidc` CLI command: open browser for OIDC flow, store API key in `~/.armur/credentials`
- [ ] Supported IdPs documented: Google, GitHub OAuth App, Okta, Auth0

### 62.4 Organization-Level Audit Log

- [ ] Store audit log entries in Redis sorted set: `org:<org-id>:audit-log` (scored by timestamp)
- [ ] Log every state-changing action: scan submitted, finding suppressed, user role changed,
  project created/deleted
- [ ] Each entry: `{ ts, actor_id, actor_email, action, resource_type, resource_id, ip_address }`
- [ ] `GET /api/v1/orgs/:id/audit-log` — paginated audit log (admin-only)
- [ ] `armur audit-log --since 2026-01-01` CLI command

### 62.5 Org-Level Aggregate Analytics

- [ ] `armur org posture` CLI command — show org-wide posture score aggregated across all projects
- [ ] `armur org findings --severity critical` — list all critical findings across all org projects
- [ ] API: `GET /api/v1/orgs/:id/posture` returns:
  ```json
  {
    "score": 73, "grade": "C",
    "projects": [{"name": "api-server", "score": 82}, {"name": "frontend", "score": 61}],
    "total_findings": {"critical": 2, "high": 14, "medium": 31, "low": 58}
  }
  ```

---

## Sprint 63 — Forensic Mode & Compromise Detection

All analysis runs via `git log --all -p` (exec.Command, same as all other git-based tools) and
regex/pattern matching on the diff output. No external tools or special privileges required.

### 63.1 Repository History Forensics

- [ ] Implement `internal/tools/forensic.go`
- [ ] `armur forensic <target>` — dedicated forensic scan mode
- [ ] Run: `git log --all --full-history --format="%H|%ae|%ai|%s" -p` — full history with patches
- [ ] For each commit diff, scan for risk patterns:
  - Sudden introduction of `eval(`, `exec(`, `subprocess.call(` in non-test files → HIGH
  - Base64-encoded payloads (`base64.b64decode(`, `atob(`) immediately followed by `exec` → CRITICAL
  - Deletion of auth middleware or rate limiting code → HIGH
  - Deletion of input validation logic → HIGH
  - Large binary blob committed (diff shows binary file, size > 1MB) → MEDIUM
  - New network listener code in unexpected files → MEDIUM
- [ ] Output: timeline report of suspicious commits, sorted by date

### 63.2 Backdoor Pattern Detection

- [ ] Semgrep rules in `configs/semgrep/forensics/backdoor.yaml`:
  - Multi-step decode+exec chains: `base64.b64decode(...).decode()` → `exec(...)` → CRITICAL
  - `chr()` concatenation to build import strings: `__import__(chr(111)+chr(115))` → CRITICAL
  - Dynamic import with obfuscated module name → HIGH
  - `time.time()` or date comparison used as execution condition ("time bomb" pattern) → HIGH
  - Outbound connection to hardcoded IP address in non-networking code → HIGH

### 63.3 Unauthorized Change Detection

- [ ] `armur forensic --since <date>` — analyze only commits since a given date
- [ ] Compare security controls in the current HEAD vs the since-date snapshot:
  - Auth middleware removed between snapshots → CRITICAL
  - Rate limiting removed → HIGH
  - New admin endpoint added without auth middleware → HIGH
- [ ] Flag commits from authors not previously seen in the repo history → INFO (new contributor)
- [ ] Flag commits with no GPG signature (if repo previously had signed commits) → MEDIUM

### 63.4 Malicious Install Hook Detection

- [ ] Parse `package.json` for lifecycle hooks: `postinstall`, `preinstall`, `prepare`
- [ ] Flag any lifecycle hook that contains: `curl`, `wget`, `eval`, `exec`, base64 content → CRITICAL
- [ ] Parse `setup.py` and `pyproject.toml` for `cmdclass` hooks that spawn subprocesses → HIGH
- [ ] Cross-reference added dependencies against known malicious package databases:
  - Query OpenSSF Package Analysis API: `https://api.osv.dev/v1/query` with `malicious` ecosystem tag
  - Flag any match → CRITICAL

### 63.5 Forensic Incident Report

- [ ] `armur forensic report --task <id>` — multi-section forensic report:
  1. Timeline: list of suspicious commits with author, date, risk reason
  2. Backdoor indicators: found patterns with code context
  3. Unauthorized changes: security control drift summary
  4. Credential exposure: secrets found in history with first-introduced / removed commit
  5. Recommended actions: rotate credentials X and Y; rewrite commit Z; add GPG signing
- [ ] Output to `~/.armur/reports/<task-id>.forensic.html` (using existing HTML report generator)

---

## Sprint 64 — Security SLA, Risk Scoring & Debt Tracker

Pure Go math + SQLite (already planned in Sprint 12). PDF generation uses `signintech/gopdf`
(already mentioned in Sprint 34.6 — same library). No new infrastructure.

### 64.1 Composite Risk Score per Finding

- [ ] Add `RiskScore float64` field to the `Finding` struct (Sprint 10.2)
- [ ] Compute in `internal/analysis/risk.go` after all tool results are merged:
  ```
  RiskScore = BaseScore
            × ExploitabilityMultiplier   (1.5 if CISA KEV, 1.2 if EPSS > 0.3, 1.0 otherwise)
            × AssetCriticalityMultiplier (1.5 if "critical", 1.2 if "high", 1.0 if "medium", 0.7 if "low")
            × ReachabilityMultiplier     (1.5 if reachable, 1.0 if unknown, 0.5 if unreachable)
  ```
- [ ] BaseScore: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, INFO=0.1
- [ ] Asset criticality read from `.armur.yml: asset-criticality: high`
- [ ] Default sort in TUI results browser changed to `RiskScore DESC` (from raw severity)

### 64.2 SLA Tracking

- [ ] Add `sla_deadline` and `sla_status` columns to `scans` table in SQLite history DB
- [ ] Default SLA deadlines (configurable in `.armur.yml: sla`):
  - CRITICAL: 48 hours
  - HIGH: 7 days
  - MEDIUM: 30 days
  - LOW: 90 days
- [ ] `armur sla status` — three-section output:
  - 🔴 Overdue: findings past their SLA deadline
  - 🟡 At Risk: findings within 20% of their deadline
  - 🟢 Compliant: findings within SLA
- [ ] SLA breach triggers a webhook notification (Sprint 14.3) with `event: "sla_breach"`

### 64.3 Security Debt Tracker

- [ ] Security debt = estimated remediation effort for all open findings
- [ ] Default effort estimates (configurable): CRITICAL=8h, HIGH=4h, MEDIUM=2h, LOW=0.5h
- [ ] `armur debt` command:
  ```
  Security Debt — ./my-project
  ──────────────────────────────────────────
  Critical (2):   16h
  High     (14):  56h
  Medium   (31):  62h
  Low      (58):  29h
  ──────────────────────────────────────────
  Total:          163h  (~20 engineering days)
  Trend:          ▼ 12h less than last scan
  ```
- [ ] Store debt per scan in SQLite; trend calculation compares against previous scan

### 64.4 Finding Suppression System

- [ ] `armur suppress <finding-id> --reason "false positive" --expires 2026-12-31` command
- [ ] Store suppressions in SQLite:
  ```sql
  CREATE TABLE IF NOT EXISTS suppressions (
      finding_id   TEXT PRIMARY KEY,
      reason       TEXT NOT NULL,
      suppressed_by TEXT,
      suppressed_at DATETIME,
      expires_at   DATETIME
  );
  ```
- [ ] Inline suppression in source code: `// armur:ignore <rule-id>` or `# armur:ignore <rule-id>`
  parsed during scan; matching findings marked as suppressed
- [ ] Expired suppressions auto-resurface on next scan (check `expires_at < now()`)
- [ ] `armur suppressions list` — show all active suppressions with expiry dates
- [ ] Suppressed findings counted separately in output: `17 findings (3 suppressed, not shown)`

### 64.5 Executive Posture Report (PDF)

- [ ] `armur report executive --task <id>` — multi-page PDF using `signintech/gopdf`:
  1. Cover page: target, scan date, posture score (large), grade letter
  2. Executive Summary: key metrics, top 3 risk drivers, trend vs previous scan
  3. Severity breakdown (ASCII-art bar chart embedded in PDF)
  4. SLA compliance: % of findings within SLA by severity tier
  5. Security debt: current debt in hours with trend
  6. Top 10 findings by risk score (one per row: file, description, risk score, SLA deadline)
  7. Recommended actions: prioritized list ordered by risk score
- [ ] `armur report executive --format pdf` — explicitly request PDF; default is Markdown if no flag

---

## Sprint 65 — OpenSSF Ecosystem & Threat Intelligence Enrichment

All integrations are: wrap an existing binary (`scorecard`), or make HTTP GET requests to public
APIs (CISA, FIRST.org), or generate JSON files. Exact same patterns used throughout the codebase.

### 65.1 OpenSSF Scorecard Integration

- [ ] Implement `internal/tools/scorecard.go`
- [ ] Run: `scorecard --repo=<url> --format=json` (binary available at `github.com/ossf/scorecard`)
- [ ] Parse `checks` array; map each failing check to a finding:
  - `Branch-Protection: 3/10` → MEDIUM: "Default branch has insufficient protection rules"
  - `Fuzzing: 0/10` → MEDIUM: "No fuzzing coverage detected"
  - `Signed-Releases: 0/10` → LOW: "Release artifacts are not signed"
  - `Dangerous-Workflow: 0/10` → HIGH: "CI workflow uses dangerous patterns (script injection risk)"
  - `Token-Permissions: 3/10` → MEDIUM: "GitHub Actions tokens have excessive permissions"
- [ ] `armur scorecard <repo-url>` — run scorecard against a repo URL (not just local path)
- [ ] Also run scorecard against top 10 direct dependencies: "Your dependency X has scorecard score 2/10"

### 65.2 CISA KEV (Known Exploited Vulnerabilities) Enrichment

- [ ] Implement `internal/intel/kev.go`
- [ ] Fetch CISA KEV catalog on each scan (with 24-hour cache in Redis):
  ```go
  resp, _ := http.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
  ```
- [ ] Build in-memory lookup map: `cveID → KevEntry { dueDate, shortDescription, ransomwareUse }`
- [ ] After SCA findings are collected: enrich any finding whose CVE ID is in the KEV catalog:
  - Escalate severity to CRITICAL regardless of original CVSS score
  - Set `Finding.ActivelyExploited = true`
  - Set `Finding.CISADueDate = entry.dueDate`
  - Add to finding message: "⚠ Actively exploited in the wild (CISA KEV)"
- [ ] `armur report kev --task <id>` — show only KEV findings with their CISA remediation deadlines

### 65.3 EPSS (Exploit Prediction Scoring System) Enrichment

- [ ] Implement `internal/intel/epss.go`
- [ ] Query FIRST.org EPSS API for each CVE found in SCA scan:
  ```go
  http.Get("https://api.first.org/data/1.0/epss?cve=CVE-2021-44228")
  ```
- [ ] Add `Finding.EPSSScore float64` (0.0–1.0 probability of exploitation in next 30 days)
- [ ] Incorporate into risk score formula (Sprint 64.1):
  - EPSS > 0.5 → ExploitabilityMultiplier = 1.5
  - EPSS 0.1–0.5 → multiplier = 1.2
  - EPSS < 0.1 → multiplier = 1.0
- [ ] Display in TUI finding detail: `Exploit probability: 73% / 30d (EPSS)`
- [ ] Batch EPSS queries: collect all CVE IDs from the scan, send one HTTP request per batch of 30

### 65.4 VEX (Vulnerability Exploitability eXchange) Support

- [ ] Consume VEX documents: if `<project>.openvex.json` exists in the repo root, parse it and mark
  CVEs with `status: "not_affected"` or `status: "fixed"` as suppressed in SCA results
- [ ] Generate VEX documents: `armur vex generate --task <id>` — creates `openvex.json` with all
  SCA findings mapped to OpenVEX statements (status defaults to `"under_investigation"`)
- [ ] VEX format: OpenVEX (CISA standard — simple JSON, no library needed beyond `encoding/json`)
- [ ] Store generated VEX documents at `~/.armur/vex/<project-id>.openvex.json`

### 65.5 SLSA Compliance Checker

- [ ] Implement `internal/tools/slsa.go` — check SLSA compliance level for the scanned repo:
  - **Level 1**: source is version-controlled (check `.git` exists) + build is scripted (`Makefile`,
    `justfile`, `package.json scripts`, `pyproject.toml [tool.poetry.scripts]` present)
  - **Level 2**: CI/CD build service used (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`)
    AND provenance is generated (`goreleaser`, `ko`, or GitHub Actions `slsa-framework/slsa-github-generator`)
  - **Level 3**: provenance is signed (Sigstore/cosign artifacts in release) + no self-hosted runners
    in CI workflows (check `runs-on: self-hosted` in GitHub Actions)
  - **Level 4**: hermetic builds (Bazel/Nix reproducible builds) — detect `WORKSPACE` (Bazel),
    `flake.nix` (Nix), or `hermetic: true` annotations
- [ ] `armur slsa <target>` — print achieved SLSA level and gaps to the next level
- [ ] Map SLSA gaps to findings: "No build provenance generated → cannot achieve SLSA Level 2"

### 65.6 OSS-Fuzz Coverage Check

- [ ] Query GitHub API to check if any direct dependency is an OSS-Fuzz integrated project:
  ```go
  http.Get("https://api.github.com/repos/google/oss-fuzz/contents/projects")
  ```
- [ ] Cache the project list in Redis (1-hour TTL)
- [ ] For each direct dependency NOT in OSS-Fuzz: emit `INFO` finding:
  "Dependency `<name>` has no continuous fuzzing coverage (not in OSS-Fuzz)"
- [ ] For dependencies that ARE in OSS-Fuzz: add a positive note in the SCA section:
  "Dependency `<name>` is continuously fuzzed by OSS-Fuzz ✓"

---

*Last updated: March 2026*
*Sprints 52–65: new capability layer added March 2026 — fuzzing, privacy/PII, crypto health, binary security, threat modeling, gamification, dependency auto-fix, LLM security, network config analysis, test generation, multi-tenant API, forensic mode, risk scoring/SLA, and OpenSSF ecosystem integration.*
