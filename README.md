<div align="center">

<img src="banner/vibescan-banner.gif" alt="vibescan banner" width="100%" />

# vibescan

### Security Scanner for Vibe-Coded Software

**Scan AI-generated code for vulnerabilities before they ship.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![GitHub Stars](https://img.shields.io/github/stars/Armur-Ai/vibescan?style=social)](https://github.com/Armur-Ai/vibescan)
[![Discord](https://img.shields.io/discord/1021371417134125106?label=Discord&logo=discord)](https://discord.gg/PEycrqvd)

[Quick Start](#quick-start) &bull; [Interactive TUI](#interactive-tui) &bull; [Features](#features) &bull; [Languages](#supported-languages) &bull; [CLI Reference](#all-commands) &bull; [CI/CD](#cicd-integration) &bull; [MCP](#ai-editor-integration-mcp) &bull; [Contributing](#contributing)

</div>

---

## Credits & Inspiration

vibescan stands on the shoulders of incredible open-source security projects. We didn't reinvent the wheel — we built an orchestration layer that unifies the best tools into a single, developer-friendly experience.

**Projects that inspired us:**

| Project | What we learned |
|---------|----------------|
| [Semgrep](https://github.com/semgrep/semgrep) | Lightweight, multi-language static analysis done right. Our core SAST engine. |
| [Trivy](https://github.com/aquasecurity/trivy) | Comprehensive vulnerability scanning for containers, filesystems, and IaC. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning at scale. Inspired our exploit template system. |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | The gold standard for open-source DAST. Influenced our sandboxed runtime testing. |
| [SonarQube](https://github.com/SonarSource/sonarqube) | Proved that continuous code quality inspection works. We wanted that for security, in the terminal. |
| [Snyk](https://snyk.io) | Showed that developer-first security UX matters more than feature count. |
| [CodeQL](https://github.com/github/codeql) | Deep semantic analysis and the GitHub Security ecosystem we integrate with via SARIF. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Fast, accurate secret detection with excellent rule coverage. |
| [Checkov](https://github.com/bridgecrewio/checkov) | Multi-framework IaC scanning. Our IaC coverage builds directly on it. |

### Open-Source Security Tools in Our Pipeline

vibescan is **not** a single scanner — it's a pipeline that runs **30+ industry-grade open-source tools**, normalizes their output, deduplicates findings, and presents unified results. Here's every tool we orchestrate:

<details>
<summary><strong>SAST — Static Application Security Testing</strong></summary>

| Tool | Language/Target | What it finds | Link |
|------|----------------|---------------|------|
| **Semgrep** | 15+ languages | Code vulnerabilities, taint tracking, custom rules | [semgrep.dev](https://github.com/semgrep/semgrep) |
| **Gosec** | Go | Security misconfigurations, crypto issues, injection flaws | [github](https://github.com/securego/gosec) |
| **Staticcheck** | Go | Bugs, performance issues, simplifications | [github](https://github.com/dominikh/go-tools) |
| **Govet** | Go | Suspicious constructs (printf args, struct tags, unreachable code) | [pkg.go.dev](https://pkg.go.dev/cmd/vet) |
| **Gocyclo** | Go | Cyclomatic complexity (identifies hard-to-test functions) | [github](https://github.com/fzipp/gocyclo) |
| **Bandit** | Python | Common security issues (eval, exec, hardcoded passwords) | [github](https://github.com/PyCQA/bandit) |
| **Pylint** | Python | Code quality, error detection, convention enforcement | [github](https://github.com/pylint-dev/pylint) |
| **Radon** | Python | Cyclomatic complexity and maintainability index | [github](https://github.com/rubik/radon) |
| **Vulture** | Python | Dead code detection | [github](https://github.com/jendrikseipp/vulture) |
| **ESLint** | JavaScript/TS | Security rules, code quality, best practices | [github](https://github.com/eslint/eslint) |
| **SpotBugs** | Java/Kotlin | 400+ bug patterns including security | [github](https://github.com/spotbugs/spotbugs) |
| **PMD** | Java/Kotlin | 300+ rules including security and code quality | [github](https://github.com/pmd/pmd) |
| **Brakeman** | Ruby/Rails | SQL injection, XSS, CSRF, mass assignment | [github](https://github.com/presidentbeef/brakeman) |
| **PHPCS** | PHP | Security sniffs, coding standards | [github](https://github.com/PHPCSStandards/PHP_CodeSniffer) |
| **Psalm** | PHP | Type inference, taint analysis, security-focused mode | [github](https://github.com/vimeo/psalm) |
| **Cppcheck** | C/C++ | Buffer overflows, null pointer derefs, memory leaks | [github](https://github.com/danmar/cppcheck) |
| **Flawfinder** | C/C++ | Security-focused source code scanner (CWE-mapped) | [github](https://github.com/david-a-wheeler/flawfinder) |
| **Slither** | Solidity | Smart contract vulnerabilities, 90+ detectors | [github](https://github.com/crytic/slither) |
| **Mythril** | Solidity | Symbolic execution for EVM bytecode | [github](https://github.com/Consensys/mythril) |
| **Clippy** | Rust | Security-relevant lints, correctness checks | [github](https://github.com/rust-lang/rust-clippy) |
| **ShellCheck** | Shell/Bash | Script analysis, injection risks, quoting issues | [github](https://github.com/koalaman/shellcheck) |
| **JSCPD** | All languages | Copy-paste detection across codebases | [github](https://github.com/kucherenko/jscpd) |

</details>

<details>
<summary><strong>SCA — Software Composition Analysis</strong></summary>

| Tool | Ecosystem | What it finds | Link |
|------|-----------|---------------|------|
| **Trivy** | All | CVEs in OS packages, language deps, and container images | [github](https://github.com/aquasecurity/trivy) |
| **OSV-Scanner** | All | Queries Google's OSV database for known vulnerabilities | [github](https://github.com/google/osv-scanner) |
| **Govulncheck** | Go | Reachability-aware Go vulnerability detection (only flags vulns your code actually calls) | [github](https://github.com/golang/vuln) |
| **Cargo Audit** | Rust | RustSec advisory database scanning | [github](https://github.com/rustsec/rustsec) |
| **Bundler Audit** | Ruby | RubyGems advisory scanning | [github](https://github.com/rubysec/bundler-audit) |
| **OWASP Dependency-Check** | Java | CVE scanning for Maven/Gradle/Ivy | [github](https://github.com/jeremylong/DependencyCheck) |
| **Grype** | Containers | Image vulnerability scanning (NVD + GitHub Advisory + OSV) | [github](https://github.com/anchore/grype) |

</details>

<details>
<summary><strong>Secrets Detection</strong></summary>

| Tool | What it finds | Link |
|------|---------------|------|
| **Gitleaks** | 150+ secret types (AWS, GCP, GitHub, Stripe, Slack, etc.) with git history scanning | [github](https://github.com/gitleaks/gitleaks) |
| **Trufflehog** | High-entropy strings, credential patterns, verified secret validation | [github](https://github.com/trufflesecurity/trufflehog) |

</details>

<details>
<summary><strong>IaC — Infrastructure as Code</strong></summary>

| Tool | Target | What it finds | Link |
|------|--------|---------------|------|
| **Checkov** | Terraform, CloudFormation, K8s, Helm, Docker | 1000+ security policies across cloud providers | [github](https://github.com/bridgecrewio/checkov) |
| **TFSec** | Terraform | AWS/Azure/GCP misconfigurations | [github](https://github.com/aquasecurity/tfsec) |
| **KICS** | Multi-IaC | 50+ platforms including Terraform, Ansible, Docker, K8s | [github](https://github.com/Checkmarx/kics) |
| **Hadolint** | Dockerfile | Dockerfile best practices + ShellCheck on RUN commands | [github](https://github.com/hadolint/hadolint) |
| **Kube-linter** | Kubernetes | Security and production-readiness checks | [github](https://github.com/stackrox/kube-linter) |
| **Kube-score** | Kubernetes | Best practice scoring for workload manifests | [github](https://github.com/zegl/kube-score) |

</details>

Every finding from every tool flows through our normalization pipeline — severity mapping, CWE enrichment, deduplication, and fingerprinting — so you get one clean, unified report instead of 30 different outputs.

---

Vibecoding is fast. But AI-generated code ships vulnerabilities you didn't write and don't understand.

**vibescan** catches them. It runs 30+ security tools, builds your app in a sandbox, simulates real attacks, maps exploit chains, and reviews every PR — all from a single interactive terminal UI.

## Quick Start

**Install** (pick one):

```bash
# macOS / Linux
brew install Armur-Ai/tap/vibescan

# npm (any platform)
npm install -g @vibescan/cli

# pip
pip install vibescan

# Direct download
curl -fsSL https://raw.githubusercontent.com/Armur-Ai/vibescan/main/scripts/install.sh | sh
```

**Then just run it:**

```bash
vibescan
```

That's it. No flags, no config. vibescan launches a full-screen interactive menu:

```
              V I B E S C A N
     Security Scanner for Vibe-Coded Software
  SAST  +  DAST  +  Exploit Simulation  +  Attack Paths

────────────────────────────────────────────────────────

  What would you like to do?

  ▸ 🔍 Scan Project          Analyze your code for vulnerabilities
    🖥  Interactive Scan       Guided wizard with live dashboard
    📋 Review Pull Request    Security review a GitHub/GitLab PR
    📊 View History           Browse past scan results
    📄 Generate Report        Create HTML, CSV, OWASP reports
    💡 Explain Finding        Get an AI explanation
    🔧 Fix Finding            Generate an AI-powered code patch
    🩺 Check Health           Verify tools and configuration
    ⚙  Initialize Project     Create .vibescan.yml config
    🔌 Setup AI / MCP         Configure editor integration

────────────────────────────────────────────────────────
  ↑↓ navigate  enter select  q quit
```

Navigate with arrow keys, press Enter to select. Every action is one keypress away.

## Interactive TUI

### Scan Flow

Select **"Scan Project"** and vibescan walks you through a 4-step wizard:

```
  VIBESCAN — Scan Configuration
  ● Target  →  ○ Language  →  ○ Depth  →  ○ Confirm

────────────────────────────────────────────────────────

  What would you like to scan?

  ● Current directory (my-project)
  ○ Enter a different path
  ○ Scan a remote repository

────────────────────────────────────────────────────────
  ↑↓ navigate  enter select  backspace back  esc cancel
```

After confirming, you get a **live dashboard** showing every tool's progress in real time:

```
╔══════════════════════════════════════════════════════╗
║  VIBESCAN  ·  ./my-project  ·  GO  ·  deep scan     ║
╠══════════════════════════════════════════════════════╣
║  Tool              Status          Found             ║
║  ──────────────────────────────────────────────────  ║
║  ✓ semgrep         completed 4s      14              ║
║  ⟳ gosec           running 2s         3              ║
║  ○ staticcheck     queued             -              ║
║  ○ gocyclo         queued             -              ║
║  ○ trufflehog      queued             -              ║
╠══════════════════════════════════════════════════════╣
║  Critical: 0  High: 3  Medium: 8  Low: 6  Info: 0  ║
║  Elapsed: 0:06                           [q] Quit   ║
╚══════════════════════════════════════════════════════╝
```

When the scan completes, you enter the **results browser** — a two-pane interactive viewer:

```
  17 findings · Showing: all · [f] filter · [↑↓/jk] navigate · [q] quit

  SEV       FILE                          LINE   MESSAGE
  ─────────────────────────────────────────────────────────────────
  [CRIT]    internal/handlers.go           42    SQL injection via user input
▸ [HIGH]    internal/auth.go              118    Hardcoded JWT secret
  [HIGH]    pkg/api/client.go              67    TLS verification disabled
  [ MED]    cmd/server/main.go             23    Missing CORS configuration
  [ LOW]    internal/utils.go             156    Unused error return

  ────────────────────────────────────────────────────────────────
  File:     internal/auth.go:118
  Severity: [HIGH]
  Rule:     gosec.G101
  CWE:      CWE-798
  Tool:     gosec
  Message:  Hardcoded credentials: JWT secret stored as string literal
```

Press `f` to filter by severity, `j/k` to navigate, `q` to quit.

### Direct Commands

Prefer flags over TUI? Everything works non-interactively too:

```bash
# Quick scan
vibescan scan .

# Deep scan with all tools
vibescan scan . --advanced

# Scan a GitHub repo
vibescan scan https://github.com/owner/repo -l go

# SARIF output for CI
vibescan scan . --format sarif --fail-on-severity high

# Watch mode — re-scan on file changes
vibescan scan . --watch
```

## Features

| Feature | What it does |
|---------|-------------|
| **SAST** | 30+ tools across 15 languages. Findings deduplicated, severity-normalized. |
| **DAST** | Auto-builds sandbox from your code, runs passive + active security tests. |
| **Exploit Simulation** | Generates PoC exploits (SQLi, XSS, RCE, SSRF) and runs them in sandbox. |
| **Attack Paths** | Chains findings into attack graphs with Mermaid visualization. |
| **PR Review** | `vibescan review <pr-url>` — SAST + secrets + DAST on the diff. |
| **AI Explain/Fix** | `vibescan explain` and `vibescan fix` powered by Claude or Ollama. |
| **MCP Server** | Works inside Claude Code, Cursor, Windsurf via MCP protocol. |
| **SCA** | Every package ecosystem: npm, pip, Go, Cargo, Maven, Ruby, PHP, NuGet, etc. |
| **Secrets** | Gitleaks + Trufflehog with git history scanning and secret validation. |
| **IaC** | Terraform, Kubernetes, Docker, Ansible, Helm — checkov, tfsec, kube-linter. |
| **Compliance** | OWASP Top 10, CWE Top 25, PCI-DSS, HIPAA, NIST mapping. |
| **Reports** | HTML, CSV, SARIF, OWASP, SANS — all from `vibescan report`. |

## Supported Languages

| Language | Tools | Categories |
|----------|-------|------------|
| **Go** | semgrep, gosec, govet, staticcheck, gocyclo, govulncheck | SAST, SCA, Quality |
| **Python** | semgrep, bandit, pylint, radon, pydocstyle, pip-audit | SAST, SCA, Quality |
| **JavaScript/TS** | semgrep, eslint | SAST, Quality |
| **Rust** | semgrep, cargo-audit, cargo-geiger, clippy | SAST, SCA |
| **Java/Kotlin** | semgrep, spotbugs, pmd, dependency-check | SAST, SCA |
| **Ruby** | semgrep, brakeman, bundler-audit | SAST, SCA |
| **PHP** | semgrep, phpcs, psalm | SAST, Quality |
| **C/C++** | semgrep, cppcheck, flawfinder | SAST |
| **C#/.NET** | semgrep, security-code-scan, roslynator | SAST, Quality |
| **Solidity** | semgrep, slither, mythril | SAST |
| **IaC** | checkov, hadolint, tfsec, kics, kube-linter, kube-score, terrascan | IaC |
| **Containers** | trivy, grype | SCA, Image |
| **Secrets** | trufflehog, gitleaks | Secrets |
| **Shell** | shellcheck | SAST |
| **Swift** | swiftlint | SAST |

## All Commands

| Command | Description |
|---------|-------------|
| `vibescan` | **Launch interactive TUI** (default when no args) |
| `vibescan scan <target>` | One-shot scan with flags |
| `vibescan run` | Guided wizard → live dashboard → results browser |
| `vibescan review <pr-url>` | Review a GitHub/GitLab pull request |
| `vibescan explain <id>` | AI explanation of a finding |
| `vibescan fix <id>` | AI-generated code patch |
| `vibescan serve` | Start the embedded API server |
| `vibescan doctor` | Check which tools are installed |
| `vibescan init` | Create `.vibescan.yml` config file |
| `vibescan history` | List past scans |
| `vibescan compare <id1> <id2>` | Diff two scan results |
| `vibescan report` | Generate HTML/CSV/OWASP/SANS reports (interactive) |
| `vibescan mcp` | Start MCP server for AI editors |
| `vibescan quickstart` | Step-by-step getting started guide |
| `vibescan completion <shell>` | Shell completions (bash/zsh/fish/powershell) |
| `vibescan version` | Print version info |

## CI/CD Integration

### GitHub Actions

```yaml
- name: vibescan Security Scan
  run: |
    curl -fsSL https://raw.githubusercontent.com/Armur-Ai/vibescan/main/scripts/install.sh | sh
    vibescan scan . --format sarif --output results.sarif --fail-on-severity high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
vibescan:
  image: vibescan/agent:latest
  script:
    - vibescan scan . --format sarif --output gl-sast-report.json --fail-on-severity high
  artifacts:
    reports:
      sast: gl-sast-report.json
```

See also: [CircleCI](docs/ci/circleci.md), [Jenkins](docs/ci/jenkins.md), [Azure DevOps](docs/ci/), [Bitbucket](docs/ci/)

## AI Editor Integration (MCP)

vibescan runs as an MCP server inside Claude Code, Cursor, and Windsurf:

```bash
# Claude Code
claude mcp add vibescan -- vibescan mcp

# Cursor — add to ~/.cursor/mcp.json:
# { "mcpServers": { "vibescan": { "command": "vibescan", "args": ["mcp"] } } }
```

MCP tools available to your AI assistant:
- `vibescan_scan_path` — scan a directory
- `vibescan_scan_code` — scan a code snippet inline
- `vibescan_check_dependency` — check a package for CVEs
- `vibescan_explain_finding` — explain a vulnerability
- `vibescan_get_history` — recent scan history

## Configuration

Create `.vibescan.yml` in your project root (or run `vibescan init`):

```yaml
scan:
  depth: quick                  # quick | deep
  severity-threshold: medium    # minimum severity to report
  fail-on-findings: true        # exit code 1 in CI

exclude:
  - vendor/
  - node_modules/
  - testdata/

tools:
  disabled:
    - gocyclo                   # skip specific tools
```

Full reference: [Configuration docs](docs/configuration/armur-yml.md)

## Architecture

```
                   ┌────────────────┐
                   │  vibescan CLI  │  (Cobra + Bubbletea TUI)
                   └──────┬─────────┘
                          │
                ┌─────────▼──────────┐
                │   API Server (Gin) │  port 4500
                └─────────┬──────────┘
                          │
              ┌───────────▼────────────┐
              │  Asynq Worker (Redis)  │
              └───────────┬────────────┘
                          │
         ┌────────────────▼─────────────────┐
         │        Tool Runners (30+)         │
         │  semgrep, gosec, bandit, eslint,  │
         │  trivy, gitleaks, slither, ...    │
         └────────────────┬─────────────────┘
                          │
              ┌───────────▼────────────┐
              │  Finding Pipeline       │
              │  Normalize → Dedup →    │
              │  Fingerprint → Score    │
              └───────────┬────────────┘
                          │
         ┌────────────────▼─────────────────┐
         │   Output: TUI, Text, JSON,       │
         │   SARIF, HTML, CSV, OWASP        │
         └──────────────────────────────────┘
```

## Self-Hosted (Docker)

```bash
docker-compose up -d

curl -X POST http://localhost:4500/api/v1/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/owner/repo", "language": "go"}'
```

API docs: `http://localhost:4500/swagger/index.html`

## Security

Found a vulnerability in vibescan? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add tools, languages, and rules.

## Roadmap

See [IMPROVEMENTS.md](IMPROVEMENTS.md) — 59 sprints across 7 phases, from core product to distributed scanning.

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**[vibescan.dev](https://vibescan.dev)** &bull; [Discord](https://discord.gg/PEycrqvd) &bull; [Docs](docs/)

*Built for the vibecoding era. Ship fast, ship safe.*

</div>
