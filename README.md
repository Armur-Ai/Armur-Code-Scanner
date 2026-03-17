<div align="center">

# vibescan

### Security Scanner for Vibe-Coded Software

**SAST + DAST + Exploit Simulation + Attack Path Analysis — All Automated**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![GitHub Stars](https://img.shields.io/github/stars/Armur-Ai/Armur-Code-Scanner?style=social)](https://github.com/Armur-Ai/Armur-Code-Scanner)
[![Discord](https://img.shields.io/discord/1021371417134125106?label=Discord&logo=discord)](https://discord.gg/PEycrqvd)

[Quick Start](#quick-start) &bull; [Features](#features) &bull; [Languages](#supported-languages) &bull; [CLI Reference](#cli-commands) &bull; [CI/CD](#cicd-integration) &bull; [MCP](#ai-editor-integration-mcp) &bull; [Contributing](#contributing)

</div>

---

vibescan is an open-source security scanner built for the vibecoding era. It that goes beyond scanning. It analyzes your code with 30+ security tools, runs your application in a sandbox for dynamic testing, simulates real exploits to confirm vulnerabilities, maps attack paths, and reviews every pull request — all automatically.

Built for the era of AI-generated code where automated security validation is essential.

## Quick Start

**Install** (pick one):

```bash
# macOS / Linux
brew install vibescan-ai/tap/vibescan

# npm (any platform)
npm install -g @vibescan/cli

# pip
pip install vibescan

# Direct download
curl -fsSL https://install.vibescan.dev | sh

# Docker (zero install)
docker run --rm -v $(pwd):/scan vibescan/agent scan /scan
```

**Run your first scan:**

```bash
# Interactive mode with guided wizard + live dashboard
vibescan run

# Direct scan of current directory
vibescan scan .

# Scan a GitHub repository
vibescan scan https://github.com/owner/repo -l go

# Deep scan with all tools
vibescan scan . --advanced
```

That's it. vibescan auto-detects the language, runs the right tools, deduplicates findings, and shows you a severity-sorted summary.

## Features

### SAST (Static Application Security Testing)
Run 30+ security tools across 10 languages with a single command. Findings are deduplicated, severity-normalized, and sorted by risk.

### DAST (Dynamic Application Security Testing)
vibescan can auto-detect your tech stack, generate a Dockerfile, build and run your app in an isolated sandbox, and hammer it with security tests — passive header checks, active injection probes, Nuclei CVE templates, and ZAP deep scans.

### Exploit Simulation
Don't just find vulnerabilities — prove they're exploitable. vibescan generates proof-of-concept exploits (SQL injection, XSS, command injection, path traversal, SSRF) and runs them safely inside the sandbox. Confirmed exploits get a `[CONFIRMED]` badge.

### Attack Path Analysis
Individual findings are noise. Attack paths are signal. vibescan chains related findings into attack graphs: "SSRF + cloud metadata = credential theft" and generates Mermaid diagrams for visualization.

### PR Security Agent
vibescan automatically reviews pull requests — runs SAST on the diff, checks for new vulnerable dependencies, scans for leaked secrets, and posts a detailed review with inline comments.

```bash
vibescan review https://github.com/owner/repo/pull/123
```

### AI-Powered Intelligence
Uses Claude API or local LLMs (Ollama) for:
- `vibescan explain <finding-id>` — plain-English explanation with attack scenario
- `vibescan fix <finding-id>` — AI-generated code patch
- Tech stack detection for DAST sandbox creation

### MCP Server for AI Editors
Works with Claude Code, Cursor, and Windsurf as an MCP server:
```bash
claude mcp add armur -- vibescan mcp
```

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
| **IaC** | semgrep, checkov, hadolint, tfsec, kics, kube-linter, kube-score, terrascan, kubesec | IaC |
| **Containers** | trivy, grype | SCA, Image |
| **Secrets** | trufflehog, gitleaks | Secrets |
| **Shell/Bash** | shellcheck | SAST |
| **Swift** | swiftlint | SAST |

**Plus:** SCA for all ecosystems (npm, pip, Go, Cargo, Maven, RubyGems, Composer, NuGet, CocoaPods, pub, Hex, Conan, sbt) via osv-scanner and ecosystem-specific auditors.

## CLI Commands

| Command | Description |
|---------|-------------|
| `vibescan run` | Interactive wizard + live TUI dashboard |
| `vibescan scan <target>` | One-shot scan (file, directory, or git URL) |
| `vibescan review <pr-url>` | Review a GitHub/GitLab pull request |
| `vibescan explain <id>` | AI explanation of a finding |
| `vibescan fix <id>` | AI-generated code patch |
| `vibescan serve` | Start the embedded API server |
| `vibescan doctor` | Check which tools are installed |
| `vibescan init` | Create `.vibescan.yml` config file |
| `vibescan history` | List past scans |
| `vibescan compare <id1> <id2>` | Diff two scan results |
| `vibescan report --format html` | Generate HTML/CSV/OWASP/SANS reports |
| `vibescan mcp` | Start MCP server for AI editors |
| `vibescan quickstart` | Interactive getting-started guide |
| `vibescan completion <shell>` | Shell completions (bash/zsh/fish/powershell) |
| `vibescan version` | Print version info |

### Key Flags

```bash
vibescan scan . --advanced              # deep scan with all tools
vibescan scan . --format sarif          # SARIF output (for GitHub Security tab)
vibescan scan . --fail-on-severity high # exit code 1 on HIGH+ findings (CI use)
vibescan scan . --min-severity medium   # suppress LOW and INFO findings
vibescan scan . --watch                 # re-scan on file changes
vibescan scan . --no-server             # skip auto-starting the embedded server
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: vibescan Security Scan
  uses: armur-ai/armur-code-scanner@main
  with:
    path: '.'
    fail-on-severity: 'high'
    upload-sarif: 'true'
```

Or use the CLI directly:

```yaml
- run: curl -fsSL https://install.vibescan.dev | sh
- run: vibescan scan . --format sarif --output results.sarif --fail-on-severity high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
armur-scan:
  image: vibescan/agent:latest
  script:
    - vibescan scan . --format sarif --output gl-sast-report.json --fail-on-severity high
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Other CI Platforms

See full guides for [CircleCI](docs/ci/circleci.md), [Jenkins](docs/ci/jenkins.md), [Azure DevOps](docs/ci/), and [Bitbucket Pipelines](docs/ci/).

## AI Editor Integration (MCP)

vibescan works as an MCP server with Claude Code, Cursor, and Windsurf:

```bash
# Claude Code
claude mcp add armur -- vibescan mcp

# Cursor — add to ~/.cursor/mcp.json
# Windsurf — add to Windsurf MCP config
```

Available MCP tools:
- `armur_scan_path` — scan a directory
- `armur_scan_code` — scan a code snippet inline
- `armur_check_dependency` — check a package for vulnerabilities
- `armur_explain_finding` — AI explanation of a finding
- `armur_get_history` — recent scan history

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
                   ┌──────────────┐
                   │   armur CLI  │  (Cobra + Bubbletea TUI)
                   └──────┬───────┘
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
         │   Output: Text, JSON, SARIF,     │
         │   HTML, CSV, OWASP, TUI          │
         └──────────────────────────────────┘
```

## Self-Hosted (Docker)

```bash
# Start server + Redis
docker-compose up -d

# Scan via API
curl -X POST http://localhost:4500/api/v1/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/owner/repo", "language": "go"}'
```

API docs available at `http://localhost:4500/swagger/index.html`

## Security

Found a vulnerability in vibescan itself? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Contributing

Contributions are welcome! See our [Contributing Guide](CONTRIBUTING.md) for:
- How to add a new tool integration
- How to add a new language
- How to write security rules
- Code style and PR process

## Roadmap

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for the full 60-sprint roadmap organized into 7 phases:

| Phase | Focus |
|-------|-------|
| v1.0 Core Product | CLI, TUI, Finding pipeline, docs, SCA |
| v2.0 Agent Edge | Rebrand, AI layer, DAST, exploits, attack paths, PR agent, MCP |
| v2.5 Distribution | npm/Homebrew/pip, GitHub App, VS Code, CI/CD |
| v3.0 Scanner Breadth | Secrets, SAST, API security, compliance, SBOM, supply chain |
| v3.5 Advanced | Observability, fuzzing, PII, crypto, threat modeling |
| v4.0 Scale | Distributed workers, threat intel, LLM security |

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**[vibescan.dev](https://vibescan.dev)** &bull; [Discord](https://discord.gg/PEycrqvd) &bull; [Documentation](docs/)

</div>
