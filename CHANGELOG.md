# Changelog

All notable changes to Armur Security Agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Phase 1: Foundation (Sprints 1-4)
- Test suite, error propagation, input validation, structured logging, API authentication
- Parallel tool execution, diff scanning, plugin system, project config, Docker images
- SARIF output, GitHub Actions, pre-commit hooks, webhooks, GitLab CI
- Language expansion: Rust, Java/Kotlin, Ruby, PHP, C/C++, IaC (Terraform, Docker, K8s), Solidity

### Phase 2: Core Product (Sprints 5-14)
- `armur serve` embedded server with auto-start, SSE progress streaming, severity summary card
- SQLite scan history, `armur init`, `armur doctor`, shell completions, `--watch` mode
- `armur run` — multi-step wizard, live Bubbletea TUI dashboard, interactive results browser
- Unified `Finding` type with severity normalization, deduplication, and fingerprinting
- Smart scanning — auto-detect language, `.armur.yml` project config, diff scanning
- Lipgloss-styled display, HTML/CSV reports, embedded miniredis for zero-infrastructure mode
- CI/CD workflows, goreleaser, issue templates, SECURITY.md, `armur version`
- Documentation site skeleton, CLI reference, config reference, tool reference
- Multi-ecosystem SCA: npm-audit, pip-audit, composer-audit, ecosystem detection

### Phase 3: The Agent Edge (Sprints 15-21)
- **Rebrand** to "Armur — Personal Security Agent" with agent pipeline orchestrator
- **AI Intelligence Layer**: Claude API + Ollama providers, tech stack detection, `armur explain`, `armur fix`
- **Sandboxed DAST**: Docker isolation, auto-Dockerfile generation, health detection, passive checks, Nuclei integration
- **Exploit Simulation**: PoC generator (SQLi, XSS, cmd injection, path traversal, SSRF), safe sandbox runner
- **Attack Path Analysis**: Graph construction, 8 chain rules, scoring, Mermaid visualization
- **PR Security Agent**: `armur review <pr-url>`, review pipeline, GitHub integration, AI narrative
- **MCP Server**: 5 MCP tools for Claude Code/Cursor/Windsurf integration

### Phase 4: Distribution & Community (Sprints 22-32)
- npm package scaffold, universal install script (`curl | sh`), GitHub Action (action.yml)
- VS Code extension scaffold, CI templates (GitLab, CircleCI, Jenkins)
- `armur quickstart` interactive guide, security posture score (0-100, A-F grading)
- Community ecosystem: template registry, exploit templates, sandbox profiles, fix recipes, attack chains

### Phase 5: Scanner Breadth (Sprints 33-43)
- Gitleaks deep secrets scanning, OpenAPI spec security analysis
- OWASP Top 10 2021 compliance mapping with CWE lookup table
- SBOM generation (CycloneDX/SPDX via cdxgen/trivy), supply chain checks
- C#/.NET (SecurityCodeScan, Roslynator), Swift/Shell (SwiftLint, ShellCheck)
- terrascan, kubesec (IaC deep), Grype and Trivy image scanning (containers)
- govulncheck with call-graph reachability analysis

### Phase 6: Advanced Capabilities (Sprints 44-55)
- Health/readiness endpoints, SSE event registry with ProgressReporter interface
- Typed API responses, batch scanning, X-Request-ID correlation middleware
- Rules marketplace registry (fetch, install, search, list)
- Go/Python/JS fuzzing integration, PII detection, cryptographic health checker
- Binary security (checksec, string scan), threat modeling with route detection + Mermaid DFD
- Dependency update automation, network config security, security test generation

### Phase 7: Scale & Intelligence (Sprints 56-59)
- File-level scan caching, monorepo service detection
- SLA tracking, security debt estimation, never-allow governance rules
- CISA KEV enrichment, EPSS exploit prediction scoring
- OWASP LLM Top 10 scanner (prompt injection, insecure output, excessive agency)
