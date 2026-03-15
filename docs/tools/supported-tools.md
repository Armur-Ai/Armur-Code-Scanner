# Supported Tools

Armur integrates with 30+ security tools across 10 languages and IaC platforms.

## Language Coverage

| Language | SAST | SCA | Secrets | Quality |
|----------|------|-----|---------|---------|
| **Go** | semgrep, gosec, govet, staticcheck | osv-scanner, trivy | trufflehog | gocyclo, golint |
| **Python** | semgrep, bandit | osv-scanner, trivy | trufflehog | pylint, radon, pydocstyle |
| **JavaScript/TS** | semgrep, eslint | osv-scanner, trivy | trufflehog | jscpd |
| **Rust** | semgrep, clippy | cargo-audit, cargo-geiger | trufflehog | — |
| **Java/Kotlin** | semgrep, spotbugs, pmd | dependency-check | trufflehog | — |
| **Ruby** | semgrep, brakeman | bundler-audit | trufflehog | — |
| **PHP** | semgrep, phpcs, psalm | — | trufflehog | — |
| **C/C++** | semgrep, cppcheck, flawfinder | — | trufflehog | — |
| **Solidity** | semgrep, slither, mythril | — | — | — |
| **IaC** | semgrep, checkov | — | — | hadolint, tfsec, kics, kube-linter, kube-score |

## Advanced Scan Tools (all languages)

| Tool | Category | Description |
|------|----------|-------------|
| jscpd | Duplicate code | Detects copy-pasted code blocks |
| checkov | IaC security | Infrastructure-as-code policy checks |
| trufflehog | Secrets | Finds leaked credentials and API keys |
| trivy | SCA + vulnerabilities | Scans dependencies for known CVEs |
| osv-scanner | SCA | Queries the OSV vulnerability database |
