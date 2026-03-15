# Changelog

All notable changes to Armur Security Agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Sprint 1-4**: Foundation — tests, error handling, validation, logging, auth, parallel execution, SARIF, GitHub Actions, webhooks, language expansion (Rust, Java, Ruby, PHP, C/C++, IaC, Solidity)
- **Sprint 5**: CLI polish — `armur serve`, SSE progress streaming, severity summary card, SQLite history, `armur init`, `armur doctor`, shell completions, `--watch` mode, HTML/CSV reports
- **Sprint 6**: Core engine — unified `Finding` type, severity normalization, deduplication, scan cancellation API
- **Sprint 7**: `armur run` — multi-step wizard, live Bubbletea dashboard, interactive results browser
- **Sprint 8**: Smart scanning — auto-detect language, `.armur.yml` project config, diff scanning
- **Sprint 9**: CLI completeness — `armur doctor`, SQLite history, completions, `--watch`, `armur version`
- **Sprint 10**: Display — lipgloss-styled findings table, summary card, tool error rendering
- **Sprint 11**: Zero-infrastructure — embedded miniredis for local mode
- **Sprint 12**: Community — GitHub Actions CI/CD, goreleaser, issue templates, SECURITY.md
