# GitHub Actions Integration

## Quick Setup

Add this workflow to `.github/workflows/armur.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  armur-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Armur
        run: curl -fsSL https://install.armur.ai | sh

      - name: Run scan
        run: armur scan . --format sarif --output results.sarif --fail-on-severity high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Fail on Severity

Use `--fail-on-severity` to fail the build when findings exceed a threshold:

```yaml
- run: armur scan . --fail-on-severity high
```

Options: `critical`, `high`, `medium`, `low`

## PR Scanning (diff mode)

Scan only changed files in a PR:

```yaml
- run: armur scan . --diff origin/main --format sarif
```

## Advanced: Deep Scan + Report

```yaml
- name: Deep scan
  run: |
    armur scan . --advanced --format sarif --output results.sarif
    armur report --task $(armur history | head -1 | awk '{print $2}') --format html
```
