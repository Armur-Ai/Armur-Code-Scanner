# Quick Start

Get your first security scan running in under 60 seconds.

## Install

```bash
# macOS / Linux
brew install armur-ai/tap/armur

# npm (any platform)
npm install -g @armur/cli

# pip
pip install armur

# Direct download
curl -fsSL https://install.armur.ai | sh
```

## Scan Your Project

```bash
# Interactive mode (guided wizard)
armur run

# Direct scan
armur scan .

# Scan a remote repository
armur scan https://github.com/owner/repo -l go
```

## What Happens

1. Armur detects the language(s) in your project
2. Runs security tools appropriate for that language
3. Deduplicates and normalizes findings
4. Shows results in a severity-sorted summary

## Next Steps

- [Configure your project](../configuration/armur-yml.md) with `.armur.yml`
- [Add to CI/CD](../ci/github-actions.md) for automated scanning
- [Set up in your editor](../tools/vscode.md) for inline findings
