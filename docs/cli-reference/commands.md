# CLI Command Reference

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--api-key` | `-k` | API key for authenticating with the Armur server |
| `--verbose` | `-v` | Enable debug output |

## Commands

### `armur run [target]`

Launch the interactive security agent with a guided wizard and live dashboard.

```bash
armur run              # scan current directory
armur run ./src        # scan specific path
armur run --no-server  # skip auto-starting embedded server
```

### `armur scan <target>`

Run a one-shot scan.

```bash
armur scan .                           # scan current directory
armur scan https://github.com/org/repo -l go  # scan remote repo
armur scan . --advanced                # deep scan with all tools
armur scan . --output json             # JSON output
armur scan . --format sarif            # SARIF output
armur scan . --fail-on-severity high   # exit code 1 on HIGH+ findings
armur scan . --min-severity medium     # suppress LOW and INFO
armur scan . --watch                   # re-scan on file changes
armur scan . --interactive             # launch wizard mode
```

### `armur serve [stop]`

Start or stop the embedded API server.

```bash
armur serve            # start on port 4500
armur serve --port 8080  # custom port
armur serve stop       # stop running server
```

### `armur init`

Create a `.armur.yml` configuration file in the current directory.

### `armur doctor`

Check which tools are installed and diagnose configuration issues.

### `armur history`

List past scans with timestamps and finding counts.

```bash
armur history              # list recent scans
armur history show <id>    # show full results
armur history clear        # clear all history
```

### `armur compare <id1> <id2>`

Compare two scan results to find new and fixed findings.

### `armur report`

Generate reports in various formats.

```bash
armur report --task <id> --format html   # standalone HTML report
armur report --task <id> --format csv    # CSV export
armur report --task <id> --format owasp  # OWASP Top 10 mapping
armur report --task <id> --format sans   # SANS mapping
```

### `armur config [key] [value]`

Manage CLI configuration.

```bash
armur config api_url http://localhost:4500
armur config api_key my-secret-key
```

### `armur completion <shell>`

Generate shell completion scripts.

```bash
armur completion bash
armur completion zsh
armur completion fish
armur completion powershell
```

### `armur version`

Print version information.
