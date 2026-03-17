package cmd

import (
	"armur-cli/internal/config"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// toolInfo describes a scanning tool that armur depends on.
type toolInfo struct {
	Name       string
	Binary     string
	VersionArg string // e.g., "--version"
	InstallCmd string // hint for how to install
}

var bundledTools = []toolInfo{
	{"Semgrep", "semgrep", "--version", "pip install semgrep"},
	{"Gosec", "gosec", "--version", "go install github.com/securego/gosec/v2/cmd/gosec@latest"},
	{"Golint", "golint", "", "go install golang.org/x/lint/golint@latest"},
	{"Staticcheck", "staticcheck", "--version", "go install honnef.co/go/tools/cmd/staticcheck@latest"},
	{"Gocyclo", "gocyclo", "", "go install github.com/fzipp/gocyclo/cmd/gocyclo@latest"},
	{"Go Vet", "go", "vet", "(bundled with Go)"},
	{"Bandit", "bandit", "--version", "pip install bandit"},
	{"Pylint", "pylint", "--version", "pip install pylint"},
	{"Radon", "radon", "--version", "pip install radon"},
	{"Pydocstyle", "pydocstyle", "--version", "pip install pydocstyle"},
	{"ESLint", "eslint", "--version", "npm install -g eslint"},
	{"Trivy", "trivy", "version", "brew install trivy"},
	{"Trufflehog", "trufflehog", "--version", "brew install trufflehog"},
	{"OSV-Scanner", "osv-scanner", "--version", "go install github.com/google/osv-scanner/cmd/osv-scanner@latest"},
	{"jscpd", "jscpd", "--version", "npm install -g jscpd"},
	{"Checkov", "checkov", "--version", "pip install checkov"},
	{"Cargo Audit", "cargo-audit", "--version", "cargo install cargo-audit"},
	{"Clippy", "cargo", "clippy --version", "(bundled with Rust)"},
	{"SpotBugs", "spotbugs", "-version", "brew install spotbugs"},
	{"Brakeman", "brakeman", "--version", "gem install brakeman"},
	{"PHPCS", "phpcs", "--version", "composer global require squizlabs/php_codesniffer"},
	{"Cppcheck", "cppcheck", "--version", "brew install cppcheck"},
	{"Flawfinder", "flawfinder", "--version", "pip install flawfinder"},
	{"Hadolint", "hadolint", "--version", "brew install hadolint"},
	{"Slither", "slither", "--version", "pip install slither-analyzer"},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check which tools are installed and diagnose configuration issues",
	Long:  `Run a self-diagnosis to verify that Armur and its dependencies are properly configured.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			color.Red("Error loading config: %v", err)
			os.Exit(1)
		}

		fmt.Println(color.CyanString("vibescan doctor"))
		fmt.Println(strings.Repeat("─", 50))

		exitCode := 0

		// Check API server
		apiAddr := strings.TrimPrefix(cfg.API.URL, "http://")
		apiAddr = strings.TrimPrefix(apiAddr, "https://")
		apiAddr = strings.TrimRight(apiAddr, "/")
		if isReachable(apiAddr) {
			printCheck(true, "API server", cfg.API.URL)
		} else {
			printCheck(false, "API server", cfg.API.URL+" (not reachable)")
			fmt.Println("              → Start with: vibescan serve")
		}

		// Check Redis
		redisAddr := "localhost:6379"
		if cfg.Redis.URL != "" {
			redisAddr = cfg.Redis.URL
		}
		if isReachable(redisAddr) {
			printCheck(true, "Redis", redisAddr)
		} else {
			printWarn("Redis", redisAddr+" (not reachable — needed for server mode)")
		}

		// Check API key
		if cfg.APIKey != "" {
			printCheck(true, "API key", "configured")
		} else {
			printWarn("API key", "not configured (set with: vibescan config set api_key <key>)")
		}

		// Check Docker
		if _, err := exec.LookPath("docker"); err == nil {
			printCheck(true, "Docker", "installed")
		} else {
			printWarn("Docker", "not found (needed for sandbox DAST)")
		}

		// Check .vibescan.yml
		if _, err := os.Stat(".vibescan.yml"); err == nil {
			printCheck(true, ".vibescan.yml", "found in current directory")
		} else {
			printWarn(".vibescan.yml", "not found (create with: vibescan init)")
		}

		fmt.Println(strings.Repeat("─", 50))

		// Check tools
		found := 0
		missing := 0
		for _, tool := range bundledTools {
			path, err := exec.LookPath(tool.Binary)
			if err != nil {
				printMissing(tool.Name, tool.InstallCmd)
				missing++
				continue
			}

			// Try to get version
			version := ""
			if tool.VersionArg != "" {
				versionArgs := strings.Fields(tool.VersionArg)
				out, err := exec.Command(path, versionArgs...).CombinedOutput()
				if err == nil {
					version = strings.TrimSpace(strings.Split(string(out), "\n")[0])
					if len(version) > 40 {
						version = version[:40]
					}
				}
			}
			if version != "" {
				printCheck(true, tool.Name, version)
			} else {
				printCheck(true, tool.Name, "installed")
			}
			found++
		}

		fmt.Println(strings.Repeat("─", 50))

		if missing > 0 {
			color.Yellow("%d tool(s) missing. Install them for full scanning coverage.", missing)
			exitCode = 1
		}
		fmt.Printf("%d / %d tools available.\n", found, len(bundledTools))

		// Check for Anthropic API key (for AI features)
		if os.Getenv("ANTHROPIC_API_KEY") != "" {
			printCheck(true, "Claude API", "key configured")
		} else {
			printWarn("Claude API", "ANTHROPIC_API_KEY not set (AI features disabled)")
		}

		// Check for Ollama
		if isReachable("localhost:11434") {
			printCheck(true, "Ollama", "running at localhost:11434")
		} else {
			printWarn("Ollama", "not running (local AI features unavailable)")
		}

		if exitCode > 0 {
			os.Exit(exitCode)
		}
	},
}

func isReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func printCheck(ok bool, name, detail string) {
	if ok {
		fmt.Printf("%s  %-16s %s\n", color.GreenString("✓"), name, detail)
	} else {
		fmt.Printf("%s  %-16s %s\n", color.RedString("✗"), name, detail)
	}
}

func printWarn(name, detail string) {
	fmt.Printf("%s  %-16s %s\n", color.YellowString("⚠"), name, detail)
}

func printMissing(name, installCmd string) {
	fmt.Printf("%s  %-16s %s\n", color.RedString("✗"), name, "NOT FOUND")
	if installCmd != "" {
		fmt.Printf("   %s → %s\n", strings.Repeat(" ", 14), color.CyanString(installCmd))
	}
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
