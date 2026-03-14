package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// defaultServerPort is the default port for the embedded Armur server.
const defaultServerPort = "4500"

// pidFilePath returns the path to the PID file for the embedded server.
func pidFilePath() string {
	return filepath.Join(os.Getenv("HOME"), ".armur", "server.pid")
}

// isServerRunning checks if a server is already listening on the given address.
func isServerRunning(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isServerHealthy checks if the server at the given base URL responds to a basic request.
func isServerHealthy(baseURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/api/v1/status/health-check")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Any response (even 400/404) means the server is alive and routing.
	return true
}

// findServerBinary locates the armur-server binary.
// It checks: 1) next to the CLI binary, 2) in PATH, 3) via `go run` fallback path.
func findServerBinary() (string, error) {
	// Check next to the current binary
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, "armur-server")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Check PATH
	if path, err := exec.LookPath("armur-server"); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("armur-server binary not found; install it or run the server with Docker")
}

// startEmbeddedServer starts the server as a background process and writes a PID file.
func startEmbeddedServer(port string) error {
	serverBin, err := findServerBinary()
	if err != nil {
		return err
	}

	cmd := exec.Command(serverBin)
	cmd.Env = append(os.Environ(), "APP_PORT="+port)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// Write PID file
	pidDir := filepath.Dir(pidFilePath())
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return fmt.Errorf("failed to create pid directory: %w", err)
	}
	if err := os.WriteFile(pidFilePath(), []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		return fmt.Errorf("failed to write pid file: %w", err)
	}

	// Wait for server to become ready
	addr := "localhost:" + port
	for i := 0; i < 30; i++ {
		if isServerRunning(addr) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("server started but not responding on %s after 15s", addr)
}

// stopEmbeddedServer stops a previously started embedded server using the PID file.
func stopEmbeddedServer() error {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return fmt.Errorf("no running server found (no pid file)")
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		os.Remove(pidFilePath())
		return fmt.Errorf("invalid pid file")
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidFilePath())
		return fmt.Errorf("process %d not found", pid)
	}

	if err := proc.Signal(os.Interrupt); err != nil {
		// Process may already be dead
		os.Remove(pidFilePath())
		return fmt.Errorf("failed to stop server (pid %d): %w", pid, err)
	}

	os.Remove(pidFilePath())
	return nil
}

// ensureServer makes sure an Armur server is available. It checks if one is
// already running; if not, it starts an embedded server. Returns the base URL.
// When noServer is true, it assumes a server is already running and skips auto-start.
func ensureServer(apiURL string, noServer bool) string {
	if noServer {
		return apiURL
	}

	// Extract host:port from the API URL
	addr := strings.TrimPrefix(apiURL, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimRight(addr, "/")

	if isServerRunning(addr) {
		return apiURL
	}

	// Server is not running — try to start it
	port := defaultServerPort
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		port = parts[1]
	}

	fmt.Println(color.YellowString("No server detected on %s — starting embedded server...", addr))
	if err := startEmbeddedServer(port); err != nil {
		color.Red("Failed to auto-start server: %v", err)
		color.Red("Start the server manually with 'armur serve' or Docker, or use --no-server to skip.")
		os.Exit(1)
	}

	color.Green("Embedded server started on port %s", port)
	return apiURL
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Armur API server locally",
	Long: `Start the Armur Code Scanner API server as a local process.
The server listens on port 4500 by default (use --port to change).
Use 'armur serve stop' to stop a previously started server.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Handle 'armur serve stop'
		if len(args) == 1 && args[0] == "stop" {
			if err := stopEmbeddedServer(); err != nil {
				color.Red("Error: %v", err)
				os.Exit(1)
			}
			color.Green("Server stopped.")
			return
		}

		port, _ := cmd.Flags().GetString("port")
		if port == "" {
			port = defaultServerPort
		}

		addr := "localhost:" + port
		if isServerRunning(addr) {
			color.Yellow("Server is already running on %s", addr)
			return
		}

		fmt.Println(color.CyanString("Starting Armur server on port %s...", port))
		if err := startEmbeddedServer(port); err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}

		color.Green("Server started successfully on port %s (PID file: %s)", port, pidFilePath())
		fmt.Println("Use 'armur serve stop' to stop the server.")
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringP("port", "p", defaultServerPort, "Port to run the server on")
}
