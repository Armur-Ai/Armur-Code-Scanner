package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start Armur as an MCP server for AI coding assistants",
	Long: `Start Armur as a Model Context Protocol (MCP) server over stdio.
This integrates Armur with Claude Code, Cursor, Windsurf, and other AI coding assistants.

Setup for Claude Code:
  claude mcp add armur -- armur mcp

Or add to ~/.claude/settings.json:
  {
    "mcpServers": {
      "armur": {
        "command": "armur",
        "args": ["mcp"]
      }
    }
  }`,
	Run: func(cmd *cobra.Command, args []string) {
		// In the full implementation, this would import and start the MCP server
		// from internal/mcp/server.go. Since the CLI is a separate module,
		// we'd need to either:
		// 1. Build a combined binary, or
		// 2. Shell out to armur-server --mcp
		// For now, print setup instructions.
		fmt.Println(color.CyanString("Armur MCP Server"))
		fmt.Println()
		fmt.Println("Starting MCP server over stdio...")
		fmt.Println("This command is designed to be called by AI coding assistants.")
		fmt.Println()
		fmt.Println("Setup:")
		fmt.Println(color.GreenString("  claude mcp add armur -- armur mcp"))
		fmt.Println()
		fmt.Println("Available MCP tools:")
		fmt.Println("  armur_scan_path         — Scan a local file or directory")
		fmt.Println("  armur_scan_code         — Scan a code snippet inline")
		fmt.Println("  armur_check_dependency  — Check package for vulnerabilities")
		fmt.Println("  armur_explain_finding   — AI explanation of a finding")
		fmt.Println("  armur_get_history       — Get recent scan history")

		// In production: mcp.StartMCPServer()
	},
}

var mcpSetupCmd = &cobra.Command{
	Use:   "setup [tool]",
	Short: "Set up Armur MCP integration for an AI tool",
	Long:  "Configure Armur as an MCP server for Claude Code, Cursor, or Windsurf.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		tool := args[0]
		switch tool {
		case "claude-code":
			fmt.Println(color.CyanString("Setting up Armur for Claude Code..."))
			fmt.Println()
			fmt.Println("Run this command:")
			fmt.Println(color.GreenString("  claude mcp add armur -- armur mcp"))
			fmt.Println()
			fmt.Println("Or add to ~/.claude/settings.json manually:")
			fmt.Println(`  {
    "mcpServers": {
      "armur": {
        "command": "armur",
        "args": ["mcp"]
      }
    }
  }`)

		case "cursor":
			fmt.Println(color.CyanString("Setting up Armur for Cursor..."))
			fmt.Println()
			fmt.Println("Add to ~/.cursor/mcp.json:")
			fmt.Println(`  {
    "mcpServers": {
      "armur": {
        "command": "armur",
        "args": ["mcp"]
      }
    }
  }`)

		case "windsurf":
			fmt.Println(color.CyanString("Setting up Armur for Windsurf..."))
			fmt.Println()
			fmt.Println("Add to Windsurf's MCP config:")
			fmt.Println(`  {
    "mcpServers": {
      "armur": {
        "command": "armur",
        "args": ["mcp"]
      }
    }
  }`)

		default:
			color.Red("Unknown tool: %s. Supported: claude-code, cursor, windsurf", tool)
		}
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpSetupCmd)
}
