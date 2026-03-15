package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// StartMCPServer starts the Armur MCP server over stdio.
func StartMCPServer() error {
	s := server.NewMCPServer(
		"armur",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
	)

	registerScanPathTool(s)
	registerScanCodeTool(s)
	registerCheckDependencyTool(s)
	registerExplainFindingTool(s)
	registerGetHistoryTool(s)
	registerResources(s)

	return server.ServeStdio(s)
}

func getArg(request mcp.CallToolRequest, key string) string {
	args := request.GetArguments()
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func registerScanPathTool(s *server.MCPServer) {
	tool := mcp.NewTool("armur_scan_path",
		mcp.WithDescription("Scan a local file or directory for security vulnerabilities"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to scan")),
		mcp.WithString("depth", mcp.Description("Scan depth: quick or deep (default: quick)")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := getArg(request, "path")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}
		depth := getArg(request, "depth")
		if depth == "" {
			depth = "quick"
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Scanning %s (depth: %s)...\n\nPlaceholder: runs in-process scan and returns findings as JSON.",
			path, depth,
		)), nil
	})
}

func registerScanCodeTool(s *server.MCPServer) {
	tool := mcp.NewTool("armur_scan_code",
		mcp.WithDescription("Scan a code snippet for security vulnerabilities"),
		mcp.WithString("code", mcp.Required(), mcp.Description("The code to scan")),
		mcp.WithString("language", mcp.Required(), mcp.Description("Programming language")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		code := getArg(request, "code")
		language := getArg(request, "language")
		if code == "" || language == "" {
			return mcp.NewToolResultError("code and language are required"), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Scanning %d bytes of %s code...\n\nPlaceholder: runs semgrep + language tools on snippet.",
			len(code), language,
		)), nil
	})
}

func registerCheckDependencyTool(s *server.MCPServer) {
	tool := mcp.NewTool("armur_check_dependency",
		mcp.WithDescription("Check if a specific package version has known vulnerabilities"),
		mcp.WithString("package", mcp.Required(), mcp.Description("Package name")),
		mcp.WithString("version", mcp.Required(), mcp.Description("Package version")),
		mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		pkg := getArg(request, "package")
		version := getArg(request, "version")
		ecosystem := getArg(request, "ecosystem")

		return mcp.NewToolResultText(fmt.Sprintf(
			"Checking %s@%s (%s) for vulnerabilities...\n\nPlaceholder: queries OSV and NVD.",
			pkg, version, ecosystem,
		)), nil
	})
}

func registerExplainFindingTool(s *server.MCPServer) {
	tool := mcp.NewTool("armur_explain_finding",
		mcp.WithDescription("Explain a security finding in plain English"),
		mcp.WithString("cwe", mcp.Description("CWE ID")),
		mcp.WithString("message", mcp.Description("Finding message")),
		mcp.WithString("file", mcp.Description("File path")),
		mcp.WithString("code_context", mcp.Description("Code around the finding")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		message := getArg(request, "message")
		cwe := getArg(request, "cwe")

		return mcp.NewToolResultText(fmt.Sprintf(
			"Explaining: %s (%s)\n\nPlaceholder: uses AI to generate explanation.",
			message, cwe,
		)), nil
	})
}

func registerGetHistoryTool(s *server.MCPServer) {
	tool := mcp.NewTool("armur_get_history",
		mcp.WithDescription("Get recent scan history"),
		mcp.WithString("path", mcp.Description("Path to get history for")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("Recent scans:\n\nPlaceholder: queries ~/.armur/history.db"), nil
	})
}

func registerResources(s *server.MCPServer) {
	s.AddResource(mcp.NewResource(
		"armur://findings/latest",
		"Latest scan findings",
		mcp.WithResourceDescription("Findings from the most recent scan"),
		mcp.WithMIMEType("application/json"),
	), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      request.Params.URI,
				MIMEType: "application/json",
				Text:     `{"findings": [], "note": "Run armur scan first"}`,
			},
		}, nil
	})
}
