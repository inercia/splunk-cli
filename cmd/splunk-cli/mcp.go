package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/inercia/splunk-cli/pkg/splunk"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var (
	mcpServerMode string
)

func init() {
	mcpCmd.Flags().StringVar(&mcpServerMode, "mcp-server", "stdio", "MCP transport to start: stdio|streamable|sse")
	rootCmd.AddCommand(mcpCmd)
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start an MCP server that exposes Splunk tools",
	Long:  "Start a Model Context Protocol (MCP) server exposing Splunk operations as tools. Initially exposes only 'search'.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Prepare MCP server
		s := server.NewMCPServer(
			"Splunk MCP Server",
			"1.0.0",
			server.WithToolCapabilities(true),
		)

		// Register the "search" tool
		searchTool := mcp.NewTool(
			"search",
			mcp.WithDescription("Execute a Splunk search and return structured results"),
			mcp.WithString("query", mcp.Required(), mcp.Description("SPL query to execute (without leading 'search ' prefix)")),
			mcp.WithString("earliest", mcp.Description("Earliest time, e.g., -24h@h")),
			mcp.WithString("latest", mcp.Description("Latest time, e.g., now")),
			mcp.WithNumber("timeoutSeconds", mcp.Description("Overall timeout in seconds (defaults to config)")),
		)

		s.AddTool(searchTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Build a fresh client per call to avoid shared state/token races
			cfg, err := splunk.NewSplunkConfig(cmd)
			if err != nil {
				return mcp.NewToolResultErrorFromErr("failed to resolve config", err), nil
			}
			client, err := splunk.NewClient(cfg)
			if err != nil {
				return mcp.NewToolResultErrorFromErr("failed to create client", err), nil
			}

			query := mcp.ParseString(req, "query", "")
			if strings.TrimSpace(query) == "" {
				return mcp.NewToolResultError("query is required"), nil
			}
			earliest := mcp.ParseString(req, "earliest", "")
			latest := mcp.ParseString(req, "latest", "")

			defaultTimeout := int(cfg.DefaultTimeout / time.Second)
			if defaultTimeout <= 0 {
				defaultTimeout = 60
			}
			timeoutSeconds := mcp.ParseInt(req, "timeoutSeconds", defaultTimeout)
			ctxTimed, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			defer cancel()

			results, err := client.Search(ctxTimed, query, splunk.JobOptions{
				EarliestTime: earliest,
				LatestTime:   latest,
			})
			if err != nil {
				return mcp.NewToolResultErrorFromErr("search failed", err), nil
			}

			structured := map[string]any{
				"fields":  results.Fields,
				"records": results.Records,
			}
			return mcp.NewToolResultStructured(structured, fmt.Sprintf("%d result(s)", len(results.Records))), nil
		})

		// Start selected transport
		switch strings.ToLower(strings.TrimSpace(mcpServerMode)) {
		case "stdio":
			fmt.Fprintln(os.Stderr, "Starting MCP stdio server...")
			return server.ServeStdio(s)
		case "streamable", "streamable-http":
			fmt.Fprintln(os.Stderr, "Starting MCP streamable HTTP server on :8080 (path /mcp)...")
			handler := server.NewStreamableHTTPServer(s)
			return handler.Start(":8080")
		case "sse":
			fmt.Fprintln(os.Stderr, "Starting MCP SSE server on :8080...")
			h := server.NewSSEServer(s)
			return h.Start(":8080")
		default:
			return fmt.Errorf("invalid --mcp-server value: %q (valid: stdio|streamable|sse)", mcpServerMode)
		}
	},
}
