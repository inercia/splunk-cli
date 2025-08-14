package main

import (
	"fmt"
	"os"

	"github.com/inercia/splunk-cli/pkg/splunk"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "splunk-cli",
	Short: "A simple Splunk search CLI",
	Long:  "A simple Splunk search CLI powered by Splunk REST API.",
}

// Execute runs the command tree.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

// Persistent flags for configuration
func init() {
	pf := rootCmd.PersistentFlags()
	pf.String("splunk-url", "", "Splunk base URL (e.g., https://localhost:8089). Overrides host/port/scheme")
	pf.String("splunk-host", "", "Splunk host (default 127.0.0.1 if URL not set)")
	pf.String("splunk-port", "", "Splunk management port (default 8089 if URL not set)")
	pf.String("splunk-scheme", "", "Scheme http|https (default https if URL not set)")
	pf.String("splunk-username", "", "Splunk username")
	pf.String("splunk-password", "", "Splunk password")
	pf.String("splunk-token", "", "Splunk auth token. If set, username/password are not required")
	pf.Bool("splunk-insecure", false, "Skip TLS certificate verification (dev only)")
	pf.Int("splunk-timeout", 0, "Overall timeout in seconds (default 60)")
	pf.BoolP("verbose", "v", false, "Enable verbose logging (prints HTTP requests/responses; redacts secrets)")
}

// newClientFromFlagsAndEnv builds a Splunk client giving precedence to CLI flags over env vars.
func newClientFromFlagsAndEnv(cmd *cobra.Command) (*splunk.Client, error) {
	cfg, err := splunk.NewSplunkConfig(cmd)
	if err != nil {
		return nil, err
	}
	return splunk.NewClient(cfg)
}
