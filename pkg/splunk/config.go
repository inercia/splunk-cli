package splunk

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Config holds configuration options for the Splunk client.
type Config struct {
    BaseURL        string
    Username       string
    Password       string
    Token          string
    SkipTLSVerify  bool
    DefaultTimeout time.Duration
}

// NewSplunkConfig constructs a splunk.Config where CLI flags take precedence
// over environment variables.
func NewSplunkConfig(cmd *cobra.Command) (Config, error) {
	// Base URL
	baseURL := getStr(cmd, "splunk-url", "SPLUNK_URL", "")
	if baseURL == "" {
		host := getStr(cmd, "splunk-host", "SPLUNK_HOST", "127.0.0.1")
		port := getStr(cmd, "splunk-port", "SPLUNK_PORT", "8089")
		scheme := getStr(cmd, "splunk-scheme", "SPLUNK_SCHEME", "https")
		baseURL = fmt.Sprintf("%s://%s:%s", scheme, host, port)
	}

	username := getStr(cmd, "splunk-username", "SPLUNK_USERNAME", "")
	password := getStr(cmd, "splunk-password", "SPLUNK_PASSWORD", "")
	token := getStr(cmd, "splunk-token", "SPLUNK_TOKEN", "")
	insecure := getBool(cmd, "splunk-insecure", "SPLUNK_INSECURE", false)
	timeoutSeconds := getInt(cmd, "splunk-timeout", "SPLUNK_TIMEOUT_SECONDS", 60)

	return Config{
		BaseURL:        baseURL,
		Username:       username,
		Password:       password,
		Token:          token,
		SkipTLSVerify:  insecure,
		DefaultTimeout: time.Duration(timeoutSeconds) * time.Second,
	}, nil
}

func getStr(cmd *cobra.Command, flagName, envName, defaultVal string) string {
	if cmd.Flags().Changed(flagName) {
		v, _ := cmd.Flags().GetString(flagName)
		return v
	}
	if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
		return v
	}
	return defaultVal
}

func getBool(cmd *cobra.Command, flagName, envName string, defaultVal bool) bool {
	if cmd.Flags().Changed(flagName) {
		v, _ := cmd.Flags().GetBool(flagName)
		return v
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envName)))
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return defaultVal
	}
}

func getInt(cmd *cobra.Command, flagName, envName string, defaultVal int) int {
	if cmd.Flags().Changed(flagName) {
		v, _ := cmd.Flags().GetInt(flagName)
		return v
	}
	if s := strings.TrimSpace(os.Getenv(envName)); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return defaultVal
}
