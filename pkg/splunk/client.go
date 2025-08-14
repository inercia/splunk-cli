// Package splunk provides a minimal REST client to execute Splunk searches.
package splunk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client is a minimal Splunk REST API client sufficient for running search jobs.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	username       string
	password       string
	token          string
	skipTLSVerify  bool
	defaultTimeout time.Duration
	verbose        bool
}

// NewClient constructs a Splunk client from the given configuration.
func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, errors.New("BaseURL is required")
	}

	transport := &http.Transport{}
	if config.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - allow opt-in for dev
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.DefaultTimeout,
	}

	client := &Client{
		baseURL:        strings.TrimRight(config.BaseURL, "/"),
		httpClient:     httpClient,
		username:       config.Username,
		password:       config.Password,
		token:          strings.TrimSpace(config.Token),
		skipTLSVerify:  config.SkipTLSVerify,
		defaultTimeout: config.DefaultTimeout,
		verbose:        config.Verbose,
	}
	return client, nil
}

func (c *Client) debugf(format string, args ...any) {
	if c.verbose {
		_, _ = fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

func (c *Client) redactHeader(key, value string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	//case "authorization", "cookie", "x-auth-token":
	//	return "***redacted***"
	default:
		return value
	}
}

func (c *Client) logRequest(req *http.Request, bodyPreview string) {
	if !c.verbose {
		return
	}
	c.debugf("%s %s", req.Method, req.URL.String())
	for k, vv := range req.Header {
		if len(vv) == 0 {
			continue
		}
		c.debugf("-> %s: %s", k, c.redactHeader(k, vv[0]))
	}
	if bodyPreview != "" {
		c.debugf("-> body: %s", bodyPreview)
	}
}

func (c *Client) logResponse(resp *http.Response, bodyPreview string) {
	if !c.verbose || resp == nil {
		return
	}
	c.debugf("<- %s", resp.Status)
	for k, vv := range resp.Header {
		if len(vv) == 0 {
			continue
		}
		c.debugf("<- %s: %s", k, c.redactHeader(k, vv[0]))
	}
	if bodyPreview != "" {
		c.debugf("<- body: %s", bodyPreview)
	}
}

// Authenticate logs into Splunk and obtains a session token if not already provided.
func (c *Client) Authenticate(ctx context.Context) error {
	if c.token != "" {
		return nil
	}
	if c.username == "" || c.password == "" {
		return errors.New("no SPLUNK_TOKEN and no SPLUNK_USERNAME/PASSWORD provided")
	}

	form := url.Values{}
	form.Set("username", c.username)
	form.Set("password", c.password)

	endpoint := c.baseURL + "/services/auth/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Log request with password redacted
	if c.verbose {
		preview := strings.ReplaceAll(form.Encode(), "password="+c.password, "password=***redacted***")
		c.logRequest(req, preview)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	c.logResponse(resp, string(body))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("login failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	// Splunk returns XML for sessionKey historically
	var xmlResp struct {
		SessionKey string `xml:"sessionKey"`
	}
	if err := xml.Unmarshal(body, &xmlResp); err != nil {
		return fmt.Errorf("failed parsing login XML: %w", err)
	}
	if strings.TrimSpace(xmlResp.SessionKey) == "" {
		return errors.New("empty session key from login")
	}
	c.token = strings.TrimSpace(xmlResp.SessionKey)
	return nil
}

// JobOptions controls search job creation.
type JobOptions struct {
	EarliestTime string
	LatestTime   string
}

// CreateSearchJob submits a search job and returns the Search ID (SID).
func (c *Client) CreateSearchJob(ctx context.Context, searchQuery string, options JobOptions) (string, error) {
	if strings.TrimSpace(searchQuery) == "" {
		return "", errors.New("search query cannot be empty")
	}
	if !strings.HasPrefix(strings.TrimSpace(searchQuery), "search ") {
		searchQuery = "search " + searchQuery
	}

	if c.token == "" {
		if err := c.Authenticate(ctx); err != nil {
			return "", err
		}
	}

	form := url.Values{}
	form.Set("search", searchQuery)
	if options.EarliestTime != "" {
		form.Set("earliest_time", options.EarliestTime)
	}
	if options.LatestTime != "" {
		form.Set("latest_time", options.LatestTime)
	}
	form.Set("output_mode", "json")

	endpoint := c.baseURL + "/services/search/jobs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Splunk "+c.token)

	c.logRequest(req, form.Encode())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		c.logResponse(resp, string(b))
		return "", fmt.Errorf("create job failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	c.logResponse(resp, string(body))

	// Splunk may return JSON or XML; try JSON first then XML
	var jsonResp struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(body, &jsonResp); err == nil && jsonResp.SID != "" {
		return jsonResp.SID, nil
	}

	var xmlResp struct {
		SID string `xml:"sid"`
	}
	if err := xml.Unmarshal(body, &xmlResp); err == nil && xmlResp.SID != "" {
		return xmlResp.SID, nil
	}

	return "", fmt.Errorf("unable to parse job creation response: %s", string(body))
}

// WaitForJob polls the job until completion or context timeout.
func (c *Client) WaitForJob(ctx context.Context, sid string, pollInterval time.Duration) error {
	if sid == "" {
		return errors.New("sid is required")
	}
	if pollInterval <= 0 {
		pollInterval = 1 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		done, err := c.isJobDone(ctx, sid)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) isJobDone(ctx context.Context, sid string) (bool, error) {
	endpoint := fmt.Sprintf("%s/services/search/jobs/%s?output_mode=json", c.baseURL, url.PathEscape(sid))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Splunk "+c.token)
	}
	c.logRequest(req, "")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		c.logResponse(resp, string(b))
		return false, fmt.Errorf("job status failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	var status struct {
		Entry []struct {
			Content struct {
				IsDone bool `json:"isDone"`
			} `json:"content"`
		} `json:"entry"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return false, err
	}
	c.logResponse(resp, "(json)")
	if len(status.Entry) == 0 {
		return false, errors.New("job status response missing entry")
	}
	return status.Entry[0].Content.IsDone, nil
}

// SearchResults represents a normalized set of results.
type SearchResults struct {
	Fields  []string
	Records []map[string]string
}

// GetSearchResults fetches results for a completed search job.
func (c *Client) GetSearchResults(ctx context.Context, sid string, count int) (*SearchResults, error) {
	if count <= 0 {
		count = 0 // 0 means Splunk default (all or server default)
	}
	query := url.Values{}
	query.Set("output_mode", "json")
	if count > 0 {
		query.Set("count", fmt.Sprintf("%d", count))
	}
	endpoint := fmt.Sprintf("%s/services/search/jobs/%s/results?%s", c.baseURL, url.PathEscape(sid), query.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Splunk "+c.token)
	}
	c.logRequest(req, "")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		c.logResponse(resp, string(b))
		return nil, fmt.Errorf("get results failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	var payload struct {
		Fields  []string         `json:"fields"`
		Results []map[string]any `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	c.logResponse(resp, "(json)")

	normalized := make([]map[string]string, 0, len(payload.Results))
	for _, rec := range payload.Results {
		dst := make(map[string]string, len(rec))
		for k, v := range rec {
			dst[k] = toString(v)
		}
		normalized = append(normalized, dst)
	}

	return &SearchResults{Fields: payload.Fields, Records: normalized}, nil
}

func toString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		// JSON numbers are float64; render without trailing .000 if whole
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// Search is a convenience method to create, wait, and fetch results.
func (c *Client) Search(ctx context.Context, query string, options JobOptions) (*SearchResults, error) {
	sid, err := c.CreateSearchJob(ctx, query, options)
	if err != nil {
		return nil, err
	}
	// Use a polling interval of 1s by default.
	if err := c.WaitForJob(ctx, sid, 1*time.Second); err != nil {
		return nil, err
	}
	return c.GetSearchResults(ctx, sid, 0)
}
