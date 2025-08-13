package splunk

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mockSplunkServer() *httptest.Server {
    mux := http.NewServeMux()
    // Login endpoint returns XML sessionKey
    mux.HandleFunc("/services/auth/login", func(w http.ResponseWriter, r *http.Request) {
        if err := r.ParseForm(); err != nil {
            http.Error(w, "bad form", http.StatusBadRequest)
            return
        }
        if r.Form.Get("username") == "user" && r.Form.Get("password") == "pass" {
            type loginResp struct {
                XMLName    xml.Name `xml:"response"`
                SessionKey string   `xml:"sessionKey"`
            }
            _ = xml.NewEncoder(w).Encode(loginResp{SessionKey: "mock-token"})
            return
        }
        http.Error(w, "unauthorized", http.StatusUnauthorized)
    })

    // Create job -> return SID
    mux.HandleFunc("/services/search/jobs", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method", http.StatusMethodNotAllowed)
            return
        }
        if !strings.HasPrefix(r.Header.Get("Authorization"), "Splunk ") {
            http.Error(w, "no auth", http.StatusUnauthorized)
            return
        }
        _ = json.NewEncoder(w).Encode(map[string]string{"sid": "12345"})
    })

    // Job status
    mux.HandleFunc("/services/search/jobs/12345", func(w http.ResponseWriter, r *http.Request) {
        _ = json.NewEncoder(w).Encode(map[string]any{
            "entry": []any{
                map[string]any{
                    "content": map[string]any{"isDone": true},
                },
            },
        })
    })

    // Results
    mux.HandleFunc("/services/search/jobs/12345/results", func(w http.ResponseWriter, r *http.Request) {
        _ = json.NewEncoder(w).Encode(map[string]any{
            "fields":  []string{"_time", "host", "message"},
            "results": []map[string]any{{"_time": "2025-01-01T00:00:00Z", "host": "local", "message": "hello"}},
        })
    })

    return httptest.NewTLSServer(mux)
}

func TestSearchFlow_WithLogin(t *testing.T) {
    server := mockSplunkServer()
    t.Cleanup(server.Close)

    client, err := NewClient(Config{
        BaseURL:        server.URL,
        Username:       "user",
        Password:       "pass",
        SkipTLSVerify:  true,
        DefaultTimeout: 10 * time.Second,
    })
    if err != nil {
        t.Fatalf("new client: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    results, err := client.Search(ctx, "index=main error", JobOptions{})
    if err != nil {
        t.Fatalf("search: %v", err)
    }
    if len(results.Records) != 1 {
        t.Fatalf("expected 1 record, got %d", len(results.Records))
    }
    if results.Records[0]["message"] != "hello" {
        t.Fatalf("unexpected message: %q", results.Records[0]["message"])
    }
}
