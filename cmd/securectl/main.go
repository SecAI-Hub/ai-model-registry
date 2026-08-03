package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

var registryURL = "http://127.0.0.1:8470"
var apiClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func init() {
	if u := os.Getenv("REGISTRY_URL"); u != "" {
		registryURL = u
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `securectl - AI model registry management CLI

Usage:
  securectl list                     List all models (all states)
  securectl info <name>              Show details for a model
  securectl verify <name>            Verify a model's hash against manifest
  securectl path <name>              Print the digest-bound runtime locator as JSON
  securectl revoke <name>            Revoke a model (mark as untrusted)
  securectl delete <name>            Soft-delete a model (metadata retained)
  securectl status                   Show registry service health

Artifact states:
  acquired      Downloaded/received, not yet scanned
  quarantined   Being scanned by quarantine pipeline
  trusted       All checks passed, available for runtime
  revoked       Revoked, blocked from runtime use
  deleted       Soft-deleted, metadata retained for audit

Environment:
  REGISTRY_URL         Registry endpoint (default: http://127.0.0.1:8470)
  SERVICE_TOKEN_PATH   Registry service token path (default: /run/secure-ai/service-token)
`)
	os.Exit(1)
}

func readServiceToken() (string, error) {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	// #nosec G703 -- administrator-selected credential path; strict link, mode, size, and identity checks follow.
	before, err := os.Lstat(tokenPath)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("service token symbolic links are not allowed")
	}
	if before.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("service token must not be accessible by group or other users")
	}
	// #nosec G304,G703 -- validated credential path with opened-file and post-open identity checks.
	f, err := os.Open(tokenPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	// #nosec G703 -- paired with pre/opened identity checks above.
	after, err := os.Lstat(tokenPath)
	if err != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return "", fmt.Errorf("service token changed while opening or is a symbolic link")
	}
	if !opened.Mode().IsRegular() || opened.Size() > 4096 {
		return "", fmt.Errorf("service token must be a regular file no larger than 4096 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", fmt.Errorf("read service token: invalid token file")
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("service token must be at least 32 bytes without whitespace")
	}
	return token, nil
}

func apiRequest(method, path string, body io.Reader) ([]byte, int, error) {
	if err := validateRegistryURL(registryURL); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(method, registryURL+path, body)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if path != "/health" {
		token, err := readServiceToken()
		if err != nil {
			return nil, 0, fmt.Errorf("service authentication unavailable: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, 0, err
	}
	if len(respBody) > 1<<20 {
		return nil, 0, fmt.Errorf("registry response exceeds 1 MiB")
	}
	return respBody, resp.StatusCode, nil
}

func validateRegistryURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid registry URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("registry URL must use http or https")
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		loopback := host == "localhost"
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			loopback = true
		}
		if !loopback {
			return fmt.Errorf("plaintext registry URL must use a loopback address")
		}
	}
	return nil
}

func apiGet(path string) ([]byte, int, error) {
	return apiRequest(http.MethodGet, path, nil)
}

func apiDelete(path string) ([]byte, int, error) {
	return apiRequest(http.MethodDelete, path, nil)
}

func apiPost(path string) ([]byte, int, error) {
	return apiRequest(http.MethodPost, path, strings.NewReader("{}"))
}

func modelQueryPath(endpoint, name string) string {
	values := url.Values{}
	values.Set("name", name)
	return endpoint + "?" + values.Encode()
}

func cmdList() {
	data, code, err := apiGet("/v1/models")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code != 200 {
		fmt.Fprintf(os.Stderr, "error: HTTP %d: %s\n", code, data)
		os.Exit(1)
	}

	var models []map[string]interface{}
	json.Unmarshal(data, &models)

	if len(models) == 0 {
		fmt.Println("No models in registry.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tFORMAT\tSTATE\tSIZE\tSHA256\tPROMOTED")
	for _, m := range models {
		name, _ := m["name"].(string)
		format, _ := m["format"].(string)
		state, _ := m["state"].(string)
		size, _ := m["size_bytes"].(float64)
		sha, _ := m["sha256"].(string)
		promoted, _ := m["promoted_at"].(string)

		sizeStr := formatBytes(int64(size))
		shortSha := sha
		if len(sha) > 12 {
			shortSha = sha[:12]
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", name, format, state, sizeStr, shortSha, promoted)
	}
	w.Flush()
}

func cmdInfo(name string) {
	data, code, err := apiGet(modelQueryPath("/v1/model", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}

	var pretty map[string]interface{}
	json.Unmarshal(data, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(out))
}

func cmdVerify(name string) {
	data, code, err := apiPost(modelQueryPath("/v1/model/verify", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result map[string]string
	json.Unmarshal(data, &result)

	if code == 200 {
		fmt.Printf("VERIFIED: %s (sha256=%s, state=%s)\n", name, result["sha256"], result["state"])
		if result["safe_to_use"] == "false" {
			fmt.Printf("  WARNING: model is not safe to use (state=%s)\n", result["state"])
			os.Exit(1)
		}
	} else {
		fmt.Printf("FAILED: %s\n", name)
		fmt.Printf("  expected: %s\n", result["expected"])
		fmt.Printf("  actual:   %s\n", result["actual"])
		os.Exit(1)
	}
}

func cmdPath(name string) {
	data, code, err := apiGet(modelQueryPath("/v1/model/path", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 403 {
		fmt.Fprintf(os.Stderr, "error: model %q is not in trusted state\n", name)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}
	var result struct {
		Path            string `json:"path"`
		SHA256          string `json:"sha256"`
		SizeBytes       int64  `json:"size_bytes"`
		StorageContract string `json:"storage_contract"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Path == "" ||
		result.SHA256 == "" || result.StorageContract != "content-addressed-v1" {
		fmt.Fprintln(os.Stderr, "error: registry returned an incomplete runtime locator")
		os.Exit(1)
	}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
}

func cmdRevoke(name string) {
	data, code, err := apiPost(modelQueryPath("/v1/model/revoke", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}
	var result map[string]string
	json.Unmarshal(data, &result)
	fmt.Printf("Revoked: %s (status=%s)\n", name, result["status"])
}

func cmdDelete(name string) {
	data, code, err := apiDelete(modelQueryPath("/v1/model/delete", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}
	var result map[string]string
	json.Unmarshal(data, &result)
	if result["status"] == "already_deleted" {
		fmt.Printf("Already deleted: %s\n", name)
	} else {
		fmt.Printf("Deleted (soft): %s - metadata retained for audit\n", name)
	}
}

func cmdStatus() {
	data, code, err := apiGet("/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Registry unreachable: %v\n", err)
		os.Exit(1)
	}
	if code != 200 {
		fmt.Fprintf(os.Stderr, "Registry unhealthy: HTTP %d\n", code)
		os.Exit(1)
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "list", "ls":
		cmdList()
	case "info":
		if len(os.Args) < 3 {
			usage()
		}
		cmdInfo(os.Args[2])
	case "verify":
		if len(os.Args) < 3 {
			usage()
		}
		cmdVerify(os.Args[2])
	case "path":
		if len(os.Args) < 3 {
			usage()
		}
		cmdPath(os.Args[2])
	case "revoke":
		if len(os.Args) < 3 {
			usage()
		}
		cmdRevoke(os.Args[2])
	case "delete", "rm":
		if len(os.Args) < 3 {
			usage()
		}
		cmdDelete(os.Args[2])
	case "status":
		cmdStatus()
	default:
		usage()
	}
}
