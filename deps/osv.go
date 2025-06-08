// deps/osv.go
package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OsvAdvisory represents a single vulnerability entry from OSV
type OsvAdvisory struct {
	ID       string `json:"id"`      // e.g., "CVE-2022-1234"
	Summary  string `json:"summary"` // human‐readable description
	Severity []struct {
		Type  string `json:"type"`  // e.g., "CVSS_V3"
		Score string `json:"score"` // e.g., "7.8"
	} `json:"severity"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// OsvResponse is the top-level OSV /v1/query response
type OsvResponse struct {
	Vulns []OsvAdvisory `json:"vulns"`
}

// queryOSV sends a POST to OSV API and returns any vulnerabilities found.
func queryOSV(moduleOrPkg, version string) ([]OsvAdvisory, error) {
	// Determine whether it’s a Go module (contains "/") or an NPM package:
	var payload map[string]interface{}
	if strings.Contains(moduleOrPkg, "/") {
		// Go module query
		payload = map[string]interface{}{
			"version": version,
			"module": map[string]string{
				"name": moduleOrPkg,
			},
		}
	} else {
		// NPM package query
		payload = map[string]interface{}{
			"version": version,
			"package": map[string]string{
				"name":      moduleOrPkg,
				"ecosystem": "npm",
			},
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV payload: %w", err)
	}

	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("OSV HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	var osvResp OsvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}
	return osvResp.Vulns, nil
}
