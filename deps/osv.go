// deps/osv.go
package deps

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

type OsvAdvisory struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type OsvResponse struct {
	Vulns []OsvAdvisory `json:"vulns"`
}

// queryOSV posts name/version to the OSV API and returns any vulnerabilities.
func queryOSV(name, version string) ([]OsvAdvisory, error) {
	var payload map[string]interface{}
	if strings.Contains(name, "/") {
		payload = map[string]interface{}{
			"version": version,
			"module":  map[string]string{"name": name},
		}
	} else {
		payload = map[string]interface{}{
			"version": version,
			"package": map[string]string{"name": name, "ecosystem": "npm"},
		}
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var osvResp OsvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}
	return osvResp.Vulns, nil
}
