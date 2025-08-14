package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	File      string `json:"file"`
}

type Vulnerability struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	Severity   string   `json:"severity"`
	CVSS       float64  `json:"cvss"`
	References []string `json:"references"`
	Published  string   `json:"published"`
	Modified   string   `json:"modified"`
	Aliases    []string `json:"aliases"`
	Affected   []string `json:"affected"`
}

// represents the response from OSV API
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// represents a vulnerability from OSV API
type OSVVulnerability struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	Modified   string         `json:"modified"`
	Published  string         `json:"published"`
	Affected   []OSVAffected  `json:"affected"`
	Severity   []OSVSeverity  `json:"severity"`
	References []OSVReference `json:"references"`
}

type OSVAffected struct {
	Package OSVPackage `json:"package"`
	Ranges  []OSVRange `json:"ranges"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// scans a dependency file for vulnerabilities
func (s *Scanner) scanDependencies(filePath, content string) ([]Issue, error) {
	var issues []Issue

	// parse dependencies based on file type
	deps, err := s.parseDependencies(filePath, content)
	if err != nil {
		return issues, fmt.Errorf("failed to parse dependencies: %w", err)
	}

	if len(deps) == 0 {
		return issues, nil
	}

	// check vulnerabilities with OSV API
	if s.config.DependencyAPIs.OSVEnabled {
		vulns, err := s.checkOSVVulnerabilities(deps)
		if err != nil && s.config.Verbose {
			fmt.Printf("Warning: OSV API check failed: %v\n", err)
		} else {
			issues = append(issues, s.convertVulnsToIssues(vulns, filePath)...)
		}
	}

	return issues, nil
}

// parses dependencies from multiple file formats
func (s *Scanner) parseDependencies(filePath, content string) ([]Dependency, error) {
	filename := strings.ToLower(filepath.Base(filePath))

	switch {
	case filename == "package.json":
		return s.parsePackageJSON(content, filePath)
	case filename == "go.mod":
		return s.parseGoMod(content, filePath)
	case filename == "requirements.txt":
		return s.parseRequirementsTxt(content, filePath)
	case filename == "gemfile":
		return s.parseGemfile(content, filePath)
	case filename == "composer.json":
		return s.parseComposerJSON(content, filePath)
	case filename == "pom.xml":
		return s.parsePomXML(content, filePath)
	case filename == "cargo.toml":
		return s.parseCargoToml(content, filePath)
	default:
		return []Dependency{}, nil
	}
}

// parses Node.js package.json
func (s *Scanner) parsePackageJSON(content, filePath string) ([]Dependency, error) {
	var deps []Dependency
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return deps, err
	}

	// parse regular dependencies
	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
			File:      filePath,
		})
	}

	// parse dev dependencies
	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
			File:      filePath,
		})
	}

	return deps, nil
}

// parses module file
func (s *Scanner) parseGoMod(content, filePath string) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(content, "\n")

	requirePattern := regexp.MustCompile(`^\s*([^\s]+)\s+v?([^\s]+)`)
	inRequire := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}

		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if strings.HasPrefix(line, "require ") || inRequire {
			// remove "require " prefix
			if strings.HasPrefix(line, "require ") {
				line = strings.TrimPrefix(line, "require ")
			}

			matches := requirePattern.FindStringSubmatch(line)
			if len(matches) == 3 {
				deps = append(deps, Dependency{
					Name:      matches[1],
					Version:   matches[2],
					Ecosystem: "Go",
					File:      filePath,
				})
			}
		}
	}

	return deps, nil
}

// parses python requirements.txt
func (s *Scanner) parseRequirementsTxt(content, filePath string) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(content, "\n")

	// regex for package==version, package>=version, etc.
	requirePattern := regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)([><=!]+)([0-9\.]+[a-zA-Z0-9\.\-]*)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := requirePattern.FindStringSubmatch(line)
		if len(matches) == 4 {
			deps = append(deps, Dependency{
				Name:      matches[1],
				Version:   matches[3],
				Ecosystem: "PyPI",
				File:      filePath,
			})
		}
	}

	return deps, nil
}

// parses Ruby Gemfile
func (s *Scanner) parseGemfile(content, filePath string) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(content, "\n")

	gemPattern := regexp.MustCompile(`gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") {
			continue
		}

		matches := gemPattern.FindStringSubmatch(line)
		if len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "RubyGems",
				File:      filePath,
			})
		}
	}

	return deps, nil
}

// parses PHP composer.json
func (s *Scanner) parseComposerJSON(content, filePath string) ([]Dependency, error) {
	var deps []Dependency
	var composer struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}

	if err := json.Unmarshal([]byte(content), &composer); err != nil {
		return deps, err
	}

	for name, version := range composer.Require {
		if name != "php" { // Skip PHP itself
			deps = append(deps, Dependency{
				Name:      name,
				Version:   cleanVersion(version),
				Ecosystem: "Packagist",
				File:      filePath,
			})
		}
	}

	for name, version := range composer.RequireDev {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "Packagist",
			File:      filePath,
		})
	}

	return deps, nil
}

// parses Maven pom.xml
func (s *Scanner) parsePomXML(content, filePath string) ([]Dependency, error) {
	var deps []Dependency

	depPattern := regexp.MustCompile(`<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>`)

	matches := depPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) == 4 {
			deps = append(deps, Dependency{
				Name:      fmt.Sprintf("%s:%s", match[1], match[2]),
				Version:   match[3],
				Ecosystem: "Maven",
				File:      filePath,
			})
		}
	}

	return deps, nil
}

// parses Rust Cargo.toml
func (s *Scanner) parseCargoToml(content, filePath string) ([]Dependency, error) {
	var deps []Dependency
	lines := strings.Split(content, "\n")

	inDependencies := false
	depPattern := regexp.MustCompile(`^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]+)"`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[dependencies]" {
			inDependencies = true
			continue
		}

		if strings.HasPrefix(line, "[") && line != "[dependencies]" {
			inDependencies = false
			continue
		}

		if inDependencies && line != "" && !strings.HasPrefix(line, "#") {
			matches := depPattern.FindStringSubmatch(line)
			if len(matches) == 3 {
				deps = append(deps, Dependency{
					Name:      matches[1],
					Version:   matches[2],
					Ecosystem: "crates.io",
					File:      filePath,
				})
			}
		}
	}

	return deps, nil
}

// checks dependencies with OSV database
func (s *Scanner) checkOSVVulnerabilities(deps []Dependency) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// group dependencies by ecosystem
	ecosystemDeps := make(map[string][]Dependency)
	for _, dep := range deps {
		ecosystemDeps[dep.Ecosystem] = append(ecosystemDeps[dep.Ecosystem], dep)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	for ecosystem, depList := range ecosystemDeps {
		// create request for OSV API
		var packages []map[string]interface{}
		for _, dep := range depList {
			packages = append(packages, map[string]interface{}{
				"package": map[string]string{
					"ecosystem": mapToOSVEcosystem(ecosystem),
					"name":      dep.Name,
				},
				"version": dep.Version,
			})
		}

		requestBody := map[string]interface{}{
			"queries": packages,
		}

		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			continue
		}

		resp, err := client.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return vulnerabilities, fmt.Errorf("OSV API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return vulnerabilities, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return vulnerabilities, fmt.Errorf("failed to read OSV response: %w", err)
		}

		var response struct {
			Results []struct {
				Vulns []OSVVulnerability `json:"vulns"`
			} `json:"results"`
		}

		if err := json.Unmarshal(body, &response); err != nil {
			return vulnerabilities, fmt.Errorf("failed to parse OSV response: %w", err)
		}

		// convert OSV vulnerabilities to the project format
		for i, result := range response.Results {
			if i < len(depList) {
				dep := depList[i]
				for _, vuln := range result.Vulns {
					vulnerabilities = append(vulnerabilities, s.convertOSVVuln(vuln, dep))
				}
			}
		}
	}

	return vulnerabilities, nil
}

// converts OSV vulnerability to project format
func (s *Scanner) convertOSVVuln(osv OSVVulnerability, dep Dependency) Vulnerability {
	vuln := Vulnerability{
		ID:        osv.ID,
		Summary:   osv.Summary,
		Details:   osv.Details,
		Published: osv.Published,
		Modified:  osv.Modified,
		Aliases:   osv.Aliases,
		Severity:  "medium",
	}

	// extract CVSS score
	for _, severity := range osv.Severity {
		if severity.Type == "CVSS_V3" {
			// Parse CVSS score (simplified)
			if strings.Contains(severity.Score, "CVSS:3.1/AV:") {
				vuln.Severity = s.extractCVSSSeverity(severity.Score)
			}
		}
	}

	// extract references
	for _, ref := range osv.References {
		vuln.References = append(vuln.References, ref.URL)
	}

	return vuln
}

// extracts severity from CVSS score
func (s *Scanner) extractCVSSSeverity(cvssString string) string {
	if strings.Contains(cvssString, "/AV:N/") && strings.Contains(cvssString, "/AC:L/") {
		return "high"
	}
	if strings.Contains(cvssString, "/PR:N/") {
		return "critical"
	}
	return "medium"
}

// converts vulnerabilities to issues
func (s *Scanner) convertVulnsToIssues(vulns []Vulnerability, filePath string) []Issue {
	var issues []Issue

	for _, vuln := range vulns {
		issues = append(issues, Issue{
			Type:        "vulnerability",
			Severity:    vuln.Severity,
			File:        filePath,
			Line:        1,
			Column:      1,
			Description: fmt.Sprintf("Vulnerability %s: %s", vuln.ID, vuln.Summary),
			Content:     vuln.Details,
			Rule:        "Dependency Vulnerability Check",
			Timestamp:   time.Now(),
		})
	}

	return issues
}

// removes version prefixes
func cleanVersion(version string) string {
	prefixes := []string{"^", "~", ">=", "<=", ">", "<", "="}
	for _, prefix := range prefixes {
		if strings.HasPrefix(version, prefix) {
			version = strings.TrimPrefix(version, prefix)
		}
	}
	return strings.TrimSpace(version)
}

// maps our ecosystem names
func mapToOSVEcosystem(ecosystem string) string {
	mapping := map[string]string{
		"npm":       "npm",
		"PyPI":      "PyPI",
		"Go":        "Go",
		"RubyGems":  "RubyGems",
		"Maven":     "Maven",
		"Packagist": "Packagist",
		"crates.io": "crates.io",
	}

	if mapped, exists := mapping[ecosystem]; exists {
		return mapped
	}
	return ecosystem
}
