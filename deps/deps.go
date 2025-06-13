// deps/deps.go
package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/JohnnyCannelloni/gitguardian/scanner"
)

type DepFinding = scanner.Finding

func ScanGoModules(root string) ([]DepFinding, error) {
	cmd := exec.Command("go", "list", "-m", "all")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var finds []DepFinding
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		parts := bytes.Fields(s.Bytes())
		if len(parts) != 2 {
			continue
		}
		module := string(parts[0])
		version := string(parts[1])
		vulns, _ := queryOSV(module, version)
		for _, v := range vulns {
			finds = append(finds, DepFinding{
				File:    "deps",
				Line:    0,
				Content: fmt.Sprintf("%s@%s vulnerable: %s (%s)", module, version, v.ID, v.Summary),
				Rule:    "VULN",
			})
		}
	}
	return finds, nil
}

func ScanJSDependencies(root string) ([]DepFinding, error) {
	lock := filepath.Join(root, "package-lock.json")
	if _, err := os.Stat(lock); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := os.ReadFile(lock)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	var finds []DepFinding
	for pkg, info := range parsed.Dependencies {
		vulns, _ := queryOSV(pkg, info.Version)
		for _, v := range vulns {
			finds = append(finds, DepFinding{
				File:    "deps",
				Line:    0,
				Content: fmt.Sprintf("%s@%s vulnerable: %s (%s)", pkg, info.Version, v.ID, v.Summary),
				Rule:    "VULN",
			})
		}
	}
	return finds, nil
}

func CombinedScan(root string) ([]DepFinding, error) {
	gm, _ := ScanGoModules(root)
	js, _ := ScanJSDependencies(root)
	return append(gm, js...), nil
}
