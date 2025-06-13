// scanner/social.go
package scanner

import (
	"bytes"
	"os/exec"
	"regexp"
)

var suspicious = map[string]*regexp.Regexp{
	"TODOSecret":    regexp.MustCompile(`(?i)\bTODO[:\s].*(secret|password|key)\b`),
	"CommentedCred": regexp.MustCompile(`(?i)//.*(AKIA|ghp_)[A-Za-z0-9]+`),
	"WeakPwInCode":  regexp.MustCompile(`(?i)password\s*=\s*['"][a-z0-9]{4,8}['"]`),
}

// ScanLastCommitMessage returns Findings for any suspicious patterns.
func ScanLastCommitMessage() ([]Finding, error) {
	out, err := exec.Command("git", "log", "-1", "--pretty=%B").Output()
	if err != nil {
		return nil, err
	}
	msg := string(bytes.TrimSpace(out))
	var finds []Finding
	for rule, re := range suspicious {
		if re.MatchString(msg) {
			finds = append(finds, Finding{
				File:    "commit-message",
				Line:    0,
				Content: msg,
				Rule:    rule,
			})
		}
	}
	return finds, nil
}
