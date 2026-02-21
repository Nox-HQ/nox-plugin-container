package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// dockerfileRule defines a single Dockerfile lint rule.
type dockerfileRule struct {
	ID          string
	Description string
	Severity    pluginv1.Severity
	Confidence  pluginv1.Confidence
	CWE         string
	Check       func(lines []dockerfileLine) []ruleMatch
}

// dockerfileLine represents a single line in a Dockerfile with its number.
type dockerfileLine struct {
	Num  int
	Text string
}

// ruleMatch records where a rule matched in the Dockerfile.
type ruleMatch struct {
	Line    int
	Message string
}

// --- Compiled regex patterns ---

var (
	// Matches FROM instructions.
	reFrom = regexp.MustCompile(`(?i)^FROM\s+(.+?)(\s+AS\s+\S+)?$`)

	// Matches FROM with an explicit tag (e.g. FROM image:tag).
	reExplicitTag = regexp.MustCompile(`(?i)^FROM\s+\S+:\S+`)

	// Matches USER instruction.
	reUser = regexp.MustCompile(`(?i)^USER\s+`)

	// Matches ADD instruction.
	reAdd = regexp.MustCompile(`(?i)^ADD\s+`)

	// Matches ADD with URL (remote fetch).
	reAddURL = regexp.MustCompile(`(?i)^ADD\s+(https?://\S+)`)

	// Matches EXPOSE instruction.
	reExpose = regexp.MustCompile(`(?i)^EXPOSE\s+(.+)`)

	// Matches RUN with apt-get/apk but no cleanup.
	reRunAptGet  = regexp.MustCompile(`(?i)^RUN\s+.*apt-get\s+install`)
	reRunApkAdd  = regexp.MustCompile(`(?i)^RUN\s+.*apk\s+add`)
	reAptClean   = regexp.MustCompile(`(?i)apt-get\s+clean|rm\s+-rf\s+/var/lib/apt`)
	reApkNoCache = regexp.MustCompile(`(?i)--no-cache`)

	// Matches RUN with curl piped to shell (curl | sh pattern).
	reCurlPipe = regexp.MustCompile(`(?i)^RUN\s+.*curl\s+.*\|\s*(?:sh|bash)`)
	reWgetPipe = regexp.MustCompile(`(?i)^RUN\s+.*wget\s+.*\|\s*(?:sh|bash)`)

	// Matches COPY or ADD of sensitive files.
	reSensitiveCopy = regexp.MustCompile(`(?i)(?:COPY|ADD)\s+.*(?:\.env|\.ssh|\.aws|id_rsa|\.gnupg|credentials|\.secret|\.key|\.pem|\.p12|\.pfx)`)

	// Matches RUN with sudo.
	reSudo = regexp.MustCompile(`(?i)^RUN\s+.*\bsudo\b`)

	// Matches HEALTHCHECK instruction.
	reHealthcheck = regexp.MustCompile(`(?i)^HEALTHCHECK\s+`)

	// Matches ENV with secrets/passwords.
	reEnvSecret = regexp.MustCompile(`(?i)^ENV\s+\S*(PASSWORD|SECRET|TOKEN|KEY|API_KEY|PRIVATE_KEY)\s*=`)

	// Matches privileged ports in EXPOSE.
	rePrivilegedPort = regexp.MustCompile(`\b(2[12]|23|25|53|110|139|445|3389)\b`)

	// Matches RUN with chmod 777.
	reChmod777 = regexp.MustCompile(`(?i)^RUN\s+.*chmod\s+777`)
)

// containerRules defines all Dockerfile security rules.
var containerRules = []dockerfileRule{
	{
		ID:          "CONTAINER-001",
		Description: "Container running as root: no USER instruction found",
		Severity:    sdk.SeverityHigh,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-250",
		Check:       checkNoUserInstruction,
	},
	{
		ID:          "CONTAINER-002",
		Description: "Using latest tag or untagged base image",
		Severity:    sdk.SeverityMedium,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-829",
		Check:       checkLatestTag,
	},
	{
		ID:          "CONTAINER-003",
		Description: "Sensitive file copied into container image",
		Severity:    sdk.SeverityHigh,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-200",
		Check:       checkSensitiveCopy,
	},
	{
		ID:          "CONTAINER-004",
		Description: "ADD instruction used instead of COPY",
		Severity:    sdk.SeverityLow,
		Confidence:  sdk.ConfidenceMedium,
		CWE:         "CWE-829",
		Check:       checkAddVsCopy,
	},
	{
		ID:          "CONTAINER-005",
		Description: "Privileged or dangerous port exposed",
		Severity:    sdk.SeverityMedium,
		Confidence:  sdk.ConfidenceMedium,
		CWE:         "CWE-284",
		Check:       checkPrivilegedPorts,
	},
	{
		ID:          "CONTAINER-006",
		Description: "No multi-stage build detected in Dockerfile",
		Severity:    sdk.SeverityLow,
		Confidence:  sdk.ConfidenceMedium,
		CWE:         "CWE-1104",
		Check:       checkNoMultiStage,
	},
	{
		ID:          "CONTAINER-007",
		Description: "Package manager cache not cleaned after install",
		Severity:    sdk.SeverityLow,
		Confidence:  sdk.ConfidenceMedium,
		CWE:         "CWE-459",
		Check:       checkPackageCacheNotCleaned,
	},
	{
		ID:          "CONTAINER-008",
		Description: "Remote script piped to shell (curl|sh pattern)",
		Severity:    sdk.SeverityCritical,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-94",
		Check:       checkCurlPipeShell,
	},
	{
		ID:          "CONTAINER-009",
		Description: "Secret or credential set via ENV instruction",
		Severity:    sdk.SeverityHigh,
		Confidence:  sdk.ConfidenceMedium,
		CWE:         "CWE-798",
		Check:       checkEnvSecrets,
	},
	{
		ID:          "CONTAINER-010",
		Description: "Overly permissive file permissions (chmod 777)",
		Severity:    sdk.SeverityMedium,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-732",
		Check:       checkChmod777,
	},
	{
		ID:          "CONTAINER-011",
		Description: "No HEALTHCHECK instruction defined",
		Severity:    sdk.SeverityLow,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-693",
		Check:       checkNoHealthcheck,
	},
	{
		ID:          "CONTAINER-012",
		Description: "Use of sudo in RUN instruction",
		Severity:    sdk.SeverityMedium,
		Confidence:  sdk.ConfidenceHigh,
		CWE:         "CWE-250",
		Check:       checkSudoUsage,
	},
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/container", version).
		Capability("container", "Dockerfile security linting and container image analysis").
		Tool("scan", "Scan Dockerfiles for security misconfigurations and best practice violations", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if isDockerfile(d.Name()) {
			return scanDockerfile(resp, path)
		}
		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// isDockerfile returns true if the file name looks like a Dockerfile.
func isDockerfile(name string) bool {
	lower := strings.ToLower(name)
	if lower == "dockerfile" {
		return true
	}
	if strings.HasPrefix(lower, "dockerfile.") {
		return true
	}
	if strings.HasSuffix(lower, ".dockerfile") {
		return true
	}
	return false
}

// scanDockerfile parses a Dockerfile and runs all rules against it.
func scanDockerfile(resp *sdk.ResponseBuilder, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var lines []dockerfileLine
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		lines = append(lines, dockerfileLine{Num: lineNum, Text: scanner.Text()})
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Resolve line continuations (backslash at end of line).
	resolved := resolveLineContinuations(lines)

	for i := range containerRules {
		rule := &containerRules[i]
		matches := rule.Check(resolved)
		for _, m := range matches {
			msg := rule.Description
			if m.Message != "" {
				msg = fmt.Sprintf("%s: %s", rule.Description, m.Message)
			}
			resp.Finding(
				rule.ID,
				rule.Severity,
				rule.Confidence,
				msg,
			).
				At(filePath, m.Line, m.Line).
				WithMetadata("cwe", rule.CWE).
				Done()
		}
	}

	return nil
}

// resolveLineContinuations merges lines ending with backslash into the following line.
func resolveLineContinuations(lines []dockerfileLine) []dockerfileLine {
	var resolved []dockerfileLine
	var buffer string
	var startLine int

	for _, l := range lines {
		trimmed := strings.TrimSpace(l.Text)

		// Skip comments and empty lines.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if buffer == "" {
				resolved = append(resolved, l)
			}
			continue
		}

		if buffer == "" {
			startLine = l.Num
		}

		if strings.HasSuffix(trimmed, "\\") {
			buffer += strings.TrimSuffix(trimmed, "\\") + " "
			continue
		}

		buffer += trimmed
		resolved = append(resolved, dockerfileLine{Num: startLine, Text: buffer})
		buffer = ""
	}

	if buffer != "" {
		resolved = append(resolved, dockerfileLine{Num: startLine, Text: buffer})
	}

	return resolved
}

// --- Rule check functions ---

func checkNoUserInstruction(lines []dockerfileLine) []ruleMatch {
	hasUser := false
	lastFromLine := 0

	for _, l := range lines {
		if reFrom.MatchString(strings.TrimSpace(l.Text)) {
			lastFromLine = l.Num
		}
		if reUser.MatchString(strings.TrimSpace(l.Text)) {
			hasUser = true
		}
	}

	if !hasUser && lastFromLine > 0 {
		return []ruleMatch{{Line: lastFromLine, Message: "consider adding a USER instruction to avoid running as root"}}
	}
	return nil
}

func checkLatestTag(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if !reFrom.MatchString(text) {
			continue
		}
		// Skip scratch base images.
		if strings.Contains(strings.ToLower(text), "from scratch") {
			continue
		}
		// Check for explicit tag that is not :latest.
		if reExplicitTag.MatchString(text) {
			// Has a tag -- check if it is :latest.
			if strings.Contains(strings.ToLower(text), ":latest") {
				matches = append(matches, ruleMatch{
					Line:    l.Num,
					Message: "base image uses :latest tag, pin to a specific version",
				})
			}
		} else {
			// No tag at all, defaults to :latest.
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "base image has no explicit tag, defaults to :latest",
			})
		}
	}
	return matches
}

func checkSensitiveCopy(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reSensitiveCopy.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "sensitive file being copied into container",
			})
		}
	}
	return matches
}

func checkAddVsCopy(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if !reAdd.MatchString(text) {
			continue
		}
		// ADD with URL has a specific purpose; flag ADD for local files instead.
		if reAddURL.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "ADD fetches remote URL; consider using RUN curl/wget for transparency",
			})
		} else {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "use COPY instead of ADD for local files",
			})
		}
	}
	return matches
}

func checkPrivilegedPorts(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		exposeMatch := reExpose.FindStringSubmatch(text)
		if len(exposeMatch) < 2 {
			continue
		}
		ports := exposeMatch[1]
		if portMatches := rePrivilegedPort.FindAllString(ports, -1); len(portMatches) > 0 {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: fmt.Sprintf("exposing privileged/dangerous port(s): %s", strings.Join(portMatches, ", ")),
			})
		}
	}
	return matches
}

func checkNoMultiStage(lines []dockerfileLine) []ruleMatch {
	fromCount := 0
	firstFromLine := 0
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reFrom.MatchString(text) {
			fromCount++
			if firstFromLine == 0 {
				firstFromLine = l.Num
			}
		}
	}

	if fromCount == 1 && firstFromLine > 0 {
		return []ruleMatch{{
			Line:    firstFromLine,
			Message: "single-stage build detected, consider multi-stage for smaller images",
		}}
	}
	return nil
}

func checkPackageCacheNotCleaned(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)

		if reRunAptGet.MatchString(text) && !reAptClean.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "apt-get install without cache cleanup (apt-get clean / rm -rf /var/lib/apt)",
			})
		}

		if reRunApkAdd.MatchString(text) && !reApkNoCache.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "apk add without --no-cache flag",
			})
		}
	}
	return matches
}

func checkCurlPipeShell(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reCurlPipe.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "curl output piped directly to shell",
			})
		}
		if reWgetPipe.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "wget output piped directly to shell",
			})
		}
	}
	return matches
}

func checkEnvSecrets(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reEnvSecret.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "secret value hardcoded in ENV instruction; use build args or secrets mount",
			})
		}
	}
	return matches
}

func checkChmod777(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reChmod777.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "chmod 777 grants excessive permissions",
			})
		}
	}
	return matches
}

func checkNoHealthcheck(lines []dockerfileLine) []ruleMatch {
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reHealthcheck.MatchString(text) {
			return nil
		}
	}

	// Only flag if we actually have a Dockerfile with at least one FROM.
	for _, l := range lines {
		if reFrom.MatchString(strings.TrimSpace(l.Text)) {
			return []ruleMatch{{Line: 1, Message: "no HEALTHCHECK instruction found"}}
		}
	}
	return nil
}

func checkSudoUsage(lines []dockerfileLine) []ruleMatch {
	var matches []ruleMatch
	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if reSudo.MatchString(text) {
			matches = append(matches, ruleMatch{
				Line:    l.Num,
				Message: "sudo is unnecessary in containers; run commands directly or use USER",
			})
		}
	}
	return matches
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-container: %v\n", err)
		return 1
	}
	return 0
}
