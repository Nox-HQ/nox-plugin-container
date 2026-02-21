package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackCoreAnalysis)
}

func TestScanFindsRunAsRoot(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-001")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-001 (running as root) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["cwe"] != "CWE-250" {
			t.Errorf("expected CWE-250 metadata, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanFindsLatestTag(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-002")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-002 (latest tag) finding")
	}
}

func TestScanFindsSensitiveCopy(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-003")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-003 (sensitive file copy) finding")
	}
}

func TestScanFindsAddVsCopy(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-004")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-004 (ADD vs COPY) finding")
	}
}

func TestScanFindsPrivilegedPorts(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-005")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-005 (privileged port) finding")
	}
}

func TestScanFindsCurlPipeShell(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-008")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-008 (curl|sh) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityCritical {
			t.Errorf("CONTAINER-008 severity should be CRITICAL, got %v", f.GetSeverity())
		}
	}
}

func TestScanFindsEnvSecrets(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-009")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-009 (ENV secret) finding")
	}
}

func TestScanFindsChmod777(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-010")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-010 (chmod 777) finding")
	}
}

func TestScanFindsSudo(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-012")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-012 (sudo usage) finding")
	}
}

func TestScanGoodDockerfileHasFewerFindings(t *testing.T) {
	client := testClient(t)
	goodDir := filepath.Join(testdataDir(t), "good")
	resp := invokeScan(t, client, goodDir)

	// The good Dockerfile should have no high-severity findings.
	for _, f := range resp.GetFindings() {
		if f.GetSeverity() == sdk.SeverityCritical || f.GetSeverity() == sdk.SeverityHigh {
			t.Errorf("good Dockerfile should not have critical/high findings, got %s: %s",
				f.GetRuleId(), f.GetMessage())
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

func TestIsDockerfile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Dockerfile", true},
		{"dockerfile", true},
		{"Dockerfile.prod", true},
		{"Dockerfile.dev", true},
		{"app.dockerfile", true},
		{"README.md", false},
		{"main.go", false},
		{"docker-compose.yml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDockerfile(tt.name)
			if got != tt.want {
				t.Errorf("isDockerfile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestScanPackageCacheNotCleaned(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "CONTAINER-007")
	if len(found) == 0 {
		t.Fatal("expected at least one CONTAINER-007 (package cache not cleaned) finding")
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
