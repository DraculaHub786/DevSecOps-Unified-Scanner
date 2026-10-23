package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/govulncheck"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/baseline"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/doctor"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/safety"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/threatmodel"
	"gopkg.in/yaml.v3"
)

// JSON-RPC 2.0 structures with authentication token
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Token   string          `json:"token"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ScanRunParams struct {
	RepoPath    string   `json:"repoPath"`
	Paths       []string `json:"paths"`
	Incremental bool     `json:"incremental"`
	Offline     bool     `json:"offline"`
	PolicyPath  string   `json:"policyPath"`
}

type ScanStatusParams struct {
	ScanID string `json:"scanId"`
}

type FindingsListParams struct {
	ScanID string `json:"scanId"`
	File   string `json:"file"`
}

type FixParams struct {
	RepoPath  string `json:"repoPath"`
	FindingID string `json:"findingId"`
}

type BaselineParams struct {
	RepoPath string `json:"repoPath"`
}

type SuppressParams struct {
	RepoPath  string `json:"repoPath"`
	FindingID string `json:"findingId"`
	Reason    string `json:"reason"`
	Expires   string `json:"expires,omitempty"`
}

type ThreatModelParams struct {
	RepoPath string `json:"repoPath"`
}

type SBOMParams struct {
	RepoPath string `json:"repoPath"`
	Format   string `json:"format"`
	Out      string `json:"out"`
}

type DASTParams struct {
	Target       string `json:"target"`
	Authorized   bool   `json:"authorized"`
	AllowPrivate bool   `json:"allowPrivate"`
}

type AgentServer struct {
	mu         sync.RWMutex
	token      string
	scans      map[string]*orchestrator.ScanResult
	scanStates map[string]string // "running", "done", "error"
}

func newAgentServer(token string) *AgentServer {
	return &AgentServer{
		token:      token,
		scans:      make(map[string]*orchestrator.ScanResult),
		scanStates: make(map[string]string),
	}
}

func main() {
	port := flag.Int("port", 48921, "TCP port for IDE agent IPC (binds strictly to 127.0.0.1)")
	flag.Parse()

	// 1. Generate cryptographic session token
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate random agent token: %v\n", err)
		os.Exit(1)
	}
	sessionToken := hex.EncodeToString(tokenBytes)

	// 2. Persist token to user cache directory with restrictive mode 0600
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	tokenDir := filepath.Join(cacheDir, "sentinel")
	_ = os.MkdirAll(tokenDir, 0700)
	tokenFile := filepath.Join(tokenDir, "agent.token")
	if err := os.WriteFile(tokenFile, []byte(sessionToken), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write agent token file %s: %v\n", tokenFile, err)
		os.Exit(1)
	}
	defer os.Remove(tokenFile)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start sentinel-agent on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("🚀 sentinel-agent IPC daemon active on %s (JSON-RPC 2.0 with session token auth)\n", addr)
	fmt.Printf("🔑 Session token stored in: %s\n", tokenFile)

	srv := newAgentServer(sessionToken)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go srv.handleConnection(conn)
	}
}

func (s *AgentServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Impose 5MB request limit
	limitedReader := io.LimitReader(conn, 5*1024*1024)
	scanner := bufio.NewScanner(limitedReader)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error:   &JSONRPCError{Code: -32700, Message: "Parse error"},
			}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
			continue
		}

		// Enforce authentication token
		if req.Token != s.token {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32001, Message: "Unauthorized: invalid or missing session token"},
			}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
			continue
		}

		resp := s.handleRequest(&req)
		data, _ := json.Marshal(resp)
		conn.Write(append(data, '\n'))
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		// Connection read error or limit exceeded
		_ = err
	}
}

func (s *AgentServer) handleRequest(req *JSONRPCRequest) JSONRPCResponse {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "scan.run":
		var params ScanRunParams
		_ = json.Unmarshal(req.Params, &params)
		if params.RepoPath == "" {
			params.RepoPath, _ = filepath.Abs(".")
		}

		scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano())
		s.mu.Lock()
		s.scanStates[scanID] = "running"
		s.mu.Unlock()

		go func() {
			var cfg *config.Config
			var err error
			if params.PolicyPath != "" {
				cfg, err = config.LoadFile(params.PolicyPath)
			} else {
				cfg, err = config.Load(params.RepoPath)
			}
			if err != nil || cfg == nil {
				cfg = config.DefaultConfig()
			}
			if params.Offline {
				cfg.Offline = true
			}
			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
				govulncheck.New(),
			)
			res, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
				RepoPath:     params.RepoPath,
				Incremental:  params.Incremental,
				ChangedFiles: params.Paths,
			})

			s.mu.Lock()
			defer s.mu.Unlock()
			if err != nil {
				s.scanStates[scanID] = "error"
			} else {
				s.scanStates[scanID] = "done"
				s.scans[scanID] = res
			}
		}()

		resp.Result = map[string]interface{}{
			"scanId": scanID,
		}

	case "scan.status":
		var params ScanStatusParams
		_ = json.Unmarshal(req.Params, &params)

		s.mu.RLock()
		state, exists := s.scanStates[params.ScanID]
		s.mu.RUnlock()

		if !exists {
			resp.Error = &JSONRPCError{Code: -32602, Message: "Scan ID not found"}
			return resp
		}

		resp.Result = map[string]interface{}{
			"state":    state,
			"progress": 100,
		}

	case "findings.list":
		var params FindingsListParams
		_ = json.Unmarshal(req.Params, &params)

		s.mu.RLock()
		res, exists := s.scans[params.ScanID]
		s.mu.RUnlock()

		if !exists || res == nil {
			resp.Result = []orchestrator.Finding{}
			return resp
		}

		var filtered []orchestrator.Finding
		for _, f := range res.Findings {
			if params.File == "" || strings.EqualFold(filepath.ToSlash(f.File), filepath.ToSlash(params.File)) {
				filtered = append(filtered, f)
			}
		}

		resp.Result = filtered

	case "fix.preview":
		var params FixParams
		_ = json.Unmarshal(req.Params, &params)

		s.mu.RLock()
		var found *orchestrator.Finding
		for _, scan := range s.scans {
			for _, f := range scan.Findings {
				if f.ID == params.FindingID {
					fCopy := f
					found = &fCopy
					break
				}
			}
		}
		s.mu.RUnlock()

		if found == nil || found.FixSuggestion == nil {
			resp.Error = &JSONRPCError{Code: -32602, Message: "No fix available for finding"}
			return resp
		}

		resp.Result = map[string]interface{}{
			"diff":        found.FixSuggestion.Diff,
			"description": found.FixSuggestion.Description,
		}

	case "fix.apply":
		var params FixParams
		_ = json.Unmarshal(req.Params, &params)

		s.mu.RLock()
		var found *orchestrator.Finding
		for _, scan := range s.scans {
			for _, f := range scan.Findings {
				if f.ID == params.FindingID {
					fCopy := f
					found = &fCopy
					break
				}
			}
		}
		s.mu.RUnlock()

		if found == nil {
			resp.Error = &JSONRPCError{Code: -32602, Message: "Finding not found"}
			return resp
		}

		diff, err := orchestrator.ApplyFix(params.RepoPath, found)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: err.Error()}
			return resp
		}

		resp.Result = map[string]interface{}{
			"success":     true,
			"appliedDiff": diff,
		}

	case "agent.handshake":
		var params struct {
			Client  string `json:"client"`
			Version string `json:"version"`
		}
		_ = json.Unmarshal(req.Params, &params)
		resp.Result = map[string]interface{}{
			"status":          "authenticated",
			"serverVersion":   "1.0.0-rc1",
			"protocolVersion": "2.0",
			"capabilities": []string{
				"scan.run",
				"scan.status",
				"findings.list",
				"fix.preview",
				"fix.apply",
				"baseline.create",
				"suppress.add",
				"threatmodel.run",
				"sbom.generate",
				"dast.run",
				"doctor.run",
				"agent.coverage",
			},
		}

	case "agent.ping", "agent.health":
		resp.Result = map[string]interface{}{
			"status":  "ok",
			"version": "1.0.0-rc1",
		}

	case "agent.coverage":
		s.mu.RLock()
		var latestScan *orchestrator.ScanResult
		for _, scan := range s.scans {
			if latestScan == nil || scan.FinishedAt.After(latestScan.FinishedAt) {
				latestScan = scan
			}
		}
		s.mu.RUnlock()

		if latestScan != nil && latestScan.Coverage != nil {
			resp.Result = latestScan.Coverage
		} else {
			resp.Result = map[string]interface{}{
				"totalCategories":  6,
				"activeCategories": 6,
				"items":            []interface{}{},
			}
		}

	case "doctor.run":
		statuses := doctor.CheckEngines()
		resp.Result = statuses

	case "baseline.create":
		var params BaselineParams
		_ = json.Unmarshal(req.Params, &params)
		if params.RepoPath == "" {
			params.RepoPath, _ = filepath.Abs(".")
		}
		s.mu.RLock()
		var findings []orchestrator.Finding
		for _, scan := range s.scans {
			findings = append(findings, scan.Findings...)
		}
		s.mu.RUnlock()

		savedPath, err := baseline.Save(params.RepoPath, findings)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("Failed to save baseline: %v", err)}
			return resp
		}
		resp.Result = map[string]interface{}{
			"success": true,
			"count":   len(findings),
			"path":    savedPath,
		}

	case "suppress.add":
		var params SuppressParams
		_ = json.Unmarshal(req.Params, &params)
		findingID := strings.TrimSpace(params.FindingID)
		reason := strings.TrimSpace(params.Reason)
		if findingID == "" {
			resp.Error = &JSONRPCError{Code: -32602, Message: "findingId is required"}
			return resp
		}
		if reason == "" {
			resp.Error = &JSONRPCError{Code: -32602, Message: "reason is mandatory"}
			return resp
		}
		if params.RepoPath == "" {
			params.RepoPath, _ = filepath.Abs(".")
		}
		cfgFile := filepath.Join(params.RepoPath, ".sentinel.yml")
		cfg, err := config.Load(params.RepoPath)
		if err != nil {
			cfg = config.DefaultConfig()
		}
		found := false
		for i, supp := range cfg.Ignore.Findings {
			if strings.EqualFold(supp.ID, findingID) {
				cfg.Ignore.Findings[i].Reason = reason
				cfg.Ignore.Findings[i].Expires = params.Expires
				found = true
				break
			}
		}
		if !found {
			cfg.Ignore.Findings = append(cfg.Ignore.Findings, config.FindingSuppression{
				ID:      findingID,
				Reason:  reason,
				Expires: params.Expires,
			})
		}
		outData, err := yaml.Marshal(cfg)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("Failed to marshal config: %v", err)}
			return resp
		}
		if err := os.WriteFile(cfgFile, outData, 0644); err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("Failed to write %s: %v", cfgFile, err)}
			return resp
		}
		resp.Result = map[string]interface{}{
			"success":   true,
			"findingId": findingID,
			"file":      cfgFile,
		}

	case "threatmodel.run":
		var params ThreatModelParams
		_ = json.Unmarshal(req.Params, &params)
		if params.RepoPath == "" {
			params.RepoPath, _ = filepath.Abs(".")
		}
		s.mu.RLock()
		var findings []orchestrator.Finding
		for _, scan := range s.scans {
			findings = append(findings, scan.Findings...)
		}
		s.mu.RUnlock()

		tmReport, err := threatmodel.GenerateThreatModel(params.RepoPath, findings)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("Threat model failed: %v", err)}
			return resp
		}
		resp.Result = tmReport

	case "sbom.generate":
		var params SBOMParams
		_ = json.Unmarshal(req.Params, &params)
		if params.RepoPath == "" {
			params.RepoPath, _ = filepath.Abs(".")
		}
		if params.Format == "" {
			params.Format = "cyclonedx"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		err := trivy.GenerateSBOM(ctx, params.RepoPath, params.Format, params.Out)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("SBOM generation failed: %v", err)}
			return resp
		}
		resp.Result = map[string]interface{}{
			"success": true,
			"format":  params.Format,
			"out":     params.Out,
		}

	case "dast.run":
		var params DASTParams
		_ = json.Unmarshal(req.Params, &params)
		if params.Target == "" {
			resp.Error = &JSONRPCError{Code: -32602, Message: "target is required"}
			return resp
		}
		if !params.Authorized {
			resp.Error = &JSONRPCError{Code: -32000, Message: "Explicit authorization required (--i-have-authorization)"}
			return resp
		}
		repoPath, _ := filepath.Abs(".")
		cfg, _ := config.Load(repoPath)
		if err := safety.ValidateTarget(params.Target, cfg.Scanners.DAST.Allowlist, params.Authorized, params.AllowPrivate); err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("Target safety refusal: %v", err)}
			return resp
		}
		adapter := nuclei.NewWithAuth(params.Authorized)
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cfg.Scanners.DAST.Target = params.Target
		findings, err := adapter.Run(ctx, repoPath, cfg, nil)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32000, Message: fmt.Sprintf("DAST scan failed: %v", err)}
			return resp
		}
		resp.Result = findings

	default:
		resp.Error = &JSONRPCError{Code: -32601, Message: "Method not found"}
	}

	return resp
}
