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
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
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
			cfg, _ := config.Load(params.RepoPath)
			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
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

	default:
		resp.Error = &JSONRPCError{Code: -32601, Message: "Method not found"}
	}

	return resp
}
