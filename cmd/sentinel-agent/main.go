package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sentinel-dev/sentinel/internal/adapters/gitleaks"
	"github.com/sentinel-dev/sentinel/internal/adapters/nuclei"
	"github.com/sentinel-dev/sentinel/internal/adapters/osv"
	"github.com/sentinel-dev/sentinel/internal/adapters/resilience"
	"github.com/sentinel-dev/sentinel/internal/adapters/semgrep"
	"github.com/sentinel-dev/sentinel/internal/adapters/trivy"
	"github.com/sentinel-dev/sentinel/internal/config"
	"github.com/sentinel-dev/sentinel/internal/orchestrator"
)

// JSON-RPC 2.0 structures
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
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
	mu          sync.RWMutex
	scans       map[string]*orchestrator.ScanResult
	scanStates  map[string]string // "running", "done", "error"
}

func newAgentServer() *AgentServer {
	return &AgentServer{
		scans:      make(map[string]*orchestrator.ScanResult),
		scanStates: make(map[string]string),
	}
}

func main() {
	port := flag.Int("port", 48921, "TCP port for IDE agent IPC")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start sentinel-agent on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("🚀 sentinel-agent IPC daemon listening on %s (JSON-RPC 2.0)\n", addr)

	srv := newAgentServer()

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
	scanner := bufio.NewScanner(conn)

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
