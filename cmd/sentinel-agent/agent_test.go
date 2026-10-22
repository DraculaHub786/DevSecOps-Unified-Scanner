package main

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
)

func TestAgentServerAuthentication(t *testing.T) {
	testToken := "test-secret-token-12345"
	srv := newAgentServer(testToken)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go srv.handleConnection(serverConn)

	clientScanner := bufio.NewScanner(clientConn)

	// 1. Test request without token -> expect -32001 Unauthorized
	unauthReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Token:   "wrong-token",
		Method:  "scan.status",
	}
	reqData, _ := json.Marshal(unauthReq)
	_, _ = clientConn.Write(append(reqData, '\n'))

	if !clientScanner.Scan() {
		t.Fatalf("Expected response from server, got none")
	}
	var unauthResp JSONRPCResponse
	if err := json.Unmarshal(clientScanner.Bytes(), &unauthResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if unauthResp.Error == nil || unauthResp.Error.Code != -32001 {
		t.Errorf("Expected error code -32001 for wrong token, got: %v", unauthResp.Error)
	}

	// 2. Test request with valid token -> expect valid response
	authReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Token:   testToken,
		Method:  "scan.status",
		Params:  json.RawMessage(`{"scanId":"non-existent"}`),
	}
	reqData, _ = json.Marshal(authReq)
	_, _ = clientConn.Write(append(reqData, '\n'))

	if !clientScanner.Scan() {
		t.Fatalf("Expected response from server for auth request")
	}
	var authResp JSONRPCResponse
	if err := json.Unmarshal(clientScanner.Bytes(), &authResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if authResp.Error != nil && authResp.Error.Code == -32001 {
		t.Errorf("Unexpected authentication failure with valid token")
	}
}

func TestAgentRPCContract(t *testing.T) {
	testToken := "test-contract-token-999"
	srv := newAgentServer(testToken)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go srv.handleConnection(serverConn)
	scanner := bufio.NewScanner(clientConn)

	callRPC := func(method string, params interface{}) JSONRPCResponse {
		var rawParams json.RawMessage
		if params != nil {
			rawParams, _ = json.Marshal(params)
		}
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      "test-id",
			Token:   testToken,
			Method:  method,
			Params:  rawParams,
		}
		data, _ := json.Marshal(req)
		_, _ = clientConn.Write(append(data, '\n'))

		if !scanner.Scan() {
			t.Fatalf("No response received for method %s", method)
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal response for method %s: %v", method, err)
		}
		return resp
	}

	// 1. Test agent.ping
	pingResp := callRPC("agent.ping", nil)
	if pingResp.Error != nil {
		t.Errorf("agent.ping returned error: %v", pingResp.Error)
	}
	resultMap, ok := pingResp.Result.(map[string]interface{})
	if !ok || resultMap["status"] != "ok" {
		t.Errorf("Expected status 'ok', got: %v", pingResp.Result)
	}

	// 2. Test doctor.run
	doctorResp := callRPC("doctor.run", nil)
	if doctorResp.Error != nil {
		t.Errorf("doctor.run returned error: %v", doctorResp.Error)
	}
	if doctorResp.Result == nil {
		t.Errorf("Expected doctor.run results array, got nil")
	}

	// 3. Test agent.coverage default
	covResp := callRPC("agent.coverage", nil)
	if covResp.Error != nil {
		t.Errorf("agent.coverage returned error: %v", covResp.Error)
	}

	// 4. Test suppress.add without reason -> expect error
	suppFailResp := callRPC("suppress.add", map[string]interface{}{
		"findingId": "SENTINEL-TEST-001",
		"reason":    "",
	})
	if suppFailResp.Error == nil {
		t.Errorf("Expected error for suppression without mandatory reason")
	}

	// 5. Test unknown method -> expect -32601
	unknownResp := callRPC("non.existent.method", nil)
	if unknownResp.Error == nil || unknownResp.Error.Code != -32601 {
		t.Errorf("Expected code -32601 for unknown method, got: %v", unknownResp.Error)
	}
}
