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
