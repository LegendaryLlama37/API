package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"log"
)

// Mock APIConfig for testing
var mockAPIConfig = NewAPIConfig(
	WithSecretKey("test-secret-key"),
	WithTokenExpiration(time.Hour*24),
)

func TestMain(m *testing.M) {
	// Set up necessary environment variables for testing
	os.Setenv("username_hash", "hashed-username")
	os.Setenv("password_hash", "hashed-password")
	os.Setenv("eventgrid_endpoint", "https://eventgrid.endpoint")
	os.Setenv("eventgrid_key", "test-key")

	// Run tests
	os.Exit(m.Run())
}

// Mock for SendPayload function (avoids sending actual HTTP requests)
var SendPayload = func(eventbody string) {
	// Instead of sending the payload, we'll just log it for testing
	log.Printf("Mock SendPayload called with event body: %s", eventbody)
}

func TestHandleStats(t *testing.T) {
	// Create a request to pass to the handler
	req, err := http.NewRequest("GET", "/stats", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleStats)

	// Call the handler
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	expected := `{"request_count":1}`
	if rr.Body.String() != expected {
		t.Errorf("Handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestHandleLogin(t *testing.T) {
	// Create a form request with username and password
	formData := []byte(`username=testuser&password=testpass`)
	req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(formData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleLogin)

	// Call the handler
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check if a token is returned
	var response map[string]string
	json.Unmarshal(rr.Body.Bytes(), &response)
	if _, ok := response["token"]; !ok {
		t.Errorf("Expected token in response, got: %v", rr.Body.String())
	}
}

func TestProcessPayload(t *testing.T) {
	// Mock payload
	payload := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	payloadBytes, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", "/process", bytes.NewBuffer(payloadBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	// Mock JWTMiddleware and SendPayload
	apiConfig = mockAPIConfig

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ProcessPayload)

	// Call the handler
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	expected := `{"status":"success"}`
	if rr.Body.String() != expected {
		t.Errorf("Handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}
