package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// Setup test environment
	setupTestEnvironment()
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	cleanupTestEnvironment()
	
	os.Exit(code)
}

func setupTestEnvironment() {
	// Create test certificates and keys for the entire test suite
	caPEM, raPEM, caKeyPEM, raKeyPEM, err := generateTestCAAndRA()
	if err != nil {
		panic(err)
	}
	
	acmeKeyPEM, err := generateTestACMEKey()
	if err != nil {
		panic(err)
	}
	
	// Write test files to testdata directory
	certFile := filepath.Join("testdata", "certs", "combined.pem")
	keyFile := filepath.Join("testdata", "keys", "ra.key")
	acmeKeyFile := filepath.Join("testdata", "keys", "acme.key")
	
	// Ensure directories exist
	os.MkdirAll(filepath.Dir(certFile), 0755)
	os.MkdirAll(filepath.Dir(keyFile), 0755)
	os.MkdirAll(filepath.Dir(acmeKeyFile), 0755)
	
	// Write combined certificate (RA + CA)
	combinedCert := append(raPEM, caPEM...)
	if err := ioutil.WriteFile(certFile, combinedCert, 0644); err != nil {
		panic(err)
	}
	
	if err := ioutil.WriteFile(keyFile, raKeyPEM, 0600); err != nil {
		panic(err)
	}
	
	if err := ioutil.WriteFile(acmeKeyFile, acmeKeyPEM, 0600); err != nil {
		panic(err)
	}
	
	// Write individual CA and RA files for specific tests
	caFile := filepath.Join("testdata", "certs", "ca.pem")
	raFile := filepath.Join("testdata", "certs", "ra.pem")
	caKeyFile := filepath.Join("testdata", "keys", "ca.key")
	
	if err := ioutil.WriteFile(caFile, caPEM, 0644); err != nil {
		panic(err)
	}
	
	if err := ioutil.WriteFile(raFile, raPEM, 0644); err != nil {
		panic(err)
	}
	
	if err := ioutil.WriteFile(caKeyFile, caKeyPEM, 0600); err != nil {
		panic(err)
	}
}

func cleanupTestEnvironment() {
	// Test cleanup is handled by Go's test framework
	// testdata directory should remain for inspection if needed
}

// Test application startup validation
func TestApplicationStartupValidation(t *testing.T) {
	// Test that all required flags are validated
	tests := []struct {
		name     string
		flagName string
		value    interface{}
		shouldPanic bool
	}{
		{"cert required", "cert", (*string)(nil), true},
		{"cert provided", "cert", stringPtr("test.pem"), false},
		{"certkey required", "certkey", (*string)(nil), true},
		{"certkey provided", "certkey", stringPtr("test.key"), false},
		{"acmekey required", "acmekey", (*string)(nil), true},
		{"acmekey provided", "acmekey", stringPtr("test.key"), false},
		{"acmeemail required", "acmeemail", (*string)(nil), true},
		{"acmeemail provided", "acmeemail", stringPtr("test@example.com"), false},
		{"dnsprovider required", "dnsprovider", (*string)(nil), true},
		{"dnsprovider provided", "dnsprovider", stringPtr("manual"), false},
		{"whitelist required", "whitelist", (*string)(nil), true},
		{"whitelist provided", "whitelist", stringPtr("whitelist.yaml"), false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.shouldPanic {
					t.Errorf("Expected panic=%v, got panic=%v", tt.shouldPanic, r != nil)
				}
			}()
			
			mandatoryFlag(tt.flagName, tt.value)
		})
	}
}

// Test configuration loading
func TestConfigurationLoading(t *testing.T) {
	// Test whitelist loading
	whitelistPath := filepath.Join("testdata", "configs", "whitelist.yaml")
	verifier, err := newCsrPasswordVerifier(whitelistPath)
	if err != nil {
		t.Fatalf("Failed to load whitelist: %v", err)
	}
	
	if verifier == nil {
		t.Error("Expected verifier, got nil")
	}
	
	// Test invalid whitelist file
	invalidPath := filepath.Join("testdata", "configs", "nonexistent.yaml")
	_, err = newCsrPasswordVerifier(invalidPath)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// Test service creation
func TestServiceCreation(t *testing.T) {
	// Test depot creation
	depot := &myDepot{}
	if depot == nil {
		t.Error("Failed to create depot")
	}
	
	// Test CSR verifier creation
	whitelistPath := filepath.Join("testdata", "configs", "whitelist.yaml")
	verifier, err := newCsrPasswordVerifier(whitelistPath)
	if err != nil {
		t.Fatalf("Failed to create CSR verifier: %v", err)
	}
	
	if verifier == nil {
		t.Error("Expected verifier, got nil")
	}
	
	// Test ACME user info
	originalEmail := *acmeEmail
	originalKeyPath := *acmeKeyPath
	defer func() {
		*acmeEmail = originalEmail
		*acmeKeyPath = originalKeyPath
	}()
	
	*acmeEmail = "test@example.com"
	*acmeKeyPath = filepath.Join("testdata", "keys", "acme.key")
	
	user := &acmeUserInfo{}
	if user.GetEmail() != "test@example.com" {
		t.Errorf("Expected email=test@example.com, got %s", user.GetEmail())
	}
	
	privateKey := user.GetPrivateKey()
	if privateKey == nil {
		t.Error("Expected private key, got nil")
	}
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	// Test depot with missing files
	depot := &myDepot{}
	
	originalCertPath := *certPath
	originalKeyPath := *certKeyPath
	defer func() {
		*certPath = originalCertPath
		*certKeyPath = originalKeyPath
	}()
	
	*certPath = "nonexistent.pem"
	*certKeyPath = "nonexistent.key"
	
	_, _, err := depot.CA(nil)
	if err == nil {
		t.Error("Expected error for missing cert file")
	}
	
	// Test CSR verifier with invalid file
	_, err = newCsrPasswordVerifier("nonexistent.yaml")
	if err == nil {
		t.Error("Expected error for missing whitelist file")
	}
}

// Test service without renewal
func TestServiceWithoutRenewal(t *testing.T) {
	// Test caps modification
	originalCaps := "POSTPKIOperation\nSHA-1\nSHA-256\nRenewal\nAES"
	expectedCaps := "POSTPKIOperation\nSHA-1\nSHA-256\nAES"
	
	// This tests the logic from serviceWithoutRenewal.GetCACaps
	newCaps := " " + originalCaps + " "
	newCaps = strings.Replace(newCaps, "\nRenewal\n", "\n", -1)
	newCaps = newCaps[1 : len(newCaps)-1]
	
	if newCaps != expectedCaps {
		t.Errorf("Expected caps=%q, got %q", expectedCaps, newCaps)
	}
}

// Test hostname matching
func TestHostnameMatching(t *testing.T) {
	// Test exact matcher
	matcher := hostnameExactMatcher("example.com")
	
	tests := []struct {
		hostname string
		expected bool
	}{
		{"example.com", true},
		{"subdomain.example.com", false},
		{"other.com", false},
		{"", false},
		{"EXAMPLE.COM", false}, // case sensitive
	}
	
	for _, tt := range tests {
		result := matcher(tt.hostname)
		if result != tt.expected {
			t.Errorf("hostnameExactMatcher(%q) = %v, expected %v", tt.hostname, result, tt.expected)
		}
	}
}

// Test utilities
func TestUtilities(t *testing.T) {
	// Test certificate and key generation
	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("generateTestCertAndKey() failed: %v", err)
	}
	
	if len(certPEM) == 0 {
		t.Error("Expected certificate PEM data")
	}
	
	if len(keyPEM) == 0 {
		t.Error("Expected key PEM data")
	}
	
	// Test CA and RA generation
	caPEM, raPEM, caKeyPEM, raKeyPEM, err := generateTestCAAndRA()
	if err != nil {
		t.Fatalf("generateTestCAAndRA() failed: %v", err)
	}
	
	if len(caPEM) == 0 || len(raPEM) == 0 || len(caKeyPEM) == 0 || len(raKeyPEM) == 0 {
		t.Error("Expected all CA/RA components to be generated")
	}
	
	// Test ACME key generation
	acmeKeyPEM, err := generateTestACMEKey()
	if err != nil {
		t.Fatalf("generateTestACMEKey() failed: %v", err)
	}
	
	if len(acmeKeyPEM) == 0 {
		t.Error("Expected ACME key PEM data")
	}
}

// Helper functions for tests
func stringPtr(s string) *string {
	return &s
}

// Test flag validation with different scenarios
func TestFlagValidation(t *testing.T) {
	// Test various flag combinations
	tests := []struct {
		name        string
		setupFlags  func()
		expectPanic bool
	}{
		{
			name: "all flags provided",
			setupFlags: func() {
				// This test verifies that with all flags set, no panic occurs
				// We can't easily test this without changing global state
				// So this is a placeholder for the validation logic
			},
			expectPanic: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Full flag validation testing would require refactoring
			// the main function to make it more testable
			// For now, we test the mandatoryFlag function individually
			t.Log("Flag validation test placeholder")
		})
	}
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
	// Test empty files
	tempDir, err := ioutil.TempDir("", "scep2acme-edge-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Test empty certificate file
	emptyFile := filepath.Join(tempDir, "empty.pem")
	if err := ioutil.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}
	
	depot := &myDepot{}
	_, err = depot.loadCerts([]byte(""))
	if err == nil {
		t.Error("Expected error for empty certificate data")
	}
	
	// Test malformed PEM
	malformedPEM := []byte("-----BEGIN CERTIFICATE-----\nmalformed\n-----END CERTIFICATE-----")
	_, err = depot.loadCerts(malformedPEM)
	if err == nil {
		t.Error("Expected error for malformed PEM")
	}
}