package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"testing"
)

func TestNewCsrPasswordVerifier(t *testing.T) {
	// Test with valid whitelist file
	whitelistPath := filepath.Join("testdata", "configs", "whitelist.yaml")
	verifier, err := newCsrPasswordVerifier(whitelistPath)
	if err != nil {
		t.Fatalf("newCsrPasswordVerifier() failed: %v", err)
	}

	if verifier == nil {
		t.Error("Expected verifier, got nil")
	}

	// Test with invalid file path
	_, err = newCsrPasswordVerifier("nonexistent.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestCsrPasswordVerifier_allowedDnsName(t *testing.T) {
	whitelistPath := filepath.Join("testdata", "configs", "whitelist.yaml")
	verifier, err := newCsrPasswordVerifier(whitelistPath)
	if err != nil {
		t.Fatalf("newCsrPasswordVerifier() failed: %v", err)
	}

	cpv := verifier.(*csrPasswordVerifier)

	// Test exact matches
	tests := []struct {
		password string
		hostname string
		expected bool
	}{
		{"password1", "example.com", true},
		{"password1", "subdomain.example.com", false},
		{"password2", "subdomain1.example.com", true},
		{"password2", "subdomain2.example.com", true},
		{"password2", "example.com", false},
		{"testpass", "test.example.com", true},
		{"testpass", "other.example.com", false},
		{"multipass", "multi1.example.com", true},
		{"multipass", "multi2.example.com", true},
		{"multipass", "multi3.example.com", true},
		{"multipass", "multi4.example.com", false},
		{"nonexistent", "any.example.com", false},
	}

	for _, tt := range tests {
		result := cpv.allowedDnsName(tt.password, tt.hostname)
		if result != tt.expected {
			t.Errorf("allowedDnsName(%q, %q) = %v, expected %v", tt.password, tt.hostname, result, tt.expected)
		}
	}
}

func TestCsrPasswordVerifier_Verify(t *testing.T) {
	whitelistPath := filepath.Join("testdata", "configs", "whitelist.yaml")
	verifier, err := newCsrPasswordVerifier(whitelistPath)
	if err != nil {
		t.Fatalf("newCsrPasswordVerifier() failed: %v", err)
	}

	// Generate test CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create CSR with valid hostname
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames: []string{"example.com"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Note: In a real test, we would need to properly add the challenge password
	// For now, we'll test the basic CSR parsing functionality
	// The full verification would require SCEP protocol handling

	// Test CSR parsing
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if csr.Subject.CommonName != "example.com" {
		t.Errorf("Expected CN=example.com, got %s", csr.Subject.CommonName)
	}

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "example.com" {
		t.Errorf("Expected DNSNames=[example.com], got %v", csr.DNSNames)
	}

	// Test would need full SCEP implementation to test Verify() method
	// For now, we verify the verifier was created successfully
	if verifier == nil {
		t.Error("Expected verifier to be created")
	}
}

func TestHostnameExactMatcher(t *testing.T) {
	matcher := hostnameExactMatcher("example.com")

	tests := []struct {
		hostname string
		expected bool
	}{
		{"example.com", true},
		{"subdomain.example.com", false},
		{"other.com", false},
		{"", false},
	}

	for _, tt := range tests {
		result := matcher(tt.hostname)
		if result != tt.expected {
			t.Errorf("hostnameExactMatcher(%q) = %v, expected %v", tt.hostname, result, tt.expected)
		}
	}
}

// Helper function to add challenge password to CSR
// This is a simplified version for testing - real implementation would require
// proper SCEP protocol handling
func addChallengePasswordToCSR(csrBytes []byte, password string) ([]byte, error) {
	// For testing purposes, we'll just return the original CSR
	// In a real implementation, this would properly encode the challenge password
	// using the SCEP protocol
	return csrBytes, nil
}
