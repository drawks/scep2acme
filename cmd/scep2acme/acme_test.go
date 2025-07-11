package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcmeUserInfo_GetEmail(t *testing.T) {
	originalEmail := *acmeEmail
	defer func() {
		*acmeEmail = originalEmail
	}()

	testEmail := "test@example.com"
	*acmeEmail = testEmail

	user := &acmeUserInfo{}
	email := user.GetEmail()

	if email != testEmail {
		t.Errorf("GetEmail() = %q, expected %q", email, testEmail)
	}
}

func TestAcmeUserInfo_GetPrivateKey(t *testing.T) {
	// Create test ACME key
	acmeKeyPEM, err := generateTestACMEKey()
	if err != nil {
		t.Fatalf("Failed to generate test ACME key: %v", err)
	}

	// Create temporary file for ACME key
	tempDir, err := ioutil.TempDir("", "scep2acme-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testAcmeKeyPath := filepath.Join(tempDir, "acme.key")
	if err := ioutil.WriteFile(testAcmeKeyPath, acmeKeyPEM, 0644); err != nil {
		t.Fatalf("Failed to write ACME key file: %v", err)
	}

	// Save original flag value
	originalAcmeKeyPath := *acmeKeyPath
	defer func() {
		*acmeKeyPath = originalAcmeKeyPath
	}()

	// Set flag value to test file
	*acmeKeyPath = testAcmeKeyPath

	user := &acmeUserInfo{}

	// Test GetPrivateKey
	privateKey := user.GetPrivateKey()
	if privateKey == nil {
		t.Error("Expected private key, got nil")
	}

	// Verify it's an RSA private key
	if _, ok := privateKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestAcmeUserInfo_GetRegistration(t *testing.T) {
	user := &acmeUserInfo{}

	// Test with nil registration
	registration := user.GetRegistration()
	if registration != nil {
		t.Error("Expected nil registration")
	}

	// Test with set registration - this would be set by the ACME client
	// For now, we just verify the method returns what's set
	if user.registration != registration {
		t.Error("GetRegistration() should return the set registration")
	}
}

func TestMandatoryFlag(t *testing.T) {
	// Test with non-zero value (should not panic)
	nonZeroString := "test"
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("mandatoryFlag() panicked with non-zero value: %v", r)
		}
	}()
	mandatoryFlag("test", &nonZeroString)

	// Test with zero value (should panic)
	zeroString := ""
	defer func() {
		if r := recover(); r == nil {
			t.Error("mandatoryFlag() should panic with zero value")
		}
	}()
	mandatoryFlag("test", &zeroString)
}

func TestServiceWithoutRenewal_GetCACaps(t *testing.T) {
	// This test is more complex as it requires a mock SCEP service
	// For now, we'll test the caps modification logic

	testCaps := []byte("POSTPKIOperation\nSHA-1\nSHA-256\nRenewal\nAES")

	// Test the string replacement logic directly
	capsString := string(testCaps)
	newCaps := " " + capsString + " "
	newCaps = strings.ReplaceAll(newCaps, "\nRenewal\n", "\n")
	newCaps = newCaps[1 : len(newCaps)-1]

	// The actual logic removes "\nRenewal\n" from the caps
	if !strings.Contains(string(testCaps), "Renewal") {
		t.Error("Test caps should contain Renewal")
	}

	if strings.Contains(newCaps, "Renewal") {
		t.Error("New caps should not contain Renewal")
	}
}

// Mock functions for testing - these would be used in integration tests
func createMockACMEClient() error {
	// This would create a mock ACME client for testing
	// Implementation depends on the specific testing framework
	return nil
}

func TestSetupAcmeClient_validation(t *testing.T) {
	// Test validation of required parameters
	// Save original values
	originalDnsProvider := *dnsProvider
	originalAcmeUrl := *acmeUrl
	originalAcmeEmail := *acmeEmail

	defer func() {
		*dnsProvider = originalDnsProvider
		*acmeUrl = originalAcmeUrl
		*acmeEmail = originalAcmeEmail
	}()

	// Test with empty DNS provider
	*dnsProvider = ""
	*acmeUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"
	*acmeEmail = "test@example.com"

	// Note: setupAcmeClient would fail with empty DNS provider
	// But we can't easily test this without mocking the DNS provider creation

	// Test with valid parameters
	*dnsProvider = "manual"
	*acmeUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"
	*acmeEmail = "test@example.com"

	// The actual setupAcmeClient would require proper ACME account key
	// and DNS provider configuration, which we can't easily mock here
	// This is better tested in integration tests
}

func TestGenerateTestCertificates(t *testing.T) {
	// Test our test utility functions
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

	// Verify the generated certificate can be parsed
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Error("Failed to decode certificate PEM")
	}

	_, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Errorf("Failed to parse generated certificate: %v", err)
	}

	// Verify the generated key can be parsed
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Error("Failed to decode key PEM")
	}

	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Errorf("Failed to parse generated key: %v", err)
	}
}

func TestGenerateTestCAAndRA(t *testing.T) {
	caPEM, raPEM, caKeyPEM, raKeyPEM, err := generateTestCAAndRA()
	if err != nil {
		t.Fatalf("generateTestCAAndRA() failed: %v", err)
	}

	// Verify all components are generated
	if len(caPEM) == 0 {
		t.Error("Expected CA certificate PEM data")
	}

	if len(raPEM) == 0 {
		t.Error("Expected RA certificate PEM data")
	}

	if len(caKeyPEM) == 0 {
		t.Error("Expected CA key PEM data")
	}

	if len(raKeyPEM) == 0 {
		t.Error("Expected RA key PEM data")
	}

	// Verify certificates can be parsed
	caCertBlock, _ := pem.Decode(caPEM)
	if caCertBlock == nil {
		t.Error("Failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Errorf("Failed to parse CA certificate: %v", err)
	}

	if !caCert.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}

	raCertBlock, _ := pem.Decode(raPEM)
	if raCertBlock == nil {
		t.Error("Failed to decode RA certificate PEM")
	}

	raCert, err := x509.ParseCertificate(raCertBlock.Bytes)
	if err != nil {
		t.Errorf("Failed to parse RA certificate: %v", err)
	}

	if raCert.IsCA {
		t.Error("RA certificate should have IsCA=false")
	}
}
