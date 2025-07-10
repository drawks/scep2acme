//go:build integration
// +build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// IntegrationTestConfig holds configuration for integration tests
type IntegrationTestConfig struct {
	VaultURL    string
	VaultToken  string
	OpenBaoURL  string
	OpenBaoToken string
	TempDir     string
}

// setupIntegrationTest prepares the environment for integration tests
func setupIntegrationTest(t *testing.T) *IntegrationTestConfig {
	// Check if we should run integration tests
	if os.Getenv("SCEP2ACME_INTEGRATION_TESTS") == "" {
		t.Skip("Integration tests skipped. Set SCEP2ACME_INTEGRATION_TESTS=1 to run.")
	}
	
	// Create temporary directory for test files
	tempDir, err := ioutil.TempDir("", "scep2acme-integration-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	
	config := &IntegrationTestConfig{
		VaultURL:    getEnvOrDefault("VAULT_URL", "http://localhost:8200"),
		VaultToken:  getEnvOrDefault("VAULT_TOKEN", "root"),
		OpenBaoURL:  getEnvOrDefault("OPENBAO_URL", "http://localhost:8201"),
		OpenBaoToken: getEnvOrDefault("OPENBAO_TOKEN", "root"),
		TempDir:     tempDir,
	}
	
	// Wait for services to be ready
	if err := waitForService(config.VaultURL, 30*time.Second); err != nil {
		t.Fatalf("Vault service not ready: %v", err)
	}
	
	if err := waitForService(config.OpenBaoURL, 30*time.Second); err != nil {
		t.Fatalf("OpenBao service not ready: %v", err)
	}
	
	return config
}

// cleanupIntegrationTest cleans up after integration tests
func cleanupIntegrationTest(config *IntegrationTestConfig) {
	if config.TempDir != "" {
		os.RemoveAll(config.TempDir)
	}
}

// waitForService waits for a service to be ready
func waitForService(url string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("service not ready within timeout")
		default:
			resp, err := client.Get(url + "/v1/sys/health")
			if err == nil && resp.StatusCode < 500 {
				resp.Body.Close()
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// setupVaultPKI configures Vault PKI for ACME
func setupVaultPKI(t *testing.T, config *IntegrationTestConfig) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	// Enable PKI secrets engine
	data := map[string]interface{}{
		"type": "pki",
	}
	
	if err := makeVaultRequest(client, config.VaultURL, config.VaultToken, "POST", "/v1/sys/mounts/pki", data); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}
	
	// Configure PKI
	configData := map[string]interface{}{
		"max_lease_ttl": "87600h",
	}
	
	if err := makeVaultRequest(client, config.VaultURL, config.VaultToken, "POST", "/v1/sys/mounts/pki/tune", configData); err != nil {
		t.Fatalf("Failed to configure PKI: %v", err)
	}
	
	// Generate root CA
	rootData := map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "87600h",
	}
	
	if err := makeVaultRequest(client, config.VaultURL, config.VaultToken, "POST", "/v1/pki/root/generate/internal", rootData); err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}
	
	// Configure ACME
	acmeData := map[string]interface{}{
		"enabled":                 true,
		"allowed_issuers":         []string{"*"},
		"allowed_roles":           []string{"*"},
		"default_directory_policy": "sign-verbatim",
	}
	
	if err := makeVaultRequest(client, config.VaultURL, config.VaultToken, "POST", "/v1/pki/config/acme", acmeData); err != nil {
		t.Fatalf("Failed to configure ACME: %v", err)
	}
	
	// Create a role for certificate issuance
	roleData := map[string]interface{}{
		"allowed_domains":  []string{"example.com", "test.example.com"},
		"allow_subdomains": true,
		"max_ttl":          "720h",
	}
	
	if err := makeVaultRequest(client, config.VaultURL, config.VaultToken, "POST", "/v1/pki/roles/test-role", roleData); err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
}

// setupOpenBaoPKI configures OpenBao PKI for ACME
func setupOpenBaoPKI(t *testing.T, config *IntegrationTestConfig) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	// Enable PKI secrets engine
	data := map[string]interface{}{
		"type": "pki",
	}
	
	if err := makeOpenBaoRequest(client, config.OpenBaoURL, config.OpenBaoToken, "POST", "/v1/sys/mounts/pki", data); err != nil {
		t.Fatalf("Failed to enable PKI: %v", err)
	}
	
	// Configure PKI
	configData := map[string]interface{}{
		"max_lease_ttl": "87600h",
	}
	
	if err := makeOpenBaoRequest(client, config.OpenBaoURL, config.OpenBaoToken, "POST", "/v1/sys/mounts/pki/tune", configData); err != nil {
		t.Fatalf("Failed to configure PKI: %v", err)
	}
	
	// Generate root CA
	rootData := map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "87600h",
	}
	
	if err := makeOpenBaoRequest(client, config.OpenBaoURL, config.OpenBaoToken, "POST", "/v1/pki/root/generate/internal", rootData); err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}
	
	// Configure ACME
	acmeData := map[string]interface{}{
		"enabled":                 true,
		"allowed_issuers":         []string{"*"},
		"allowed_roles":           []string{"*"},
		"default_directory_policy": "sign-verbatim",
	}
	
	if err := makeOpenBaoRequest(client, config.OpenBaoURL, config.OpenBaoToken, "POST", "/v1/pki/config/acme", acmeData); err != nil {
		t.Fatalf("Failed to configure ACME: %v", err)
	}
	
	// Create a role for certificate issuance
	roleData := map[string]interface{}{
		"allowed_domains":  []string{"example.com", "test.example.com"},
		"allow_subdomains": true,
		"max_ttl":          "720h",
	}
	
	if err := makeOpenBaoRequest(client, config.OpenBaoURL, config.OpenBaoToken, "POST", "/v1/pki/roles/test-role", roleData); err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}
}

// makeVaultRequest makes an HTTP request to Vault
func makeVaultRequest(client *http.Client, baseURL, token, method, path string, data interface{}) error {
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(jsonData)
	}
	
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return err
	}
	
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	return nil
}

// makeOpenBaoRequest makes an HTTP request to OpenBao
func makeOpenBaoRequest(client *http.Client, baseURL, token, method, path string, data interface{}) error {
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(jsonData)
	}
	
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return err
	}
	
	req.Header.Set("X-Vault-Token", token)  // OpenBao uses same header format
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	return nil
}

// TestVaultACMEIntegration tests SCEP2ACME with Vault PKI backend
func TestVaultACMEIntegration(t *testing.T) {
	config := setupIntegrationTest(t)
	defer cleanupIntegrationTest(config)
	
	// Setup Vault PKI
	setupVaultPKI(t, config)
	
	// Create test certificates and keys
	caPEM, raPEM, caKeyPEM, raKeyPEM, err := generateTestCAAndRA()
	if err != nil {
		t.Fatalf("Failed to generate test CA and RA: %v", err)
	}
	
	acmeKeyPEM, err := generateTestACMEKey()
	if err != nil {
		t.Fatalf("Failed to generate ACME key: %v", err)
	}
	
	// Write test files
	certFile := filepath.Join(config.TempDir, "cert.pem")
	keyFile := filepath.Join(config.TempDir, "key.pem")
	acmeKeyFile := filepath.Join(config.TempDir, "acme.key")
	whitelistFile := filepath.Join(config.TempDir, "whitelist.yaml")
	
	// Write combined certificate (RA + CA)
	combinedCert := append(raPEM, caPEM...)
	if err := ioutil.WriteFile(certFile, combinedCert, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	
	if err := ioutil.WriteFile(keyFile, raKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	
	if err := ioutil.WriteFile(acmeKeyFile, acmeKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write ACME key file: %v", err)
	}
	
	whitelistContent := `testpass: test.example.com`
	if err := ioutil.WriteFile(whitelistFile, []byte(whitelistContent), 0644); err != nil {
		t.Fatalf("Failed to write whitelist file: %v", err)
	}
	
	// Test ACME directory access
	vaultACMEURL := config.VaultURL + "/v1/pki/acme/directory"
	if err := testACMEDirectory(vaultACMEURL); err != nil {
		t.Fatalf("Failed to access Vault ACME directory: %v", err)
	}
	
	t.Logf("Successfully tested Vault ACME integration")
}

// TestOpenBaoACMEIntegration tests SCEP2ACME with OpenBao PKI backend
func TestOpenBaoACMEIntegration(t *testing.T) {
	config := setupIntegrationTest(t)
	defer cleanupIntegrationTest(config)
	
	// Setup OpenBao PKI
	setupOpenBaoPKI(t, config)
	
	// Test ACME directory access
	openBaoACMEURL := config.OpenBaoURL + "/v1/pki/acme/directory"
	if err := testACMEDirectory(openBaoACMEURL); err != nil {
		t.Fatalf("Failed to access OpenBao ACME directory: %v", err)
	}
	
	t.Logf("Successfully tested OpenBao ACME integration")
}

// testACMEDirectory tests access to ACME directory
func testACMEDirectory(url string) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	// Parse ACME directory response
	var directory map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&directory); err != nil {
		return err
	}
	
	// Check for required ACME directory fields
	requiredFields := []string{"newNonce", "newAccount", "newOrder", "keyChange", "revokeCert"}
	for _, field := range requiredFields {
		if _, exists := directory[field]; !exists {
			return fmt.Errorf("missing required ACME directory field: %s", field)
		}
	}
	
	return nil
}

// TestSCEPWorkflowWithVault tests the full SCEP workflow with Vault backend
func TestSCEPWorkflowWithVault(t *testing.T) {
	config := setupIntegrationTest(t)
	defer cleanupIntegrationTest(config)
	
	// Setup Vault PKI
	setupVaultPKI(t, config)
	
	// This test would involve:
	// 1. Starting the SCEP2ACME server with Vault ACME backend
	// 2. Creating a SCEP client
	// 3. Performing SCEP enrollment
	// 4. Verifying the certificate was issued by Vault
	
	// For now, we'll test the component integration
	t.Logf("SCEP workflow with Vault test placeholder - full implementation requires SCEP client")
}

// TestSCEPWorkflowWithOpenBao tests the full SCEP workflow with OpenBao backend
func TestSCEPWorkflowWithOpenBao(t *testing.T) {
	config := setupIntegrationTest(t)
	defer cleanupIntegrationTest(config)
	
	// Setup OpenBao PKI
	setupOpenBaoPKI(t, config)
	
	// This test would involve:
	// 1. Starting the SCEP2ACME server with OpenBao ACME backend
	// 2. Creating a SCEP client
	// 3. Performing SCEP enrollment
	// 4. Verifying the certificate was issued by OpenBao
	
	// For now, we'll test the component integration
	t.Logf("SCEP workflow with OpenBao test placeholder - full implementation requires SCEP client")
}

// TestCSRCreation tests creating CSRs for SCEP enrollment
func TestCSRCreation(t *testing.T) {
	// Generate a private key for the CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	
	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Organization"},
		},
		DNSNames: []string{"test.example.com"},
	}
	
	// Create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}
	
	// Verify CSR can be parsed
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}
	
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN=test.example.com, got %s", csr.Subject.CommonName)
	}
	
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "test.example.com" {
		t.Errorf("Expected DNSNames=[test.example.com], got %v", csr.DNSNames)
	}
}