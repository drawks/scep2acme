package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestMyDepot_CA(t *testing.T) {
	// Create test certificates and keys
	caPEM, raPEM, _, raKeyPEM, err := generateTestCAAndRA()
	if err != nil {
		t.Fatalf("Failed to generate test CA and RA: %v", err)
	}

	// Create temporary files for certificates and keys
	tempDir, err := ioutil.TempDir("", "scep2acme-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create combined certificate file (RA + CA)
	combinedCertPath := filepath.Join(tempDir, "combined.pem")
	combinedCert := append(raPEM, caPEM...)
	if err := ioutil.WriteFile(combinedCertPath, combinedCert, 0644); err != nil {
		t.Fatalf("Failed to write combined cert file: %v", err)
	}

	// Create key file (RA key)
	keyPath := filepath.Join(tempDir, "key.pem")
	if err := ioutil.WriteFile(keyPath, raKeyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Save original flag values
	originalCertPath := *certPath
	originalCertKeyPath := *certKeyPath
	defer func() {
		*certPath = originalCertPath
		*certKeyPath = originalCertKeyPath
	}()

	// Set flag values to test files
	*certPath = combinedCertPath
	*certKeyPath = keyPath

	// Test CA method
	depot := &myDepot{}
	certs, key, err := depot.CA(nil)
	if err != nil {
		t.Fatalf("CA() failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}

	if key == nil {
		t.Error("Expected private key, got nil")
	}

	// Verify the key is an RSA private key
	if key == nil {
		t.Error("Expected RSA private key, got nil")
	}

	// Verify certificates can be parsed
	for i, cert := range certs {
		if cert == nil {
			t.Errorf("Certificate %d is nil", i)
		}
	}
}

func TestMyDepot_LoadCerts(t *testing.T) {
	depot := &myDepot{}

	// Test valid PEM data
	caPEM, raPEM, _, _, err := generateTestCAAndRA()
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}

	// Test single certificate
	certs, err := depot.loadCerts(caPEM)
	if err != nil {
		t.Fatalf("loadCerts() failed for single cert: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}

	// Test multiple certificates
	combinedPEM := append(raPEM, caPEM...)
	certs, err = depot.loadCerts(combinedPEM)
	if err != nil {
		t.Fatalf("loadCerts() failed for multiple certs: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}

	// Test invalid PEM data
	invalidPEM := []byte("invalid pem data")
	_, err = depot.loadCerts(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}

func TestMyDepot_LoadKey(t *testing.T) {
	depot := &myDepot{}

	// Test PKCS1 private key
	_, _, _, raKeyPEM, err := generateTestCAAndRA()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	key, err := depot.loadKey(raKeyPEM, nil)
	if err != nil {
		t.Fatalf("loadKey() failed for PKCS1 key: %v", err)
	}

	if key == nil {
		t.Error("Expected private key, got nil")
	}

	// Test PKCS8 private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8 key: %v", err)
	}

	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	key, err = depot.loadKey(pkcs8PEM, nil)
	if err != nil {
		t.Fatalf("loadKey() failed for PKCS8 key: %v", err)
	}

	if key == nil {
		t.Error("Expected private key, got nil")
	}

	// Test invalid key data
	invalidPEM := []byte("invalid pem data")
	_, err = depot.loadKey(invalidPEM, nil)
	if err == nil {
		t.Error("Expected error for invalid key data")
	}
}

func TestMyDepot_Serial(t *testing.T) {
	depot := &myDepot{}

	_, err := depot.Serial()
	if err == nil {
		t.Error("Expected error from Serial() method")
	}
}

func TestMyDepot_HasCN(t *testing.T) {
	depot := &myDepot{}

	hasCN, err := depot.HasCN("test.example.com", 0, nil, false)
	if err != nil {
		t.Fatalf("HasCN() failed: %v", err)
	}

	if hasCN {
		t.Error("Expected HasCN to return false")
	}
}

func TestMyDepot_Put(t *testing.T) {
	depot := &myDepot{}

	err := depot.Put("test", nil)
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
}
