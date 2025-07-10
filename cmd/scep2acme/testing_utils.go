package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// generateTestCertAndKey generates a test certificate and private key for testing
func generateTestCertAndKey() (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Test City"},
			StreetAddress: []string{"Test Street"},
			PostalCode:    []string{"12345"},
			CommonName:    "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"test.example.com", "*.test.example.com"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDER})

	return certPEM, keyPEM, nil
}

// generateTestCAAndRA generates a test CA certificate and RA certificate signed by CA
func generateTestCAAndRA() (caPEM, raPEM, caKeyPEM, raKeyPEM []byte, err error) {
	// Generate CA private key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Test City"},
			CommonName:    "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Generate RA private key
	raPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create RA certificate template
	raTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test RA Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Test City"},
			CommonName:    "Test RA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Parse CA certificate for signing RA
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create RA certificate signed by CA
	raCertDER, err := x509.CreateCertificate(rand.Reader, &raTemplate, caCert, &raPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Encode certificates to PEM
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	raPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raCertDER})

	// Encode private keys to PEM
	caPrivateKeyDER := x509.MarshalPKCS1PrivateKey(caPrivateKey)
	caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: caPrivateKeyDER})

	raPrivateKeyDER := x509.MarshalPKCS1PrivateKey(raPrivateKey)
	raKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: raPrivateKeyDER})

	return caPEM, raPEM, caKeyPEM, raKeyPEM, nil
}

// generateTestACMEKey generates a test ACME account key
func generateTestACMEKey() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDER})

	return keyPEM, nil
}