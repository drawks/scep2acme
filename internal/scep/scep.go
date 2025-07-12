package scep

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	scepserver "github.com/micromdm/scep/server"
)

// ServiceWithoutRenewal wraps a SCEP service and disables renewal capability
type ServiceWithoutRenewal struct {
	scepserver.Service
}

// GetCACaps returns CA capabilities without renewal support
func (s ServiceWithoutRenewal) GetCACaps(ctx context.Context) ([]byte, error) {
	capsBytes, err := s.Service.GetCACaps(ctx)
	if err != nil {
		return nil, err
	}

	newCaps := strings.ReplaceAll(" "+string(capsBytes)+" ", "\nRenewal\n", "\n")
	return []byte(newCaps[1 : len(newCaps)-1]), nil
}

// Depot implements the SCEP depot interface for certificate management
type Depot struct {
	certPath    string
	certKeyPath string
}

// NewDepot creates a new SCEP depot
func NewDepot(certPath, certKeyPath string) *Depot {
	return &Depot{
		certPath:    certPath,
		certKeyPath: certKeyPath,
	}
}

// CA returns the CA certificate chain and private key
func (d *Depot) CA(_ []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	caPEM, err := os.ReadFile(d.certPath)
	if err != nil {
		return nil, nil, err
	}
	certs, err := d.loadCerts(caPEM)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(d.certKeyPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := d.loadKey(keyPEM, nil)
	if err != nil {
		return nil, nil, err
	}

	return certs, key, nil
}

// loadKey loads a private key from PEM data
func (d *Depot) loadKey(data []byte, _ []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}

	if pemBlock.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	}

	ret, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := ret.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	return rsaKey, nil
}

// loadCerts loads certificates from PEM data
func (d *Depot) loadCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var pemBlock *pem.Block
		pemBlock, data = pem.Decode(data)
		if pemBlock == nil {
			if len(certs) == 0 {
				return nil, fmt.Errorf("PEM decode failed")
			}

			break
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing cert %v: %w", len(certs), err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// Serial returns a serial number for certificate generation (not used in this implementation)
func (d *Depot) Serial() (*big.Int, error) {
	return nil, fmt.Errorf("depot cannot create certificates")
}

// HasCN checks if a CN exists (not used in this implementation)
func (d *Depot) HasCN(_ string, _ int, _ *x509.Certificate, _ bool) (bool, error) {
	// TODO: does this matter?
	return false, nil
}

// Put stores a certificate (not used in this implementation)
func (d *Depot) Put(_ string, _ *x509.Certificate) error {
	return nil
}
