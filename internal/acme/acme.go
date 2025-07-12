package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/micromdm/scep/scep"
	scepserver "github.com/micromdm/scep/server"
)

// UserInfo holds ACME user information
type UserInfo struct {
	email        string
	keyPath      string
	registration *registration.Resource
}

// NewUserInfo creates a new UserInfo
func NewUserInfo(email, keyPath string) *UserInfo {
	return &UserInfo{
		email:   email,
		keyPath: keyPath,
	}
}

// GetEmail returns the ACME user email
func (u *UserInfo) GetEmail() string {
	return u.email
}

// GetRegistration returns the ACME registration
func (u *UserInfo) GetRegistration() *registration.Resource {
	return u.registration
}

// GetPrivateKey returns the ACME user private key
func (u *UserInfo) GetPrivateKey() crypto.PrivateKey {
	data, err := os.ReadFile(u.keyPath)
	if err != nil {
		panic(err)
	}

	keyData, _ := pem.Decode(data)
	if keyData == nil {
		panic("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyData.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

// Client wraps a lego ACME client
type Client struct {
	*lego.Client
}

// NewClient creates a new ACME client
func NewClient(email, keyPath, acmeURL, dnsProvider string) (*Client, error) {
	acmeUser := NewUserInfo(email, keyPath)
	acmeConfig := lego.NewConfig(acmeUser)
	acmeConfig.CADirURL = acmeURL

	client, err := lego.NewClient(acmeConfig)
	if err != nil {
		return nil, fmt.Errorf("creating acme client: %w", err)
	}

	provider, err := dns.NewDNSChallengeProviderByName(dnsProvider)
	if err != nil {
		return nil, fmt.Errorf("creating challenge provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, fmt.Errorf("setting challenge provider: %w", err)
	}

	acmeUser.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering acme account: %w", err)
	}

	return &Client{Client: client}, nil
}

// CertificateSource returns a SCEP certificate source that uses ACME to obtain certificates
func (c *Client) CertificateSource() scepserver.CertificateSource {
	return scepserver.CertificateSourceFunc(func(ctx context.Context, msg *scep.PKIMessage) (*x509.Certificate, error) {
		request := certificate.ObtainForCSRRequest{
			CSR:    msg.CSR,
			Bundle: false,
		}
		res, err := c.Certificate.ObtainForCSR(request)
		if err != nil {
			return nil, fmt.Errorf("ObtainForCSR: %w", err)
		}

		certBytes, _ := pem.Decode(res.Certificate)
		crt, err := x509.ParseCertificate(certBytes.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing obtained cert: %w", err)
		}

		return crt, nil
	})
}
