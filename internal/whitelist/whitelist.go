package whitelist

import (
	"crypto/x509"
	"fmt"
	"os"
	"reflect"

	"github.com/micromdm/scep/crypto/x509util"
	"github.com/micromdm/scep/csrverifier"
	"gopkg.in/yaml.v2"
)

// HostnameMatcher is a function that checks if a hostname matches a pattern
type HostnameMatcher func(hostname string) bool

// CSRPasswordVerifier verifies CSRs based on password-hostname mapping
type CSRPasswordVerifier struct {
	passwordMatchers map[string][]HostnameMatcher
}

// allowedDNSName checks if a DNS name is allowed for the given password
func (c *CSRPasswordVerifier) allowedDNSName(password string, dnsName string) bool {
	for _, matcher := range c.passwordMatchers[password] {
		if matcher(dnsName) {
			return true
		}
	}
	return false
}

// Verify implements the CSRVerifier interface
func (c *CSRPasswordVerifier) Verify(data []byte) (bool, error) {
	cp, err := x509util.ParseChallengePassword(data)
	if err != nil {
		return false, fmt.Errorf("scep: parse challenge password in pkiEnvelope: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return false, err
	}

	if !c.allowedDNSName(cp, csr.Subject.CommonName) {
		fmt.Printf("Subject CN not allowed: %v\n", csr.Subject.CommonName)
		return false, nil
	}

	for _, name := range csr.DNSNames {
		if !c.allowedDNSName(cp, name) {
			fmt.Printf("SAN not allowed: %v\n", name)
			return false, nil
		}
	}

	fmt.Printf("CSR passed verification: %+v\n", csr)

	return true, nil
}

// hostnameExactMatcher creates a matcher that checks for exact hostname matches
func hostnameExactMatcher(name string) HostnameMatcher {
	return func(hostname string) bool {
		return name == hostname
	}
}

// NewCSRPasswordVerifier creates a new CSRPasswordVerifier from a YAML file
func NewCSRPasswordVerifier(yamlPath string) (csrverifier.CSRVerifier, error) {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var mapping map[string]interface{}
	err = yaml.Unmarshal(data, &mapping)
	if err != nil {
		return nil, fmt.Errorf("parsing file: %w", err)
	}

	c := &CSRPasswordVerifier{
		passwordMatchers: map[string][]HostnameMatcher{},
	}

	for pass, value := range mapping {
		items := []interface{}{value}

		if v, ok := value.([]interface{}); ok {
			items = v
		}

		for _, item := range items {
			switch v := item.(type) {
			case string:
				c.passwordMatchers[pass] = append(c.passwordMatchers[pass], hostnameExactMatcher(v))
			default:
				return nil, fmt.Errorf("unknown item: %v (type %v)", item, reflect.TypeOf(item))
			}
		}
	}

	return c, nil
}
