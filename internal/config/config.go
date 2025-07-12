package config

import (
	"flag"
	"fmt"
	"reflect"

	"github.com/go-acme/lego/v4/lego"
)

// Config holds all configuration for the scep2acme application
type Config struct {
	ListenPort    string
	CertPath      string
	CertKeyPath   string
	ACMEKeyPath   string
	ACMEEmail     string
	ACMEURL       string
	WhitelistPath string
	DNSProvider   string
	Debug         bool
}

// ParseFlags parses command line flags and returns a Config
func ParseFlags() *Config {
	var (
		listenPort    = flag.String("listen", "127.0.0.1:8383", "Listen IP and port")
		certPath      = flag.String("cert", "", "Path to certificate file - should include 2 certificates (RA & CA). RA certificate should be signed by CA.")
		certKeyPath   = flag.String("certkey", "", "Path to certificate key")
		acmeKeyPath   = flag.String("acmekey", "", "Path to ACME account key")
		acmeEmail     = flag.String("acmeemail", "", "ACME account email address - Terms of Service will be accepted automatically")
		acmeURL       = flag.String("acmeurl", lego.LEDirectoryStaging, fmt.Sprintf("ACME directory URL (default is the Let's Encrypt staging directory, to switch to production directory use \"%v\")", lego.LEDirectoryProduction))
		whitelistPath = flag.String("whitelist", "", "Path to hostname whitelist configuration")
		dnsProvider   = flag.String("dnsprovider", "", "DNS provider used for DNS-01 challenges - environment variables should be used for configuration, docs at https://go-acme.github.io/lego/dns/")
		debug         = flag.Bool("debug", false, "Enable debug logging")
	)

	flag.Parse()

	cfg := &Config{
		ListenPort:    *listenPort,
		CertPath:      *certPath,
		CertKeyPath:   *certKeyPath,
		ACMEKeyPath:   *acmeKeyPath,
		ACMEEmail:     *acmeEmail,
		ACMEURL:       *acmeURL,
		WhitelistPath: *whitelistPath,
		DNSProvider:   *dnsProvider,
		Debug:         *debug,
	}

	return cfg
}

// Validate validates the configuration and panics if any mandatory fields are missing
func (c *Config) Validate() {
	c.mandatoryFlag("cert", c.CertPath)
	c.mandatoryFlag("certkey", c.CertKeyPath)
	c.mandatoryFlag("acmeemail", c.ACMEEmail)
	c.mandatoryFlag("acmekey", c.ACMEKeyPath)
	c.mandatoryFlag("dnsprovider", c.DNSProvider)
	c.mandatoryFlag("whitelist", c.WhitelistPath)
}

func (c *Config) mandatoryFlag(name string, value interface{}) {
	if reflect.Indirect(reflect.ValueOf(value)).IsZero() {
		panic(fmt.Sprintf("-%v is mandatory, use -help for help", name))
	}
}
