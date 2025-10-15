package caddytls

import (
	"crypto/x509"
	"os"
	"strconv"
	"time"

	"github.com/admpub/caddy"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

var issuerParsers = make(map[string]func(*caddy.Controller, *Config) error)

func RegisterIssuerParser(name string, issuer func(*caddy.Controller, *Config) error) {
	issuerParsers[name] = issuer
	caddy.RegisterPlugin("tls.issuer."+name, caddy.Plugin{})
}

func init() {
	RegisterIssuerParser("acme", issuerParserACME)
	RegisterIssuerParser("zerossl", issuerParserZeroSSL)
}

func issuerParserACME(c *caddy.Controller, config *Config) error {
	args := c.RemainingArgs()
	var argCAURL string
	if len(args) > 0 {
		argCAURL = args[0]
	}
	if len(argCAURL) > 0 {
		config.setIssuerCA(argCAURL)
	}
	dnsSolver := &certmagic.DNS01Solver{}
	var err error
	// check the configuration block for options { key ..., secret ..., region ... }
	for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
		switch c.Val() {
		case "dir":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.setIssuerCA(arg[0])
		case "test_dir":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.TestCA = arg[0]
		case "email":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.Email = arg[0]
		case "timeout":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.CertObtainTimeout, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "disable_http_challenge":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.DisableHTTPChallenge, err = strconv.ParseBool(arg[0])
			if err != nil {
				return err
			}
		case "disable_tlsalpn_challenge":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.DisableTLSALPNChallenge, err = strconv.ParseBool(arg[0])
			if err != nil {
				return err
			}
		case "trusted_roots":
			arg := c.RemainingArgs()
			if len(arg) < 1 {
				return c.ArgErr()
			}
			certPool := x509.NewCertPool()
			for _, certFile := range arg {
				var certBytes []byte
				certBytes, err = os.ReadFile(certFile)
				if err != nil {
					return err
				}
				var cert *x509.Certificate
				cert, err = x509.ParseCertificate(certBytes)
				if err != nil {
					return err
				}
				certPool.AddCert(cert)
			}
			config.Issuer.TrustedRoots = certPool
		case "dns_challenge_override_domain":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsSolver.OverrideDomain = arg[0]
		case "preferred_chains":
			arg := c.RemainingArgs()
			if len(arg) > 0 {
				smallest, _ := strconv.ParseBool(arg[0])
				config.Issuer.PreferredChains.Smallest = &smallest
			}
			for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
				switch c.Val() {
				case "root_common_name":
					arg := c.RemainingArgs()
					if len(arg) < 1 {
						return c.ArgErr()
					}
					config.Issuer.PreferredChains.RootCommonName = arg
				case "any_common_name":
					arg := c.RemainingArgs()
					if len(arg) < 1 {
						return c.ArgErr()
					}
					config.Issuer.PreferredChains.AnyCommonName = arg
				}
			}
		case "eab": // External Account Binding: eab <key_id> <mac_key>
			arg := c.RemainingArgs()
			if len(arg) != 2 {
				return c.ArgErr()
			}
			eab := &acme.EAB{
				KeyID:  arg[0],
				MACKey: arg[1],
			}
			config.Issuer.ExternalAccount = eab
		case "alt_http_port":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.AltHTTPPort, err = strconv.Atoi(arg[0])
			if err != nil {
				return err
			}
		case "alt_tlsalpn_port":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			config.Issuer.AltTLSALPNPort, err = strconv.Atoi(arg[0])
			if err != nil {
				return err
			}
		case "propagation_delay":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsSolver.PropagationDelay, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "propagation_timeout":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsSolver.PropagationTimeout, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "dns_ttl":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsSolver.TTL, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "resolvers":
			arg := c.RemainingArgs()
			if len(arg) < 1 {
				return c.ArgErr()
			}
			dnsSolver.Resolvers = arg
		case "dns":
			if !c.NextArg() {
				return c.ArgErr()
			}
			dnsProvName := c.Val()
			dnsProvConstructor, ok := dnsProviders[dnsProvName]
			if !ok {
				return c.Errf("Unknown DNS provider by name '%s'", dnsProvName)
			}
			dnsProv, err := dnsProvConstructor(c)
			if err != nil {
				return c.Errf("Setting up DNS provider '%s': %v", dnsProvName, err)
			}
			dnsSolver.DNSProvider = dnsProv
		}
	}
	if dnsSolver.DNSProvider != nil {
		config.Issuer.DNS01Solver = dnsSolver
	}
	if len(config.Manager.Issuers) == 0 {
		config.Manager.Issuers = []certmagic.Issuer{config.Issuer}
	}
	return nil
}

func issuerParserZeroSSL(c *caddy.Controller, config *Config) error {
	args := c.RemainingArgs()
	var argCAToken string
	if len(args) > 0 {
		argCAToken = args[0]
	}
	issuer := &certmagic.ZeroSSLIssuer{
		APIKey: os.Getenv(`ZEROSSL_API_KEY`),
		Logger: config.Manager.Logger,
	}
	if len(issuer.APIKey) == 0 && len(argCAToken) > 1 {
		issuer.APIKey = argCAToken
	}
	if len(issuer.APIKey) == 0 {
		return c.Err("ZeroSSL API key is required but not set. You can use the environment variable ZEROSSL_API_KEY to set this value.")
	}
	dnsManager := &certmagic.DNSManager{}
	var err error
	// check the configuration block for options { key ..., secret ..., region ... }
	for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
		switch c.Val() {
		case "validity_days":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			issuer.ValidityDays, err = strconv.Atoi(arg[0])
			if err != nil {
				return err
			}
		case "alt_http_port":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			issuer.AltHTTPPort, err = strconv.Atoi(arg[0])
			if err != nil {
				return err
			}
		case "propagation_delay":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsManager.PropagationDelay, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "propagation_timeout":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsManager.PropagationTimeout, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "dns_ttl":
			arg := c.RemainingArgs()
			if len(arg) != 1 {
				return c.ArgErr()
			}
			dnsManager.TTL, err = time.ParseDuration(arg[0])
			if err != nil {
				return err
			}
		case "resolvers":
			arg := c.RemainingArgs()
			if len(arg) < 1 {
				return c.ArgErr()
			}
			dnsManager.Resolvers = arg
		case "dns":
			if !c.NextArg() {
				return c.ArgErr()
			}
			dnsProvName := c.Val()
			dnsProvConstructor, ok := dnsProviders[dnsProvName]
			if !ok {
				return c.Errf("Unknown DNS provider by name '%s'", dnsProvName)
			}
			dnsProv, err := dnsProvConstructor(c)
			if err != nil {
				return c.Errf("Setting up DNS provider '%s': %v", dnsProvName, err)
			}
			dnsManager.DNSProvider = dnsProv
		}
	}
	if dnsManager.DNSProvider != nil {
		issuer.CNAMEValidation = dnsManager
	}
	if len(config.Manager.Issuers) > 0 {
		config.Manager.Issuers[0] = issuer
	} else {
		config.Manager.Issuers = []certmagic.Issuer{issuer}
	}
	return nil
}
