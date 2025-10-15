package caddytls

import (
	"os"
	"strconv"
	"time"

	"github.com/admpub/caddy"
	"github.com/caddyserver/certmagic"
)

var issuerParsers = make(map[string]func(*caddy.Controller, *Config) error)

func RegisterIssuerParser(name string, issuer func(*caddy.Controller, *Config) error) {
	issuerParsers[name] = issuer
	caddy.RegisterPlugin("tls.issuer."+name, caddy.Plugin{})
}

func init() {
	//RegisterIssuerParser("acme", issuerParserACME)
	RegisterIssuerParser("zerossl", issuerParserZeroSSL)
}

// func issuerParserACME(c *caddy.Controller, config *Config) error {
// 	return nil
// }

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
