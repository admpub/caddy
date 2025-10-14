package acmedns

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/admpub/caddy"
	"github.com/admpub/caddy/caddytls"
	"github.com/admpub/caddy/dnsproviders"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/acmedns"
)

const (
	// envNamespace is the prefix for ACME-DNS environment variables.
	envNamespace = "ACME_DNS_"

	// EnvAPIBase is the environment variable name for the ACME-DNS API address.
	// (e.g. https://acmedns.your-domain.com).
	EnvAPIBase = envNamespace + "API_BASE"
	// EnvStoragePath is the environment variable name for the ACME-DNS JSON account data file.
	// A per-domain account will be registered/persisted to this file and used for TXT updates.
	EnvStoragePath = envNamespace + "STORAGE_PATH"
)

func init() {
	caddytls.RegisterDNSProvider("acmedns", NewDNSProvider)
	dnsproviders.RegisterInputs("acmedns", inputs)
}

var inputs = []dnsproviders.Input{
	{
		Type:        "text",
		Name:        "server_url",
		Label:       "Server URL",
		Placeholder: "https://acme-dns.example.com",
		Help:        "The ACME-DNS server URL.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "text",
		Name:        "storage",
		Label:       "Storage",
		Placeholder: "/path/to/storage.json",
		Help:        "The path to the ACME-DNS JSON account data file.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "text",
		Name:        "username",
		Label:       "Username",
		Placeholder: "",
		Help:        "The username to use for ACME-DNS.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "password",
		Name:        "password",
		Label:       "Password",
		Placeholder: "",
		Help:        "The password to use for ACME-DNS.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "text",
		Name:        "subdomain",
		Label:       "Subdomain",
		Placeholder: "",
		Help:        "The subdomain to use for ACME-DNS.",
		Required:    false,
		Pattern:     "",
	},
}

// NewDNSProvider returns a new acmedns DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment or block:
//
//	        tls dns acmedns {
//	            server_url <server_url>
//	            storage /path/to/storage.json
//	            username <username>
//	            password <password>
//		        subdomain <subdomain>
//	        }
func NewDNSProvider(c *caddy.Controller) (certmagic.DNSProvider, error) {
	credentials := c.RemainingArgs()

	switch len(credentials) {
	case 0:
		configPath := os.Getenv(EnvStoragePath)
		provider := &acmedns.Provider{
			// Try to get credentials from environment variables.
			ServerURL: os.Getenv(EnvAPIBase),
		}

		// Try to get credentials from the config block.
		for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
			switch c.Val() {
			case "server_url":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
			case "storage":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				configPath = c.Val()
			case "username":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.Username = c.Val()
			case "password":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.Password = c.Val()
			case "subdomain":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.Subdomain = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}

		if configPath != "" {
			provider.Configs = unmarshalAccountDataFile(configPath)
		}

		return provider, nil
	default:
		return nil, errors.New("invalid credentials length")
	}
}

func unmarshalAccountDataFile(path string) map[string]acmedns.DomainConfig {
	accounts := make(map[string]acmedns.DomainConfig)
	// Opportunistically try to load the account data. Return an empty account if
	// any errors occur.
	if jsonData, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(jsonData, &accounts); err != nil {
			return accounts
		}
	}
	return accounts
}
