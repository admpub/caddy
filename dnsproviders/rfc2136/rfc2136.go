package rfc2136

import (
	"errors"
	"os"

	"github.com/admpub/caddy"
	"github.com/admpub/caddy/caddytls"
	"github.com/admpub/caddy/dnsproviders"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/rfc2136"
)

const (
	envNamespace = "RFC2136_"

	EnvTSIGKey       = envNamespace + "TSIG_KEY"
	EnvTSIGSecret    = envNamespace + "TSIG_SECRET"
	EnvTSIGAlgorithm = envNamespace + "TSIG_ALGORITHM"
	EnvNameserver    = envNamespace + "NAMESERVER"
)

func init() {
	caddytls.RegisterDNSProvider("rfc2136", NewDNSProvider)
	dnsproviders.RegisterInputs("rfc2136", `RFC2136`, inputs)
}

var inputs = []dnsproviders.Input{
	{
		Type:        "text",
		Name:        "nameserver",
		Label:       "Nameserver",
		Placeholder: "",
		Help:        "The nameserver to use for RFC2136.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "text",
		Name:        "algorithm",
		Label:       "TSIG Algorithm",
		Placeholder: "",
		Help:        "The TSIG algorithm to use for RFC2136.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "text",
		Name:        "key",
		Label:       "TSIG Key",
		Placeholder: "",
		Help:        "The TSIG key to use for RFC2136.",
		Required:    false,
		Pattern:     "",
	},
	{
		Type:        "password",
		Name:        "secret",
		Label:       "TSIG Secret",
		Placeholder: "",
		Help:        "The TSIG secret to use for RFC2136.",
		Required:    false,
		Pattern:     "",
	},
}

// NewDNSProvider returns a new RFC 2136 DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment or configuration block
// len(4): credentials[0] = nameserver
// ------- credentials[1] = TSIG algorithm
// ------- credentials[2] = TSIG key
// ------- credentials[3] = TSIG secret
func NewDNSProvider(c *caddy.Controller) (certmagic.DNSProvider, error) {
	provider := &rfc2136.Provider{
		KeyName: os.Getenv(EnvTSIGKey),
		Key:     os.Getenv(EnvTSIGSecret),
		KeyAlg:  os.Getenv(EnvTSIGAlgorithm),
		Server:  os.Getenv(EnvNameserver),
	}

	credentials := c.RemainingArgs()

	switch len(credentials) {
	case 0:
		// check the configuration block for options { key ..., secret ..., algorithm ..., nameserver ... }
		for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
			switch c.Val() {
			case "key":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.KeyName = c.Val()
			case "secret":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.Key = c.Val()
			case "algorithm":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.KeyAlg = c.Val()
			case "nameserver":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.Server = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	case 4:
		provider.Server = credentials[0]
		provider.KeyAlg = credentials[1]
		provider.KeyName = credentials[2]
		provider.Key = credentials[3]
	default:
		return nil, errors.New("invalid credentials length")
	}

	if provider.Server == "" {
		return nil, errors.New("missing nameserver")
	}

	if provider.KeyName == "" || provider.Key == "" || provider.KeyAlg == "" {
		return nil, errors.New("missing TSIG key configuration")
	}

	return provider, nil
}
