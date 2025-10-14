package dnspod

import (
	"errors"
	"os"

	"github.com/admpub/caddy"
	"github.com/admpub/caddy/caddytls"
	"github.com/admpub/caddy/dnsproviders"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/dnspod"
)

const (
	envNamespace = "DNSPOD_"

	EnvAPIKey = envNamespace + "API_TOKEN"
)

func init() {
	caddytls.RegisterDNSProvider("dnspod", NewDNSProvider)
	dnsproviders.RegisterInputs("dnspod", inputs)
}

var inputs = []dnsproviders.Input{
	{
		Type:        "text",
		Name:        "token",
		Label:       "API Token",
		Placeholder: "",
		Help:        "API token for DNSPOD API",
		Required:    true,
		Pattern:     "[a-zA-Z0-9_-]+",
	},
}

// NewDNSProvider returns a new dnspod DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment
// len(1): credentials[0] = access token (API key)
func NewDNSProvider(c *caddy.Controller) (certmagic.DNSProvider, error) {
	provider := &dnspod.Provider{
		APIToken: os.Getenv(EnvAPIKey),
	}

	credentials := c.RemainingArgs()

	switch len(credentials) {
	case 0:
		// Try to get credentials from the block (`{ key ... }`)
		for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
			switch c.Val() {
			case "token":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.APIToken = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	case 1:
		provider.APIToken = credentials[0]
	default:
		return nil, errors.New("invalid credentials length")
	}

	if provider.APIToken == "" {
		return nil, errors.New("dnspod: missing credentials")
	}

	return provider, nil
}
