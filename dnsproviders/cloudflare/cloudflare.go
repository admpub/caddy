package cloudflare

import (
	"errors"
	"os"
	"strings"

	"github.com/admpub/caddy"
	"github.com/admpub/caddy/caddytls"
	"github.com/admpub/caddy/dnsproviders"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

const tokenErr = "cloudflare: email and API tokens are no longer supported in Caddy, please use Scoped Tokens only. " +
	"More info: https://pkg.go.dev/github.com/libdns/cloudflare#readme-authenticating"

func init() {
	caddytls.RegisterDNSProvider("cloudflare", NewDNSProvider)
	dnsproviders.RegisterInputs("cloudflare", `Cloudflare`, inputs)
}

var inputs = []dnsproviders.Input{
	{
		Type:        "text",
		Name:        "api_token",
		Label:       "API Token",
		Placeholder: "",
		Help:        "API token for Cloudflare API",
		Required:    true,
		Pattern:     "[a-zA-Z0-9_-]+",
	},
	{
		Type:        "text",
		Name:        "zone_token",
		Label:       "Zone Token",
		Placeholder: "",
		Help:        "Zone token for Cloudflare API",
	},
}

var envAPITokenNames = []string{
	"CLOUDFLARE_DNS_API_TOKEN",
	"CF_DNS_API_TOKEN",
	"CF_API_TOKEN",
}

var envZoneTokenNames = []string{
	"CLOUDFLARE_ZONE_API_TOKEN",
	"CF_ZONE_API_TOKEN",
	"CF_ZONE_TOKEN",
}

func getAPIToken() string {
	for _, envName := range envAPITokenNames {
		if v, ok := os.LookupEnv(envName); ok && len(v) > 0 {
			return v
		}
	}
	return ""
}

func getZoneToken() string {
	for _, envName := range envZoneTokenNames {
		if v, ok := os.LookupEnv(envName); ok && len(v) > 0 {
			return v
		}
	}
	return ""
}

// NewDNSProvider returns a new Cloudflare DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment, or block (`{ token ... }`)
// len(1): credentials[0] = Scoped API token
// len(2): credentials[0] = token type (must be "zonetoken")
// ------- credentials[1] = Scoped API token
func NewDNSProvider(c *caddy.Controller) (certmagic.DNSProvider, error) {
	provider := &cloudflare.Provider{
		APIToken:  getAPIToken(),
		ZoneToken: getZoneToken(),
	}

	credentials := c.RemainingArgs()

	switch len(credentials) {
	case 0:
		// Try to get credentials from environment variables.
		if len(provider.APIToken) == 0 {
			// Try to get credentials from the block (`{ token ... }`)
			for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
				switch c.Val() {
				case "api_token":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					provider.APIToken = c.Val()
				case "zone_token":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					provider.ZoneToken = c.Val()
				default:
					return nil, c.Errf("unknown property '%s'", c.Val())
				}
			}
		}
	case 1:
		provider.APIToken = credentials[0]
	case 2:
		if strings.Contains(credentials[0], "@") {
			return nil, errors.New(tokenErr)
		}

		switch credentials[0] {
		case "zonetoken":
			provider.APIToken = credentials[1]
		default:
			return nil, errors.New(tokenErr)
		}
	default:
		return nil, errors.New("invalid credentials length")
	}

	if provider.APIToken == "" {
		return nil, errors.New("cloudflare: missing credentials")
	}

	return provider, nil
}
