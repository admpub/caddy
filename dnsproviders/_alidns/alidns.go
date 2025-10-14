package alidns

import (
	"errors"
	"os"

	"github.com/admpub/caddy"
	"github.com/admpub/caddy/caddytls"
	"github.com/admpub/caddy/dnsproviders"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
)

const (
	envNamespace = "ALIDNS_"

	EnvKeyID     = envNamespace + "KEY_ID"
	EnvKeySecret = envNamespace + "KEY_SECRET"
	EnvRegionID  = envNamespace + "REGION_ID"
)

func init() {
	caddytls.RegisterDNSProvider("alidns", NewDNSProvider)
	dnsproviders.RegisterInputs("alidns", `阿里DNS`, inputs)
}

var inputs = []dnsproviders.Input{
	{
		Type:        "text",
		Name:        "key",
		Label:       "Access Key Id",
		Placeholder: "",
		Help:        "",
		Required:    true,
		Pattern:     "[a-zA-Z0-9_-]+",
	},
	{
		Type:        "password",
		Name:        "secret",
		Label:       "Access Key Secret",
		Placeholder: "",
		Help:        "",
		Required:    true,
		Pattern:     "[a-zA-Z0-9_-]+",
	},
	{
		Type:        "text",
		Name:        "region",
		Label:       "Region Id",
		Placeholder: "",
		Help:        "",
		Pattern:     "[a-zA-Z0-9_-]*",
	},
}

// NewDNSProvider returns a new ALIDNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment or configuration block
// len(3): credentials[0] = key
// ------- credentials[1] = secret
// ------- credentials[2] = region
func NewDNSProvider(c *caddy.Controller) (certmagic.DNSProvider, error) {
	provider := &alidns.Provider{
		AccKeyID:     os.Getenv(EnvKeyID),
		AccKeySecret: os.Getenv(EnvKeySecret),
		RegionID:     os.Getenv(EnvRegionID),
	}

	credentials := c.RemainingArgs()

	switch len(credentials) {
	case 0:
		// check the configuration block for options { key ..., secret ..., region ... }
		for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
			switch c.Val() {
			case "key", "key_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.AccKeyID = c.Val()
			case "secret", "key_secret":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.AccKeySecret = c.Val()
			case "region", "region_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.RegionID = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	case 3:
		provider.RegionID = credentials[2]
		fallthrough
	case 2:
		provider.AccKeyID = credentials[0]
		provider.AccKeySecret = credentials[1]
	default:
		return nil, errors.New("invalid credentials length")
	}

	if provider.AccKeySecret == "" || provider.AccKeyID == "" {
		return nil, errors.New("missing ALIDNS key configuration")
	}

	return provider, nil
}
