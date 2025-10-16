package edgeone

import (
	"errors"
	"os"

	"github.com/admpub/caddy"
	"github.com/admpub/caddy/caddytls"
	"github.com/admpub/caddy/dnsproviders"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/edgeone"
)

const (
	envNamespace = "TENCENTCLOUD_" // egeone的配置和tencentcloud的一致

	EnvSecretID     = envNamespace + "SECRET_ID"
	EnvSecretKey    = envNamespace + "SECRET_KEY"
	EnvRegion       = envNamespace + "REGION"
	EnvSessionToken = envNamespace + "SESSION_TOKEN"
)

func init() {
	caddytls.RegisterDNSProvider("edgeone", NewDNSProvider)
	dnsproviders.RegisterInputs("edgeone", `EgeOne`, inputs)
}

var inputs = []dnsproviders.Input{
	{
		Type:        "text",
		Name:        "secret_id",
		Label:       "Secret Id",
		Placeholder: "",
		Help:        "",
		Required:    true,
		Pattern:     "[a-zA-Z0-9_-]+",
	},
	{
		Type:        "password",
		Name:        "secret_key",
		Label:       "Secret Key",
		Placeholder: "",
		Help:        "",
		Required:    true,
		Pattern:     "[a-zA-Z0-9_-]+",
	},
	{
		Type:        "text",
		Name:        "region",
		Label:       "Region",
		Placeholder: "",
		Help:        "",
		Pattern:     "[a-zA-Z0-9_-]*",
	},
	{
		Type:        "text",
		Name:        "session_token",
		Label:       "Session Token",
		Placeholder: "",
		Help:        "",
	},
}

// NewDNSProvider returns a new TENCENTCLOUD DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment or configuration block
// len(4): credentials[0] = secret_id
// ------- credentials[1] = secret_key
// ------- credentials[2] = region
// ------- credentials[3] = session_token
func NewDNSProvider(c *caddy.Controller) (certmagic.DNSProvider, error) {
	provider := &edgeone.Provider{
		SecretId:     os.Getenv(EnvSecretID),
		SecretKey:    os.Getenv(EnvSecretKey),
		Region:       os.Getenv(EnvRegion),
		SessionToken: os.Getenv(EnvSessionToken),
	}

	credentials := c.RemainingArgs()

	switch len(credentials) {
	case 0:
		// check the configuration block for options { key ..., secret ..., region ... }
		for nesting := c.Nesting(); c.NextBlockNesting(nesting); {
			switch c.Val() {
			case "secret_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.SecretId = c.Val()
			case "secret_key":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.SecretKey = c.Val()
			case "region":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.Region = c.Val()
			case "session_token":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				provider.SessionToken = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	case 4:
		provider.SessionToken = credentials[3]
		fallthrough
	case 3:
		provider.Region = credentials[2]
		fallthrough
	case 2:
		provider.SecretId = credentials[0]
		provider.SecretKey = credentials[1]
	default:
		return nil, errors.New("invalid credentials length")
	}

	if provider.SecretId == "" || provider.SecretKey == "" {
		return nil, errors.New("missing EgeOne DNS key configuration")
	}

	return provider, nil
}
