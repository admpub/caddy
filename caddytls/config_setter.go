package caddytls

import "github.com/caddyserver/certmagic"

func (c *Config) setIssuerCA(ca string) {
	c.Issuer.CA = ca
	switch c.Issuer.CA {
	case certmagic.LetsEncryptProductionCA:
		c.Issuer.TestCA = certmagic.LetsEncryptStagingCA
	case certmagic.GoogleTrustProductionCA:
		c.Issuer.TestCA = certmagic.GoogleTrustStagingCA
	default:
		c.Issuer.TestCA = ``
	}
}
