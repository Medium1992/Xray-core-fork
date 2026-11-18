package tls

import (
	"net"

	utls "github.com/refraction-networking/utls"
)

// UClientOption changes the ClientHello that NewUClient builds.
type UClientOption func(*uClientOptions)

type uClientOptions struct {
	spec *utls.ClientHelloSpec
}

// WithClientHelloSpec builds the ClientHello from spec instead of the
// fingerprint's own: the hello a browser sends when it resumes.
func WithClientHelloSpec(spec *utls.ClientHelloSpec) UClientOption {
	return func(options *uClientOptions) {
		options.spec = spec
	}
}

// NewUClient returns a uTLS client for c whose ClientHello is built: the
// fingerprint, or the spec an option gives, is applied, and the randomized
// presets get the key shares FixRandomizedHello leaves them. REALITY seals
// its session ID into this hello before the handshake sends it. The client
// works on a copy of config, which uTLS would otherwise change while building
// the hello. When NewUClient fails the caller still owns c.
func NewUClient(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID, options ...UClientOption) (*utls.UConn, error) {
	var settings uClientOptions
	for _, option := range options {
		option(&settings)
	}
	config = config.Clone()
	var uConn *utls.UConn
	if settings.spec != nil {
		uConn = utls.UClient(c, config, utls.HelloCustom)
		if err := uConn.ApplyPreset(settings.spec); err != nil {
			return nil, err
		}
	} else {
		uConn = utls.UClient(c, config, fingerprint)
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if err := FixRandomizedHello(uConn); err != nil {
		return nil, err
	}
	return uConn, nil
}
