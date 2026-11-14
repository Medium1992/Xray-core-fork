package tls

import (
	gotls "crypto/tls"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Whatever seed a process draws, the "randomized" presets offer
// X25519MLKEM768 together with its key share, and send no P-256 key share:
// REALITY turns away a hello without the hybrid key share, and a hybrid key
// share without its group breaks RFC 8446, Section 4.2.8.
func TestRandomizedPresetsAlwaysSendTheHybridKeyShare(t *testing.T) {
	for _, base := range []utls.ClientHelloID{utls.HelloRandomizedALPN, utls.HelloRandomizedNoALPN} {
		var noGroup, noShare, p256 int
		const seeds = 400
		for range seeds {
			id := base
			id.Seed, _ = utls.NewPRNGSeed()
			id.Weights = &randomizedWeights
			client, server := net.Pipe()
			server.Close()
			uConn := UClient(client, &gotls.Config{ServerName: "example.com"}, &id).(*UConn)
			if err := uConn.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			group, share := false, false
			for _, extension := range uConn.Extensions {
				switch e := extension.(type) {
				case *utls.SupportedCurvesExtension:
					for _, curve := range e.Curves {
						if curve == utls.X25519MLKEM768 {
							group = true
						}
					}
				case *utls.KeyShareExtension:
					for _, ks := range e.KeyShares {
						switch ks.Group {
						case utls.X25519MLKEM768:
							share = true
						case utls.CurveP256:
							p256++
						}
					}
				}
			}
			if !group {
				noGroup++
			}
			if !share {
				noShare++
			}
			client.Close()
		}
		if noGroup+noShare+p256 != 0 {
			t.Errorf("%s: of %d seeds, %d offer no X25519MLKEM768, %d send no X25519MLKEM768 key share, %d send a P-256 key share",
				base.Client, seeds, noGroup, noShare, p256)
		}
	}
}
