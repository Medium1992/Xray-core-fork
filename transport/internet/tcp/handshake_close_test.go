package tcp_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	gonet "net"
	"runtime/debug"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// fakeServer accepts connections, takes the ClientHello and answers with
// reply, or nothing. It reports when the client closes a connection.
func fakeServer(t *testing.T, reply string) (net.Port, <-chan struct{}) {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	closed := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if reply != "" {
					c.Read(make([]byte, 4096))
					c.Write([]byte(reply))
				}
				io.Copy(io.Discard, c) // until the client closes
				closed <- struct{}{}
			}()
		}
	}()
	return net.Port(ln.Addr().(*gonet.TCPAddr).Port), closed
}

// A dial whose TLS or REALITY handshake fails closes its connection instead
// of leaving it to the garbage collector, also when the server answers with
// something other than TLS, as a block page does.
func TestDialClosesTheConnectionOfAFailedHandshake(t *testing.T) {
	// Keep the finalizers of a lost connection from closing it for the test.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	securities := []struct {
		name     string
		typ      string
		settings any
	}{
		{"uTLS", "tls", &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		}},
		{"crypto/tls", "tls", &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
			Fingerprint:          "unsafe",
		}},
		{"REALITY", "reality", &reality.Config{
			ServerName:  "example.com",
			PublicKey:   key.PublicKey().Bytes(),
			Fingerprint: "chrome",
		}},
	}
	transports := []struct {
		name     string
		settings any
		reality  bool
	}{
		{"tcp", &tcp.Config{}, true},
		{"websocket", &websocket.Config{}, false},
		{"httpupgrade", &httpupgrade.Config{}, false},
		{"splithttp", &splithttp.Config{Path: "x"}, true},
	}
	answers := []struct{ name, reply string }{
		{"no answer", ""},
		{"HTTP instead", "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"},
	}
	for _, transport := range transports {
		for _, security := range securities {
			if security.typ == "reality" && !transport.reality {
				continue
			}
			for _, answer := range answers {
				t.Run(transport.name+", "+security.name+", "+answer.name, func(t *testing.T) {
					port, closed := fakeServer(t, answer.reply)
					streamSettings := &internet.MemoryStreamConfig{
						ProtocolName:     transport.name,
						ProtocolSettings: transport.settings,
						SecurityType:     security.typ,
						SecuritySettings: security.settings,
					}
					ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
					defer cancel()
					conn, err := internet.Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), port), streamSettings)
					if err == nil {
						// XHTTP dials lazily: its handshake runs on the first read.
						conn.SetReadDeadline(time.Now().Add(time.Second))
						_, err = conn.Read(make([]byte, 1))
						conn.Close()
						if err == nil {
							t.Fatal("read through a failed handshake succeeded")
						}
					}
					select {
					case <-closed:
					case <-time.After(2 * time.Second):
						t.Fatalf("the connection of the failed handshake is still open: %v", err)
					}
				})
			}
		}
	}
}
