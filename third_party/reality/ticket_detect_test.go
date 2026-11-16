package reality

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func testCertificate(t *testing.T, name string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// goTarget serves TLS with crypto/tls, as Caddy does: one ticket, sent with
// the server's first flight.
func goTarget(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM := testCertificate(t, "example.com")
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// opensslTarget serves TLS with openssl s_server, as nginx does: two
// tickets after a full handshake and one after a resumed one, both after
// the client's Finished.
func opensslTarget(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	dir := t.TempDir()
	certPEM, keyPEM := testCertificate(t, "example.com")
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cmd := exec.Command(bin, "s_server", "-accept", addr, "-cert", certFile, "-key", keyFile,
		"-alpn", "h2,http/1.1", "-www", "-quiet")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatal("openssl s_server did not start")
		}
	}
}

func TestProbeTicketShapeGoTarget(t *testing.T) {
	config := &Config{Type: "tcp", Dest: goTarget(t)}
	shape, err := probeTicketShape(config, "example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", shape)
	if !shape.Resumes || shape.Tickets != 1 || shape.ResTickets != 1 {
		t.Fatalf("crypto/tls issues one ticket per handshake: %+v", shape)
	}
	if shape.HelloDelta != 6 || shape.Lifetime != 7*24*3600 {
		t.Fatalf("ServerHello delta %d, lifetime %d", shape.HelloDelta, shape.Lifetime)
	}
	if len(shape.Prefix) > 2 {
		t.Fatalf("crypto/tls tickets start with a random IV, prefix %x", shape.Prefix)
	}
}

func TestProbeTicketShapeOpenSSLTarget(t *testing.T) {
	config := &Config{Type: "tcp", Dest: opensslTarget(t)}
	shape, err := probeTicketShape(config, "example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", shape)
	if !shape.Resumes || shape.Tickets != 2 || shape.ResTickets != 1 {
		t.Fatalf("OpenSSL issues two tickets, one after resumption: %+v", shape)
	}
	if shape.HelloDelta != 6 {
		t.Fatalf("ServerHello delta %d", shape.HelloDelta)
	}
	if len(shape.Prefix) < 16 {
		t.Fatalf("OpenSSL tickets start with a 16-byte key name, prefix %x", shape.Prefix)
	}
}

func TestProbeTicketShapeNoTickets(t *testing.T) {
	certPEM, keyPEM := testCertificate(t, "example.com")
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates:           []gotls.Certificate{cert},
		SessionTicketsDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	shape, err := probeTicketShape(&Config{Type: "tcp", Dest: ln.Addr().String()}, "example.com", 0)
	if err == nil || shape != nil {
		t.Fatalf("a target without tickets has no shape: %+v", shape)
	}
}
