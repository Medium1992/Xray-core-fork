package reality

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// A target that accepts TCP and never answers must not hold the probe of its
// post-handshake records: Server keeps every authenticated connection with
// that SNI waiting until the probe has stored its result.
func TestDetectPostHandshakeRecordsLensIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				io.Copy(io.Discard, conn) // take the ClientHello, answer nothing
			}()
		}
	}()

	config := &Config{
		Type:        "tcp",
		Dest:        ln.Addr().String(),
		ServerNames: map[string]bool{"silent.example": true},
	}
	DetectPostHandshakeRecordsLens(config)
	deadline := time.Now().Add(14 * time.Second)
	for alpn := range 3 {
		key := config.Dest + " silent.example " + strconv.Itoa(alpn)
		for {
			if val, _ := GlobalPostHandshakeRecordsLens.Load(key); val != nil {
				if _, pending := val.(bool); !pending {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("the probe for ALPN %d still runs after 14s against a silent target", alpn)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
