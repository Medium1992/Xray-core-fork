package dispatcher

import (
	"context"
	gotls "crypto/tls"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// The sniffer tests taken from Jolymmiles/Xray-core call its dispatcher by
// these names.

// snifferContext supplies the core instance newFakeDNSSniffer requires.
func snifferContext() context.Context {
	return context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
}

func newCachedReader(reader buf.TimeoutReader) *cachedReader {
	return &cachedReader{reader: reader}
}

func newSniffer(ctx context.Context) Sniffer {
	return *NewSniffer(ctx)
}

func sniff(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network, _ Sniffer) (SniffResult, error) {
	return sniffer(ctx, cReader, metadataOnly, network)
}

// defaultProtocolSniffers are the sniffers NewSniffer starts with, fake DNS
// aside.
var defaultProtocolSniffers = NewSniffer(snifferContext()).sniffer

func tlsClientHello() []byte {
	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()

	captured := make(chan []byte, 1)
	go func() {
		record := make([]byte, 4096)
		n, err := server.Read(record)
		if err != nil {
			captured <- nil
			return
		}
		captured <- record[:n]
	}()

	conn := gotls.Client(client, &gotls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = conn.HandshakeContext(ctx)

	return <-captured
}

func newTestCachedReader(t *testing.T, link buf.TimeoutReader) *cachedReader {
	t.Helper()
	reader := newCachedReader(link)
	t.Cleanup(func() {
		reader.Lock()
		buf.ReleaseMulti(reader.cache)
		reader.cache = nil
		reader.Unlock()
	})
	return reader
}

// countingReader is a datagramReader that counts the reads of its link.
type countingReader struct {
	datagramReader
	reads int
}

func (r *countingReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	r.reads++
	return r.datagramReader.ReadMultiBufferTimeout(timeout)
}
