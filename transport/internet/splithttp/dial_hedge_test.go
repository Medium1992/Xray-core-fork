package splithttp

import (
	"context"
	"errors"
	"io"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// withHedge turns hedged dials on for the test, as XRAY_XHTTP_DIAL_HEDGE=on.
func withHedge(t *testing.T) {
	t.Helper()
	was := hedgeEnabled.Load()
	hedgeEnabled.Store(true)
	t.Cleanup(func() { hedgeEnabled.Store(was) })
}

// fakeConn is a net.Conn that records Close.
type fakeConn struct {
	gonet.Conn
	closed atomic.Bool
}

func (c *fakeConn) Close() error {
	c.closed.Store(true)
	return nil
}

// A dial whose handshake hangs does not hold the dial: another attempt starts
// after the hedge delay, its connection is returned, and the hung attempt is
// cancelled.
func TestDialHedgedTakesTheNextAttemptOverAStuckOne(t *testing.T) {
	won := &fakeConn{}
	var attempts atomic.Int32
	stuckCancelled := make(chan struct{})
	dial := func(ctx context.Context) (gonet.Conn, error) {
		if attempts.Add(1) == 1 {
			<-ctx.Done()
			close(stuckCancelled)
			return nil, ctx.Err()
		}
		return won, nil
	}
	start := time.Now()
	conn, err := dialHedged(context.Background(), 50*time.Millisecond, dial)
	if err != nil || conn != won {
		t.Fatalf("dialHedged = %v, %v; want the second attempt's conn", conn, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %v; the second attempt starts after 50ms", elapsed)
	}
	select {
	case <-stuckCancelled:
	case <-time.After(time.Second):
		t.Fatal("the stuck attempt was not cancelled")
	}
}

// A dial that answers in time starts no other attempt.
func TestDialHedgedStartsNoAttemptWhileTheFirstIsInTime(t *testing.T) {
	var attempts atomic.Int32
	dial := func(ctx context.Context) (gonet.Conn, error) {
		attempts.Add(1)
		time.Sleep(20 * time.Millisecond)
		return &fakeConn{}, nil
	}
	if _, err := dialHedged(context.Background(), 200*time.Millisecond, dial); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := attempts.Load(); n != 1 {
		t.Fatalf("%d attempts, want 1", n)
	}
}

// An error is the answer: it is returned at once and starts no attempt, so a
// refusing server is dialed as often as before.
func TestDialHedgedReturnsAnErrorWithoutRetrying(t *testing.T) {
	refused := errors.New("refused")
	var attempts atomic.Int32
	dial := func(ctx context.Context) (gonet.Conn, error) {
		attempts.Add(1)
		return nil, refused
	}
	start := time.Now()
	if _, err := dialHedged(context.Background(), 50*time.Millisecond, dial); err != refused {
		t.Fatalf("err = %v, want refused", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := attempts.Load(); n != 1 || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("%d attempts; want one, answered at once", n)
	}
}

// While every attempt hangs, at most maxDialAttempts are in flight, and the
// dial ends with the attempts' error once they have all ended.
func TestDialHedgedBoundsTheAttempts(t *testing.T) {
	var attempts atomic.Int32
	hang := 300 * time.Millisecond
	timeout := errors.New("handshake timeout")
	dial := func(ctx context.Context) (gonet.Conn, error) {
		attempts.Add(1)
		select {
		case <-time.After(hang):
			return nil, timeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	_, err := dialHedged(context.Background(), 20*time.Millisecond, dial)
	if err != timeout {
		t.Fatalf("err = %v, want the attempts' timeout", err)
	}
	if n := attempts.Load(); n != maxDialAttempts {
		t.Fatalf("%d attempts, want %d", n, maxDialAttempts)
	}
}

// A connection that an attempt makes after another attempt won is closed.
func TestDialHedgedClosesALateWinner(t *testing.T) {
	late := &fakeConn{}
	release := make(chan struct{})
	var attempts atomic.Int32
	dial := func(ctx context.Context) (gonet.Conn, error) {
		if attempts.Add(1) == 1 {
			<-release // ignores ctx, as a dial past its last cancellation point does
			return late, nil
		}
		return &fakeConn{}, nil
	}
	if _, err := dialHedged(context.Background(), 20*time.Millisecond, dial); err != nil {
		t.Fatal(err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for !late.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the late connection was not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Cancelling the dial's context ends it at once, with every attempt.
func TestDialHedgedEndsWithItsContext(t *testing.T) {
	var running atomic.Int32
	dial := func(ctx context.Context) (gonet.Conn, error) {
		running.Add(1)
		defer running.Add(-1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if _, err := dialHedged(ctx, 20*time.Millisecond, dial); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("returned after %v", elapsed)
	}
	deadline := time.Now().Add(time.Second)
	for running.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d attempts still run", running.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// After a dial that failed, the next one makes a single attempt, also from a
// new client to the same server; after a dial that succeeded, a slow attempt
// is hedged again.
func TestHedgedDialerStopsHedgingAfterAFailure(t *testing.T) {
	withHedge(t)
	var attempts atomic.Int32
	var down atomic.Bool
	down.Store(true)
	d := &hedgedDialer{history: new(dialHistory), dial: func(ctx context.Context) (gonet.Conn, error) {
		attempts.Add(1)
		if down.Load() {
			select {
			case <-time.After(1500 * time.Millisecond):
				return nil, errors.New("handshake timeout")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &fakeConn{}, nil
	}}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("dial through a down path succeeded")
	}
	if n := attempts.Swap(0); n < 2 {
		t.Fatalf("first dial: %d attempts, want it hedged", n)
	}
	d = &hedgedDialer{history: d.history, dial: d.dial} // XMUX's next client
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("dial through a down path succeeded")
	}
	if n := attempts.Swap(0); n != 1 {
		t.Fatalf("dial after a failure: %d attempts, want 1", n)
	}
	down.Store(false)
	if _, err := d.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.history.failed.Load() && d.history.lastHandshake.Load() > 0 {
		return
	}
	t.Fatal("a successful dial did not turn hedging back on")
}

// Unless XRAY_XHTTP_DIAL_HEDGE is on, a dial makes one attempt and waits on
// it: no second ClientHello goes out while a handshake hangs.
func TestHedgedDialerDialsOnceByDefault(t *testing.T) {
	was := hedgeEnabled.Load()
	hedgeEnabled.Store(false)
	t.Cleanup(func() { hedgeEnabled.Store(was) })
	var attempts atomic.Int32
	d := &hedgedDialer{history: new(dialHistory), dial: func(ctx context.Context) (gonet.Conn, error) {
		attempts.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if _, err := d.Dial(ctx); err == nil {
		t.Fatal("dial through a hung handshake succeeded")
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("%d attempts while a handshake hung, want 1", n)
	}
}

func TestHedgeDelay(t *testing.T) {
	for _, tc := range []struct{ last, want time.Duration }{
		{0, time.Second},
		{50 * time.Millisecond, 250 * time.Millisecond},
		{300 * time.Millisecond, 600 * time.Millisecond},
		{time.Second, 2 * time.Second},
		{5 * time.Second, 3 * time.Second},
	} {
		if got := hedgeDelay(tc.last); got != tc.want {
			t.Errorf("hedgeDelay(%v) = %v, want %v", tc.last, got, tc.want)
		}
	}
}

// Through a path that blackholes the first connection after its ClientHello,
// as a lost or dropped handshake does, the XHTTP client gets its answer from
// a second connection within a few seconds, not after the handshake bound.
func Test_DialRetriesAStuckHandshake(t *testing.T) {
	withHedge(t)
	listenPort := tcp.PickPort()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "shs"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		},
	}
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			var b [1024]byte
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Read(b[:]); err != nil {
				return
			}
			conn.Write([]byte("Response"))
		}()
	})
	common.Must(err)
	defer listen.Close()

	relay, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer relay.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := relay.Accept()
			if err != nil {
				return
			}
			if accepted.Add(1) == 1 {
				defer c.Close() // the kernel takes the ClientHello, nobody answers
				continue
			}
			go func(c gonet.Conn) {
				defer c.Close()
				up, err := gonet.Dial("tcp", gonet.JoinHostPort("127.0.0.1", listenPort.String()))
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()

	start := time.Now()
	relayPort := net.Port(relay.Addr().(*gonet.TCPAddr).Port)
	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), relayPort), streamSettings)
	common.Must(err)
	defer conn.Close()
	if _, err := conn.Write([]byte("Test")); err != nil {
		t.Fatal(err)
	}
	var b [1024]byte
	n, _ := io.ReadFull(conn, b[:len("Response")])
	if string(b[:n]) != "Response" {
		t.Fatalf("read %q", b[:n])
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("answered after %v; a second connection starts after a second", elapsed.Round(time.Millisecond))
	}
	if n := accepted.Load(); n > maxDialAttempts+1 {
		t.Fatalf("%d connections through the relay", n)
	}
}
