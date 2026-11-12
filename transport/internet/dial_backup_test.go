package internet_test

import (
	"context"
	"errors"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/transport/internet"
)

// scriptedDialer answers each Dial with the next of its steps.
type scriptedDialer struct {
	mu    sync.Mutex
	steps []func(ctx context.Context) (net.Conn, error)
	calls atomic.Int32
}

func (d *scriptedDialer) Dial(ctx context.Context, _ net.Address, _ net.Destination, _ *SocketConfig) (net.Conn, error) {
	n := int(d.calls.Add(1)) - 1
	d.mu.Lock()
	step := d.steps[min(n, len(d.steps)-1)]
	d.mu.Unlock()
	return step(ctx)
}

func (d *scriptedDialer) DestIpAddress() net.IP { return nil }

func useDialer(t *testing.T, d SystemDialer) {
	t.Helper()
	UseAlternativeSystemDialer(d)
	t.Cleanup(func() { UseAlternativeSystemDialer(nil) })
}

// recordConn is a net.Conn that records Close.
type recordConn struct {
	gonet.Conn
	closed atomic.Bool
}

func (c *recordConn) Close() error {
	c.closed.Store(true)
	return nil
}

func hangUntilCancelled(cancelled chan<- struct{}) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		if cancelled != nil {
			close(cancelled)
		}
		return nil, ctx.Err()
	}
}

func answer(conn net.Conn, after time.Duration) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		time.Sleep(after)
		return conn, nil
	}
}

var tcpDest = net.TCPDestination(net.LocalHostIP, 443)

// A TCP connect whose SYN goes unanswered gets one backup connect after
// 250ms, as Chrome and Firefox start one; the first connection made is used
// and the other attempt is cancelled.
func TestDialSystemStartsABackupForAStuckConnect(t *testing.T) {
	won := &recordConn{}
	cancelled := make(chan struct{})
	d := &scriptedDialer{steps: []func(context.Context) (net.Conn, error){hangUntilCancelled(cancelled), answer(won, 0)}}
	useDialer(t, d)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := DialSystem(ctx, tcpDest, nil)
	if err != nil || conn != won {
		t.Fatalf("DialSystem = %v, %v; want the backup's conn", conn, err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > time.Second {
		t.Fatalf("answered after %v; the backup starts after 250ms", elapsed)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("the stuck connect was not cancelled")
	}
	if n := d.calls.Load(); n != 2 {
		t.Fatalf("%d connects, want 2", n)
	}
}

// A connect that completes in time starts no backup, and a slow one starts
// only one.
func TestDialSystemStartsAtMostOneBackup(t *testing.T) {
	d := &scriptedDialer{steps: []func(context.Context) (net.Conn, error){answer(&recordConn{}, 50*time.Millisecond)}}
	useDialer(t, d)
	if _, err := DialSystem(context.Background(), tcpDest, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("a connect in time: %d connects, want 1", n)
	}

	d = &scriptedDialer{steps: []func(context.Context) (net.Conn, error){hangUntilCancelled(nil)}}
	useDialer(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := DialSystem(ctx, tcpDest, nil); err == nil {
		t.Fatal("a connect nobody answers succeeded")
	}
	if n := d.calls.Load(); n != 2 {
		t.Fatalf("connects nobody answers: %d, want 2", n)
	}
}

// A refused connect is an answer: it is returned at once and starts no
// backup.
func TestDialSystemReturnsARefusalWithoutABackup(t *testing.T) {
	refused := errors.New("connection refused")
	d := &scriptedDialer{steps: []func(context.Context) (net.Conn, error){func(context.Context) (net.Conn, error) { return nil, refused }}}
	useDialer(t, d)
	if _, err := DialSystem(context.Background(), tcpDest, nil); err != refused {
		t.Fatalf("err = %v, want the refusal", err)
	}
	time.Sleep(400 * time.Millisecond)
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("%d connects, want 1", n)
	}
}

// A connection the first attempt makes after the backup won is closed.
func TestDialSystemClosesALateConnect(t *testing.T) {
	late := &recordConn{}
	d := &scriptedDialer{steps: []func(context.Context) (net.Conn, error){answer(late, 600*time.Millisecond), answer(&recordConn{}, 0)}}
	useDialer(t, d)
	conn, err := DialSystem(context.Background(), tcpDest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn == late {
		t.Fatal("the slow first connect was used; no backup started")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !late.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the late connection was not closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// UDP has no connect to back up.
func TestDialSystemStartsNoBackupForUDP(t *testing.T) {
	d := &scriptedDialer{steps: []func(context.Context) (net.Conn, error){answer(&recordConn{}, 400*time.Millisecond)}}
	useDialer(t, d)
	if _, err := DialSystem(context.Background(), net.UDPDestination(net.LocalHostIP, 53), nil); err != nil {
		t.Fatal(err)
	}
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("%d dials, want 1", n)
	}
}
