package splithttp

import (
	"context"
	gonet "net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/platform"
)

// hedgeEnabled turns on dialHedged for the XHTTP client: off unless
// XRAY_XHTTP_DIAL_HEDGE is on, true or 1. While a handshake hangs, a hedged
// dial sends up to three more ClientHellos to the server within seconds,
// which a censor may block on; without it the client waits on one attempt
// until the handshake bound. It is read again when the config's "env"
// changes the environment.
var hedgeEnabled atomic.Bool

func reloadHedgeEnv() error {
	switch strings.ToLower(strings.TrimSpace(platform.NewEnvFlag(platform.XHTTPDialHedge).GetValue(func() string { return "" }))) {
	case "on", "true", "1":
		hedgeEnabled.Store(true)
	default:
		hedgeEnabled.Store(false)
	}
	return nil
}

func init() {
	platform.RegisterEnvReload(reloadHedgeEnv)
}

// maxDialAttempts bounds the attempts of one dial that run side by side.
const maxDialAttempts = 4

// hedgeDelay is how long an attempt's handshake may take before another one
// starts: twice the last handshake that completed, within 250ms and 3s, or a
// second before any has.
func hedgeDelay(last time.Duration) time.Duration {
	if last <= 0 {
		return time.Second
	}
	return min(max(2*last, 250*time.Millisecond), 3*time.Second)
}

type dialResult struct {
	conn gonet.Conn
	err  error
}

// dialHedged dials with dial, and starts another attempt each time the
// attempts in flight have gone delay without an answer, up to
// maxDialAttempts. Every request queued behind a connection waits on its
// dial, so one handshake lost on the way would hold them all until its
// timeout; a fresh attempt gets through as soon as the path does. The first
// connection made is returned and the other attempts are cancelled; a
// connection one of them makes anyway is closed. An attempt's error ends the
// dial when no other attempt is in flight: an error is an answer, and is not
// retried here.
func dialHedged(ctx context.Context, delay time.Duration, dial func(context.Context) (gonet.Conn, error)) (gonet.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan dialResult, maxDialAttempts)
	start := func() {
		go func() {
			conn, err := dial(ctx)
			results <- dialResult{conn, err}
		}()
	}

	start()
	started, inFlight := 1, 1
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case r := <-results:
			inFlight--
			if r.err == nil {
				cancel()
				go closeLate(results, inFlight)
				return r.conn, nil
			}
			if inFlight == 0 {
				cancel()
				return nil, r.err
			}
		case <-timer.C:
			if started < maxDialAttempts {
				start()
				started++
				inFlight++
				timer.Reset(delay)
			}
		case <-ctx.Done():
			cancel()
			go closeLate(results, inFlight)
			return nil, ctx.Err()
		}
	}
}

// closeLate waits for the n attempts still in flight and closes any
// connection they make.
func closeLate(results <-chan dialResult, n int) {
	for range n {
		if r := <-results; r.conn != nil {
			r.conn.Close()
		}
	}
}

// dialHistory is what the dials to a server have shown so far: how long its
// last handshake took, and whether its last dial failed. XMUX replaces a
// client whose connection failed, so it is kept per server, not per client.
type dialHistory struct {
	lastHandshake atomic.Int64
	failed        atomic.Bool
}

var dialHistories sync.Map // server address -> *dialHistory

func dialHistoryOf(server string) *dialHistory {
	h, _ := dialHistories.LoadOrStore(server, new(dialHistory))
	return h.(*dialHistory)
}

// hedgedDialer dials a server with dialHedged, timing the hedge by the last
// handshake. Once a dial has failed it dials with one attempt until one
// succeeds: a path that stays down past the handshake bound gains nothing
// from more attempts, which would only multiply the dials during it.
type hedgedDialer struct {
	dial    func(context.Context) (gonet.Conn, error)
	history *dialHistory
}

func (d *hedgedDialer) Dial(ctx context.Context) (gonet.Conn, error) {
	h := d.history
	timed := func(ctx context.Context) (gonet.Conn, error) {
		start := time.Now()
		conn, err := d.dial(ctx)
		if err == nil {
			h.lastHandshake.Store(int64(time.Since(start)))
		}
		return conn, err
	}
	var conn gonet.Conn
	var err error
	if !hedgeEnabled.Load() || h.failed.Load() {
		conn, err = timed(ctx)
	} else {
		conn, err = dialHedged(ctx, hedgeDelay(time.Duration(h.lastHandshake.Load())), timed)
	}
	h.failed.Store(err != nil)
	return conn, err
}
