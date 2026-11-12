package internet

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// backupConnectDelay is how long a TCP connect may go unanswered before a
// backup connect starts beside it, as Chrome's and Firefox's do (250ms): a
// lost SYN is otherwise sent again only after the kernel's 1s timeout.
const backupConnectDelay = 250 * time.Millisecond

type connectResult struct {
	conn net.Conn
	err  error
}

// connectWithBackup runs connect, and once more beside it if the first has
// not answered after backupConnectDelay. The first connection made is
// returned; the other attempt is cancelled, and a connection it makes anyway
// is closed. An error is an answer: it is returned once no attempt is left.
// Only the connect is backed up, never a TLS or REALITY handshake on top of
// it, so a handshake that hangs still has one connection, as in browsers.
func connectWithBackup(ctx context.Context, connect func(context.Context) (net.Conn, error)) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan connectResult, 2)
	start := func() {
		go func() {
			conn, err := connect(ctx)
			results <- connectResult{conn, err}
		}()
	}

	start()
	inFlight := 1
	timer := time.NewTimer(backupConnectDelay)
	defer timer.Stop()
	var lastErr error
	for {
		select {
		case r := <-results:
			inFlight--
			if r.err == nil {
				cancel()
				go closeLateConnects(results, inFlight)
				return r.conn, nil
			}
			lastErr = r.err
			if inFlight == 0 {
				cancel()
				return nil, lastErr
			}
		case <-timer.C:
			start()
			inFlight++
		case <-ctx.Done():
			cancel()
			go closeLateConnects(results, inFlight)
			return nil, ctx.Err()
		}
	}
}

// closeLateConnects waits for the n attempts still in flight and closes any
// connection they make.
func closeLateConnects(results <-chan connectResult, n int) {
	for range n {
		if r := <-results; r.conn != nil {
			r.conn.Close()
		}
	}
}
