package mux_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// pausedConn reports its downlink as long silent, but holds each check until
// the test releases it, so that a test can close the worker in between.
type pausedConn struct {
	net.Conn
	checking chan struct{}
	resume   chan struct{}
}

func (c pausedConn) MuxKeepAlive() (int32, int32)      { return 1, 1 }
func (c pausedConn) MuxKeepAliveBytes() (int32, int32) { return 0, 0 }
func (c pausedConn) DownlinkIdle() time.Duration {
	c.checking <- struct{}{}
	<-c.resume
	return time.Hour
}

// countingWriter accepts writes the way a VLESS link writer does and counts
// them.
type countingWriter struct{ writes atomic.Int32 }

func (w *countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	w.writes.Add(1)
	return nil
}

// idleReader is an uplink that sends nothing until the test ends it.
type idleReader struct{ eof chan struct{} }

func (r idleReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.eof
	return nil, io.EOF
}

// discardLogs handles records in place: the default logger starts a goroutine
// that waits on channels created outside a synctest bubble.
type discardLogs struct{}

func (discardLogs) Handle(log.Message) {}

// A worker that is closing must not get a KeepAlive frame, even when the
// loop was already checking the downlink as Close began.
func TestServerWorkerKeepAliveSkipsClosingWorker(t *testing.T) {
	log.RegisterHandler(discardLogs{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		reader := idleReader{eof: make(chan struct{})}
		defer close(reader.eof)
		writer := &countingWriter{}
		conn := pausedConn{checking: make(chan struct{}), resume: make(chan struct{})}
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: conn})
		worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, &transport.Link{Reader: reader, Writer: writer})
		common.Must(err)

		<-conn.checking
		common.Must(worker.Close())
		close(conn.resume)
		synctest.Wait()
		if n := writer.writes.Load(); n != 0 {
			t.Fatalf("KeepAlive wrote %d frame(s) to a worker that was closing", n)
		}
	})
}
