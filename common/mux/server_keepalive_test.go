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

// stuckWriter is a downlink whose peer stopped reading: a write waits until
// the worker interrupts the link.
type stuckWriter struct {
	writing chan struct{}
	gone    chan struct{}
}

func (w stuckWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	w.writing <- struct{}{}
	<-w.gone
	return io.ErrClosedPipe
}

func (w stuckWriter) Close() error {
	close(w.gone)
	return nil
}

// idleConn asks for a KeepAlive every second and reports its downlink as long
// silent.
type idleConn struct{ net.Conn }

func (idleConn) MuxKeepAlive() (int32, int32)      { return 1, 1 }
func (idleConn) MuxKeepAliveBytes() (int32, int32) { return 0, 0 }
func (idleConn) DownlinkIdle() time.Duration       { return time.Hour }

// The KeepAlive loop ends with its worker, whether the worker closes while a
// KeepAlive is stuck on the downlink or while the loop waits for the next
// one: synctest.Test fails on any goroutine left blocked in the bubble.
func TestServerWorkerKeepAliveEndsWithWorker(t *testing.T) {
	log.RegisterHandler(discardLogs{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	t.Run("stuck write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			reader := idleReader{eof: make(chan struct{})}
			defer close(reader.eof)
			writer := stuckWriter{writing: make(chan struct{}), gone: make(chan struct{})}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: idleConn{}})
			worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, &transport.Link{Reader: reader, Writer: writer})
			common.Must(err)
			<-writer.writing
			common.Must(worker.Close())
		})
	})
	t.Run("uplink ends", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			reader := idleReader{eof: make(chan struct{})}
			writer := &countingWriter{}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: idleConn{}})
			worker, err := mux.NewServerWorker(ctx, &TestDispatcher{}, &transport.Link{Reader: reader, Writer: writer})
			common.Must(err)
			time.Sleep(1500 * time.Millisecond)
			close(reader.eof)
			<-worker.WaitClosed()
			if n := writer.writes.Load(); n < 1 {
				t.Fatal("no KeepAlive before the uplink ended")
			}
		})
	})
}
