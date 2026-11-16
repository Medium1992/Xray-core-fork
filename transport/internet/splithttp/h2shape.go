package splithttp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Under REALITY, a censor sees the records the server sends after the
// handshake and compares them with the target's. nginx and Cloudflare send
// their SETTINGS, of three parameters, with a WINDOW_UPDATE in one record,
// then the acknowledgement of the client's SETTINGS alone. Go's server sends
// SETTINGS of six parameters alone, then the WINDOW_UPDATE with the
// acknowledgement: records no such server sends. shapeConn rewrites the
// server's first frames into the target's records: SETTINGS keeps
// MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE and MAX_FRAME_SIZE, the ones
// nginx sends; it waits for the WINDOW_UPDATE to go with it; the rest goes
// in a record of its own. REALITY pads the first record to the target's
// length (reality.Config.AppRecords). Values are not visible, lengths are;
// the server keeps its windows.
//
// Dropping MAX_HEADER_LIST_SIZE leaves it unannounced, which is advisory;
// dropping ENABLE_CONNECT_PROTOCOL leaves extended CONNECT off, which XHTTP
// does not use.

const (
	frameHeaderLen  = 9
	frameSettings   = 0x4
	frameWindowUpd  = 0x8
	settingMaxConc  = 0x3
	settingInitWin  = 0x4
	settingMaxFrame = 0x5
)

// shapeWait is how long the server's SETTINGS waits for the WINDOW_UPDATE
// that goes with it.
const shapeWait = 50 * time.Millisecond

type shapeListener struct {
	net.Listener
}

func (l *shapeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &shapeConn{Conn: conn}, nil
}

type shapeConn struct {
	net.Conn
	mu    sync.Mutex
	state int // 0 before the first write, 1 holding SETTINGS, 2 passing through
	held  []byte
	timer *time.Timer
	err   error
}

func (c *shapeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case 0:
		settings, rest, ok := splitFrame(b, frameSettings)
		if !ok {
			c.state = 2
			return c.Conn.Write(b)
		}
		c.held = trimSettings(settings)
		c.state = 1
		if len(rest) > 0 {
			return len(b), c.release(rest)
		}
		c.timer = time.AfterFunc(shapeWait, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.state == 1 {
				c.err = c.release(nil)
			}
		})
		return len(b), nil
	case 1:
		if c.timer != nil {
			c.timer.Stop()
		}
		return len(b), c.release(b)
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Write(b)
}

// release writes the held SETTINGS with the connection's WINDOW_UPDATE
// frames from next, in one write, as nginx does, then the rest, the
// acknowledgement of the client's SETTINGS in a write of its own.
func (c *shapeConn) release(next []byte) error {
	c.state = 2
	first := c.held
	c.held = nil
	var rest []byte
	for p := 0; p < len(next); {
		if p+frameHeaderLen > len(next) {
			rest = append(rest, next[p:]...)
			break
		}
		n := frameHeaderLen + (int(next[p])<<16 | int(next[p+1])<<8 | int(next[p+2]))
		if p+n > len(next) {
			rest = append(rest, next[p:]...)
			break
		}
		f := next[p : p+n]
		if f[3] == frameWindowUpd && binary.BigEndian.Uint32(f[5:9])&0x7fffffff == 0 {
			first = append(first, f...)
		} else {
			rest = append(rest, f...)
		}
		p += n
	}
	if _, err := c.Conn.Write(first); err != nil {
		return err
	}
	if len(rest) > 0 {
		_, err := (&ackConn{Conn: c.Conn}).Write(rest)
		return err
	}
	return nil
}

// splitFrame returns the frame b starts with if it is of type typ, not an
// acknowledgement, and the bytes after it.
func splitFrame(b []byte, typ byte) (frame, rest []byte, ok bool) {
	if len(b) < frameHeaderLen || b[3] != typ || b[4]&0x1 != 0 {
		return nil, b, false
	}
	n := frameHeaderLen + (int(b[0])<<16 | int(b[1])<<8 | int(b[2]))
	if n > len(b) {
		return nil, b, false
	}
	return b[:n], b[n:], true
}

// trimSettings keeps the parameters nginx sends.
func trimSettings(frame []byte) []byte {
	out := append([]byte(nil), frame[:frameHeaderLen]...)
	for p := frameHeaderLen; p+6 <= len(frame); p += 6 {
		switch binary.BigEndian.Uint16(frame[p:]) {
		case settingMaxConc, settingInitWin, settingMaxFrame:
			out = append(out, frame[p:p+6]...)
		}
	}
	n := len(out) - frameHeaderLen
	out[0], out[1], out[2] = byte(n>>16), byte(n>>8), byte(n)
	return out
}

// ackConn writes the acknowledgement of the server's SETTINGS in a record of
// its own, as Chrome does; Go's client writes it with the WINDOW_UPDATE
// that follows.
type ackConn struct {
	net.Conn
}

func (c *ackConn) Write(b []byte) (int, error) {
	at := -1
	for p := 0; p+frameHeaderLen <= len(b); {
		n := frameHeaderLen + (int(b[p])<<16 | int(b[p+1])<<8 | int(b[p+2]))
		if p+n > len(b) {
			break
		}
		if b[p+3] == frameSettings && b[p+4]&0x1 != 0 {
			at = p
			break
		}
		p += n
	}
	if at < 0 || len(b) == frameHeaderLen {
		return c.Conn.Write(b)
	}
	written := 0
	for _, part := range [][]byte{b[:at], b[at : at+frameHeaderLen], b[at+frameHeaderLen:]} {
		if len(part) == 0 {
			continue
		}
		n, err := c.Conn.Write(part)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
