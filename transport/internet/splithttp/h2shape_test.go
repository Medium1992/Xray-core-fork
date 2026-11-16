package splithttp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type writesConn struct {
	net.Conn
	writes [][]byte
}

func (c *writesConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), nil
}

func frame(typ, flags byte, stream uint32, payload []byte) []byte {
	b := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[5:], stream)
	return append(b, payload...)
}

func settings(ids ...uint16) []byte {
	var p []byte
	for _, id := range ids {
		p = binary.BigEndian.AppendUint16(p, id)
		p = binary.BigEndian.AppendUint32(p, 1<<16)
	}
	return frame(frameSettings, 0, 0, p)
}

// Go's server writes SETTINGS of six parameters, then WINDOW_UPDATE with
// the acknowledgement; nginx writes SETTINGS of three with WINDOW_UPDATE,
// then the acknowledgement.
func TestShapeConnWritesTheFramesAsNginx(t *testing.T) {
	under := &writesConn{}
	c := &shapeConn{Conn: under}
	goSettings := settings(0x5, 0x3, 0x6, 0x1, 0x4, 0x8)
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	ack := frame(frameSettings, 0x1, 0, nil)
	c.Write(goSettings)
	if len(under.writes) != 0 {
		t.Fatal("SETTINGS waits for the WINDOW_UPDATE")
	}
	c.Write(append(append([]byte(nil), wu...), ack...))
	want := [][]byte{append(settings(0x5, 0x3, 0x4), wu...), ack}
	if len(under.writes) != 2 || !bytes.Equal(under.writes[0], want[0]) || !bytes.Equal(under.writes[1], want[1]) {
		t.Fatalf("writes %x, want %x", under.writes, want)
	}
	if len(under.writes[0]) != 40 {
		t.Fatalf("SETTINGS and WINDOW_UPDATE take %d bytes, nginx's 40", len(under.writes[0]))
	}
	c.Write([]byte("data"))
	if len(under.writes) != 3 {
		t.Fatal("then everything passes")
	}
}

func TestShapeConnSendsSettingsAlone(t *testing.T) {
	under := &writesConn{}
	c := &shapeConn{Conn: under}
	c.Write(settings(0x5, 0x3, 0x4))
	time.Sleep(2 * shapeWait)
	c.mu.Lock()
	n := len(under.writes)
	c.mu.Unlock()
	if n != 1 {
		t.Fatal("SETTINGS goes alone when nothing follows")
	}
}

func TestShapeConnPassesOtherProtocols(t *testing.T) {
	under := &writesConn{}
	c := &shapeConn{Conn: under}
	c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if len(under.writes) != 1 {
		t.Fatal("HTTP/1.1 passes")
	}
}

func TestAckConnWritesTheAcknowledgementAlone(t *testing.T) {
	under := &writesConn{}
	c := &ackConn{Conn: under}
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	ack := frame(frameSettings, 0x1, 0, nil)
	if n, err := c.Write(append(append([]byte(nil), ack...), wu...)); n != len(ack)+len(wu) || err != nil {
		t.Fatal(n, err)
	}
	if len(under.writes) != 2 || !bytes.Equal(under.writes[0], ack) || !bytes.Equal(under.writes[1], wu) {
		t.Fatalf("writes %x", under.writes)
	}
	c.Write(wu)
	if len(under.writes) != 3 {
		t.Fatal("other writes pass")
	}
}

// Go may write the acknowledgement before the connection's WINDOW_UPDATE.
func TestShapeConnMovesTheWindowUpdate(t *testing.T) {
	under := &writesConn{}
	c := &shapeConn{Conn: under}
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	ack := frame(frameSettings, 0x1, 0, nil)
	c.Write(settings(0x5, 0x3, 0x4, 0x6))
	c.Write(append(append([]byte(nil), ack...), wu...))
	if len(under.writes) != 2 || !bytes.Equal(under.writes[0], append(settings(0x5, 0x3, 0x4), wu...)) || !bytes.Equal(under.writes[1], ack) {
		t.Fatalf("writes %x", under.writes)
	}
}
