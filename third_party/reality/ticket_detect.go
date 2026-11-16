package reality

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

// Reality specific file: how the target issues and resumes TLS 1.3 session
// tickets, so that REALITY can issue and accept its own in the same shape.

// GlobalTicketShapes maps the key of GlobalPostHandshakeRecordsLens to the
// *TicketShape probed for it, or to false while the probe runs. A target
// without a usable shape maps to a *TicketShape with Resumes false.
var GlobalTicketShapes sync.Map

// TicketShape is what an observer sees of the target's session tickets.
type TicketShape struct {
	// Resumes reports that the target issues tickets and accepts them back.
	// The other fields are meaningful only when it is true.
	Resumes bool

	// TicketLen and ResTicketLen are the lengths of the target's tickets
	// after a full and after a resumed handshake, as clients send them back
	// in pre_shared_key. OpenSSL's grow with what the session holds.
	TicketLen    int
	ResTicketLen int
	// Prefix is what all of the target's tickets start with, such as the
	// key name OpenSSL puts first. Tickets that differ there would set
	// REALITY's apart from the target's.
	Prefix []byte
	// NonceLen is the length of the target's ticket_nonce. With it, the
	// length of a ticket follows from that of its record, which varies
	// with the target's tickets.
	NonceLen int
	// Lifetime is the ticket_lifetime the target announces, in seconds.
	Lifetime uint32
	// Tickets is the number of tickets after a full handshake.
	Tickets int
	// FullRecords are the encrypted records after the ServerHello of a full
	// handshake, lengths including headers: EncryptedExtensions,
	// Certificate, CertificateVerify, Finished, then what follows.
	FullRecords []int

	// HelloDelta is how much longer the ServerHello of a resumed handshake
	// is than that of a full one: the pre_shared_key extension.
	HelloDelta int
	// PSKIndex is the position of pre_shared_key among the extensions of
	// the target's ServerHello.
	PSKIndex int
	// ResRecords are the encrypted records after the ServerHello of a
	// resumed handshake: EncryptedExtensions, Finished, then the tickets,
	// either with the flight or after the client's Finished, and what
	// follows. Which of the two the target does shows in its live answer.
	ResRecords []int
	// ResTickets is the number of tickets after a resumed handshake.
	ResTickets int
}

// ticketRecordOverhead is what a TLS 1.3 record holding a NewSessionTicket
// adds to its nonce and ticket: the record header, the AEAD tag, the inner
// content type, and the message's type, length, lifetime, age_add and
// length prefixes.
const ticketRecordOverhead = recordHeaderLen + 16 + 1 + 4 + 4 + 4 + 1 + 2 + 2

const (
	ticketProbeTimeout = 10 * time.Second
	// ticketProbeWait is how long a probe reads after the handshake for the
	// tickets and other records the target sends without being asked.
	ticketProbeWait = 3 * time.Second
)

// DetectTicketShape probes the target once for key, see DetectPostHandshakeRecordsLens.
func DetectTicketShape(config *Config, key, sni string, alpn int) {
	if _, loaded := GlobalTicketShapes.LoadOrStore(key, false); loaded {
		return
	}
	go func() {
		shape, _ := probeTicketShape(config, sni, alpn)
		if shape == nil {
			shape = &TicketShape{}
		}
		GlobalTicketShapes.Store(key, shape)
	}()
}

// LoadTicketShape returns the shape probed for key, or nil while the probe
// runs or when the target does not resume.
func LoadTicketShape(key string) *TicketShape {
	val, ok := GlobalTicketShapes.Load(key)
	if !ok {
		return nil
	}
	shape, ok := val.(*TicketShape)
	if !ok || !shape.Resumes {
		return nil
	}
	return shape
}

// ticketRecorder is a ClientSessionCache that keeps every ticket put in it
// and hands out replay.
type ticketRecorder struct {
	sync.Mutex
	sessions []*utls.ClientSessionState
	replay   *utls.ClientSessionState
}

func (r *ticketRecorder) Get(string) (*utls.ClientSessionState, bool) {
	r.Lock()
	defer r.Unlock()
	return r.replay, r.replay != nil
}

func (r *ticketRecorder) Put(_ string, cs *utls.ClientSessionState) {
	if cs == nil {
		return
	}
	r.Lock()
	defer r.Unlock()
	r.sessions = append(r.sessions, cs)
}

func (r *ticketRecorder) take() []*utls.ClientSessionState {
	r.Lock()
	defer r.Unlock()
	sessions := r.sessions
	r.sessions = nil
	return sessions
}

// probeCaptureConn records what the target sends.
type probeCaptureConn struct {
	net.Conn
	mu sync.Mutex
	in []byte
}

func (c *probeCaptureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.in = append(c.in, b[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *probeCaptureConn) received() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.in)
}

type probeRecord struct {
	typ  byte
	body []byte // without the header
}

func (r probeRecord) len() int { return recordHeaderLen + len(r.body) }

// splitRecords cuts b into TLS records; an incomplete last record is dropped.
func splitRecords(b []byte) []probeRecord {
	var records []probeRecord
	for len(b) >= recordHeaderLen {
		n := recordHeaderLen + int(binary.BigEndian.Uint16(b[3:5]))
		if n > len(b) {
			break
		}
		records = append(records, probeRecord{typ: b[0], body: b[recordHeaderLen:n]})
		b = b[n:]
	}
	return records
}

func recordLens(records []probeRecord) []int {
	lens := make([]int, 0, len(records))
	for _, r := range records {
		lens = append(lens, r.len())
	}
	return lens
}

// probeHandshake is one probe connection.
type probeHandshake struct {
	hello    probeRecord   // ServerHello
	records  []probeRecord // encrypted records after it
	resumed  bool
	sessions []*utls.ClientSessionState
}

func probeOnce(config *Config, sni string, alpn int, replay *utls.ClientSessionState) (*probeHandshake, error) {
	dial := config.DialContext
	if dial == nil {
		dial = new(net.Dialer).DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), ticketProbeTimeout)
	defer cancel()
	target, err := dial(ctx, config.Type, config.Dest)
	if err != nil {
		return nil, err
	}
	defer target.Close()
	target.SetDeadline(time.Now().Add(ticketProbeTimeout))
	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
			return nil, err
		}
	}
	capture := &probeCaptureConn{Conn: target}
	recorder := &ticketRecorder{replay: replay}
	var nextProtos []string
	switch alpn {
	case 1:
		nextProtos = []string{"http/1.1"}
	case 2:
		nextProtos = []string{"h2", "http/1.1"}
	}
	uConn := utls.UClient(capture, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
		ClientSessionCache: recorder,
	}, utls.HelloGolang)
	if err = uConn.Handshake(); err != nil {
		return nil, err
	}
	// Tickets are processed as they are read.
	target.SetReadDeadline(time.Now().Add(ticketProbeWait))
	io.Copy(io.Discard, uConn)

	records := splitRecords(capture.received())
	if len(records) < 2 || records[0].typ != byte(recordTypeHandshake) {
		return nil, errors.New("reality: unexpected server flight")
	}
	h := &probeHandshake{
		hello:    records[0],
		resumed:  uConn.ConnectionState().DidResume,
		sessions: recorder.take(),
	}
	for _, r := range records[1:] {
		if r.typ == byte(recordTypeApplicationData) {
			h.records = append(h.records, r)
		}
	}
	return h, nil
}

// probeTicketShape does a full handshake with the target, then resumes it
// with the first ticket the target issued.
func probeTicketShape(config *Config, sni string, alpn int) (*TicketShape, error) {
	full, err := probeOnce(config, sni, alpn, nil)
	if err != nil {
		return nil, err
	}
	if len(full.sessions) == 0 {
		return nil, errors.New("reality: the target issues no tickets")
	}
	res, err := probeOnce(config, sni, alpn, full.sessions[0])
	if err != nil {
		return nil, err
	}
	if !res.resumed {
		return nil, errors.New("reality: the target does not resume its own ticket")
	}

	shape := &TicketShape{
		Tickets:     len(full.sessions),
		ResTickets:  len(res.sessions),
		FullRecords: recordLens(full.records),
		ResRecords:  recordLens(res.records),
		HelloDelta:  res.hello.len() - full.hello.len(),
	}
	// One record per handshake message: the Finished of a full handshake
	// is its fourth record, that of a resumed one its second.
	if len(shape.FullRecords) < 4 || len(shape.ResRecords) < 2+shape.ResTickets ||
		shape.FullRecords[3] != shape.ResRecords[1] {
		return nil, errors.New("reality: unsupported handshake records")
	}
	var tickets [][]byte
	for _, cs := range append(full.sessions, res.sessions...) {
		ticket, state, err := cs.ResumptionState()
		if err != nil || state == nil {
			return nil, errors.New("reality: unreadable ticket")
		}
		tickets = append(tickets, ticket)
		if lifetime, ok := ticketLifetime(state); ok && shape.Lifetime == 0 {
			shape.Lifetime = lifetime
		}
	}
	shape.TicketLen = len(tickets[0])
	shape.ResTicketLen = shape.TicketLen
	if len(res.sessions) != 0 {
		shape.ResTicketLen = len(tickets[len(full.sessions)])
	}
	shape.Prefix = commonPrefix(tickets)
	// The first record after the Finished of the full handshake is its
	// first ticket.
	if len(shape.FullRecords) < 5 {
		return nil, errors.New("reality: tickets not where expected")
	}
	shape.NonceLen = shape.FullRecords[4] - ticketRecordOverhead - shape.TicketLen
	if shape.NonceLen < 0 || shape.NonceLen > 255 {
		return nil, errors.New("reality: tickets not where expected")
	}

	if shape.PSKIndex, err = pskExtensionIndex(res.hello.body); err != nil {
		return nil, err
	}
	if shape.Lifetime == 0 {
		return nil, errors.New("reality: no ticket lifetime")
	}
	shape.Resumes = true
	return shape, nil
}

// ticketLifetime reads the lifetime a client session was given from its
// encoding, see SessionState.Bytes: created_at follows version, type and
// cipher_suite, use_by and age_add end a TLS 1.3 client session.
func ticketLifetime(state *utls.SessionState) (uint32, bool) {
	b, err := state.Bytes()
	if err != nil || len(b) < 5+8+12 || b[2] != 2 {
		return 0, false
	}
	createdAt := binary.BigEndian.Uint64(b[5:13])
	useBy := binary.BigEndian.Uint64(b[len(b)-12 : len(b)-4])
	if useBy <= createdAt {
		return 0, false
	}
	return uint32(useBy - createdAt), true
}

func commonPrefix(tickets [][]byte) []byte {
	prefix := tickets[0]
	for _, ticket := range tickets[1:] {
		n := 0
		for n < len(prefix) && n < len(ticket) && prefix[n] == ticket[n] {
			n++
		}
		prefix = prefix[:n]
	}
	if len(tickets) < 2 {
		prefix = nil // one ticket shows no prefix
	}
	return bytes.Clone(prefix)
}

// pskExtensionIndex finds pre_shared_key among the extensions of a
// ServerHello record body.
func pskExtensionIndex(hello []byte) (int, error) {
	types, err := serverHelloExtensionTypes(hello)
	if err != nil {
		return 0, err
	}
	for i, t := range types {
		if t == extensionPreSharedKey {
			return i, nil
		}
	}
	return 0, errors.New("reality: no pre_shared_key in the resumed ServerHello")
}

// serverHelloExtensions returns the offset of the extensions block of a
// ServerHello handshake message and the types in it.
func serverHelloExtensions(msg []byte) (offset int, types []uint16, err error) {
	// type(1) length(3) version(2) random(32)
	p := 4 + 2 + 32
	if len(msg) < p+1 || msg[0] != typeServerHello {
		return 0, nil, errors.New("reality: not a ServerHello")
	}
	p += 1 + int(msg[p]) // session id
	p += 2 + 1           // cipher suite, compression
	if len(msg) < p+2 {
		return 0, nil, errors.New("reality: short ServerHello")
	}
	offset = p
	end := p + 2 + int(binary.BigEndian.Uint16(msg[p:]))
	if end != len(msg) {
		return 0, nil, errors.New("reality: bad ServerHello extensions")
	}
	for p += 2; p < end; {
		if p+4 > end {
			return 0, nil, errors.New("reality: bad ServerHello extension")
		}
		types = append(types, binary.BigEndian.Uint16(msg[p:]))
		p += 4 + int(binary.BigEndian.Uint16(msg[p+2:]))
	}
	if p != end {
		return 0, nil, errors.New("reality: bad ServerHello extension")
	}
	return offset, types, nil
}

func serverHelloExtensionTypes(msg []byte) ([]uint16, error) {
	_, types, err := serverHelloExtensions(msg)
	return types, err
}
