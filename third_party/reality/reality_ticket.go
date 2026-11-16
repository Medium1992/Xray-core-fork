package reality

import (
	"bytes"
	"crypto/aes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/xtls/reality/tls13"
)

// Reality specific file: session tickets in the shape of the target's.
//
// A client asks for tickets with realityTicketsFlag in the reserved byte of
// its encrypted session id; others get the empty records they always got.
// The tickets are encrypted with a key derived from the private key, so
// every server sharing the key accepts them, across restarts. A client that
// offers one seals its session id over the ClientHello with the binders
// zeroed, as the binders cover the session id.

// realityTicketsFlag is the bit of the session id's reserved byte by which
// a client asks for tickets.
const realityTicketsFlag = 1

// recordsKey is the key of GlobalPostHandshakeRecordsLens and
// GlobalTicketShapes for this ClientHello.
func recordsKey(config *Config, hello *clientHelloMsg) (key string, alpn int) {
	switch {
	case len(hello.alpnProtocols) == 0:
		alpn = 0
	case hello.alpnProtocols[0] == "h2":
		alpn = 2
	default:
		alpn = 1
	}
	return config.Dest + " " + hello.serverName + " " + strconv.Itoa(alpn), alpn
}

// pskAAD returns the additional data of the session id of a ClientHello
// that offers a ticket: the ClientHello with its binders zeroed.
func pskAAD(original []byte, binders [][]byte) []byte {
	n := 2
	for _, binder := range binders {
		n += 1 + len(binder)
	}
	aad := bytes.Clone(original)
	if n <= len(aad) {
		clear(aad[len(aad)-n:])
	}
	return aad
}

// realityTicketKeys derives the session ticket key from the private key.
func (c *Config) realityTicketKeys() []ticketKey {
	if c.PrivateKey == nil {
		return nil
	}
	secret, err := hkdf.Key(sha256.New, c.PrivateKey.Bytes(), nil, "REALITY session ticket", 32)
	if err != nil {
		return nil
	}
	return []ticketKey{c.ticketKeyFromBytes([32]byte(secret))}
}

// realityTicketMsg returns a NewSessionTicket that fills a record of
// recordLen bytes as the target's does: a nonce as long as the target's and
// the ticket taking the rest, or nil if it cannot.
func (c *Conn) realityTicketMsg(shape *TicketShape, recordLen int) []byte {
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	keys := c.config.realityTicketKeys()
	if _, ok := c.out.cipher.(aead); suite == nil || !ok || c.resumptionSecret == nil || keys == nil {
		return nil
	}
	ticketLen := recordLen - ticketRecordOverhead - shape.NonceLen
	if ticketLen < len(shape.Prefix) {
		return nil
	}
	nonce := make([]byte, shape.NonceLen)
	ageAdd := make([]byte, 4)
	if _, err := io.ReadFull(c.config.rand(), nonce); err != nil {
		return nil
	}
	if _, err := io.ReadFull(c.config.rand(), ageAdd); err != nil {
		return nil
	}

	state := c.sessionState()
	state.secret = tls13.ExpandLabel(suite.hash.New, c.resumptionSecret, "resumption", nonce, suite.hash.Size())
	// An Extra entry pads the encrypted state to the length of the
	// target's tickets; the entry itself takes 3 bytes.
	base, err := state.Bytes()
	if err != nil {
		return nil
	}
	sealed := ticketLen - len(shape.Prefix)
	if pad := sealed - aes.BlockSize - sha256.Size - len(base); pad >= 3 {
		state.Extra = [][]byte{make([]byte, pad-3)}
	} else if pad != 0 {
		return nil
	}
	stateBytes, err := state.Bytes()
	if err != nil || aes.BlockSize+len(stateBytes)+sha256.Size != sealed {
		return nil
	}
	ticket, err := c.config.encryptTicket(stateBytes, keys)
	if err != nil {
		return nil
	}
	m := &newSessionTicketMsgTLS13{
		lifetime: shape.Lifetime,
		ageAdd:   binary.LittleEndian.Uint32(ageAdd),
		nonce:    nonce,
		label:    append(bytes.Clone(shape.Prefix), ticket...),
	}
	msg, err := m.marshal()
	if err != nil {
		return nil
	}
	return msg
}

// writeTicketRecord writes msg as a handshake record of length bytes, after
// the handshake, the way the empty records of the target's lengths are.
func (c *Conn) writeTicketRecord(msg []byte, length int) error {
	plainText := make([]byte, length-c.out.cipher.(aead).Overhead())
	if len(plainText) < recordHeaderLen+len(msg)+1 {
		return errors.New("reality: ticket does not fit its record")
	}
	plainText[0] = byte(recordTypeApplicationData)
	plainText[1] = 3
	plainText[2] = 3
	binary.BigEndian.PutUint16(plainText[3:], uint16(length-recordHeaderLen))
	copy(plainText[recordHeaderLen:], msg)
	plainText[recordHeaderLen+len(msg)] = byte(recordTypeHandshake)
	record := c.out.cipher.(aead).Seal(plainText[:recordHeaderLen], c.out.seq[:], plainText[recordHeaderLen:], plainText[:recordHeaderLen])
	c.out.incSeq()
	_, err := c.write(record)
	return err
}

// realityResume accepts the ticket the client offers if REALITY issued it,
// and turns the handshake into a resumed one in the shape the target
// resumes its own tickets: a ServerHello with pre_shared_key and no
// certificate. Otherwise the handshake stays a full one, as with a target
// that does not know a ticket.
func (hs *serverHandshakeStateTLS13) realityResume(shape *TicketShape) bool {
	c := hs.c
	ch := hs.clientHello
	if !slices.Contains(ch.pskModes, pskModeDHE) || len(ch.pskIdentities) == 0 ||
		len(ch.pskIdentities) != len(ch.pskBinders) {
		return false
	}
	// Only targets that send one record per handshake message.
	if c.out.handshakeBuf != nil || c.out.handshakeLen[2] == 0 || c.out.handshakeLen[5] == 0 {
		return false
	}
	label := ch.pskIdentities[0].label
	if !bytes.HasPrefix(label, shape.Prefix) {
		return false
	}
	plaintext := c.config.decryptTicket(label[len(shape.Prefix):], c.config.realityTicketKeys())
	if plaintext == nil {
		return false
	}
	session, err := ParseSessionState(plaintext)
	if err != nil || session.version != VersionTLS13 || session.isClient {
		return false
	}
	age := c.config.time().Sub(time.Unix(int64(session.createdAt), 0))
	if age < -time.Minute || age > time.Duration(shape.Lifetime)*time.Second {
		return false
	}
	pskSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if pskSuite == nil || pskSuite.hash != hs.suite.hash {
		return false
	}
	earlySecret := tls13.NewEarlySecret(hs.suite.hash.New, session.secret)
	transcript := hs.suite.hash.New()
	helloBytes, err := ch.marshalWithoutBinders()
	if err != nil {
		return false
	}
	transcript.Write(helloBytes)
	if !hmac.Equal(ch.pskBinders[0], hs.suite.finishedHash(earlySecret.ResumptionBinderKey(), transcript)) {
		return false
	}
	ee := c.out.handshakeLen[2] + shape.ResRecords[0] - shape.FullRecords[0]
	if ee <= recordHeaderLen {
		return false
	}
	hello, err := insertPSKExtension(hs.hello.original, shape.PSKIndex)
	if err != nil {
		return false
	}

	hs.hello.original = hello
	hs.hello.selectedIdentityPresent = true
	hs.hello.selectedIdentity = 0
	hs.earlySecret = earlySecret
	hs.usingPSK = true
	c.didResume = true
	c.out.handshakeLen[2] = ee
	c.out.handshakeLen[3] = 0
	c.out.handshakeLen[4] = 0
	if c.out.handshakeLen[6] != 0 && len(shape.ResRecords) > 2 {
		c.out.handshakeLen[6] = shape.ResRecords[2]
	}
	return true
}

// insertPSKExtension adds pre_shared_key, selecting the first identity, to
// a ServerHello handshake message at the index of the extensions.
func insertPSKExtension(hello []byte, index int) ([]byte, error) {
	offset, types, err := serverHelloExtensions(hello)
	if err != nil {
		return nil, err
	}
	if slices.Contains(types, extensionPreSharedKey) || index > len(types) {
		return nil, errors.New("reality: cannot add pre_shared_key")
	}
	at := offset + 2
	for range index {
		at += 4 + int(binary.BigEndian.Uint16(hello[at+2:]))
	}
	ext := []byte{0, byte(extensionPreSharedKey), 0, 2, 0, 0}
	out := make([]byte, 0, len(hello)+len(ext))
	out = append(out, hello[:at]...)
	out = append(out, ext...)
	out = append(out, hello[at:]...)
	msgLen := len(out) - 4
	out[1], out[2], out[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)
	binary.BigEndian.PutUint16(out[offset:], uint16(len(out)-offset-2))
	return out, nil
}

// postHandshakeRecords returns the records to send after the client's
// Finished, given the target's after a full handshake, and how many of the
// first of them are tickets.
func (hs *serverHandshakeStateTLS13) postHandshakeRecords(lens []int) ([]int, int) {
	shape := hs.ticketShape
	if shape == nil {
		return lens, 0
	}
	inFlight := 0
	if hs.ticketInFlight {
		inFlight = 1
	}
	if hs.usingPSK {
		return shape.ResRecords[min(2+inFlight, len(shape.ResRecords)):], max(shape.ResTickets-inFlight, 0)
	}
	return lens, max(shape.Tickets-inFlight, 0)
}
