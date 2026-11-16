package reality

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/net"
)

// Session resumption the way browsers do it: the second and later
// connections to a server offer a ticket the server issued, in a
// pre_shared_key extension, and resume with a short handshake.
//
// A REALITY server issues tickets only to clients that set
// realityTicketsFlag; older servers ignore the flag and issue none, so the
// client keeps doing full handshakes with them. Tickets are kept only from
// connections the client verified as REALITY, and each is used once, at most
// two per server, as Chrome keeps them. A resumed connection is verified by
// completing: only the server that issued the ticket knows its key.

// realityTicketsFlag is the bit of the session id's reserved byte by which
// the client asks for tickets, see github.com/xtls/reality.
const realityTicketsFlag = 1

const (
	ticketsPerServer = 2
	ticketServers    = 256
)

var tickets = &ticketStore{sessions: make(map[string][]*utls.ClientSessionState)}

type ticketStore struct {
	sync.Mutex
	sessions map[string][]*utls.ClientSessionState
}

func (s *ticketStore) pop(key string) *utls.ClientSessionState {
	s.Lock()
	defer s.Unlock()
	list := s.sessions[key]
	if len(list) == 0 {
		return nil
	}
	session := list[len(list)-1]
	if len(list) == 1 {
		delete(s.sessions, key)
	} else {
		s.sessions[key] = list[:len(list)-1]
	}
	return session
}

func (s *ticketStore) push(key string, session *utls.ClientSessionState) {
	s.Lock()
	defer s.Unlock()
	list := s.sessions[key]
	if list == nil && len(s.sessions) >= ticketServers {
		for k := range s.sessions { // drop one server, whichever
			delete(s.sessions, k)
			break
		}
	}
	list = append(list, session)
	if len(list) > ticketsPerServer {
		list = list[len(list)-ticketsPerServer:]
	}
	s.sessions[key] = list
}

func (s *ticketStore) clear(key string) {
	s.Lock()
	defer s.Unlock()
	delete(s.sessions, key)
}

// connTickets is the ClientSessionCache of one connection. It holds the
// ticket the connection offers, taken from the store before the
// ClientHello is built, since the ClientHello depends on it; uTLS puts the
// tickets the server sends, and only those of a verified connection are
// kept.
type connTickets struct {
	key     string
	conn    *UConn
	session *utls.ClientSessionState
}

func (c *connTickets) Get(string) (*utls.ClientSessionState, bool) {
	session := c.session
	c.session = nil
	return session, session != nil
}

func (c *connTickets) Put(_ string, session *utls.ClientSessionState) {
	if session == nil {
		tickets.clear(c.key)
		return
	}
	if c.conn.Verified {
		tickets.push(c.key, session)
	}
}

// resumptionSpec returns the ClientHello of fingerprint as its browser
// sends it when it offers a ticket, or nil when that is the ClientHello of
// fingerprint plus pre_shared_key. Firefox drops the empty session_ticket
// extension then.
func resumptionSpec(fingerprint utls.ClientHelloID) *utls.ClientHelloSpec {
	if fingerprint.Client != "Firefox" {
		return nil
	}
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil
	}
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		if _, ok := extension.(utls.ISessionTicketExtension); !ok {
			extensions = append(extensions, extension)
		}
	}
	spec.Extensions = extensions
	return &spec
}

// ticketKey names the tickets of one REALITY server as one outbound sees it.
func ticketKey(config *Config, dest net.Destination, serverName string) string {
	return dest.NetAddr() + " " + serverName + " " + hex.EncodeToString(config.PublicKey) + " " +
		hex.EncodeToString(config.ShortId) + " " + config.Fingerprint
}

// resumesSessions reports whether the browser of fingerprint resumes
// sessions: its ClientHello advertises session_ticket and
// psk_key_exchange_modes, so pre_shared_key belongs in it once a ticket is
// there. Randomized fingerprints have no browser to follow.
func resumesSessions(fingerprint utls.ClientHelloID) bool {
	if strings.HasPrefix(fingerprint.Client, "Randomized") {
		return false
	}
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return false
	}
	hasModes, hasTicket, hasTLS13 := false, false, false
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case utls.PreSharedKeyExtension:
			return false
		case *utls.PSKKeyExchangeModesExtension:
			hasModes = true
		case utls.ISessionTicketExtension:
			hasTicket = true
		case *utls.SupportedVersionsExtension:
			hasTLS13 = slices.Contains(e.Versions, utls.VersionTLS13)
		}
	}
	return hasModes && hasTicket && hasTLS13
}

// offeredPSK returns the pre_shared_key extension of the built ClientHello
// if it offers a ticket.
func offeredPSK(uConn *utls.UConn) *utls.UtlsPreSharedKeyExtension {
	for _, extension := range uConn.Extensions {
		if psk, ok := extension.(*utls.UtlsPreSharedKeyExtension); ok && len(psk.Identities) != 0 {
			return psk
		}
	}
	return nil
}

// pskAAD returns the additional data of the session id of a ClientHello
// that offers a ticket: the ClientHello with its binders zeroed, as the
// binders cover the session id.
func pskAAD(raw []byte, binders [][]byte) []byte {
	n := 2
	for _, binder := range binders {
		n += 1 + len(binder)
	}
	aad := bytes.Clone(raw)
	if n <= len(aad) {
		clear(aad[len(aad)-n:])
	}
	return aad
}
