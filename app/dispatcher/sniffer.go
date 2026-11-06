package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/bittorrent"
	"github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/common/protocol/stun"
	"github.com/xtls/xray-core/common/protocol/tls"
)

type SniffResult interface {
	Protocol() string
	Domain() string
}

type protocolSniffer func(context.Context, []byte) (SniffResult, error)

// datagramSniffer sniffs a UDP flow from its datagrams kept apart; payload
// concatenates them, as a protocolSniffer reads them.
type datagramSniffer func(ctx context.Context, payload []byte, datagrams [][]byte) (SniffResult, error)

type protocolSnifferWithMetadata struct {
	protocolSniffer protocolSniffer
	// datagramSniffer, when set, takes the place of protocolSniffer when the
	// datagrams of a UDP flow can be told apart.
	datagramSniffer datagramSniffer
	// A Metadata sniffer will be invoked on connection establishment only, with nil body,
	// for both TCP and UDP connections
	// It will not be shown as a traffic type for routing unless there is no other successful sniffing.
	metadataSniffer bool
	network         net.Network
}

type Sniffer struct {
	sniffer []protocolSnifferWithMetadata
}

func NewSniffer(ctx context.Context) *Sniffer {
	ret := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			// Before HTTP, which would take a tracker request for HTTP.
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffHTTPTracker(b) }, network: net.Network_TCP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return http.SniffHTTP(b, c) }, network: net.Network_TCP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return tls.SniffTLS(b) }, network: net.Network_TCP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffBittorrent(b) }, network: net.Network_TCP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return stun.SniffSTUN(b) }, network: net.Network_TCP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return quic.SniffQUIC(b) }, network: net.Network_UDP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffUTP(b) }, network: net.Network_UDP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffDHT(b) }, network: net.Network_UDP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffUDPTracker(b) }, network: net.Network_UDP},
			{protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffLSD(b) }, network: net.Network_UDP},
			{
				protocolSniffer: func(c context.Context, b []byte) (SniffResult, error) { return stun.SniffSTUN(b) },
				// A STUN message over UDP is its first datagram.
				datagramSniffer: func(_ context.Context, _ []byte, datagrams [][]byte) (SniffResult, error) {
					return stun.SniffSTUNDatagram(datagrams[0])
				},
				network: net.Network_UDP,
			},
		},
	}
	if sniffer, err := newFakeDNSSniffer(ctx); err == nil {
		others := ret.sniffer
		ret.sniffer = append(ret.sniffer, sniffer)
		fakeDNSThenOthers, err := newFakeDNSThenOthers(ctx, sniffer, others)
		if err == nil {
			ret.sniffer = append([]protocolSnifferWithMetadata{fakeDNSThenOthers}, ret.sniffer...)
		}
	}
	return ret
}

var errUnknownContent = errors.New("unknown content")

func (s *Sniffer) Sniff(c context.Context, payload []byte, network net.Network) (SniffResult, error) {
	return s.SniffDatagrams(c, payload, nil, network)
}

// SniffDatagrams is Sniff for a payload that concatenates the datagrams of a
// UDP flow, given apart as well: a sniffer that reads datagrams on their own
// gets them, the others the payload.
func (s *Sniffer) SniffDatagrams(c context.Context, payload []byte, datagrams [][]byte, network net.Network) (SniffResult, error) {
	var pendingSniffer []protocolSnifferWithMetadata
	for _, si := range s.sniffer {
		protocolSniffer := si.protocolSniffer
		if si.metadataSniffer || si.network != network {
			continue
		}
		var result SniffResult
		var err error
		if si.datagramSniffer != nil && len(datagrams) != 0 {
			result, err = si.datagramSniffer(c, payload, datagrams)
		} else {
			result, err = protocolSniffer(c, payload)
		}
		if err == common.ErrNoClue {
			pendingSniffer = append(pendingSniffer, si)
			continue
		} else if err == protocol.ErrProtoNeedMoreData { // Sniffer protocol matched, but need more data to complete sniffing
			s.sniffer = []protocolSnifferWithMetadata{si}
			return nil, err
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if len(pendingSniffer) > 0 {
		s.sniffer = pendingSniffer
		return nil, common.ErrNoClue
	}

	return nil, errUnknownContent
}

func (s *Sniffer) SniffMetadata(c context.Context) (SniffResult, error) {
	var pendingSniffer []protocolSnifferWithMetadata
	for _, si := range s.sniffer {
		s := si.protocolSniffer
		if !si.metadataSniffer {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}
		result, err := s(c, nil)
		if err == common.ErrNoClue {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if len(pendingSniffer) > 0 {
		s.sniffer = pendingSniffer
		return nil, common.ErrNoClue
	}

	return nil, errUnknownContent
}

func CompositeResult(domainResult SniffResult, protocolResult SniffResult) SniffResult {
	return &compositeResult{domainResult: domainResult, protocolResult: protocolResult}
}

type compositeResult struct {
	domainResult   SniffResult
	protocolResult SniffResult
}

func (c compositeResult) Protocol() string {
	return c.protocolResult.Protocol()
}

func (c compositeResult) Domain() string {
	return c.domainResult.Domain()
}

func (c compositeResult) ProtocolForDomainResult() string {
	return c.domainResult.Protocol()
}

type SnifferResultComposite interface {
	ProtocolForDomainResult() string
}

type SnifferIsProtoSubsetOf interface {
	IsProtoSubsetOf(protocolName string) bool
}
