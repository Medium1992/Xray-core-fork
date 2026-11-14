package dispatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
)

// With "fakedns+others", a flow to a fake address the engine has no domain
// for is sniffed by the other sniffers through a wrapper, which must hand the
// sniffers that read datagrams apart the datagrams too: two uTP SYNs or a
// Discord request read in one batch are still told.
func TestFakeDNSThenOthersSniffsDatagramsApart(t *testing.T) {
	inRange := protocolSnifferWithMetadata{
		protocolSniffer: func(ctx context.Context, _ []byte) (SniffResult, error) {
			yes := true
			ctx.Value(ipAddressInRange).(*ipAddressInRangeOpt).addressInRange = &yes
			return nil, common.ErrNoClue
		},
		metadataSniffer: true,
	}
	wrapper, err := newFakeDNSThenOthers(context.Background(), inRange, defaultProtocolSniffers)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		datagrams [][]byte
		protocol  string
	}{
		"uTP SYN twice":     {[][]byte{vUTPSYN(), vUTPSYN()}, "bittorrent"},
		"Discord, then RTP": {[][]byte{discordIPDiscovery(), make([]byte, 60)}, "discordrtc"},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := wrapper.datagramSniffer(context.Background(), bytes.Join(tc.datagrams, nil), tc.datagrams)
			others, ok := result.(DNSThenOthersSniffResult)
			if err != nil || !ok || others.protocolOriginalName != tc.protocol {
				t.Fatalf("sniffed %v, %v; want %s", result, err, tc.protocol)
			}
		})
	}
}
