package scenarios

import (
	"bufio"
	"fmt"
	"io"
	gonet "net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/testing/servers/tcp"
	xproxy "golang.org/x/net/proxy"
)

// halfCloseTarget answers a request in one of two ways:
//
//   - "close": it replies and closes, ending a close-delimited answer;
//   - "after-eof": it reads until the client's FIN, then replies and closes.
type halfCloseTarget struct {
	ln   gonet.Listener
	mode string
}

func startHalfCloseTarget(t *testing.T, mode string) *halfCloseTarget {
	t.Helper()
	ln, err := gonet.Listen("tcp4", "127.0.0.1:0")
	common.Must(err)
	target := &halfCloseTarget{ln: ln, mode: mode}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go target.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return target
}

func (s *halfCloseTarget) serve(conn gonet.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	switch s.mode {
	case "close":
		buf := make([]byte, 64)
		conn.Read(buf)
		conn.Write([]byte("reply"))
	case "after-eof":
		io.Copy(io.Discard, conn)
		conn.Write([]byte("reply after eof"))
	}
}

func (s *halfCloseTarget) port() net.Port {
	return net.Port(s.ln.Addr().(*gonet.TCPAddr).Port)
}

// halfCloseProxy runs one Xray with a SOCKS, an HTTP and a dokodemo-door
// inbound, all to freedom.
func halfCloseProxy(t *testing.T, dokodemoTarget net.Port) (socksPort, httpPort, dokodemoPort net.Port) {
	t.Helper()
	socksPort, httpPort, dokodemoPort = tcp.PickPort(), tcp.PickPort(), tcp.PickPort()
	receiver := func(port net.Port) *serial.TypedMessage {
		return serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
			Listen:   net.NewIPOrDomain(net.LocalHostIP),
		})
	}
	config := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: receiver(socksPort),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
					Address:  net.NewIPOrDomain(net.LocalHostIP),
				}),
			},
			{
				ReceiverSettings: receiver(httpPort),
				ProxySettings:    serial.ToTypedMessage(&http.ServerConfig{}),
			},
			{
				ReceiverSettings: receiver(dokodemoPort),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
					RewritePort:     uint32(dokodemoTarget),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}
	servers, err := InitializeServerConfigs(config)
	common.Must(err)
	t.Cleanup(func() { CloseAllServers(servers) })
	return
}

type halfCloseDialer func(target net.Port) (*gonet.TCPConn, error)

func halfCloseDialers(socksPort, httpPort, dokodemoPort net.Port) map[string]halfCloseDialer {
	return map[string]halfCloseDialer{
		"socks": func(target net.Port) (*gonet.TCPConn, error) {
			dialer, err := xproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, xproxy.Direct)
			if err != nil {
				return nil, err
			}
			conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", target))
			if err != nil {
				return nil, err
			}
			return conn.(*gonet.TCPConn), nil
		},
		"http connect": func(target net.Port) (*gonet.TCPConn, error) {
			conn, err := gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", target, target)
			// Read the status line and headers byte by byte, so nothing of the
			// tunneled stream is left in a buffer.
			var header strings.Builder
			b := make([]byte, 1)
			for !strings.HasSuffix(header.String(), "\r\n\r\n") {
				if _, err := conn.Read(b); err != nil {
					conn.Close()
					return nil, err
				}
				header.WriteByte(b[0])
			}
			status, _ := bufio.NewReader(strings.NewReader(header.String())).ReadString('\n')
			if !strings.Contains(status, " 200 ") {
				conn.Close()
				return nil, fmt.Errorf("CONNECT: %q", status)
			}
			return conn.(*gonet.TCPConn), nil
		},
		"dokodemo": func(net.Port) (*gonet.TCPConn, error) {
			conn, err := gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", dokodemoPort))
			if err != nil {
				return nil, err
			}
			return conn.(*gonet.TCPConn), nil
		},
	}
}

// When the target closes after its answer, the client reads the end of the
// answer as the target sent it, not once the inbound's uplinkOnly timer
// (1 s by default) has run out on the client's idle upload.
func TestHalfCloseTargetEndReachesTheClient(t *testing.T) {
	target := startHalfCloseTarget(t, "close")
	socksPort, httpPort, dokodemoPort := halfCloseProxy(t, target.port())
	for name, dial := range halfCloseDialers(socksPort, httpPort, dokodemoPort) {
		t.Run(name, func(t *testing.T) {
			conn, err := dial(target.port())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			start := time.Now()
			if _, err := conn.Write([]byte("request")); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			elapsed := time.Since(start)
			if err != nil || string(got) != "reply" {
				t.Fatalf("read %q, %v; want the reply and EOF", got, err)
			}
			if elapsed > 500*time.Millisecond {
				t.Fatalf("EOF arrived after %v; the target closed at once", elapsed.Round(time.Millisecond))
			}
		})
	}
}

// A client that half-closes after its request reaches a target that answers
// only on EOF: the FIN is passed on, and the answer comes back.
func TestHalfCloseClientEndReachesTheTarget(t *testing.T) {
	target := startHalfCloseTarget(t, "after-eof")
	socksPort, httpPort, dokodemoPort := halfCloseProxy(t, target.port())
	for name, dial := range halfCloseDialers(socksPort, httpPort, dokodemoPort) {
		t.Run(name, func(t *testing.T) {
			conn, err := dial(target.port())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("request")); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			if err != nil || string(got) != "reply after eof" {
				t.Fatalf("read %q, %v; want the target's answer to the client's FIN", got, err)
			}
		})
	}
}
