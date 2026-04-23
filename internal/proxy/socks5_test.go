package proxy

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type nopRWC struct{}

func (nopRWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopRWC) Write(b []byte) (int, error) { return len(b), nil }
func (nopRWC) Close() error                { return nil }

type closeWriteRWC struct {
	nopRWC
	closeWriteCalled bool
}

func (r *closeWriteRWC) CloseWrite() error {
	r.closeWriteCalled = true
	return nil
}

type recordingDialer struct {
	lastDest string
}

func (d *recordingDialer) DialTunnel(_ context.Context, destAddr string) (io.ReadWriteCloser, error) {
	d.lastDest = destAddr
	return nopRWC{}, nil
}

func TestRWCConnLocalAddrIsSerializable(t *testing.T) {
	conn := &rwcConn{rwc: nopRWC{}, addr: "example.com:443"}

	addr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("LocalAddr type = %T, want *net.TCPAddr", conn.LocalAddr())
	}
	if addr.IP == nil || addr.IP.To4() == nil {
		t.Fatalf("LocalAddr IP = %v, want IPv4 zero address", addr.IP)
	}
}

func TestRWCConnCloseWriteDelegatesToWrappedConnection(t *testing.T) {
	wrapped := &closeWriteRWC{}
	conn := &rwcConn{rwc: wrapped, addr: "example.com:443"}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}
	if !wrapped.closeWriteCalled {
		t.Fatal("CloseWrite should delegate to wrapped connection")
	}
}

func TestDialViaSpectrumWithRequestPreservesFQDN(t *testing.T) {
	dialer := &recordingDialer{}
	server, err := NewSocks5Server("127.0.0.1:0", dialer)
	if err != nil {
		t.Fatalf("NewSocks5Server failed: %v", err)
	}

	req := &socks5.Request{
		RawDestAddr: &statute.AddrSpec{
			FQDN: "example.com",
			IP:   net.IPv4(8, 8, 8, 8),
			Port: 443,
		},
	}

	conn, err := server.dialViaSpectrumWithRequest(context.Background(), "tcp", "8.8.8.8:443", req)
	if err != nil {
		t.Fatalf("dialViaSpectrumWithRequest failed: %v", err)
	}
	defer conn.Close()

	if dialer.lastDest != "example.com:443" {
		t.Fatalf("DialTunnel called with %q, want %q", dialer.lastDest, "example.com:443")
	}
}

func TestClientTunnelDialTunnelRejectsClosedTunnel(t *testing.T) {
	keys := &scrypto.SessionKeys{
		SessionKey: make([]byte, scrypto.SessionKeySize),
		BaseIV:     make([]byte, scrypto.BaseIVSize),
	}
	tunnel := NewClientTunnel(nil, keys, nil)
	tunnel.cancel()

	conn, err := tunnel.DialTunnel(context.Background(), "example.com:443")
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("DialTunnel should fail on a closed tunnel")
	}
	if !strings.Contains(err.Error(), "tunnel closed") {
		t.Fatalf("DialTunnel error = %q, want tunnel closed", err)
	}
}
