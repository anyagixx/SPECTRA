package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// ConnectRequest represents a parsed SOCKS5 CONNECT request destined for the tunnel.
type ConnectRequest struct {
	DestAddr string
	DestPort int
	Conn     net.Conn // The accepted SOCKS5 client connection
}

// TunnelDialer is the interface the SOCKS5 server uses to send connections through the SPECTRA tunnel.
type TunnelDialer interface {
	DialTunnel(ctx context.Context, destAddr string) (io.ReadWriteCloser, error)
}

// Socks5Server wraps go-socks5 and routes connections through the SPECTRA tunnel.
type Socks5Server struct {
	listenAddr string
	dialer     TunnelDialer
	server     *socks5.Server
	listener   net.Listener
	mu         sync.Mutex
}

// NewSocks5Server creates a SOCKS5 server that tunnels through the given dialer.
func NewSocks5Server(listenAddr string, dialer TunnelDialer) (*Socks5Server, error) {
	s := &Socks5Server{
		listenAddr: listenAddr,
		dialer:     dialer,
	}

	server := socks5.NewServer(
		socks5.WithDialAndRequest(s.dialViaSpectrumWithRequest),
		socks5.WithLogger(socks5.NewLogger(log.Default())),
	)

	s.server = server
	return s, nil
}

// dialViaSpectrum is the custom dialer that routes SOCKS5 connections through the SPECTRA tunnel.
func (s *Socks5Server) dialViaSpectrum(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.Lock()
	dialer := s.dialer
	s.mu.Unlock()

	if dialer == nil {
		return nil, fmt.Errorf("proxy: tunnel not connected")
	}

	rwc, err := dialer.DialTunnel(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: tunnel dial failed for %s: %w", addr, err)
	}

	// Wrap ReadWriteCloser as net.Conn if needed
	if conn, ok := rwc.(net.Conn); ok {
		return conn, nil
	}

	return &rwcConn{rwc: rwc, addr: addr}, nil
}

// dialViaSpectrumWithRequest preserves the original FQDN when the SOCKS5 client
// asked for remote hostname resolution, avoiding local DNS leakage on the client.
func (s *Socks5Server) dialViaSpectrumWithRequest(ctx context.Context, network, addr string, req *socks5.Request) (net.Conn, error) {
	destAddr := addr
	if req != nil && req.RawDestAddr != nil && req.RawDestAddr.FQDN != "" {
		destAddr = net.JoinHostPort(req.RawDestAddr.FQDN, strconv.Itoa(req.RawDestAddr.Port))
	}
	return s.dialViaSpectrum(ctx, network, destAddr)
}

// ListenAndServe starts the SOCKS5 server.
func (s *Socks5Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("proxy: failed to listen on %s: %w", s.listenAddr, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	log.Printf("[SOCKS5] Listening on %s", s.listenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return s.server.Serve(ln)
}

// SwapDialer atomically replaces the tunnel dialer (used during reconnect).
func (s *Socks5Server) SwapDialer(dialer TunnelDialer) {
	s.mu.Lock()
	s.dialer = dialer
	s.mu.Unlock()
}

// Close stops the SOCKS5 server.
func (s *Socks5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// rwcConn wraps an io.ReadWriteCloser to satisfy net.Conn.
type rwcConn struct {
	rwc  io.ReadWriteCloser
	addr string
}

func (c *rwcConn) Read(b []byte) (int, error)  { return c.rwc.Read(b) }
func (c *rwcConn) Write(b []byte) (int, error) { return c.rwc.Write(b) }
func (c *rwcConn) Close() error                { return c.rwc.Close() }

func (c *rwcConn) CloseWrite() error {
	if cw, ok := c.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *rwcConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *rwcConn) RemoteAddr() net.Addr               { return parseAddr(c.addr) }
func (c *rwcConn) SetDeadline(_ time.Time) error      { return nil }
func (c *rwcConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *rwcConn) SetWriteDeadline(_ time.Time) error { return nil }

func parseAddr(addr string) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	return a
}

// DirectDialer dials upstream TCP connections directly (used on the server side).
type DirectDialer struct{}

// Dial connects to the target address directly over TCP.
func (d *DirectDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// ParseSOCKS5Addr parses a SOCKS5 address into host:port string.
func ParseSOCKS5Addr(req *statute.AddrSpec) string {
	if req.FQDN != "" {
		return fmt.Sprintf("%s:%d", req.FQDN, req.Port)
	}
	return fmt.Sprintf("%s:%d", req.IP.String(), req.Port)
}
