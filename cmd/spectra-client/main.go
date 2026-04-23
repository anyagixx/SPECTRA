package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/anyagixx/SPECTRA/internal/buildinfo"
	"github.com/anyagixx/SPECTRA/internal/camouflage"
	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
	"github.com/anyagixx/SPECTRA/internal/handshake"
	"github.com/anyagixx/SPECTRA/internal/proxy"
)

func main() {
	serverAddr := flag.String("server", "", "SPECTRA server address (host:port)")
	sni := flag.String("sni", "", "TLS SNI hostname")
	pskHex := flag.String("psk", "", "Pre-shared key (hex, 64 chars)")
	socksListen := flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address")
	profilePath := flag.String("profile", "configs/profiles/geforcenow.json", "Traffic profile JSON path")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (testing only)")
	showVersion := flag.Bool("version", false, "Show SPECTRA version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SPECTRA %s\n", buildinfo.Version)
		return
	}

	// Environment variable overrides
	if env := os.Getenv("SPECTRA_SERVER"); env != "" && *serverAddr == "" {
		*serverAddr = env
	}
	if env := os.Getenv("SPECTRA_SNI"); env != "" && *sni == "" {
		*sni = env
	}
	if env := os.Getenv("SPECTRA_PSK"); env != "" && *pskHex == "" {
		*pskHex = env
	}
	if env := os.Getenv("SPECTRA_SOCKS_LISTEN"); env != "" {
		*socksListen = env
	}
	if env := os.Getenv("SPECTRA_PROFILE"); env != "" {
		*profilePath = env
	}

	if *serverAddr == "" {
		log.Fatal("[client] Server address is required. Set via --server or SPECTRA_SERVER.")
	}
	if *pskHex == "" {
		log.Fatal("[client] PSK is required. Set via --psk or SPECTRA_PSK.")
	}
	if *sni == "" {
		// Extract hostname from server address
		host := *serverAddr
		for i := len(host) - 1; i >= 0; i-- {
			if host[i] == ':' {
				host = host[:i]
				break
			}
		}
		*sni = host
	}

	psk, err := scrypto.PSKFromHex(*pskHex)
	if err != nil {
		log.Fatalf("[client] Invalid PSK: %v", err)
	}

	profile, err := camouflage.LoadProfile(*profilePath)
	if err != nil {
		log.Fatalf("[client] Failed to load profile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[client] Shutting down...")
		cancel()
	}()

	// Create SOCKS5 server (dialer will be set on first connect)
	socks, err := proxy.NewSocks5Server(*socksListen, nil)
	if err != nil {
		log.Fatalf("[client] Failed to create SOCKS5 server: %v", err)
	}

	// Start SOCKS5 listener once — it persists across reconnects
	go func() {
		if err := socks.ListenAndServe(ctx); err != nil {
			if ctx.Err() == nil {
				log.Fatalf("[client] SOCKS5 server error: %v", err)
			}
		}
	}()
	log.Printf("[client] SOCKS5 proxy listening on %s", *socksListen)

	// Reconnect loop
	for {
		if ctx.Err() != nil {
			return
		}

		tunnel, err := connectWithRetry(ctx, *serverAddr, *sni, psk, profile, *insecure)
		if err != nil {
			return // context cancelled
		}

		log.Printf("[client] Tunnel established to %s", *serverAddr)
		socks.SwapDialer(tunnel)
		tunnel.StartPaddingGenerator()
		go tunnel.RunReceiver()

		// Wait for tunnel death or app shutdown
		select {
		case <-tunnel.Done():
		case <-ctx.Done():
		}

		tunnel.Close()

		if ctx.Err() != nil {
			return // clean shutdown
		}

		log.Println("[client] Connection lost, reconnecting...")
	}
}

// connectWithRetry keeps trying to connect with exponential backoff until success
// or context cancellation.
func connectWithRetry(ctx context.Context, addr, sni string, psk []byte, profile *camouflage.Profile, insecure bool) (*proxy.ClientTunnel, error) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		tunnel, err := connectToServer(ctx, addr, sni, psk, profile, insecure)
		if err == nil {
			return tunnel, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		log.Printf("[client] Connection failed: %v, retrying in %v...", err, backoff)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connectToServer establishes the QUIC connection and performs the SPECTRA handshake.
func connectToServer(ctx context.Context, addr, sni string, psk []byte, profile *camouflage.Profile, insecure bool) (*proxy.ClientTunnel, error) {
	tlsConfig := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecure,
	}

	quicConfig := proxy.DefaultQUICConfig()

	log.Printf("[client] Connecting to %s (SNI: %s)...", addr, sni)

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	// Open control stream for handshake
	stream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(1, "handshake failed")
		return nil, err
	}

	// Build and send AUTH_INIT
	authInit, err := handshake.BuildAuthInit(psk)
	if err != nil {
		conn.CloseWithError(1, "handshake failed")
		return nil, err
	}

	if _, err := stream.Write(authInit.Marshal()); err != nil {
		conn.CloseWithError(1, "handshake failed")
		return nil, err
	}

	// Read AUTH_OK
	okBuf := make([]byte, handshake.AuthOKSize)
	if _, err := io.ReadFull(stream, okBuf); err != nil {
		conn.CloseWithError(1, "handshake failed")
		return nil, err
	}

	authOK, err := handshake.UnmarshalAuthOK(okBuf)
	if err != nil {
		conn.CloseWithError(1, "handshake failed")
		return nil, err
	}

	// Verify server response
	if err := handshake.VerifyAuthOK(psk, authInit.Salt, authOK); err != nil {
		conn.CloseWithError(1, "server auth failed")
		return nil, err
	}

	// Derive session keys
	keys, err := scrypto.DeriveSessionKeysDirect(psk, authInit.Salt)
	if err != nil {
		conn.CloseWithError(1, "key derivation failed")
		return nil, err
	}

	// Send AUTH_CONFIRM (encrypted "SPECTRA-READY")
	confirmCipher, err := scrypto.Encrypt(
		keys.SessionKey,
		scrypto.BuildNonce(keys.BaseIV, scrypto.StreamControl, 0),
		handshake.ConfirmPayload,
		nil,
	)
	if err != nil {
		conn.CloseWithError(1, "auth confirm failed")
		return nil, err
	}

	if _, err := stream.Write(confirmCipher); err != nil {
		conn.CloseWithError(1, "auth confirm failed")
		return nil, err
	}

	stream.Close()
	log.Printf("[client] Authentication successful")

	// Create tunnel
	shaper := camouflage.NewShaper(profile)
	tunnel := proxy.NewClientTunnel(conn, keys, shaper)

	return tunnel, nil
}
