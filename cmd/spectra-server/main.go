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
	listen := flag.String("listen", ":443", "QUIC listen address")
	pskHex := flag.String("psk", "", "Pre-shared key (hex, 64 chars)")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS private key file")
	profilePath := flag.String("profile", "configs/profiles/geforcenow.json", "Traffic profile JSON path")
	showVersion := flag.Bool("version", false, "Show SPECTRA version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SPECTRA %s\n", buildinfo.Version)
		return
	}

	// Environment variable overrides
	if env := os.Getenv("SPECTRA_PSK"); env != "" && *pskHex == "" {
		*pskHex = env
	}
	if env := os.Getenv("SPECTRA_LISTEN"); env != "" {
		*listen = env
	}
	if env := os.Getenv("SPECTRA_CERT"); env != "" {
		*certFile = env
	}
	if env := os.Getenv("SPECTRA_KEY"); env != "" {
		*keyFile = env
	}
	if env := os.Getenv("SPECTRA_PROFILE"); env != "" {
		*profilePath = env
	}

	if *pskHex == "" {
		log.Fatal("[server] PSK is required. Set via --psk or SPECTRA_PSK env var.")
	}
	if *certFile == "" || *keyFile == "" {
		log.Fatal("[server] TLS cert and key are required. Set via --cert/--key or SPECTRA_CERT/SPECTRA_KEY.")
	}

	psk, err := scrypto.PSKFromHex(*pskHex)
	if err != nil {
		log.Fatalf("[server] Invalid PSK: %v", err)
	}

	profile, err := camouflage.LoadProfile(*profilePath)
	if err != nil {
		log.Fatalf("[server] Failed to load profile: %v", err)
	}

	tlsCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("[server] Failed to load TLS certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"}, // Mimic HTTP/3 / cloud gaming ALPN
		MinVersion:   tls.VersionTLS13,
	}

	quicConfig := proxy.DefaultQUICConfig()

	listener, err := quic.ListenAddr(*listen, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("[server] Failed to listen on %s: %v", *listen, err)
	}

	log.Printf("[server] SPECTRA server listening on %s", *listen)
	log.Printf("[server] Profile: %s", profile.Name)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[server] Shutting down...")
		cancel()
		listener.Close()
	}()

	verifier := handshake.NewServerVerifier(psk)

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[server] Accept error: %v", err)
			continue
		}

		go handleConnection(ctx, conn, psk, verifier, profile)
	}
}

func handleConnection(ctx context.Context, conn quic.Connection, psk []byte, verifier *handshake.ServerVerifier, profile *camouflage.Profile) {
	log.Printf("[server] New connection from %s", conn.RemoteAddr())

	// Wait for the first stream (control stream for auth)
	authCtx, authCancel := context.WithTimeout(ctx, 5*time.Second)
	defer authCancel()

	stream, err := conn.AcceptStream(authCtx)
	if err != nil {
		log.Printf("[server] No auth stream received, serving decoy: %v", err)
		serveDecoy(conn)
		return
	}

	// Read AUTH_INIT
	initBuf := make([]byte, handshake.AuthInitSize)
	if _, err := io.ReadFull(stream, initBuf); err != nil {
		log.Printf("[server] Failed to read AUTH_INIT, serving decoy: %v", err)
		serveDecoy(conn)
		return
	}

	authInit, err := handshake.UnmarshalAuthInit(initBuf)
	if err != nil {
		log.Printf("[server] Invalid AUTH_INIT, serving decoy: %v", err)
		serveDecoy(conn)
		return
	}

	// Verify
	if err := verifier.VerifyAuthInit(authInit); err != nil {
		log.Printf("[server] Auth verification failed, serving decoy: %v", err)
		serveDecoy(conn)
		return
	}

	// Send AUTH_OK
	authOK, err := handshake.BuildAuthOK(psk, authInit.Salt)
	if err != nil {
		log.Printf("[server] Failed to build AUTH_OK: %v", err)
		conn.CloseWithError(1, "internal error")
		return
	}

	if _, err := stream.Write(authOK.Marshal()); err != nil {
		log.Printf("[server] Failed to send AUTH_OK: %v", err)
		return
	}

	// Read AUTH_CONFIRM
	confirmBuf := make([]byte, handshake.AuthConfirmSize)
	if _, err := io.ReadFull(stream, confirmBuf); err != nil {
		log.Printf("[server] Failed to read AUTH_CONFIRM: %v", err)
		return
	}

	// Derive session keys
	keys, err := scrypto.DeriveSessionKeysDirect(psk, authInit.Salt)
	if err != nil {
		log.Printf("[server] Key derivation failed: %v", err)
		return
	}

	// Decrypt and verify AUTH_CONFIRM
	confirmPlain, err := scrypto.Decrypt(
		keys.SessionKey,
		scrypto.BuildNonce(keys.BaseIV, scrypto.StreamControl, 0),
		confirmBuf,
		nil,
	)
	if err != nil || string(confirmPlain) != string(handshake.ConfirmPayload) {
		log.Printf("[server] AUTH_CONFIRM verification failed")
		serveDecoy(conn)
		return
	}

	log.Printf("[server] Authentication successful from %s", conn.RemoteAddr())
	stream.Close()

	// Create server tunnel and begin serving
	shaper := camouflage.NewShaper(profile)
	tunnel := proxy.NewServerTunnel(conn, keys, shaper)
	defer tunnel.Close()

	tunnel.Serve()
}

// serveDecoy sends an HTTP/3-like decoy response and closes the connection.
func serveDecoy(conn quic.Connection) {
	// Try to open a response stream
	stream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(0, "")
		return
	}

	decoyHTML := `<!DOCTYPE html>
<html>
<head><title>CloudPlay™ Gaming Service</title></head>
<body>
<h1>CloudPlay™</h1>
<p>Welcome to CloudPlay Gaming Service. Please use the CloudPlay client application to connect.</p>
<p>For support, visit <a href="https://support.cloudplay.example.com">our help center</a>.</p>
</body>
</html>`

	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nServer: nginx/1.25.3\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(decoyHTML), decoyHTML)

	stream.Write([]byte(resp))
	stream.Close()

	time.Sleep(100 * time.Millisecond)
	conn.CloseWithError(0, "")
}
