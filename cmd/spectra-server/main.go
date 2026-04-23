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

	const maxConcurrent = 256
	sem := make(chan struct{}, maxConcurrent)

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[server] Accept error: %v", err)
			continue
		}

		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				handleConnection(ctx, conn, psk, verifier, profile)
			}()
		default:
			log.Printf("[server] Connection limit reached, rejecting %s", conn.RemoteAddr())
			conn.CloseWithError(0, "")
		}
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
	tunnel := proxy.NewServerTunnel(conn, psk, keys, shaper)
	defer tunnel.Close()

	tunnel.Serve()
}

// serveDecoy sends an HTTP/3 decoy response and closes the connection.
// The response uses proper HTTP/3 binary framing (HEADERS + DATA frames)
// so active probes see a legitimate H3 web server.
func serveDecoy(conn quic.Connection) {
	stream, err := conn.OpenUniStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "")
		return
	}

	// HTTP/3 requires a unidirectional control stream (type 0x00) to exist.
	// Send a minimal control stream with SETTINGS frame.
	stream.Write(encodeH3VarInt(0x00))                    // stream type: control
	stream.Write(encodeH3Frame(0x04, []byte{0x01, 0x00})) // SETTINGS frame: SETTINGS_MAX_FIELD_SECTION_SIZE = 0 (no limit implied)
	stream.Close()

	// Now open a request-response bidirectional stream for the decoy page.
	biStream, err := conn.OpenStream()
	if err != nil {
		conn.CloseWithError(0, "")
		return
	}

	decoyHTML := []byte(`<!DOCTYPE html>
<html>
<head><title>CloudPlay™ Gaming Service</title></head>
<body>
<h1>CloudPlay™</h1>
<p>Welcome to CloudPlay Gaming Service. Please use the CloudPlay client application to connect.</p>
<p>For support, visit <a href="https://support.cloudplay.example.com">our help center</a>.</p>
</body>
</html>`)

	// Build QPACK-encoded header block for "403 Forbidden".
	// Using QPACK static table indices (RFC 9204):
	//   Index 27: :status 403
	//   Literal with name reference for server, content-type, content-length
	var qpackHeaders []byte
	// Required QPACK prefix: Required Insert Count = 0, Delta Base = 0
	qpackHeaders = append(qpackHeaders, 0x00, 0x00)
	// :status 403 — indexed field line (static table index 27, prefix 11xxxxxx)
	qpackHeaders = append(qpackHeaders, 0xC0|27)
	// content-type: text/html; charset=utf-8 — literal with name reference
	// Static index 53 = content-type (01Nxxxxx, N=0, index 53)
	qpackHeaders = append(qpackHeaders, 0x40|53)
	ct := []byte("text/html; charset=utf-8")
	qpackHeaders = append(qpackHeaders, byte(len(ct)))
	qpackHeaders = append(qpackHeaders, ct...)
	// server: nginx/1.25.3 — literal with literal name (no static index to avoid overflow)
	// Literal field line with literal name: 0x20 | N(0) prefix, then name length + name + value length + value
	qpackHeaders = append(qpackHeaders, 0x20) // literal with literal name, N=0
	serverName := []byte("server")
	qpackHeaders = append(qpackHeaders, byte(len(serverName))) // name length (3-bit prefix, Huffman=0)
	qpackHeaders = append(qpackHeaders, serverName...)
	sv := []byte("nginx/1.25.3")
	qpackHeaders = append(qpackHeaders, byte(len(sv)))
	qpackHeaders = append(qpackHeaders, sv...)

	// Write HEADERS frame (type 0x01) + DATA frame (type 0x00)
	biStream.Write(encodeH3Frame(0x01, qpackHeaders))
	biStream.Write(encodeH3Frame(0x00, decoyHTML))
	biStream.Close()

	time.Sleep(100 * time.Millisecond)
	conn.CloseWithError(0x0100, "") // H3_NO_ERROR
}

// encodeH3Frame builds an HTTP/3 frame: varint(type) + varint(length) + payload.
func encodeH3Frame(frameType uint64, payload []byte) []byte {
	var buf []byte
	buf = append(buf, encodeH3VarInt(frameType)...)
	buf = append(buf, encodeH3VarInt(uint64(len(payload)))...)
	buf = append(buf, payload...)
	return buf
}

// encodeH3VarInt encodes a uint64 as a QUIC variable-length integer (RFC 9000 §16).
func encodeH3VarInt(v uint64) []byte {
	switch {
	case v < 0x40:
		return []byte{byte(v)}
	case v < 0x4000:
		return []byte{byte(v>>8) | 0x40, byte(v)}
	case v < 0x40000000:
		b := make([]byte, 4)
		b[0] = byte(v>>24) | 0x80
		b[1] = byte(v >> 16)
		b[2] = byte(v >> 8)
		b[3] = byte(v)
		return b
	default:
		b := make([]byte, 8)
		b[0] = byte(v>>56) | 0xC0
		b[1] = byte(v >> 48)
		b[2] = byte(v >> 40)
		b[3] = byte(v >> 32)
		b[4] = byte(v >> 24)
		b[5] = byte(v >> 16)
		b[6] = byte(v >> 8)
		b[7] = byte(v)
		return b
	}
}
