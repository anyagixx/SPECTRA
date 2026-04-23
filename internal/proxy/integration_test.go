package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"

	"github.com/quic-go/quic-go"

	"github.com/anyagixx/SPECTRA/internal/camouflage"
	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
	"github.com/anyagixx/SPECTRA/internal/handshake"
	"github.com/anyagixx/SPECTRA/internal/protocol"
)

// testProfile returns a minimal traffic profile for integration tests.
func testProfile() *camouflage.Profile {
	return &camouflage.Profile{
		Name:    "test",
		Version: "1.0",
		PacketSizes: camouflage.PacketSizes{
			Video: camouflage.VideoSizes{
				PFrame:      camouflage.Distribution{Min: 200, Max: 1400, Mean: 800, Stddev: 200, Distribution: "normal"},
				IFrame:      camouflage.Distribution{Min: 2000, Max: 5000, Mean: 3000, Stddev: 500, Distribution: "normal"},
				IFrameRatio: 0.05,
			},
			Audio: camouflage.Distribution{Min: 40, Max: 160, Mean: 80, Stddev: 20, Distribution: "normal"},
			Input: camouflage.Distribution{Min: 20, Max: 120, Mean: 50, Stddev: 15, Distribution: "normal"},
		},
		Timing: camouflage.Timing{
			VideoIntervalMs: camouflage.Distribution{Min: 10, Max: 25, Mean: 16, Stddev: 2, Distribution: "normal"},
			AudioIntervalMs: camouflage.Distribution{Min: 15, Max: 30, Mean: 20, Stddev: 1, Distribution: "normal"},
			InputIntervalMs: camouflage.Distribution{Min: 2, Max: 20, Mean: 8, Stddev: 3, Distribution: "exponential"},
		},
		MarkovChain: camouflage.MarkovChain{
			States: []string{"idle", "video", "audio", "input", "iframe"},
			TransitionMatrix: [][]float64{
				{0.05, 0.50, 0.20, 0.20, 0.05},
				{0.03, 0.55, 0.22, 0.15, 0.05},
				{0.03, 0.52, 0.20, 0.20, 0.05},
				{0.05, 0.50, 0.20, 0.20, 0.05},
				{0.03, 0.60, 0.20, 0.12, 0.05},
			},
		},
	}
}

// generateTestTLSConfig creates a self-signed TLS certificate for testing.
func generateTestTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spectra-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	certPool := x509.NewCertPool()
	parsedCert, _ := x509.ParseCertificate(certDER)
	certPool.AddCert(parsedCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
		RootCAs:      certPool,
	}, nil
}

// TestIntegrationE2E verifies the full path: SOCKS5 → ClientTunnel → QUIC →
// ServerTunnel → upstream HTTP and back.
func TestIntegrationE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// 1. Start a plain HTTP upstream server.
	const responseBody = "hello from upstream"
	upstream := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	})}
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upstream.Close()
	go upstream.Serve(upstreamLn)

	// 2. Generate test crypto material.
	psk, err := scrypto.GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK: %v", err)
	}
	tlsConf, err := generateTestTLSConfig()
	if err != nil {
		t.Fatalf("generateTestTLSConfig: %v", err)
	}
	profile := testProfile()

	// 3. Start QUIC server.
	serverTLS := &tls.Config{
		Certificates: tlsConf.Certificates,
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}
	quicListener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("QUIC listen: %v", err)
	}
	defer quicListener.Close()

	serverAddr := quicListener.Addr().String()
	verifier := handshake.NewServerVerifier(psk)

	// Server accept loop.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := quicListener.Accept(context.Background())
		if err != nil {
			return
		}
		// Perform server-side handshake.
		authCtx, authCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer authCancel()
		stream, err := conn.AcceptStream(authCtx)
		if err != nil {
			return
		}
		initBuf := make([]byte, handshake.AuthInitSize)
		if _, err := io.ReadFull(stream, initBuf); err != nil {
			return
		}
		authInit, err := handshake.UnmarshalAuthInit(initBuf)
		if err != nil {
			return
		}
		if err := verifier.VerifyAuthInit(authInit); err != nil {
			return
		}
		authOK, _ := handshake.BuildAuthOK(psk, authInit.Salt)
		stream.Write(authOK.Marshal())
		confirmBuf := make([]byte, handshake.AuthConfirmSize)
		io.ReadFull(stream, confirmBuf)
		keys, _ := scrypto.DeriveSessionKeysDirect(psk, authInit.Salt)
		confirmPlain, err := scrypto.Decrypt(
			keys.SessionKey,
			scrypto.BuildNonce(keys.BaseIV, scrypto.StreamControl, 0),
			confirmBuf, nil,
		)
		if err != nil || string(confirmPlain) != string(handshake.ConfirmPayload) {
			return
		}
		stream.Close()

		shaper := camouflage.NewShaper(profile)
		tunnel := NewServerTunnel(conn, psk, keys, shaper)
		defer tunnel.Close()
		tunnel.Serve()
	}()

	// 4. Client connects.
	clientTLS := &tls.Config{
		ServerName:         "localhost",
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	qconn, err := quic.DialAddr(context.Background(), serverAddr, clientTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("QUIC dial: %v", err)
	}

	// Client handshake.
	cStream, _ := qconn.OpenStream()
	authInit, _ := handshake.BuildAuthInit(psk)
	cStream.Write(authInit.Marshal())
	okBuf := make([]byte, handshake.AuthOKSize)
	io.ReadFull(cStream, okBuf)
	authOK, _ := handshake.UnmarshalAuthOK(okBuf)
	handshake.VerifyAuthOK(psk, authInit.Salt, authOK)
	keys, _ := scrypto.DeriveSessionKeysDirect(psk, authInit.Salt)
	confirmCipher, _ := scrypto.Encrypt(
		keys.SessionKey,
		scrypto.BuildNonce(keys.BaseIV, scrypto.StreamControl, 0),
		handshake.ConfirmPayload, nil,
	)
	cStream.Write(confirmCipher)
	cStream.Close()

	shaper := camouflage.NewShaper(profile)
	clientTunnel := NewClientTunnel(qconn, psk, keys, shaper)
	go clientTunnel.RunReceiver()
	defer clientTunnel.Close()

	// 5. Dial through the tunnel to the upstream HTTP server.
	rwc, err := clientTunnel.DialTunnel(context.Background(), upstreamLn.Addr().String())
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}

	// Send a minimal HTTP/1.1 request through the tunnel.
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamLn.Addr())
	if _, err := rwc.Write([]byte(httpReq)); err != nil {
		t.Fatalf("Write HTTP request: %v", err)
	}

	resp, err := io.ReadAll(rwc)
	if err != nil {
		t.Fatalf("ReadAll response: %v", err)
	}
	rwc.Close()

	respStr := string(resp)
	if len(respStr) == 0 {
		t.Fatal("Empty response from upstream")
	}

	// The response should contain our expected body.
	if !containsSubstring(respStr, responseBody) {
		t.Fatalf("Response does not contain %q:\n%s", responseBody, respStr)
	}

	// 6. Verify padding frame type is valid.
	ft := shaper.NextFrameType()
	if ft != protocol.FrameVideo && ft != protocol.FrameAudio &&
		ft != protocol.FrameInput && ft != protocol.FramePadding {
		t.Fatalf("Unexpected frame type: %v", ft)
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && searchSubstring(s, sub))
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
