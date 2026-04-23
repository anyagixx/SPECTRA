package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
)

const (
	// MaxTimestampDrift is the maximum allowed clock difference between client and server.
	MaxTimestampDrift = 30 * time.Second

	// AuthInitSize = version(1) + salt(32) + timestamp(8) + hmac(32) = 73 bytes
	AuthInitSize = 1 + scrypto.SaltSize + 8 + 32

	// AuthOKSize = server_random(32) + hmac(32) = 64 bytes
	AuthOKSize = 32 + 32

	// AuthConfirmSize = encrypted "SPECTRA-READY" string
	// plaintext(13) + poly1305 tag(16) = 29 bytes
	AuthConfirmSize = 29

	// ProtocolVersion is the current SPECTRA protocol version.
	ProtocolVersion uint8 = 0x01

	// BloomFilterSize controls the anti-replay bloom filter capacity.
	BloomFilterSize = 65536
	BloomHashCount  = 8
)

// AuthInit is the client's initial authentication message.
type AuthInit struct {
	Version   uint8
	Salt      []byte // 32 bytes
	Timestamp int64  // Unix timestamp in seconds
	HMAC      []byte // 32 bytes: HMAC-SHA256(PSK, salt || timestamp)
}

// Marshal serializes an AuthInit message.
func (a *AuthInit) Marshal() []byte {
	buf := make([]byte, AuthInitSize)
	buf[0] = a.Version
	copy(buf[1:33], a.Salt)
	binary.BigEndian.PutUint64(buf[33:41], uint64(a.Timestamp))
	copy(buf[41:73], a.HMAC)
	return buf
}

// UnmarshalAuthInit parses an AuthInit from bytes.
func UnmarshalAuthInit(data []byte) (*AuthInit, error) {
	if len(data) < AuthInitSize {
		return nil, fmt.Errorf("handshake: AuthInit too short: %d < %d", len(data), AuthInitSize)
	}
	return &AuthInit{
		Version:   data[0],
		Salt:      data[1:33],
		Timestamp: int64(binary.BigEndian.Uint64(data[33:41])),
		HMAC:      data[41:73],
	}, nil
}

// AuthOK is the server's authentication response on success.
type AuthOK struct {
	ServerRandom []byte // 32 bytes
	HMAC         []byte // 32 bytes: HMAC-SHA256(PSK, salt || server_random)
}

// Marshal serializes an AuthOK message.
func (a *AuthOK) Marshal() []byte {
	buf := make([]byte, AuthOKSize)
	copy(buf[0:32], a.ServerRandom)
	copy(buf[32:64], a.HMAC)
	return buf
}

// UnmarshalAuthOK parses an AuthOK from bytes.
func UnmarshalAuthOK(data []byte) (*AuthOK, error) {
	if len(data) < AuthOKSize {
		return nil, fmt.Errorf("handshake: AuthOK too short: %d < %d", len(data), AuthOKSize)
	}
	return &AuthOK{
		ServerRandom: data[0:32],
		HMAC:         data[32:64],
	}, nil
}

// BuildAuthInit constructs a client AuthInit message.
func BuildAuthInit(psk []byte) (*AuthInit, error) {
	salt, err := scrypto.GenerateSalt()
	if err != nil {
		return nil, err
	}

	ts := time.Now().Unix()

	// HMAC(PSK, salt || timestamp)
	hmacData := make([]byte, scrypto.SaltSize+8)
	copy(hmacData[:scrypto.SaltSize], salt)
	binary.BigEndian.PutUint64(hmacData[scrypto.SaltSize:], uint64(ts))

	mac := scrypto.ComputeHMAC(psk, hmacData)

	return &AuthInit{
		Version:   ProtocolVersion,
		Salt:      salt,
		Timestamp: ts,
		HMAC:      mac,
	}, nil
}

// ServerVerifier handles server-side authentication verification with anti-replay.
type ServerVerifier struct {
	psk   []byte
	bloom *BloomFilter
	mu    sync.Mutex
}

// NewServerVerifier creates a new server-side auth verifier.
func NewServerVerifier(psk []byte) *ServerVerifier {
	return &ServerVerifier{
		psk:   psk,
		bloom: NewBloomFilter(BloomFilterSize, BloomHashCount),
	}
}

// VerifyAuthInit validates a client's AuthInit message.
// Returns the connection salt on success for key derivation.
func (sv *ServerVerifier) VerifyAuthInit(init *AuthInit) error {
	// Check version
	if init.Version != ProtocolVersion {
		return fmt.Errorf("handshake: unsupported version: 0x%02X", init.Version)
	}

	// Check timestamp within drift window
	now := time.Now().Unix()
	drift := now - init.Timestamp
	if drift < 0 {
		drift = -drift
	}
	if drift > int64(MaxTimestampDrift.Seconds()) {
		return errors.New("handshake: timestamp outside acceptable window")
	}

	// Verify HMAC
	hmacData := make([]byte, scrypto.SaltSize+8)
	copy(hmacData[:scrypto.SaltSize], init.Salt)
	binary.BigEndian.PutUint64(hmacData[scrypto.SaltSize:], uint64(init.Timestamp))

	if !scrypto.VerifyHMAC(sv.psk, hmacData, init.HMAC) {
		return errors.New("handshake: HMAC verification failed")
	}

	// Anti-replay: check bloom filter
	sv.mu.Lock()
	defer sv.mu.Unlock()

	replayKey := append(init.Salt, hmacData[scrypto.SaltSize:]...)
	if sv.bloom.Test(replayKey) {
		return errors.New("handshake: replay detected")
	}
	sv.bloom.Add(replayKey)

	return nil
}

// BuildAuthOK constructs the server's AuthOK response.
func BuildAuthOK(psk, clientSalt []byte) (*AuthOK, error) {
	serverRandom, err := scrypto.GenerateSalt() // reuse 32-byte random generator
	if err != nil {
		return nil, err
	}

	// HMAC(PSK, salt || server_random)
	hmacData := make([]byte, scrypto.SaltSize+32)
	copy(hmacData[:scrypto.SaltSize], clientSalt)
	copy(hmacData[scrypto.SaltSize:], serverRandom)

	mac := scrypto.ComputeHMAC(psk, hmacData)

	return &AuthOK{
		ServerRandom: serverRandom,
		HMAC:         mac,
	}, nil
}

// VerifyAuthOK validates the server's AuthOK on the client side.
func VerifyAuthOK(psk, clientSalt []byte, ok *AuthOK) error {
	hmacData := make([]byte, scrypto.SaltSize+32)
	copy(hmacData[:scrypto.SaltSize], clientSalt)
	copy(hmacData[scrypto.SaltSize:], ok.ServerRandom)

	if !scrypto.VerifyHMAC(psk, hmacData, ok.HMAC) {
		return errors.New("handshake: server HMAC verification failed")
	}
	return nil
}

// ConfirmPayload is the expected plaintext for the AUTH_CONFIRM message.
var ConfirmPayload = []byte("SPECTRA-READY")

var (
	ErrAuthFailed      = errors.New("handshake: authentication failed")
	ErrReplay          = errors.New("handshake: replay detected")
	ErrVersionMismatch = errors.New("handshake: version mismatch")
)
