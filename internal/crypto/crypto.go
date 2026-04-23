package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	PSKSize        = 32                          // 256-bit pre-shared key
	SaltSize       = 32                          // 256-bit connection salt
	SessionKeySize = 32                          // 256-bit session key for XChaCha20
	BaseIVSize     = 24                          // 192-bit base IV for XChaCha20
	NonceSize      = chacha20poly1305.NonceSizeX // 24 bytes
	TagSize        = chacha20poly1305.Overhead   // 16 bytes
)

// StreamID identifies which QUIC stream a nonce belongs to, ensuring domain separation.
type StreamID byte

const (
	StreamControl StreamID = 0x00
	StreamVideo   StreamID = 0x01
	StreamAudio   StreamID = 0x02
	StreamInput   StreamID = 0x03
)

// SessionKeys holds the derived cryptographic material for a single connection.
type SessionKeys struct {
	SessionKey []byte // 32 bytes — XChaCha20-Poly1305 key
	BaseIV     []byte // 24 bytes — base IV, XORed with stream+counter to form nonce
}

// GeneratePSK creates a new random 256-bit pre-shared key.
func GeneratePSK() ([]byte, error) {
	psk := make([]byte, PSKSize)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate PSK: %w", err)
	}
	return psk, nil
}

// GenerateSalt creates a new random 256-bit connection salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveSessionKeysDirect derives session keys using HKDF-SHA256 (extract then expand).
func DeriveSessionKeysDirect(psk, connectionSalt []byte) (*SessionKeys, error) {
	if len(psk) != PSKSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidPSK, len(psk), PSKSize)
	}
	if len(connectionSalt) != SaltSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidSalt, len(connectionSalt), SaltSize)
	}

	// Extract PRK
	prk := hkdf.Extract(sha256.New, psk, connectionSalt)

	// Expand for session key
	sessionKeyReader := hkdf.Expand(sha256.New, prk, []byte("spectra-session-key"))
	sessionKey := make([]byte, SessionKeySize)
	if _, err := io.ReadFull(sessionKeyReader, sessionKey); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive session key: %w", err)
	}

	// Expand for base IV
	baseIVReader := hkdf.Expand(sha256.New, prk, []byte("spectra-session-iv"))
	baseIV := make([]byte, BaseIVSize)
	if _, err := io.ReadFull(baseIVReader, baseIV); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive base IV: %w", err)
	}

	return &SessionKeys{
		SessionKey: sessionKey,
		BaseIV:     baseIV,
	}, nil
}

// BuildNonce constructs a 24-byte XChaCha20 nonce from the BaseIV, stream ID, and counter.
// Nonce = BaseIV XOR (streamID || 0x00...00 || counter_big_endian_48bit)
func BuildNonce(baseIV []byte, stream StreamID, counter uint64) []byte {
	nonce := make([]byte, NonceSize)
	BuildNonceInto(nonce, baseIV, stream, counter)
	return nonce
}

// BuildNonceInto writes a 24-byte XChaCha20 nonce into dst without heap allocation.
// dst must be at least NonceSize bytes.
func BuildNonceInto(dst, baseIV []byte, stream StreamID, counter uint64) {
	copy(dst, baseIV)
	dst[0] ^= byte(stream)
	dst[18] ^= byte(counter >> 40)
	dst[19] ^= byte(counter >> 32)
	dst[20] ^= byte(counter >> 24)
	dst[21] ^= byte(counter >> 16)
	dst[22] ^= byte(counter >> 8)
	dst[23] ^= byte(counter)
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with the given session key and nonce.
// Returns ciphertext (encrypted data + 16-byte Poly1305 tag).
func Encrypt(sessionKey, nonce, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AEAD: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using XChaCha20-Poly1305 with the given session key and nonce.
// Returns the plaintext.
func Decrypt(sessionKey, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryption, err)
	}
	return plaintext, nil
}

// ComputeHMAC computes HMAC-SHA256 over the given data using the provided key.
func ComputeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMAC performs constant-time verification of an HMAC-SHA256 tag.
func VerifyHMAC(key, data, expectedMAC []byte) bool {
	computed := ComputeHMAC(key, data)
	return subtle.ConstantTimeCompare(computed, expectedMAC) == 1
}

// PSKFromHex parses a hex-encoded PSK string into bytes.
func PSKFromHex(hexPSK string) ([]byte, error) {
	psk, err := hex.DecodeString(hexPSK)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex: %v", ErrInvalidPSK, err)
	}
	if len(psk) != PSKSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidPSK, len(psk), PSKSize)
	}
	return psk, nil
}

// Encryptor manages per-stream nonce counters and provides stateful encryption.
// It is safe for concurrent use. The AEAD cipher is created once and reused.
type Encryptor struct {
	keys     *SessionKeys
	aead     cipher.AEAD
	counters map[StreamID]uint64
	nonceBuf [NonceSize]byte
	mu       sync.Mutex
}

// NewEncryptor creates a new Encryptor with the given session keys.
// Panics if the session key is invalid (programmer error).
func NewEncryptor(keys *SessionKeys) *Encryptor {
	aead, err := chacha20poly1305.NewX(keys.SessionKey)
	if err != nil {
		panic("crypto: invalid session key for encryptor: " + err.Error())
	}
	return &Encryptor{
		keys:     keys,
		aead:     aead,
		counters: make(map[StreamID]uint64),
	}
}

// Seal encrypts data for the specified stream, auto-incrementing the nonce counter.
// Safe for concurrent use.
func (e *Encryptor) Seal(stream StreamID, plaintext, ad []byte) ([]byte, uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	counter := e.counters[stream]
	BuildNonceInto(e.nonceBuf[:], e.keys.BaseIV, stream, counter)
	ciphertext := e.aead.Seal(nil, e.nonceBuf[:], plaintext, ad)
	e.counters[stream] = counter + 1
	return ciphertext, counter, nil
}

// Rekey atomically replaces the session keys and AEAD cipher, resetting all
// nonce counters. This is used for in-session key rotation.
func (e *Encryptor) Rekey(keys *SessionKeys) error {
	aead, err := chacha20poly1305.NewX(keys.SessionKey)
	if err != nil {
		return fmt.Errorf("crypto: rekey failed: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keys = keys
	e.aead = aead
	e.counters = make(map[StreamID]uint64)
	return nil
}

// Decryptor manages per-stream nonce counters and provides stateful decryption.
// It is safe for concurrent use. The AEAD cipher is created once and reused.
type Decryptor struct {
	keys     *SessionKeys
	aead     cipher.AEAD
	counters map[StreamID]uint64
	nonceBuf [NonceSize]byte
	mu       sync.Mutex
}

// NewDecryptor creates a new Decryptor with the given session keys.
// Panics if the session key is invalid (programmer error).
func NewDecryptor(keys *SessionKeys) *Decryptor {
	aead, err := chacha20poly1305.NewX(keys.SessionKey)
	if err != nil {
		panic("crypto: invalid session key for decryptor: " + err.Error())
	}
	return &Decryptor{
		keys:     keys,
		aead:     aead,
		counters: make(map[StreamID]uint64),
	}
}

// Open decrypts data for the specified stream using the expected counter value.
// Safe for concurrent use.
func (d *Decryptor) Open(stream StreamID, ciphertext, ad []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	counter := d.counters[stream]
	BuildNonceInto(d.nonceBuf[:], d.keys.BaseIV, stream, counter)
	plaintext, err := d.aead.Open(nil, d.nonceBuf[:], ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryption, err)
	}
	d.counters[stream] = counter + 1
	return plaintext, nil
}

// OpenWithCounter decrypts data for the specified stream with an explicit counter (for out-of-order).
// Safe for concurrent use.
func (d *Decryptor) OpenWithCounter(stream StreamID, counter uint64, ciphertext, ad []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	BuildNonceInto(d.nonceBuf[:], d.keys.BaseIV, stream, counter)
	plaintext, err := d.aead.Open(nil, d.nonceBuf[:], ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryption, err)
	}
	if counter >= d.counters[stream] {
		d.counters[stream] = counter + 1
	}
	return plaintext, nil
}

// Rekey atomically replaces the session keys and AEAD cipher, resetting all
// nonce counters. This is used for in-session key rotation.
func (d *Decryptor) Rekey(keys *SessionKeys) error {
	aead, err := chacha20poly1305.NewX(keys.SessionKey)
	if err != nil {
		return fmt.Errorf("crypto: rekey failed: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys = keys
	d.aead = aead
	d.counters = make(map[StreamID]uint64)
	return nil
}

var (
	ErrInvalidPSK  = errors.New("crypto: invalid PSK")
	ErrInvalidSalt = errors.New("crypto: invalid salt")
	ErrDecryption  = errors.New("crypto: decryption failed")
)
