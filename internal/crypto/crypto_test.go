package crypto

import (
	"bytes"
	"testing"
)

func TestGeneratePSK(t *testing.T) {
	psk, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK failed: %v", err)
	}
	if len(psk) != PSKSize {
		t.Fatalf("PSK length = %d, want %d", len(psk), PSKSize)
	}

	// Two PSKs should differ
	psk2, _ := GeneratePSK()
	if bytes.Equal(psk, psk2) {
		t.Fatal("Two generated PSKs should not be equal")
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	psk, _ := GeneratePSK()
	salt, _ := GenerateSalt()

	keys, err := DeriveSessionKeysDirect(psk, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKeysDirect failed: %v", err)
	}
	if len(keys.SessionKey) != SessionKeySize {
		t.Fatalf("SessionKey length = %d, want %d", len(keys.SessionKey), SessionKeySize)
	}
	if len(keys.BaseIV) != BaseIVSize {
		t.Fatalf("BaseIV length = %d, want %d", len(keys.BaseIV), BaseIVSize)
	}

	// Same inputs → same keys (deterministic)
	keys2, _ := DeriveSessionKeysDirect(psk, salt)
	if !bytes.Equal(keys.SessionKey, keys2.SessionKey) {
		t.Fatal("Same PSK+salt should produce same session key")
	}
	if !bytes.Equal(keys.BaseIV, keys2.BaseIV) {
		t.Fatal("Same PSK+salt should produce same base IV")
	}

	// Different salt → different keys
	salt2, _ := GenerateSalt()
	keys3, _ := DeriveSessionKeysDirect(psk, salt2)
	if bytes.Equal(keys.SessionKey, keys3.SessionKey) {
		t.Fatal("Different salt should produce different session key")
	}
}

func TestBuildNonce(t *testing.T) {
	baseIV := make([]byte, NonceSize)
	for i := range baseIV {
		baseIV[i] = 0xAA
	}

	n1 := BuildNonce(baseIV, StreamVideo, 0)
	n2 := BuildNonce(baseIV, StreamVideo, 1)
	n3 := BuildNonce(baseIV, StreamAudio, 0)

	if bytes.Equal(n1, n2) {
		t.Fatal("Different counters should produce different nonces")
	}
	if bytes.Equal(n1, n3) {
		t.Fatal("Different streams should produce different nonces")
	}
	if len(n1) != NonceSize {
		t.Fatalf("Nonce length = %d, want %d", len(n1), NonceSize)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	psk, _ := GeneratePSK()
	salt, _ := GenerateSalt()
	keys, _ := DeriveSessionKeysDirect(psk, salt)

	plaintext := []byte("Hello, SPECTRA protocol!")
	nonce := BuildNonce(keys.BaseIV, StreamVideo, 42)
	ad := []byte{0x01} // frame type as AD

	ciphertext, err := Encrypt(keys.SessionKey, nonce, plaintext, ad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("Ciphertext should differ from plaintext")
	}

	// Correct decryption
	decrypted, err := Decrypt(keys.SessionKey, nonce, ciphertext, ad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypted = %q, want %q", decrypted, plaintext)
	}

	// Wrong nonce → fail
	wrongNonce := BuildNonce(keys.BaseIV, StreamVideo, 99)
	_, err = Decrypt(keys.SessionKey, wrongNonce, ciphertext, ad)
	if err == nil {
		t.Fatal("Decrypt with wrong nonce should fail")
	}

	// Wrong AD → fail
	_, err = Decrypt(keys.SessionKey, nonce, ciphertext, []byte{0x02})
	if err == nil {
		t.Fatal("Decrypt with wrong AD should fail")
	}

	// Tampered ciphertext → fail
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF
	_, err = Decrypt(keys.SessionKey, nonce, tampered, ad)
	if err == nil {
		t.Fatal("Decrypt with tampered ciphertext should fail")
	}
}

func TestEncryptorDecryptor(t *testing.T) {
	psk, _ := GeneratePSK()
	salt, _ := GenerateSalt()
	keys, _ := DeriveSessionKeysDirect(psk, salt)

	enc := NewEncryptor(keys)
	dec := NewDecryptor(keys)

	messages := []string{
		"first message",
		"second message",
		"third message with more data to encrypt and verify",
	}

	for _, msg := range messages {
		ct, _, err := enc.Seal(StreamVideo, []byte(msg), nil)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		pt, err := dec.Open(StreamVideo, ct, nil)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if string(pt) != msg {
			t.Fatalf("Open = %q, want %q", pt, msg)
		}
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long!!!!!")
	data := []byte("some data to authenticate")

	mac := ComputeHMAC(key, data)
	if len(mac) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(mac))
	}

	if !VerifyHMAC(key, data, mac) {
		t.Fatal("VerifyHMAC should return true for valid MAC")
	}

	// Tampered data
	if VerifyHMAC(key, []byte("tampered data"), mac) {
		t.Fatal("VerifyHMAC should return false for tampered data")
	}

	// Wrong key
	if VerifyHMAC([]byte("wrong-key-32-bytes-long!!!!!!!!!"), data, mac) {
		t.Fatal("VerifyHMAC should return false for wrong key")
	}
}

func TestPSKFromHex(t *testing.T) {
	psk, _ := GeneratePSK()
	hex := ""
	for _, b := range psk {
		hex += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0x0F])
	}

	parsed, err := PSKFromHex(hex)
	if err != nil {
		t.Fatalf("PSKFromHex failed: %v", err)
	}
	if !bytes.Equal(parsed, psk) {
		t.Fatal("Parsed PSK should equal original")
	}

	// Invalid hex
	_, err = PSKFromHex("not-hex")
	if err == nil {
		t.Fatal("PSKFromHex should fail for invalid hex")
	}

	// Wrong length
	_, err = PSKFromHex("abcd")
	if err == nil {
		t.Fatal("PSKFromHex should fail for wrong length")
	}
}
