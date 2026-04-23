package protocol

import (
	"testing"

	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
)

func TestDemuxerDecryptsOutOfOrderFrames(t *testing.T) {
	psk, err := scrypto.GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK failed: %v", err)
	}
	salt, err := scrypto.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	keys, err := scrypto.DeriveSessionKeysDirect(psk, salt)
	if err != nil {
		t.Fatalf("DeriveSessionKeysDirect failed: %v", err)
	}

	muxer := NewMuxer(scrypto.NewEncryptor(keys))
	demuxer := NewDemuxer(scrypto.NewDecryptor(keys))

	firstInner := &InnerPayload{Cmd: CmdData, ConnID: 1, Data: []byte("first")}
	secondInner := &InnerPayload{Cmd: CmdData, ConnID: 1, Data: []byte("second")}

	firstFrame, err := muxer.EncryptAndFrame(FrameInput, firstInner)
	if err != nil {
		t.Fatalf("EncryptAndFrame(first) failed: %v", err)
	}
	secondFrame, err := muxer.EncryptAndFrame(FrameInput, secondInner)
	if err != nil {
		t.Fatalf("EncryptAndFrame(second) failed: %v", err)
	}

	decodedSecond, err := demuxer.DecryptFrame(secondFrame)
	if err != nil {
		t.Fatalf("DecryptFrame(second) failed: %v", err)
	}
	if string(decodedSecond.Data) != "second" {
		t.Fatalf("second data = %q, want %q", decodedSecond.Data, "second")
	}

	decodedFirst, err := demuxer.DecryptFrame(firstFrame)
	if err != nil {
		t.Fatalf("DecryptFrame(first) failed after out-of-order second: %v", err)
	}
	if string(decodedFirst.Data) != "first" {
		t.Fatalf("first data = %q, want %q", decodedFirst.Data, "first")
	}
}
