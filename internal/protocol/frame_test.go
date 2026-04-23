package protocol

import (
	"bytes"
	"io"
	"testing"
)

type shortWriter struct {
	buf       bytes.Buffer
	chunkSize int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.chunkSize <= 0 {
		return 0, io.ErrShortWrite
	}
	if len(p) > w.chunkSize {
		p = p[:w.chunkSize]
	}
	return w.buf.Write(p)
}

func TestFrameMarshalUnmarshal(t *testing.T) {
	payload := []byte("encrypted-payload-data-here")
	padding := []byte{0x00, 0x00, 0x00, 0x00}

	f := &Frame{
		Type:           FrameVideo,
		Flags:          FlagKeyFrame,
		SequenceNumber: 42,
		Payload:        payload,
		Padding:        padding,
	}

	data := f.Marshal()

	// Unmarshal
	reader := bytes.NewReader(data)
	f2, err := UnmarshalFrame(reader)
	if err != nil {
		t.Fatalf("UnmarshalFrame failed: %v", err)
	}

	if f2.Type != FrameVideo {
		t.Fatalf("Type = %v, want VIDEO", f2.Type)
	}
	if f2.SequenceNumber != 42 {
		t.Fatalf("SeqNum = %d, want 42", f2.SequenceNumber)
	}
	if f2.Flags&FlagHasPadding == 0 {
		t.Fatal("HAS_PADDING flag should be set")
	}
	if f2.Flags&FlagKeyFrame == 0 {
		t.Fatal("KEY_FRAME flag should be set")
	}
}

func TestFrameNoPadding(t *testing.T) {
	f := &Frame{
		Type:           FrameAudio,
		Flags:          0,
		SequenceNumber: 1,
		Payload:        []byte("audio-data"),
	}

	data := f.Marshal()
	reader := bytes.NewReader(data)
	f2, err := UnmarshalFrame(reader)
	if err != nil {
		t.Fatalf("UnmarshalFrame failed: %v", err)
	}

	if f2.Type != FrameAudio {
		t.Fatalf("Type = %v, want AUDIO", f2.Type)
	}
	if f2.Flags&FlagHasPadding != 0 {
		t.Fatal("HAS_PADDING should not be set")
	}
}

func TestPaddingFrame(t *testing.T) {
	f := NewPaddingFrame(99, 64)
	if f.Type != FramePadding {
		t.Fatalf("Type = %v, want PADDING", f.Type)
	}
	if len(f.Payload) != 64 {
		t.Fatalf("Payload length = %d, want 64", len(f.Payload))
	}

	data := f.Marshal()
	reader := bytes.NewReader(data)
	f2, err := UnmarshalFrame(reader)
	if err != nil {
		t.Fatalf("UnmarshalFrame failed: %v", err)
	}
	if f2.Type != FramePadding {
		t.Fatalf("Type = %v, want PADDING", f2.Type)
	}
}

func TestMultipleFrames(t *testing.T) {
	frames := []*Frame{
		NewDataFrame(FrameVideo, 0, []byte("video-frame-0")),
		NewDataFrame(FrameAudio, 1, []byte("audio-frame-1")),
		NewDataFrame(FrameInput, 2, []byte("input-frame-2")),
	}

	var buf bytes.Buffer
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame failed: %v", err)
		}
	}

	reader := &buf
	for i, expected := range frames {
		f, err := UnmarshalFrame(reader)
		if err != nil {
			t.Fatalf("Frame %d: UnmarshalFrame failed: %v", i, err)
		}
		if f.Type != expected.Type {
			t.Fatalf("Frame %d: Type = %v, want %v", i, f.Type, expected.Type)
		}
		if f.SequenceNumber != expected.SequenceNumber {
			t.Fatalf("Frame %d: SeqNum = %d, want %d", i, f.SequenceNumber, expected.SequenceNumber)
		}
	}
}

func TestWriteFrameHandlesShortWriter(t *testing.T) {
	f := NewDataFrame(FrameVideo, 7, []byte("frame-data-that-needs-multiple-writes"))
	w := &shortWriter{chunkSize: 5}

	if err := WriteFrame(w, f); err != nil {
		t.Fatalf("WriteFrame failed with short writer: %v", err)
	}

	parsed, err := UnmarshalFrame(bytes.NewReader(w.buf.Bytes()))
	if err != nil {
		t.Fatalf("UnmarshalFrame failed after short writer serialization: %v", err)
	}
	if parsed.Type != f.Type {
		t.Fatalf("Type = %v, want %v", parsed.Type, f.Type)
	}
	if parsed.SequenceNumber != f.SequenceNumber {
		t.Fatalf("SequenceNumber = %d, want %d", parsed.SequenceNumber, f.SequenceNumber)
	}
	if !bytes.Equal(parsed.Payload, f.Payload) {
		t.Fatalf("Payload mismatch after short writer serialization")
	}
}

func TestInnerPayloadMarshalUnmarshal(t *testing.T) {
	inner := &InnerPayload{
		Cmd:    CmdData,
		ConnID: 7,
		Data:   []byte("hello world from tunnel"),
	}

	data := inner.MarshalInner()
	parsed, err := UnmarshalInner(data)
	if err != nil {
		t.Fatalf("UnmarshalInner failed: %v", err)
	}

	if parsed.Cmd != CmdData {
		t.Fatalf("Cmd = %v, want DATA", parsed.Cmd)
	}
	if parsed.ConnID != 7 {
		t.Fatalf("ConnID = %d, want 7", parsed.ConnID)
	}
	if !bytes.Equal(parsed.Data, inner.Data) {
		t.Fatalf("Data mismatch")
	}
}

func TestInnerPayloadConnect(t *testing.T) {
	inner := &InnerPayload{
		Cmd:    CmdConnect,
		ConnID: 1,
		Data:   []byte("example.com:443"),
	}

	data := inner.MarshalInner()
	parsed, err := UnmarshalInner(data)
	if err != nil {
		t.Fatalf("UnmarshalInner failed: %v", err)
	}

	if parsed.Cmd != CmdConnect {
		t.Fatalf("Cmd = %v, want CONNECT", parsed.Cmd)
	}
	if string(parsed.Data) != "example.com:443" {
		t.Fatalf("Data = %q, want example.com:443", parsed.Data)
	}
}

func TestInnerPayloadTooShort(t *testing.T) {
	_, err := UnmarshalInner([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("UnmarshalInner should fail for short data")
	}
}

func TestFrameTypeString(t *testing.T) {
	tests := []struct {
		ft   FrameType
		want string
	}{
		{FrameControl, "CONTROL"},
		{FrameVideo, "VIDEO"},
		{FrameAudio, "AUDIO"},
		{FrameInput, "INPUT"},
		{FramePadding, "PADDING"},
		{FrameType(0x99), "UNKNOWN(0x99)"},
	}
	for _, tt := range tests {
		if got := tt.ft.String(); got != tt.want {
			t.Errorf("FrameType(%d).String() = %q, want %q", tt.ft, got, tt.want)
		}
	}
}
