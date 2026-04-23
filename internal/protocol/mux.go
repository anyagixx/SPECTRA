package protocol

import (
	"fmt"
	"io"
	"sync"

	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
)

// Buffer pools to reduce per-frame heap allocations.
var (
	// innerBufPool holds reusable buffers for serialized InnerPayload plaintext.
	innerBufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, InnerPayloadHeaderSize+MaxFramePayloadSize)
			return &b
		},
	}
	// frameBufPool holds reusable buffers for serialized wire-format frames.
	frameBufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, FrameHeaderSize+MaxFramePayloadSize+64)
			return &b
		},
	}
)

// Muxer handles multiplexing of inner payloads into encrypted SPECTRA frames.
type Muxer struct {
	enc     *scrypto.Encryptor
	mu      sync.Mutex
	seqNums map[FrameType]uint32
}

// NewMuxer creates a new Muxer with the provided encryptor.
func NewMuxer(enc *scrypto.Encryptor) *Muxer {
	return &Muxer{
		enc:     enc,
		seqNums: make(map[FrameType]uint32),
	}
}

// frameTypeToStreamID maps frame types to crypto stream IDs for nonce domain separation.
func frameTypeToStreamID(ft FrameType) scrypto.StreamID {
	switch ft {
	case FrameControl:
		return scrypto.StreamControl
	case FrameVideo:
		return scrypto.StreamVideo
	case FrameAudio:
		return scrypto.StreamAudio
	case FrameInput:
		return scrypto.StreamInput
	default:
		return scrypto.StreamControl
	}
}

// EncryptAndFrame encrypts an inner payload and wraps it in a SPECTRA frame.
func (m *Muxer) EncryptAndFrame(frameType FrameType, inner *InnerPayload) (*Frame, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Serialize inner payload into a pooled buffer to avoid allocation.
	bp := innerBufPool.Get().(*[]byte)
	plaintext := inner.AppendInner((*bp)[:0])
	streamID := frameTypeToStreamID(frameType)

	// Stack-allocated AD — avoids per-frame heap escape.
	var ad [1]byte
	ad[0] = byte(frameType)

	ciphertext, _, err := m.enc.Seal(streamID, plaintext, ad[:])

	// Return the pooled buffer immediately after encryption.
	*bp = (*bp)[:0]
	innerBufPool.Put(bp)

	if err != nil {
		return nil, fmt.Errorf("mux: encryption failed: %w", err)
	}

	seq := m.seqNums[frameType]
	m.seqNums[frameType] = seq + 1

	return &Frame{
		Type:           frameType,
		Flags:          0,
		SequenceNumber: seq,
		Payload:        ciphertext,
	}, nil
}

// Rekey atomically replaces the encryption keys and resets sequence numbers.
func (m *Muxer) Rekey(keys *scrypto.SessionKeys) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqNums = make(map[FrameType]uint32)
	return m.enc.Rekey(keys)
}

// WriteFrame serializes and writes a frame to the given writer.
// Uses a pooled buffer to avoid per-frame allocation.
func WriteFrame(w io.Writer, f *Frame) error {
	bp := frameBufPool.Get().(*[]byte)
	data := f.AppendMarshal((*bp)[:0])

	var writeErr error
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			writeErr = err
			break
		}
		if n <= 0 {
			writeErr = io.ErrShortWrite
			break
		}
		data = data[n:]
	}

	*bp = (*bp)[:0]
	frameBufPool.Put(bp)
	return writeErr
}

// Demuxer handles demultiplexing of SPECTRA frames into decrypted inner payloads.
type Demuxer struct {
	dec *scrypto.Decryptor
}

// NewDemuxer creates a new Demuxer with the provided decryptor.
func NewDemuxer(dec *scrypto.Decryptor) *Demuxer {
	return &Demuxer{dec: dec}
}

// DecryptFrame decrypts a received frame and returns the inner payload.
func (d *Demuxer) DecryptFrame(f *Frame) (*InnerPayload, error) {
	if f.Type == FramePadding {
		return nil, nil // Padding frames carry no meaningful data
	}

	streamID := frameTypeToStreamID(f.Type)
	ad := []byte{byte(f.Type)}

	plaintext, err := d.dec.OpenWithCounter(streamID, uint64(f.SequenceNumber), f.Payload, ad)
	if err != nil {
		return nil, fmt.Errorf("demux: decryption failed for %s frame seq=%d: %w",
			f.Type, f.SequenceNumber, err)
	}

	inner, err := UnmarshalInner(plaintext)
	if err != nil {
		return nil, fmt.Errorf("demux: failed to parse inner payload: %w", err)
	}

	return inner, nil
}

// Rekey atomically replaces the decryption keys.
func (d *Demuxer) Rekey(keys *scrypto.SessionKeys) error {
	return d.dec.Rekey(keys)
}

// ReadAndDecrypt reads a frame from the reader and decrypts it.
// Returns nil InnerPayload for padding frames.
func (d *Demuxer) ReadAndDecrypt(r io.Reader) (*Frame, *InnerPayload, error) {
	frame, err := UnmarshalFrame(r)
	if err != nil {
		return nil, nil, err
	}

	inner, err := d.DecryptFrame(frame)
	if err != nil {
		return frame, nil, err
	}

	return frame, inner, nil
}
