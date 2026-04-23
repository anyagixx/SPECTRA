package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame header size: Type(1) + Flags(1) + PayloadLength(2) + SequenceNumber(4) = 8 bytes
const FrameHeaderSize = 8

// FrameType identifies the type of SPECTRA frame.
type FrameType uint8

const (
	FrameControl FrameType = 0x00
	FrameVideo   FrameType = 0x01
	FrameAudio   FrameType = 0x02
	FrameInput   FrameType = 0x03
	FramePadding FrameType = 0xFF
)

// String returns the human-readable name of a FrameType.
func (ft FrameType) String() string {
	switch ft {
	case FrameControl:
		return "CONTROL"
	case FrameVideo:
		return "VIDEO"
	case FrameAudio:
		return "AUDIO"
	case FrameInput:
		return "INPUT"
	case FramePadding:
		return "PADDING"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", uint8(ft))
	}
}

// Frame flags
const (
	FlagKeyFrame   uint8 = 0x01 // Mimics I-frame (allows larger packet)
	FlagHasPadding uint8 = 0x02 // Padding bytes follow the auth tag
)

// Frame represents a single SPECTRA protocol frame.
type Frame struct {
	Type           FrameType
	Flags          uint8
	SequenceNumber uint32
	Payload        []byte // Encrypted payload + Poly1305 tag
	Padding        []byte // Optional padding bytes
}

// TotalSize returns the total wire size of the frame.
func (f *Frame) TotalSize() int {
	return FrameHeaderSize + len(f.Payload) + len(f.Padding)
}

// Marshal serializes a Frame into wire format.
func (f *Frame) Marshal() []byte {
	flags := f.Flags
	if len(f.Padding) > 0 {
		flags |= FlagHasPadding
	}

	payloadLen := uint16(len(f.Payload) + len(f.Padding))
	buf := make([]byte, FrameHeaderSize+int(payloadLen))

	buf[0] = byte(f.Type)
	buf[1] = flags
	binary.BigEndian.PutUint16(buf[2:4], payloadLen)
	binary.BigEndian.PutUint32(buf[4:8], f.SequenceNumber)

	copy(buf[FrameHeaderSize:], f.Payload)
	if len(f.Padding) > 0 {
		copy(buf[FrameHeaderSize+len(f.Payload):], f.Padding)
	}

	return buf
}

// AppendMarshal appends the wire-format frame to dst without allocating a new buffer.
func (f *Frame) AppendMarshal(dst []byte) []byte {
	flags := f.Flags
	if len(f.Padding) > 0 {
		flags |= FlagHasPadding
	}
	payloadLen := uint16(len(f.Payload) + len(f.Padding))
	dst = append(dst, byte(f.Type), flags,
		byte(payloadLen>>8), byte(payloadLen),
		byte(f.SequenceNumber>>24), byte(f.SequenceNumber>>16),
		byte(f.SequenceNumber>>8), byte(f.SequenceNumber))
	dst = append(dst, f.Payload...)
	if len(f.Padding) > 0 {
		dst = append(dst, f.Padding...)
	}
	return dst
}

// UnmarshalFrame reads and parses a single Frame from a reader.
func UnmarshalFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, fmt.Errorf("protocol: failed to read frame header: %w", err)
	}

	frameType := FrameType(header[0])
	flags := header[1]
	payloadLen := binary.BigEndian.Uint16(header[2:4])
	seqNum := binary.BigEndian.Uint32(header[4:8])

	if payloadLen > MaxFramePayloadSize {
		return nil, fmt.Errorf("protocol: frame payload too large: %d > %d", payloadLen, MaxFramePayloadSize)
	}

	data := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("protocol: failed to read frame payload: %w", err)
		}
	}

	frame := &Frame{
		Type:           frameType,
		Flags:          flags,
		SequenceNumber: seqNum,
	}

	// If HAS_PADDING flag is not set, entire data is payload
	frame.Payload = data
	frame.Padding = nil

	return frame, nil
}

// MaxFramePayloadSize is the maximum allowed payload size in a single frame (16KB).
const MaxFramePayloadSize = 16384

// Command types inside the decrypted payload
type Command uint8

const (
	CmdConnect   Command = 0x01
	CmdData      Command = 0x02
	CmdClose     Command = 0x03
	CmdPadding   Command = 0x04
	CmdKeepalive Command = 0x05
)

// String returns the human-readable name of a Command.
func (c Command) String() string {
	switch c {
	case CmdConnect:
		return "CONNECT"
	case CmdData:
		return "DATA"
	case CmdClose:
		return "CLOSE"
	case CmdPadding:
		return "PADDING"
	case CmdKeepalive:
		return "KEEPALIVE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", uint8(c))
	}
}

// InnerPayload represents the decrypted inner payload structure.
type InnerPayload struct {
	Cmd      Command
	ConnID   uint16 // Connection multiplexing ID
	Data     []byte
}

// InnerPayload header: Cmd(1) + ConnID(2) + DataLength(2) = 5 bytes
const InnerPayloadHeaderSize = 5

// MarshalInner serializes an InnerPayload into bytes.
func (p *InnerPayload) MarshalInner() []byte {
	buf := make([]byte, InnerPayloadHeaderSize+len(p.Data))
	buf[0] = byte(p.Cmd)
	binary.BigEndian.PutUint16(buf[1:3], p.ConnID)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(p.Data)))
	copy(buf[InnerPayloadHeaderSize:], p.Data)
	return buf
}

// AppendInner appends a serialized InnerPayload to dst without allocating a new buffer.
func (p *InnerPayload) AppendInner(dst []byte) []byte {
	dataLen := uint16(len(p.Data))
	dst = append(dst, byte(p.Cmd), byte(p.ConnID>>8), byte(p.ConnID), byte(dataLen>>8), byte(dataLen))
	dst = append(dst, p.Data...)
	return dst
}

// UnmarshalInner parses an InnerPayload from bytes.
func UnmarshalInner(data []byte) (*InnerPayload, error) {
	if len(data) < InnerPayloadHeaderSize {
		return nil, errors.New("protocol: inner payload too short")
	}

	cmd := Command(data[0])
	connID := binary.BigEndian.Uint16(data[1:3])
	dataLen := binary.BigEndian.Uint16(data[3:5])

	if int(dataLen) > len(data)-InnerPayloadHeaderSize {
		return nil, fmt.Errorf("protocol: inner payload data length mismatch: declared %d, available %d",
			dataLen, len(data)-InnerPayloadHeaderSize)
	}

	return &InnerPayload{
		Cmd:    cmd,
		ConnID: connID,
		Data:   data[InnerPayloadHeaderSize : InnerPayloadHeaderSize+int(dataLen)],
	}, nil
}

// NewDataFrame creates a new data-carrying frame for the given stream type.
func NewDataFrame(frameType FrameType, seq uint32, encryptedPayload []byte) *Frame {
	return &Frame{
		Type:           frameType,
		Flags:          0,
		SequenceNumber: seq,
		Payload:        encryptedPayload,
	}
}

// NewPaddingFrame creates a padding-only frame of the specified size.
func NewPaddingFrame(seq uint32, size int) *Frame {
	return &Frame{
		Type:           FramePadding,
		Flags:          0,
		SequenceNumber: seq,
		Payload:        make([]byte, size),
	}
}

var (
	ErrFrameTooLarge    = errors.New("protocol: frame exceeds maximum size")
	ErrInvalidFrame     = errors.New("protocol: invalid frame")
	ErrPayloadTooShort  = errors.New("protocol: payload too short")
)
