package camouflage

import (
	crand "crypto/rand"
	"math/rand"
	"sync"
	"time"

	"github.com/anyagixx/SPECTRA/internal/protocol"
)

const maxFrameWireSize = protocol.FrameHeaderSize + protocol.MaxFramePayloadSize

// Shaper applies traffic shaping to match the loaded profile's statistical distribution.
// It decides frame types, sizes, timing, and generates padding.
type Shaper struct {
	profile *Profile
	stepper *MarkovStepper
	rng     *rand.Rand
	mu      sync.Mutex
}

// NewShaper creates a new traffic shaper using the given profile.
func NewShaper(profile *Profile) *Shaper {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &Shaper{
		profile: profile,
		stepper: NewMarkovStepper(profile, rng),
		rng:     rng,
	}
}

// ShapedFrame holds a frame along with its scheduled send delay.
type ShapedFrame struct {
	Frame *protocol.Frame
	Delay time.Duration // How long to wait before sending this frame
}

// NextFrameType advances the Markov chain and returns the corresponding FrameType.
func (s *Shaper) NextFrameType() protocol.FrameType {
	s.mu.Lock()
	state := s.stepper.Step()
	s.mu.Unlock()
	switch state {
	case "video":
		return protocol.FrameVideo
	case "audio":
		return protocol.FrameAudio
	case "input":
		return protocol.FrameInput
	case "iframe":
		return protocol.FrameVideo // I-frame is a video variant
	case "idle":
		return protocol.FramePadding
	default:
		return protocol.FramePadding
	}
}

// IsIFrame returns true if the current Markov state is "iframe".
func (s *Shaper) IsIFrame() bool {
	return s.stepper.CurrentState() == "iframe"
}

// PadToTarget pads data to a target size sampled from the profile distribution.
// Returns the padded data and the amount of padding added.
func (s *Shaper) PadToTarget(data []byte, frameType protocol.FrameType) ([]byte, []byte) {
	s.mu.Lock()
	targetSize := s.samplePacketSize(frameType)
	s.mu.Unlock()

	if len(data) >= targetSize {
		return data, nil
	}

	padding := make([]byte, targetSize-len(data))
	// Fill padding with cryptographically random bytes to avoid PRNG prediction
	crand.Read(padding)

	return data, padding
}

// samplePacketSize samples a target packet size from the profile for the given frame type.
func (s *Shaper) samplePacketSize(frameType protocol.FrameType) int {
	switch frameType {
	case protocol.FrameVideo:
		if s.IsIFrame() {
			return s.profile.PacketSizes.Video.IFrame.Sample(s.rng)
		}
		return s.profile.PacketSizes.Video.PFrame.Sample(s.rng)
	case protocol.FrameAudio:
		return s.profile.PacketSizes.Audio.Sample(s.rng)
	case protocol.FrameInput:
		return s.profile.PacketSizes.Input.Sample(s.rng)
	default:
		return s.profile.PacketSizes.Audio.Sample(s.rng) // padding uses audio-sized frames
	}
}

// SampleDelay returns the inter-arrival time for the given frame type.
func (s *Shaper) SampleDelay(frameType protocol.FrameType) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ms float64
	switch frameType {
	case protocol.FrameVideo:
		ms = s.profile.Timing.VideoIntervalMs.SampleFloat(s.rng)
	case protocol.FrameAudio:
		ms = s.profile.Timing.AudioIntervalMs.SampleFloat(s.rng)
	case protocol.FrameInput:
		ms = s.profile.Timing.InputIntervalMs.SampleFloat(s.rng)
	default:
		ms = s.profile.Timing.VideoIntervalMs.SampleFloat(s.rng)
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// SamplePacketSize returns a packet size sampled from the profile distribution
// for the given frame type. Safe for concurrent use.
func (s *Shaper) SamplePacketSize(frameType protocol.FrameType) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.samplePacketSize(frameType)
}

// GeneratePaddingFrame creates a padding-only frame with a profile-appropriate size.
func (s *Shaper) GeneratePaddingFrame(seq uint32) *protocol.Frame {
	s.mu.Lock()
	size := s.samplePacketSize(protocol.FramePadding)
	s.mu.Unlock()
	return protocol.NewPaddingFrame(seq, size)
}

// FragmentData splits data into chunks that fit within profile packet size distributions.
// Each chunk is sized to match the target distribution for the given frame type.
func (s *Shaper) FragmentData(data []byte, frameType protocol.FrameType) [][]byte {
	s.mu.Lock()
	targetSize := s.samplePacketSize(frameType)
	s.mu.Unlock()
	return s.FragmentDataWithTarget(data, targetSize)
}

// FragmentDataWithTarget splits data into chunks that fit within a specific
// wire-size budget. targetSize is the total frame size on the wire, including
// frame header, inner payload header, and AEAD tag.
func (s *Shaper) FragmentDataWithTarget(data []byte, targetSize int) [][]byte {
	if len(data) == 0 {
		return nil
	}

	if targetSize < 1 {
		targetSize = 1
	}
	if targetSize > maxFrameWireSize {
		targetSize = maxFrameWireSize
	}

	var chunks [][]byte
	offset := 0
	for offset < len(data) {
		// Account for frame header + encryption overhead
		overhead := protocol.FrameHeaderSize + protocol.InnerPayloadHeaderSize + 16 // 16 = poly1305 tag
		maxPayload := targetSize - overhead
		if maxPayload < 1 {
			maxPayload = 1
		}

		end := offset + maxPayload
		if end > len(data) {
			end = len(data)
		}

		chunk := make([]byte, end-offset)
		copy(chunk, data[offset:end])
		chunks = append(chunks, chunk)
		offset = end
	}

	return chunks
}
