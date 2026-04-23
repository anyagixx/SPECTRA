package camouflage

import (
	"math"
	"math/rand"
	"testing"

	"github.com/anyagixx/SPECTRA/internal/protocol"
)

func testProfile() *Profile {
	return &Profile{
		Name:    "test",
		Version: "1.0",
		PacketSizes: PacketSizes{
			Video: VideoSizes{
				PFrame:      Distribution{Min: 900, Max: 1400, Mean: 1200, Stddev: 120, Distribution: "normal"},
				IFrame:      Distribution{Min: 3000, Max: 8000, Mean: 5500, Stddev: 1200, Distribution: "normal"},
				IFrameRatio: 0.033,
			},
			Audio: Distribution{Min: 40, Max: 160, Mean: 80, Stddev: 25, Distribution: "normal"},
			Input: Distribution{Min: 20, Max: 120, Mean: 52, Stddev: 18, Distribution: "normal"},
		},
		Timing: Timing{
			VideoIntervalMs: Distribution{Min: 10, Max: 25, Mean: 16, Stddev: 2, Distribution: "normal"},
			AudioIntervalMs: Distribution{Min: 15, Max: 30, Mean: 20, Stddev: 1, Distribution: "normal"},
			InputIntervalMs: Distribution{Min: 2, Max: 20, Mean: 8, Stddev: 3, Distribution: "exponential"},
		},
		MarkovChain: MarkovChain{
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

func TestDistributionSample(t *testing.T) {
	d := Distribution{Min: 100, Max: 200, Mean: 150, Stddev: 20, Distribution: "normal"}
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 1000; i++ {
		v := d.Sample(rng)
		if v < d.Min || v > d.Max {
			t.Fatalf("Sample %d out of range [%d, %d]: %d", i, d.Min, d.Max, v)
		}
	}
}

func TestDistributionMean(t *testing.T) {
	d := Distribution{Min: 100, Max: 200, Mean: 150, Stddev: 20, Distribution: "normal"}
	rng := rand.New(rand.NewSource(42))

	sum := 0.0
	n := 10000
	for i := 0; i < n; i++ {
		sum += float64(d.Sample(rng))
	}
	mean := sum / float64(n)

	if math.Abs(mean-d.Mean) > 5.0 {
		t.Fatalf("Empirical mean = %.1f, expected ~%.1f", mean, d.Mean)
	}
}

func TestMarkovStepper(t *testing.T) {
	profile := testProfile()
	rng := rand.New(rand.NewSource(42))
	stepper := NewMarkovStepper(profile, rng)

	stateCount := make(map[string]int)
	n := 10000
	for i := 0; i < n; i++ {
		state := stepper.Step()
		stateCount[state]++
	}

	// "video" should be the most common state
	if stateCount["video"] < stateCount["idle"] {
		t.Fatal("video should be more common than idle")
	}

	// All states should appear
	for _, s := range profile.MarkovChain.States {
		if stateCount[s] == 0 {
			t.Fatalf("State %q never appeared in %d steps", s, n)
		}
	}
}

func TestShaperNextFrameType(t *testing.T) {
	profile := testProfile()
	shaper := NewShaper(profile)

	typeCount := make(map[protocol.FrameType]int)
	n := 1000
	for i := 0; i < n; i++ {
		ft := shaper.NextFrameType()
		typeCount[ft]++
	}

	// VIDEO should dominate
	if typeCount[protocol.FrameVideo] < typeCount[protocol.FramePadding] {
		t.Fatal("VIDEO frames should be more common than PADDING")
	}
}

func TestShaperPadToTarget(t *testing.T) {
	profile := testProfile()
	shaper := NewShaper(profile)

	data := []byte("short data")
	payload, padding := shaper.PadToTarget(data, protocol.FrameVideo)

	if len(payload) != len(data) {
		t.Fatal("Payload should be unchanged")
	}
	if len(padding) == 0 {
		t.Fatal("Padding should be added for short data on video stream")
	}
}

func TestShaperFragmentData(t *testing.T) {
	profile := testProfile()
	shaper := NewShaper(profile)

	// Large data that should be split into multiple chunks
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunks := shaper.FragmentData(data, protocol.FrameVideo)
	if len(chunks) < 2 {
		t.Fatalf("Expected multiple chunks, got %d", len(chunks))
	}

	// Verify all data is preserved
	var reassembled []byte
	for _, c := range chunks {
		reassembled = append(reassembled, c...)
	}
	if len(reassembled) != len(data) {
		t.Fatalf("Reassembled length = %d, want %d", len(reassembled), len(data))
	}
	for i := range data {
		if reassembled[i] != data[i] {
			t.Fatalf("Data mismatch at byte %d", i)
			break
		}
	}
}

func TestShaperFragmentDataWithTarget(t *testing.T) {
	profile := testProfile()
	shaper := NewShaper(profile)

	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}

	chunks := shaper.FragmentDataWithTarget(data, protocol.FrameHeaderSize+protocol.MaxFramePayloadSize)
	if len(chunks) == 0 {
		t.Fatal("Expected chunks for non-empty data")
	}

	var reassembled []byte
	maxChunk := 0
	for _, c := range chunks {
		reassembled = append(reassembled, c...)
		if len(c) > maxChunk {
			maxChunk = len(c)
		}
	}
	if len(reassembled) != len(data) {
		t.Fatalf("Reassembled length = %d, want %d", len(reassembled), len(data))
	}
	if maxChunk < 8*1024 {
		t.Fatalf("Expected large chunks for max-sized target, got max chunk %d bytes", maxChunk)
	}
}

func TestShaperSampleDelay(t *testing.T) {
	profile := testProfile()
	shaper := NewShaper(profile)

	for i := 0; i < 100; i++ {
		d := shaper.SampleDelay(protocol.FrameVideo)
		if d < 0 {
			t.Fatalf("Delay should not be negative: %v", d)
		}
	}
}

func TestProfileValidation(t *testing.T) {
	p := testProfile()
	if err := p.validate(); err != nil {
		t.Fatalf("Valid profile should pass validation: %v", err)
	}

	// Bad: row doesn't sum to 1
	bad := testProfile()
	bad.MarkovChain.TransitionMatrix[0] = []float64{0.1, 0.1, 0.1, 0.1, 0.1}
	if err := bad.validate(); err == nil {
		t.Fatal("Should reject matrix row not summing to 1")
	}

	// Bad: wrong number of columns
	bad2 := testProfile()
	bad2.MarkovChain.TransitionMatrix[0] = []float64{0.5, 0.5}
	if err := bad2.validate(); err == nil {
		t.Fatal("Should reject matrix row with wrong column count")
	}
}

func TestLoadBundledProfileProducesPositiveDelays(t *testing.T) {
	profile, err := LoadProfile("../../configs/profiles/geforcenow.json")
	if err != nil {
		t.Fatalf("LoadProfile failed: %v", err)
	}

	shaper := NewShaper(profile)
	frameTypes := []protocol.FrameType{
		protocol.FrameVideo,
		protocol.FrameAudio,
		protocol.FrameInput,
		protocol.FramePadding,
	}

	for _, frameType := range frameTypes {
		delay := shaper.SampleDelay(frameType)
		if delay <= 0 {
			t.Fatalf("SampleDelay(%v) = %v, want > 0", frameType, delay)
		}
	}
}
