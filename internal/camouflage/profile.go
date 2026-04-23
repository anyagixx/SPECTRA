package camouflage

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync"
)

// Profile holds the statistical traffic profile used for camouflage shaping.
type Profile struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Description  string       `json:"description"`
	PacketSizes  PacketSizes  `json:"packet_sizes"`
	Timing       Timing       `json:"timing"`
	MarkovChain  MarkovChain  `json:"markov_chain"`
	FlowFeatures FlowFeatures `json:"flow_features"`
}

// PacketSizes defines the packet size distributions for each stream type.
type PacketSizes struct {
	Video VideoSizes   `json:"video"`
	Audio Distribution `json:"audio"`
	Input Distribution `json:"input"`
}

// VideoSizes has separate distributions for P-frames and I-frames.
type VideoSizes struct {
	PFrame      Distribution `json:"p_frame"`
	IFrame      Distribution `json:"i_frame"`
	IFrameRatio float64      `json:"i_frame_ratio"`
}

// Distribution describes a statistical distribution for sampling.
type Distribution struct {
	Min          int     `json:"min"`
	Max          int     `json:"max"`
	Mean         float64 `json:"mean"`
	Stddev       float64 `json:"stddev"`
	Distribution string  `json:"distribution"` // "normal" or "exponential"
}

// Timing defines inter-arrival time distributions per stream type.
type Timing struct {
	VideoIntervalMs Distribution `json:"video_interval_ms"`
	AudioIntervalMs Distribution `json:"audio_interval_ms"`
	InputIntervalMs Distribution `json:"input_interval_ms"`
}

// MarkovChain defines the traffic pattern state machine.
type MarkovChain struct {
	States           []string    `json:"states"`
	TransitionMatrix [][]float64 `json:"transition_matrix"`
}

// FlowFeatures defines aggregate flow-level characteristics.
// Reserved for future use in flow-level traffic analysis evasion (e.g. byte
// ratio enforcement, session duration bounding). Not currently consumed by the
// Shaper, but kept in the profile schema for forward compatibility.
type FlowFeatures struct {
	UpDownByteRatio  RangeF `json:"upstream_downstream_byte_ratio"`
	SessionDurationS RangeI `json:"session_duration_seconds"`
}

// RangeF is a float64 min/max/mean range.
type RangeF struct {
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
}

// RangeI is an integer min/max/mean range.
type RangeI struct {
	Min  int `json:"min"`
	Max  int `json:"max"`
	Mean int `json:"mean"`
}

// LoadProfile reads and parses a traffic profile from a JSON file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("camouflage: failed to read profile %s: %w", path, err)
	}

	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("camouflage: failed to parse profile %s: %w", path, err)
	}

	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("camouflage: invalid profile %s: %w", path, err)
	}

	return &p, nil
}

// validate checks that the profile is internally consistent.
func (p *Profile) validate() error {
	mc := p.MarkovChain
	n := len(mc.States)
	if n == 0 {
		return fmt.Errorf("no states defined")
	}
	if len(mc.TransitionMatrix) != n {
		return fmt.Errorf("transition matrix rows (%d) != states (%d)", len(mc.TransitionMatrix), n)
	}
	for i, row := range mc.TransitionMatrix {
		if len(row) != n {
			return fmt.Errorf("transition matrix row %d has %d cols, want %d", i, len(row), n)
		}
		sum := 0.0
		for _, v := range row {
			sum += v
		}
		if math.Abs(sum-1.0) > 0.01 {
			return fmt.Errorf("transition matrix row %d sums to %f, want ~1.0", i, sum)
		}
	}
	return nil
}

// Sample draws a random value from the given Distribution, clamped to [Min, Max].
func (d *Distribution) Sample(rng *rand.Rand) int {
	var val float64
	switch d.Distribution {
	case "exponential":
		val = rng.ExpFloat64() * d.Mean
	default: // "normal"
		val = rng.NormFloat64()*d.Stddev + d.Mean
	}

	clamped := int(math.Round(val))
	if clamped < d.Min {
		clamped = d.Min
	}
	if clamped > d.Max {
		clamped = d.Max
	}
	return clamped
}

// SampleFloat draws a float64 from the given Distribution, clamped to [Min, Max].
func (d *Distribution) SampleFloat(rng *rand.Rand) float64 {
	var val float64
	switch d.Distribution {
	case "exponential":
		val = rng.ExpFloat64() * d.Mean
	default:
		val = rng.NormFloat64()*d.Stddev + d.Mean
	}
	if val < float64(d.Min) {
		val = float64(d.Min)
	}
	if val > float64(d.Max) {
		val = float64(d.Max)
	}
	return val
}

// MarkovStepper walks the Markov chain to produce a sequence of traffic states.
type MarkovStepper struct {
	profile *Profile
	state   int
	rng     *rand.Rand
	mu      sync.Mutex
}

// NewMarkovStepper creates a stepper starting in the "idle" state (index 0).
func NewMarkovStepper(profile *Profile, rng *rand.Rand) *MarkovStepper {
	return &MarkovStepper{
		profile: profile,
		state:   0,
		rng:     rng,
	}
}

// Step advances the Markov chain by one step and returns the new state name.
func (ms *MarkovStepper) Step() string {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	row := ms.profile.MarkovChain.TransitionMatrix[ms.state]
	r := ms.rng.Float64()
	cumulative := 0.0
	for i, p := range row {
		cumulative += p
		if r <= cumulative {
			ms.state = i
			return ms.profile.MarkovChain.States[i]
		}
	}
	// Fallback to last state (rounding)
	ms.state = len(row) - 1
	return ms.profile.MarkovChain.States[ms.state]
}

// CurrentState returns the current state name.
func (ms *MarkovStepper) CurrentState() string {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.profile.MarkovChain.States[ms.state]
}
