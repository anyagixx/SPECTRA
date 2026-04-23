package handshake

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// bloomBucket is a single Bloom filter bucket used inside the rotating filter.
type bloomBucket struct {
	bits  []uint64
	size  uint
	count uint
}

func newBloomBucket(size uint) *bloomBucket {
	words := (size + 63) / 64
	return &bloomBucket{
		bits: make([]uint64, words),
		size: size,
	}
}

func (b *bloomBucket) set(idx uint) {
	b.bits[idx/64] |= 1 << (idx % 64)
}

func (b *bloomBucket) test(idx uint) bool {
	return b.bits[idx/64]&(1<<(idx%64)) != 0
}

func (b *bloomBucket) reset() {
	for i := range b.bits {
		b.bits[i] = 0
	}
	b.count = 0
}

// BloomFilter is a time-rotating Bloom filter for anti-replay detection.
// It maintains two buckets (current and previous) that rotate at a fixed
// interval. Test() checks both buckets; Add() inserts into current only.
// Entries survive for 1–2 rotation intervals, aligning with the handshake
// timestamp window.
type BloomFilter struct {
	current  *bloomBucket
	previous *bloomBucket
	size     uint
	hashes   uint
	mu       sync.Mutex

	rotateInterval time.Duration
	lastRotation   time.Time
}

// NewBloomFilter creates a new time-rotating Bloom filter.
// size is the bit capacity of each bucket; hashes is the number of hash functions.
func NewBloomFilter(size, hashes uint) *BloomFilter {
	return NewBloomFilterWithRotation(size, hashes, MaxTimestampDrift)
}

// NewBloomFilterWithRotation creates a Bloom filter with a custom rotation interval.
func NewBloomFilterWithRotation(size, hashes uint, rotateInterval time.Duration) *BloomFilter {
	return &BloomFilter{
		current:        newBloomBucket(size),
		previous:       newBloomBucket(size),
		size:           size,
		hashes:         hashes,
		rotateInterval: rotateInterval,
		lastRotation:   time.Now(),
	}
}

// maybeRotate promotes current → previous and resets current if the
// rotation interval has elapsed. Caller must hold bf.mu.
func (bf *BloomFilter) maybeRotate() {
	if time.Since(bf.lastRotation) >= bf.rotateInterval {
		bf.previous, bf.current = bf.current, bf.previous
		bf.current.reset()
		bf.lastRotation = time.Now()
	}
}

// Add inserts an element into the current Bloom filter bucket.
func (bf *BloomFilter) Add(data []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	bf.maybeRotate()

	for i := uint(0); i < bf.hashes; i++ {
		bf.current.set(bf.hash(data, i))
	}
	bf.current.count++
}

// Test checks if an element might be in the Bloom filter (current or previous bucket).
func (bf *BloomFilter) Test(data []byte) bool {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	bf.maybeRotate()

	// Check current bucket
	for i := uint(0); i < bf.hashes; i++ {
		idx := bf.hash(data, i)
		if !bf.current.test(idx) {
			goto checkPrevious
		}
	}
	return true

checkPrevious:
	// Check previous bucket
	for i := uint(0); i < bf.hashes; i++ {
		idx := bf.hash(data, i)
		if !bf.previous.test(idx) {
			return false
		}
	}
	return true
}

// hash computes the i-th hash of data using double-hashing with SHA-256.
func (bf *BloomFilter) hash(data []byte, i uint) uint {
	h := sha256.Sum256(data)
	h1 := binary.BigEndian.Uint32(h[0:4])
	h2 := binary.BigEndian.Uint32(h[4:8])
	return uint((uint64(h1) + uint64(i)*uint64(h2)) % uint64(bf.size))
}

// Count returns the number of elements in the current bucket.
func (bf *BloomFilter) Count() uint {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	return bf.current.count
}
