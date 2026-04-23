package handshake

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// BloomFilter is a simple Bloom filter for anti-replay detection.
// It is periodically reset to avoid false-positive buildup.
type BloomFilter struct {
	bits    []uint64
	size    uint
	hashes  uint
	mu      sync.RWMutex
	count   uint
	maxLoad uint
}

// NewBloomFilter creates a new Bloom filter with the given bit size and hash count.
func NewBloomFilter(size, hashes uint) *BloomFilter {
	words := (size + 63) / 64
	return &BloomFilter{
		bits:    make([]uint64, words),
		size:    size,
		hashes:  hashes,
		maxLoad: size / 2, // reset when 50% full to limit false positive rate
	}
}

// Add inserts an element into the Bloom filter.
func (bf *BloomFilter) Add(data []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	// Auto-reset if too full
	if bf.count >= bf.maxLoad {
		bf.reset()
	}

	for i := uint(0); i < bf.hashes; i++ {
		idx := bf.hash(data, i)
		word := idx / 64
		bit := idx % 64
		bf.bits[word] |= 1 << bit
	}
	bf.count++
}

// Test checks if an element might be in the Bloom filter.
func (bf *BloomFilter) Test(data []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	for i := uint(0); i < bf.hashes; i++ {
		idx := bf.hash(data, i)
		word := idx / 64
		bit := idx % 64
		if bf.bits[word]&(1<<bit) == 0 {
			return false
		}
	}
	return true
}

// reset clears the Bloom filter.
func (bf *BloomFilter) reset() {
	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
}

// hash computes the i-th hash of data using double-hashing with SHA-256.
func (bf *BloomFilter) hash(data []byte, i uint) uint {
	// Use SHA-256 and split into two 32-bit hashes for double hashing
	h := sha256.Sum256(data)
	h1 := binary.BigEndian.Uint32(h[0:4])
	h2 := binary.BigEndian.Uint32(h[4:8])
	return uint((uint64(h1) + uint64(i)*uint64(h2)) % uint64(bf.size))
}

// Count returns the number of elements added since last reset.
func (bf *BloomFilter) Count() uint {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.count
}
