package transport

import (
	"sync"
	"time"
)

// pacer spreads packet transmissions evenly over time instead of sending
// bursts. This is critical for BBR: without pacing, a burst of packets
// fills router buffers, causing queuing delay and false loss signals.
//
// The pacer uses a token-bucket model:
//   - Tokens accumulate at `rate` bytes/sec.
//   - Each send consumes `packetSize` tokens.
//   - If no tokens are available, the sender sleeps until the next slot.
//
// Thread-safe: all methods acquire mu.
type pacer struct {
	mu sync.Mutex

	rate int64 // target pacing rate in bytes/sec (0 = unlimited)

	// Token bucket state.
	tokens    float64   // available tokens (bytes)
	maxBurst  int       // max tokens that can accumulate (bytes) — prevents large bursts after idle
	lastFill  time.Time // last time tokens were replenished

	// Stats.
	totalWait time.Duration // cumulative time spent waiting for pacing slots
	waitCount int64         // number of times a send had to wait
}

// newPacer creates a pacer with the given initial rate and burst size.
// maxBurst limits how many bytes can accumulate while idle — typically
// 10 × MTU to allow a small initial burst without violating pacing.
func newPacer(rate int64, maxBurst int) *pacer {
	return &pacer{
		rate:     rate,
		tokens:   float64(maxBurst), // start with full burst allowance
		maxBurst: maxBurst,
		lastFill: time.Now(),
	}
}

// SetRate updates the pacing rate. Called by the BBR state machine whenever
// BtlBw or pacing_gain changes.
func (p *pacer) SetRate(bytesPerSec int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rate = bytesPerSec
}

// Rate returns the current pacing rate in bytes/sec.
func (p *pacer) Rate() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate
}

// timeToSend returns how long the caller should wait before sending
// a packet of the given size. Returns 0 if the packet can be sent
// immediately (tokens available).
func (p *pacer) timeToSend(packetSize int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rate <= 0 {
		return 0 // unlimited
	}

	p.fillTokens()

	need := float64(packetSize)
	if p.tokens >= need {
		// Enough tokens — can send immediately.
		p.tokens -= need
		return 0
	}

	// Deficit: compute wait time.
	deficit := need - p.tokens
	wait := time.Duration(deficit * float64(time.Second) / float64(p.rate))
	return wait
}

// WaitForSlot blocks until the pacer allows sending a packet of the given size.
// Returns immediately if tokens are available.
func (p *pacer) WaitForSlot(packetSize int) {
	wait := p.timeToSend(packetSize)
	if wait <= 0 {
		return
	}

	time.Sleep(wait)

	// After sleeping, consume the tokens.
	p.mu.Lock()
	p.fillTokens()
	p.tokens -= float64(packetSize)
	if p.tokens < 0 {
		p.tokens = 0
	}
	p.totalWait += wait
	p.waitCount++
	p.mu.Unlock()
}

// TokensAvailable returns true if a packet of the given size can be sent
// immediately without waiting.
func (p *pacer) TokensAvailable(packetSize int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rate <= 0 {
		return true
	}

	p.fillTokens()
	return p.tokens >= float64(packetSize)
}

// fillTokens replenishes tokens based on elapsed time since last fill.
// Must be called with mu held.
func (p *pacer) fillTokens() {
	now := time.Now()
	elapsed := now.Sub(p.lastFill)
	if elapsed <= 0 {
		return
	}

	p.lastFill = now
	added := float64(p.rate) * elapsed.Seconds()
	p.tokens += added
	if p.tokens > float64(p.maxBurst) {
		p.tokens = float64(p.maxBurst)
	}
}

// Stats returns cumulative pacing wait statistics.
func (p *pacer) Stats() (totalWait time.Duration, waitCount int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalWait, p.waitCount
}

// Reset clears the pacer state, keeping the current rate.
func (p *pacer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens = float64(p.maxBurst)
	p.lastFill = time.Now()
	p.totalWait = 0
	p.waitCount = 0
}
