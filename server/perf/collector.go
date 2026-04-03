// Package perf provides lightweight performance instrumentation for the VPN
// data path. It collects latency histograms, counters and gauges at key points
// (obfuscation, encryption, mux framing, TUN I/O) and exposes atomic snapshots
// for the diagnostics API.
//
// Design constraints:
//   - Zero-allocation on the hot path (atomic operations only).
//   - No locks on Track* calls — all metrics use atomic uint64.
//   - Snapshot() copies atomics into a plain struct (safe for JSON).
package perf

import (
	"sync/atomic"
	"time"
)

// Stage identifies a point in the data path where latency is measured.
type Stage string

const (
	StageObfsWrite    Stage = "obfs_write"
	StageObfsRead     Stage = "obfs_read"
	StageObfsReadWait Stage = "obfs_read_wait" // time spent blocked waiting for data from network
	StageObfsReadProc Stage = "obfs_read_proc" // time spent processing/defragmenting TLS records
	StageNoiseEnc     Stage = "noise_encrypt"
	StageNoiseDec     Stage = "noise_decrypt"
	StageMuxWrite     Stage = "mux_write"
	StageMuxRead      Stage = "mux_read"
	StageTunWrite     Stage = "tun_write"
	StageTunRead      Stage = "tun_read"
	StageHandshake    Stage = "handshake"
	StageFullIngress  Stage = "full_ingress" // socket → TUN
	StageFullEgress   Stage = "full_egress"  // TUN → socket
)

// allStages enumerates every Stage for iteration.
var allStages = []Stage{
	StageObfsWrite, StageObfsRead,
	StageObfsReadWait, StageObfsReadProc,
	StageNoiseEnc, StageNoiseDec,
	StageMuxWrite, StageMuxRead,
	StageTunWrite, StageTunRead,
	StageHandshake,
	StageFullIngress, StageFullEgress,
}

// histogram is a lock-free approximate latency histogram.
// It uses fixed log2-based buckets: <1µs, <2µs, <4µs, … <~537s (30 buckets).
// 30 buckets cover up to 2^29 µs ≈ 537 seconds, enough for blocking I/O
// stages like full_ingress where TCP retransmission timeouts (~30s) and
// tun_read (up to 14s observed) can push latencies far beyond the old
// 20-bucket ceiling of ~512ms.
const histBuckets = 30

type histogram struct {
	buckets [histBuckets]atomic.Uint64
	count   atomic.Uint64
	sumNs   atomic.Uint64 // total nanoseconds for mean calculation
	maxNs   atomic.Uint64 // approximate max (relaxed store)
}

// record adds a single observation. Lock-free, allocation-free.
func (h *histogram) record(d time.Duration) {
	ns := uint64(d.Nanoseconds())
	if ns == 0 {
		ns = 1
	}

	// Bucket index = floor(log2(ns / 1000)). Clamp to [0, histBuckets-1].
	usec := ns / 1000
	if usec == 0 {
		usec = 1
	}
	idx := 0
	v := usec
	for v > 1 && idx < histBuckets-1 {
		v >>= 1
		idx++
	}
	h.buckets[idx].Add(1)
	h.count.Add(1)
	h.sumNs.Add(ns)

	// Approximate max — relaxed CAS is fine for diagnostics.
	for {
		cur := h.maxNs.Load()
		if ns <= cur {
			break
		}
		if h.maxNs.CompareAndSwap(cur, ns) {
			break
		}
	}
}

// HistogramSnapshot is a JSON-friendly copy of a histogram.
type HistogramSnapshot struct {
	Count   uint64  `json:"count"`
	MeanUs  float64 `json:"mean_us"`
	MaxUs   float64 `json:"max_us"`
	P50Us   float64 `json:"p50_us"`
	P95Us   float64 `json:"p95_us"`
	P99Us   float64 `json:"p99_us"`
}

// snapshot returns an approximate point-in-time copy.
func (h *histogram) snapshot() HistogramSnapshot {
	snap := HistogramSnapshot{
		Count: h.count.Load(),
		MaxUs: float64(h.maxNs.Load()) / 1000.0,
	}
	if snap.Count == 0 {
		return snap
	}
	snap.MeanUs = float64(h.sumNs.Load()) / float64(snap.Count) / 1000.0

	// Compute percentiles from bucket counts.
	var bucketCounts [histBuckets]uint64
	for i := range bucketCounts {
		bucketCounts[i] = h.buckets[i].Load()
	}
	snap.P50Us = percentile(bucketCounts, snap.Count, 0.50)
	snap.P95Us = percentile(bucketCounts, snap.Count, 0.95)
	snap.P99Us = percentile(bucketCounts, snap.Count, 0.99)
	return snap
}

// percentile estimates the pth percentile from histogram buckets.
// Each bucket i covers [2^i, 2^(i+1)) microseconds; we return the upper bound
// of the bucket that contains the target rank.
func percentile(buckets [histBuckets]uint64, total uint64, p float64) float64 {
	target := uint64(float64(total)*p + 0.5)
	if target == 0 {
		target = 1
	}
	var cumulative uint64
	for i, c := range buckets {
		cumulative += c
		if cumulative >= target {
			// Upper bound of bucket i in microseconds.
			if i == 0 {
				return 1.0
			}
			return float64(uint64(1) << uint(i))
		}
	}
	return float64(uint64(1) << uint(histBuckets-1))
}

// stageMetrics holds the histogram and packet counter for one Stage.
type stageMetrics struct {
	hist    histogram
	bytes   atomic.Uint64
	packets atomic.Uint64
}

// TCPInfo holds OS-level TCP metrics polled from VPN client sockets.
// Fields are updated atomically by pollTCPInfo (platform-specific).
type TCPInfo struct {
	RTTUs          atomic.Uint64 // smoothed RTT in microseconds
	RTTVarUs       atomic.Uint64 // RTT variance in microseconds
	RetransmitSegs atomic.Uint64 // total retransmitted segments (cumulative)
	LostSegs       atomic.Uint64 // segments considered lost
	CwndSegs       atomic.Uint64 // current congestion window in segments
	SndMSS         atomic.Uint64 // sender maximum segment size
}

// TCPInfoSnapshot is a JSON-friendly copy of TCPInfo.
type TCPInfoSnapshot struct {
	RTTUs          uint64 `json:"rtt_us"`
	RTTVarUs       uint64 `json:"rtt_var_us"`
	RetransmitSegs uint64 `json:"retransmit_segs"`
	LostSegs       uint64 `json:"lost_segs"`
	CwndSegs       uint64 `json:"cwnd_segs"`
	SndMSS         uint64 `json:"snd_mss"`
}

func (ti *TCPInfo) snapshot() TCPInfoSnapshot {
	return TCPInfoSnapshot{
		RTTUs:          ti.RTTUs.Load(),
		RTTVarUs:       ti.RTTVarUs.Load(),
		RetransmitSegs: ti.RetransmitSegs.Load(),
		LostSegs:       ti.LostSegs.Load(),
		CwndSegs:       ti.CwndSegs.Load(),
		SndMSS:         ti.SndMSS.Load(),
	}
}

// Collector is the central metrics aggregator. Create one per Server via
// NewCollector() and pass it to components that need instrumentation.
// All methods are safe for concurrent use.
type Collector struct {
	stages map[Stage]*stageMetrics

	// Global counters.
	ActiveSessions   atomic.Int64
	TotalSessions    atomic.Uint64
	RetransmitCount  atomic.Uint64
	CongestionWindow atomic.Int64
	SSThresh         atomic.Int64

	// TCP is the latest OS-level TCP info from a representative client connection.
	TCP TCPInfo
}

// NewCollector creates a ready-to-use Collector.
func NewCollector() *Collector {
	c := &Collector{
		stages: make(map[Stage]*stageMetrics, len(allStages)),
	}
	for _, s := range allStages {
		c.stages[s] = &stageMetrics{}
	}
	return c
}

// TrackLatency records a single latency observation for the given stage.
// Designed for the hot path: no locks, no allocations.
func (c *Collector) TrackLatency(stage Stage, d time.Duration) {
	if m, ok := c.stages[stage]; ok {
		m.hist.record(d)
	}
}

// TrackPacket records one packet of the given size passing through a stage.
func (c *Collector) TrackPacket(stage Stage, size int) {
	if m, ok := c.stages[stage]; ok {
		m.packets.Add(1)
		m.bytes.Add(uint64(size))
	}
}

// TrackRetransmit increments the global retransmit counter.
func (c *Collector) TrackRetransmit() {
	c.RetransmitCount.Add(1)
}

// SetCongestion updates the congestion window and ssthresh gauges.
func (c *Collector) SetCongestion(cwnd, ssthresh int) {
	c.CongestionWindow.Store(int64(cwnd))
	c.SSThresh.Store(int64(ssthresh))
}

// Timer returns a function that, when called, records elapsed time since now.
// Usage:   done := collector.Timer(perf.StageNoiseEnc); ...; done()
func (c *Collector) Timer(stage Stage) func() {
	start := time.Now()
	return func() {
		c.TrackLatency(stage, time.Since(start))
	}
}

// StageSnapshot is the JSON-friendly snapshot for one stage.
type StageSnapshot struct {
	Latency HistogramSnapshot `json:"latency"`
	Packets uint64            `json:"packets"`
	Bytes   uint64            `json:"bytes"`
}

// Snapshot is the full metrics snapshot returned by the API.
type Snapshot struct {
	Timestamp        time.Time                `json:"timestamp"`
	Stages           map[string]StageSnapshot `json:"stages"`
	ActiveSessions   int64                    `json:"active_sessions"`
	TotalSessions    uint64                   `json:"total_sessions"`
	RetransmitCount  uint64                   `json:"retransmit_count"`
	CongestionWindow int64                    `json:"congestion_window"`
	SSThresh         int64                    `json:"ssthresh"`
	TCPInfo          TCPInfoSnapshot          `json:"tcp_info"`
}

// Snapshot returns a point-in-time copy of all metrics.
func (c *Collector) Snapshot() Snapshot {
	s := Snapshot{
		Timestamp:        time.Now(),
		Stages:           make(map[string]StageSnapshot, len(allStages)),
		ActiveSessions:   c.ActiveSessions.Load(),
		TotalSessions:    c.TotalSessions.Load(),
		RetransmitCount:  c.RetransmitCount.Load(),
		CongestionWindow: c.CongestionWindow.Load(),
		SSThresh:         c.SSThresh.Load(),
		TCPInfo:          c.TCP.snapshot(),
	}
	for _, stage := range allStages {
		m := c.stages[stage]
		s.Stages[string(stage)] = StageSnapshot{
			Latency: m.hist.snapshot(),
			Packets: m.packets.Load(),
			Bytes:   m.bytes.Load(),
		}
	}
	return s
}

// Reset zeroes all counters and histograms. Useful for periodic reporting.
func (c *Collector) Reset() {
	for _, m := range c.stages {
		for i := range m.hist.buckets {
			m.hist.buckets[i].Store(0)
		}
		m.hist.count.Store(0)
		m.hist.sumNs.Store(0)
		m.hist.maxNs.Store(0)
		m.bytes.Store(0)
		m.packets.Store(0)
	}
	c.RetransmitCount.Store(0)
}
