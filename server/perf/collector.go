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
//
// Integer type (vs the previous string type) enables O(1) direct array access
// instead of a string-hash map lookup on every hot-path Track call.
// At 30 Mbps (~2630 packets/sec), with up to 7 Track calls per packet,
// this eliminates ~18,000 string hash computations and map bucket scans per
// second — replacing them with cheap bounds-checked array loads.
type Stage int

const (
	StageObfsWrite Stage = iota
	StageObfsRead
	StageObfsReadWait // time spent blocked waiting for data from network
	StageObfsReadProc // time spent processing/defragmenting TLS records
	StageNoiseEnc
	StageNoiseDec
	StageMuxWrite
	StageMuxRead
	StageTunWrite
	StageTunRead
	StageHandshake
	StageFullIngress  // socket → TUN
	StageFullEgress   // TUN → socket
	stageCount        // sentinel — total number of stages (not a valid Stage)
)

// stageName maps each Stage integer to its stable JSON/API name.
// Index order must stay in sync with the iota constants above.
var stageName = [stageCount]string{
	StageObfsWrite:    "obfs_write",
	StageObfsRead:     "obfs_read",
	StageObfsReadWait: "obfs_read_wait",
	StageObfsReadProc: "obfs_read_proc",
	StageNoiseEnc:     "noise_encrypt",
	StageNoiseDec:     "noise_decrypt",
	StageMuxWrite:     "mux_write",
	StageMuxRead:      "mux_read",
	StageTunWrite:     "tun_write",
	StageTunRead:      "tun_read",
	StageHandshake:    "handshake",
	StageFullIngress:  "full_ingress",
	StageFullEgress:   "full_egress",
}

// Name returns the stable string name for this Stage (e.g. "noise_encrypt").
// Returns "unknown" for out-of-range values.
func (s Stage) Name() string {
	if s >= 0 && s < stageCount {
		return stageName[s]
	}
	return "unknown"
}

// allStages enumerates every valid Stage constant for iteration.
var allStages = func() []Stage {
	ss := make([]Stage, stageCount)
	for i := range ss {
		ss[i] = Stage(i)
	}
	return ss
}()

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
	SSThresh       atomic.Uint64 // slow start threshold in segments
}

// TCPInfoSnapshot is a JSON-friendly copy of TCPInfo.
type TCPInfoSnapshot struct {
	RTTUs          uint64 `json:"rtt_us"`
	RTTVarUs       uint64 `json:"rtt_var_us"`
	RetransmitSegs uint64 `json:"retransmit_segs"`
	LostSegs       uint64 `json:"lost_segs"`
	CwndSegs       uint64 `json:"cwnd_segs"`
	SndMSS         uint64 `json:"snd_mss"`
	SSThresh       uint64 `json:"ssthresh"`
}

func (ti *TCPInfo) snapshot() TCPInfoSnapshot {
	return TCPInfoSnapshot{
		RTTUs:          ti.RTTUs.Load(),
		RTTVarUs:       ti.RTTVarUs.Load(),
		RetransmitSegs: ti.RetransmitSegs.Load(),
		LostSegs:       ti.LostSegs.Load(),
		CwndSegs:       ti.CwndSegs.Load(),
		SndMSS:         ti.SndMSS.Load(),
		SSThresh:       ti.SSThresh.Load(),
	}
}

// Collector is the central metrics aggregator. Create one per Server via
// NewCollector() and pass it to components that need instrumentation.
// All methods are safe for concurrent use.
type Collector struct {
	// stages is a fixed-size array indexed directly by Stage integer.
	// Direct array access (bounds-check + load, ~2 ns) vs the previous
	// map[Stage]*stageMetrics (string hash + bucket scan + pointer deref, ~15 ns).
	// Memory layout: all stageMetrics contiguous — cache-friendly iteration in Snapshot/Reset.
	stages [stageCount]stageMetrics

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
// The stages array is zero-value initialized — no map allocation or loop needed.
func NewCollector() *Collector {
	return &Collector{}
}

// TrackLatency records a single latency observation for the given stage.
// Designed for the hot path: bounds-checked array access, no locks, no allocations.
func (c *Collector) TrackLatency(stage Stage, d time.Duration) {
	if stage >= 0 && stage < stageCount {
		c.stages[stage].hist.record(d)
	}
}

// TrackPacket records one packet of the given size passing through a stage.
func (c *Collector) TrackPacket(stage Stage, size int) {
	if stage >= 0 && stage < stageCount {
		c.stages[stage].packets.Add(1)
		c.stages[stage].bytes.Add(uint64(size))
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
		Stages:           make(map[string]StageSnapshot, int(stageCount)),
		ActiveSessions:   c.ActiveSessions.Load(),
		TotalSessions:    c.TotalSessions.Load(),
		RetransmitCount:  c.RetransmitCount.Load(),
		CongestionWindow: c.CongestionWindow.Load(),
		SSThresh:         c.SSThresh.Load(),
		TCPInfo:          c.TCP.snapshot(),
	}
	for i := Stage(0); i < stageCount; i++ {
		m := &c.stages[i]
		s.Stages[stageName[i]] = StageSnapshot{
			Latency: m.hist.snapshot(),
			Packets: m.packets.Load(),
			Bytes:   m.bytes.Load(),
		}
	}
	return s
}

// Reset zeroes all counters and histograms. Useful for periodic reporting.
func (c *Collector) Reset() {
	for i := range c.stages {
		m := &c.stages[i]
		for j := range m.hist.buckets {
			m.hist.buckets[j].Store(0)
		}
		m.hist.count.Store(0)
		m.hist.sumNs.Store(0)
		m.hist.maxNs.Store(0)
		m.bytes.Store(0)
		m.packets.Store(0)
	}
	c.RetransmitCount.Store(0)
}
