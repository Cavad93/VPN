package transport

import (
	"sync"
	"time"
)

// BBR state machine phases.
type bbrPhase int

const (
	// BBRStartup: exponential growth until BtlBw plateaus.
	BBRStartup bbrPhase = iota
	// BBRDrain: drain queue built during Startup.
	BBRDrain
	// BBRProbeBW: steady state — 8-phase pacing cycle.
	BBRProbeBW
	// BBRProbeRTT: periodically measure true propagation delay.
	BBRProbeRTT
)

// String returns a human-readable name for the BBR phase.
func (p bbrPhase) String() string {
	switch p {
	case BBRStartup:
		return "Startup"
	case BBRDrain:
		return "Drain"
	case BBRProbeBW:
		return "ProbeBW"
	case BBRProbeRTT:
		return "ProbeRTT"
	default:
		return "Unknown"
	}
}

// BBR pacing gain constants.
const (
	// startupPacingGain: 2/ln(2) ≈ 2.89 — aggressive probing in Startup.
	startupPacingGain = 2.885

	// drainPacingGain: inverse of startup gain — drain the queue.
	drainPacingGain = 1.0 / startupPacingGain // ≈ 0.346

	// startupCwndGain: cwnd headroom during Startup.
	startupCwndGain = 2.0

	// probeBWCwndGain: 2× BDP headroom during ProbeBW.
	probeBWCwndGain = 2.0

	// probeRTTCwndPackets: minimum cwnd during ProbeRTT.
	probeRTTCwndPackets = 4
	// Note: actual ProbeRTT uses max(probeRTTCwndPackets, minCwndPackets).

	// probeRTTDuration: how long to hold minimum cwnd in ProbeRTT.
	probeRTTDuration = 200 * time.Millisecond

	// fullBwThreshold: BtlBw must grow by at least 25% to count as "still growing".
	fullBwThreshold = 1.25

	// fullBwCount: number of rounds without BtlBw growth to exit Startup.
	fullBwCountMax = 3

	// minCwndPackets: absolute minimum cwnd.
	// 32 packets (46 KB) prevents throughput from collapsing below ~4 Mbps
	// at 87ms RTT even if BBR's BtlBw estimate is temporarily low.
	// A floor of 4 (5.8 KB) was too small: at 87ms RTT the throughput
	// floor was only 0.54 Mbps, making recovery from ACK-delay spirals slow.
	minCwndPackets = 32
)

// ProbeBW 8-phase pacing gains. Each phase lasts ~1 RTT.
// Phase 0 (5/4): probe for more bandwidth.
// Phase 1 (3/4): drain any queue from probing.
// Phases 2-7 (1.0): cruise at estimated BtlBw.
var probeBWGains = [8]float64{
	5.0 / 4.0, // probe
	3.0 / 4.0, // drain
	1.0, 1.0, 1.0, 1.0, 1.0, 1.0, // cruise
}

// BBRState is the BBR congestion control state machine.
// It consumes ACK/loss events and produces (cwndTarget, pacingRate) outputs
// that the transport layer uses to control sending.
//
// Thread-safe: all public methods acquire mu.
type BBRState struct {
	mu sync.Mutex

	phase     bbrPhase
	estimator *bbrEstimator
	inflight  *inflightTracker
	pacer     *pacer

	// --- Startup state ---
	fullBwCount int   // consecutive rounds without BtlBw growth
	fullBw      int64 // BtlBw at last growth check

	// --- ProbeBW state ---
	cycleIndex int       // 0..7 in probeBWGains
	cycleStart time.Time // when current cycle phase started

	// --- ProbeRTT state ---
	probeRTTDoneTime time.Time // when ProbeRTT min-cwnd period started
	probeRTTRoundDone bool     // true when we've been at min cwnd for >= probeRTTDuration
	priorCwnd        int       // cwnd to restore after ProbeRTT

	// --- Outputs (read by transport layer) ---
	cwndTarget int   // target congestion window in packets
	pacingRate int64 // target pacing rate in bytes/sec

	// --- Configuration ---
	mss int // maximum segment size (= MaxPayloadSize)
}

// NewBBRState creates a new BBR state machine. The estimator, inflight
// tracker, and pacer must be pre-created. mss is the maximum segment size
// (typically MaxPayloadSize = 1400).
func NewBBRState(est *bbrEstimator, ifl *inflightTracker, p *pacer, mss int) *BBRState {
	return &BBRState{
		phase:      BBRStartup,
		estimator:  est,
		inflight:   ifl,
		pacer:      p,
		mss:        mss,
		cwndTarget: minCwndPackets,
	}
}

// Phase returns the current BBR phase.
func (s *BBRState) Phase() bbrPhase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// CwndTarget returns the current congestion window target in packets.
func (s *BBRState) CwndTarget() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cwndTarget
}

// CwndTargetBytes returns the current congestion window target in bytes.
func (s *BBRState) CwndTargetBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(s.cwndTarget) * int64(s.mss)
}

// PacingRate returns the current pacing rate in bytes/sec.
func (s *BBRState) PacingRate() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacingRate
}

// SetInitialBandwidth skips the slow Startup phase entirely by seeding the
// BBR model with a known bandwidth and RTT estimate. This is critical for
// high-RTT paths (like SPb→Astana, 65ms) where Startup needs ~10 RTTs
// (650ms) to discover the bandwidth — during which throughput is very low.
//
// After calling this, BBR jumps straight to ProbeBW (steady-state) and
// begins probing around the given values. If the real bandwidth is higher,
// BBR will discover it within 1-2 RTTs via ProbeBW's 5/4 gain phase.
// If the real bandwidth is lower, BBR will quickly converge down via
// the 3/4 drain phase.
//
// Recommended: call with the ISP's advertised bandwidth (e.g. 100 Mbps)
// and a rough RTT estimate (e.g. 50ms for domestic, 100ms for international).
//
//   bbr.SetInitialBandwidth(100_000_000 / 8, 65*time.Millisecond) // 100 Mbps, 65ms RTT
func (s *BBRState) SetInitialBandwidth(bytesPerSec int64, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bytesPerSec <= 0 || rtt <= 0 {
		return
	}

	// Seed the estimator with synthetic BtlBw and RTprop.
	s.estimator.SeedBandwidth(bytesPerSec, rtt)

	// Compute BDP.
	bdpBytes := bytesPerSec * rtt.Microseconds() / 1_000_000
	bdpPackets := int(bdpBytes) / s.mss
	if bdpPackets < minCwndPackets {
		bdpPackets = minCwndPackets
	}

	// Jump directly to ProbeBW phase.
	s.phase = BBRProbeBW
	s.cwndTarget = int(float64(bdpPackets) * probeBWCwndGain)
	s.pacingRate = bytesPerSec
	s.cycleIndex = 2 // start at cruise (skip initial probe/drain)
	s.cycleStart = time.Now()

	// Update pacer.
	s.pacer.SetRate(s.pacingRate)
}

// OnACK is called for each ACK event. It updates the BBR model and
// transitions between phases as needed.
//
// Parameters:
//   - rtt: round-trip time measured for this ACK
//   - ackedBytes: bytes confirmed by this ACK
//   - pkt: the inflight metadata of the ACKed packet (delivery snapshots)
func (s *BBRState) OnACK(rtt time.Duration, ackedBytes int64, pkt *inflightPkt) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check RTprop expiry BEFORE feeding the estimator (which refreshes the stamp).
	// Only check if we have at least one RTprop sample (rtpropUs > 0).
	rtpropExpired := s.phase != BBRProbeRTT && s.estimator.RTprop() > 0 && s.estimator.RTpropExpired()

	// Feed the estimator.
	s.estimator.OnACK(
		rtt, ackedBytes,
		pkt.Delivered, pkt.DeliveredTime,
		pkt.SentAt, pkt.AppLimited,
	)

	// Phase-specific logic.
	switch s.phase {
	case BBRStartup:
		s.onACKStartup()
	case BBRDrain:
		s.onACKDrain()
	case BBRProbeBW:
		s.onACKProbeBW()
	case BBRProbeRTT:
		s.onACKProbeRTT()
	}

	// Enter ProbeRTT if RTprop had expired before this ACK updated it.
	if rtpropExpired {
		s.enterProbeRTT()
	}

	// Update pacer with new rate.
	s.pacer.SetRate(s.pacingRate)
}

// OnLoss is called when a packet is detected as lost.
// BBR does NOT halve cwnd on loss (unlike CUBIC/Reno). It only limits
// cwnd when loss rate exceeds 2% (BBRv2 behavior).
//
// Parameters:
//   - lostBytes: bytes in this loss event
func (s *BBRState) OnLoss(lostBytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute loss rate over the current window: lost / (inflight + lost).
	// We use cumulative inflight.LostBytes() for the lost side and
	// the current cwndTarget as the window denominator.
	cumulativeLost := s.inflight.LostBytes()
	windowBytes := int64(s.cwndTarget) * int64(s.mss)
	if windowBytes <= 0 {
		windowBytes = int64(minCwndPackets) * int64(s.mss)
	}
	total := windowBytes + cumulativeLost
	if total <= 0 {
		return
	}

	lossRate := float64(cumulativeLost) / float64(total)
	if lossRate > 0.02 {
		// High loss: limit cwnd. Use BDP if available, otherwise scale cwnd directly.
		bdpBytes := s.estimator.BDP()
		if bdpBytes > 0 {
			inflightHi := int64(float64(bdpBytes) * (1.0 - lossRate))
			cwndNew := int(inflightHi / int64(s.mss))
			if cwndNew < minCwndPackets {
				cwndNew = minCwndPackets
			}
			if cwndNew < s.cwndTarget {
				s.cwndTarget = cwndNew
			}
		} else {
			// No BDP estimate yet — scale cwnd by (1 - lossRate).
			cwndNew := int(float64(s.cwndTarget) * (1.0 - lossRate))
			if cwndNew < minCwndPackets {
				cwndNew = minCwndPackets
			}
			if cwndNew < s.cwndTarget {
				s.cwndTarget = cwndNew
			}
		}
	}
	// At loss_rate <= 2%: BBR just retransmits without touching cwnd.
}

// --- Startup phase ---

func (s *BBRState) onACKStartup() {
	btlbw := s.estimator.BtlBw()

	// Pacing: aggressive probing on every ACK.
	s.pacingRate = int64(float64(btlbw) * startupPacingGain)
	s.cwndTarget = s.bdpPackets(startupCwndGain)

	// Check BtlBw growth ONLY at round boundaries (not per-ACK).
	// The BBR paper specifies: "exit Startup after 3 consecutive *rounds*
	// without 25% BtlBw growth." Checking per-ACK causes premature exit
	// because multiple ACKs within the same RTT report similar delivery rates.
	if !s.estimator.IsRoundStart() {
		return
	}

	if float64(btlbw) >= float64(s.fullBw)*fullBwThreshold {
		// Still growing — reset counter.
		s.fullBw = btlbw
		s.fullBwCount = 0
	} else {
		s.fullBwCount++
	}

	// Exit Startup if BtlBw hasn't grown for 3 consecutive rounds.
	if s.fullBwCount >= fullBwCountMax {
		s.enterDrain()
	}
}

// --- Drain phase ---

func (s *BBRState) enterDrain() {
	s.phase = BBRDrain
	s.pacingRate = int64(float64(s.estimator.BtlBw()) * drainPacingGain)
	s.cwndTarget = s.bdpPackets(startupCwndGain) // keep Startup cwnd during Drain
}

func (s *BBRState) onACKDrain() {
	btlbw := s.estimator.BtlBw()
	s.pacingRate = int64(float64(btlbw) * drainPacingGain)

	// Exit Drain when inflight ≤ BDP.
	bdpBytes := s.estimator.BDP()
	inflightBytes := s.inflight.Bytes()
	if bdpBytes > 0 && inflightBytes <= bdpBytes {
		s.enterProbeBW()
	}
}

// --- ProbeBW phase ---

func (s *BBRState) enterProbeBW() {
	s.phase = BBRProbeBW
	s.cycleIndex = 0
	s.cycleStart = time.Now()
	s.updateProbeBW()
}

func (s *BBRState) onACKProbeBW() {
	// Advance cycle phase every ~1 RTT.
	rtprop := s.estimator.RTpropDuration()
	if rtprop <= 0 {
		rtprop = 50 * time.Millisecond // sane default
	}
	if time.Since(s.cycleStart) > rtprop {
		s.cycleIndex = (s.cycleIndex + 1) % 8
		s.cycleStart = time.Now()
	}
	s.updateProbeBW()
}

func (s *BBRState) updateProbeBW() {
	gain := probeBWGains[s.cycleIndex]
	btlbw := s.estimator.BtlBw()
	s.pacingRate = int64(float64(btlbw) * gain)
	s.cwndTarget = s.bdpPackets(probeBWCwndGain)
}

// --- ProbeRTT phase ---

func (s *BBRState) enterProbeRTT() {
	s.priorCwnd = s.cwndTarget
	s.phase = BBRProbeRTT
	s.cwndTarget = probeRTTCwndPackets
	s.probeRTTDoneTime = time.Time{} // will be set when inflight drops
	s.probeRTTRoundDone = false
}

func (s *BBRState) onACKProbeRTT() {
	// Wait for inflight to drop to probeRTTCwndPackets.
	if s.probeRTTDoneTime.IsZero() {
		if s.inflight.Count() <= probeRTTCwndPackets {
			s.probeRTTDoneTime = time.Now()
		}
		return
	}

	// Once inflight is low, hold for probeRTTDuration.
	if time.Since(s.probeRTTDoneTime) >= probeRTTDuration {
		s.probeRTTRoundDone = true
		// Restore cwnd and return to ProbeBW.
		s.cwndTarget = s.priorCwnd
		if s.cwndTarget < minCwndPackets {
			s.cwndTarget = minCwndPackets
		}
		s.enterProbeBW()
	}
}

// --- Helpers ---

// bdpPackets returns BDP in packets, multiplied by gain, with a minimum.
func (s *BBRState) bdpPackets(gain float64) int {
	bdpBytes := s.estimator.BDP()
	if bdpBytes <= 0 {
		return minCwndPackets
	}
	pkts := int(float64(bdpBytes) * gain / float64(s.mss))
	if pkts < minCwndPackets {
		pkts = minCwndPackets
	}
	return pkts
}

// Reset resets the BBR state machine to Startup.
func (s *BBRState) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = BBRStartup
	s.fullBwCount = 0
	s.fullBw = 0
	s.cycleIndex = 0
	s.cwndTarget = minCwndPackets
	s.pacingRate = 0
	s.estimator.Reset()
	s.inflight.Reset()
	s.pacer.Reset()
}
