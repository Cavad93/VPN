package transport

import (
	"sync"
	"sync/atomic"
	"time"
)

// BBR estimator constants.
const (
	// rtpropFilterLen is the time window for the minimum RTT filter.
	// BBR paper: 10 seconds. We use RTprop as the propagation delay —
	// the minimum RTT observed in this window with high probability
	// reflects the true propagation delay without queuing.
	rtpropFilterLen = 10 * time.Second

	// btlbwFilterLen is the number of round-trips for the max bandwidth filter.
	// BBR paper: 6–10 round-trips. We use 10 for stability.
	btlbwFilterLen = 10
)

// rtSample is a single round-trip measurement produced when an ACK arrives.
type rtSample struct {
	RTT          time.Duration // round-trip time for this ACK
	DeliveryRate int64         // bytes/sec measured at this ACK
	Delivered    int64         // total delivered bytes at ACK time
	SendTime     time.Time     // when the ACKed packet was sent
	AckTime      time.Time     // when this ACK arrived
	IsAppLimited bool          // true if sender was idle when this packet was sent
}

// windowedMinFilter tracks the minimum value over a sliding time window.
// Used for RTprop — we want the minimum RTT (= propagation delay).
type windowedMinFilter struct {
	val    time.Duration // current minimum value
	stamp  time.Time     // when val was recorded
	window time.Duration // filter window length
}

// newWindowedMinFilter creates a min filter with the given window.
func newWindowedMinFilter(window time.Duration) windowedMinFilter {
	return windowedMinFilter{
		val:    time.Duration(1<<63 - 1), // max duration = "no sample yet"
		window: window,
	}
}

// update feeds a new sample into the filter. Returns the current minimum.
func (f *windowedMinFilter) update(val time.Duration, now time.Time) time.Duration {
	// If new sample is smaller or equal, it becomes the new minimum.
	if val <= f.val {
		f.val = val
		f.stamp = now
		return f.val
	}
	// If the current minimum has expired, replace it.
	if now.Sub(f.stamp) > f.window {
		f.val = val
		f.stamp = now
	}
	return f.val
}

// get returns the current minimum value.
func (f *windowedMinFilter) get() time.Duration {
	return f.val
}

// expired returns true if the filter hasn't been updated within its window.
func (f *windowedMinFilter) expired(now time.Time) bool {
	return now.Sub(f.stamp) > f.window
}

// reset clears the filter to its initial state.
func (f *windowedMinFilter) reset() {
	f.val = time.Duration(1<<63 - 1)
	f.stamp = time.Time{}
}

// windowedMaxFilter tracks the maximum value over the last N round-trips.
// Used for BtlBw — we want the maximum delivery rate (= bottleneck bandwidth).
//
// Implementation: ring buffer of N slots. Each slot stores the max value
// seen during one round-trip. On each new round-trip, the oldest slot is
// evicted and a new one starts.
type windowedMaxFilter struct {
	samples []maxSample // ring buffer
	size    int         // capacity (btlbwFilterLen)
	head    int         // write position
	count   int         // number of valid samples
	best    int64       // cached maximum across all samples
}

type maxSample struct {
	val   int64 // delivery rate in bytes/sec
	round int64 // round number when this sample was taken
}

// newWindowedMaxFilter creates a max filter with the given number of round-trips.
func newWindowedMaxFilter(rounds int) windowedMaxFilter {
	return windowedMaxFilter{
		samples: make([]maxSample, rounds),
		size:    rounds,
	}
}

// update feeds a new sample at the given round number. Returns the current max.
func (f *windowedMaxFilter) update(val int64, round int64) int64 {
	// New sample — find its position.
	s := maxSample{val: val, round: round}

	// If this value is >= current best, it becomes the new best immediately.
	if val >= f.best || f.count == 0 {
		f.best = val
		f.samples[f.head] = s
		f.head = (f.head + 1) % f.size
		if f.count < f.size {
			f.count++
		}
		return f.best
	}

	// Store the sample.
	f.samples[f.head] = s
	f.head = (f.head + 1) % f.size
	if f.count < f.size {
		f.count++
	}

	// Recalculate best — only consider samples within the window.
	f.recalcBest(round)
	return f.best
}

// recalcBest scans the ring buffer for the maximum value within the window.
func (f *windowedMaxFilter) recalcBest(currentRound int64) {
	f.best = 0
	minRound := currentRound - int64(f.size) + 1
	if minRound < 0 {
		minRound = 0
	}
	for i := 0; i < f.count; i++ {
		idx := (f.head - 1 - i + f.size) % f.size
		if f.samples[idx].round >= minRound && f.samples[idx].val > f.best {
			f.best = f.samples[idx].val
		}
	}
}

// get returns the current maximum value.
func (f *windowedMaxFilter) get() int64 {
	return f.best
}

// reset clears the filter.
func (f *windowedMaxFilter) reset() {
	f.best = 0
	f.count = 0
	f.head = 0
}

// bbrEstimator continuously estimates the two core BBR parameters:
//   - RTprop: minimum RTT (propagation delay without queuing)
//   - BtlBw:  maximum delivery rate (bottleneck bandwidth)
//
// Thread-safe: all public methods acquire mu.
type bbrEstimator struct {
	mu sync.Mutex

	// RTprop — windowed minimum RTT over the last 10 seconds.
	rtpropFilter windowedMinFilter
	rtpropUs     atomic.Int64 // cached RTprop in microseconds (lock-free reads)

	// BtlBw — windowed maximum delivery rate over the last 10 round-trips.
	btlbwFilter windowedMaxFilter
	btlbwBps    atomic.Int64 // cached BtlBw in bytes/sec (lock-free reads)

	// Delivery rate tracking.
	// On each ACK we compute: delivery_rate = delta_delivered / delta_time
	// where delta is measured from the ACKed packet's send-time snapshot.
	delivered     int64     // total bytes confirmed delivered (cumulative)
	deliveredTime time.Time // timestamp of last delivered update

	// Atomic mirrors for lock-free DeliveredSnapshot reads from the send path.
	deliveredAtomic     atomic.Int64
	deliveredTimeNano   atomic.Int64

	// Round-trip counting for BtlBw filter.
	roundCount    int64 // incremented each time a full RTT's worth of data is ACKed
	roundStart    bool  // set when a new round begins
	nextRoundDelivered int64 // delivered count at which next round starts
}

// newBBREstimator creates a new estimator with empty filters.
func newBBREstimator() *bbrEstimator {
	now := time.Now()
	e := &bbrEstimator{
		rtpropFilter:  newWindowedMinFilter(rtpropFilterLen),
		btlbwFilter:   newWindowedMaxFilter(btlbwFilterLen),
		deliveredTime: now, // initialize to now — prevents first ACK from computing zero delivery rate
	}
	e.deliveredTimeNano.Store(now.UnixNano())
	return e
}

// OnACK processes an ACK event. The caller provides:
//   - rtt: measured round-trip time for the ACKed packet
//   - ackedBytes: number of bytes confirmed by this ACK
//   - sendDelivered: snapshot of e.delivered at the time the ACKed packet was sent
//   - sendDeliveredTime: snapshot of e.deliveredTime at the time the ACKed packet was sent
//   - sendTime: when the ACKed packet was originally sent
//   - isAppLimited: true if sender was idle when the ACKed packet was sent
//
// Returns the rtSample for the caller (BBR state machine) to use.
func (e *bbrEstimator) OnACK(
	rtt time.Duration,
	ackedBytes int64,
	sendDelivered int64,
	sendDeliveredTime time.Time,
	sendTime time.Time,
	isAppLimited bool,
) rtSample {
	now := time.Now()

	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Update delivered counter.
	e.delivered += ackedBytes
	e.deliveredTime = now
	// Publish for lock-free reads.
	e.deliveredAtomic.Store(e.delivered)
	e.deliveredTimeNano.Store(now.UnixNano())

	// 2. Compute delivery rate for this ACK.
	//    delivery_rate = (delivered_now - delivered_at_send) / max(ack_elapsed, send_elapsed)
	//    This is the "per-ACK" delivery rate from the BBR paper §4.1.
	//    We use max(ack_elapsed, send_elapsed) per the Linux BBR implementation
	//    to avoid overestimating the rate when ACKs are compressed.
	var deliveryRate int64
	deliveredInterval := e.delivered - sendDelivered
	ackElapsed := now.Sub(sendDeliveredTime) // time since last delivery at send time
	sendElapsed := now.Sub(sendTime)          // time since the packet was sent (≈ RTT)
	timeInterval := ackElapsed
	if sendElapsed > timeInterval {
		timeInterval = sendElapsed
	}
	if timeInterval > 0 && deliveredInterval > 0 {
		deliveryRate = deliveredInterval * int64(time.Second) / int64(timeInterval)
	}

	// 3. Update round-trip counter.
	//    A "round" completes when we ACK a packet whose sendDelivered >=
	//    nextRoundDelivered — i.e., a packet sent AFTER the previous round
	//    started. This matches the Linux BBR round counting logic.
	e.roundStart = false // reset each ACK
	if sendDelivered >= e.nextRoundDelivered {
		e.roundCount++
		e.roundStart = true
		// Next round starts when we ACK a packet sent with delivered >= current.
		e.nextRoundDelivered = e.delivered
	}

	// 4. Update RTprop filter (minimum RTT).
	e.rtpropFilter.update(rtt, now)
	e.rtpropUs.Store(e.rtpropFilter.get().Microseconds())

	// 5. Update BtlBw filter (maximum delivery rate).
	//    Only non-app-limited samples are used for BtlBw — if the sender
	//    was idle, the delivery rate underestimates the true bottleneck.
	if !isAppLimited || deliveryRate > e.btlbwFilter.get() {
		e.btlbwFilter.update(deliveryRate, e.roundCount)
		e.btlbwBps.Store(e.btlbwFilter.get())
	}

	return rtSample{
		RTT:          rtt,
		DeliveryRate: deliveryRate,
		Delivered:    e.delivered,
		SendTime:     sendTime,
		AckTime:      now,
		IsAppLimited: isAppLimited,
	}
}

// RTprop returns the current propagation delay estimate in microseconds (lock-free).
func (e *bbrEstimator) RTprop() int64 {
	return e.rtpropUs.Load()
}

// RTpropDuration returns the current propagation delay as time.Duration.
func (e *bbrEstimator) RTpropDuration() time.Duration {
	us := e.rtpropUs.Load()
	if us <= 0 {
		return 0
	}
	return time.Duration(us) * time.Microsecond
}

// BtlBw returns the current bottleneck bandwidth estimate in bytes/sec (lock-free).
func (e *bbrEstimator) BtlBw() int64 {
	return e.btlbwBps.Load()
}

// BDP returns the estimated bandwidth-delay product in bytes (lock-free).
// BDP = BtlBw × RTprop — the optimal amount of data "in flight".
func (e *bbrEstimator) BDP() int64 {
	rtUs := e.rtpropUs.Load()
	bw := e.btlbwBps.Load()
	if rtUs <= 0 || bw <= 0 {
		return 0
	}
	return bw * rtUs / 1_000_000
}

// Delivered returns the total delivered byte count.
func (e *bbrEstimator) Delivered() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.delivered
}

// DeliveredSnapshot returns a snapshot of (delivered, deliveredTime)
// for stamping outgoing packets. Lock-free via atomic reads.
func (e *bbrEstimator) DeliveredSnapshot() (int64, time.Time) {
	d := e.deliveredAtomic.Load()
	tNano := e.deliveredTimeNano.Load()
	if tNano == 0 {
		return d, time.Time{}
	}
	return d, time.Unix(0, tNano)
}

// RoundCount returns the current round-trip count.
func (e *bbrEstimator) RoundCount() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.roundCount
}

// IsRoundStart returns true if the most recent OnACK call started a new round.
func (e *bbrEstimator) IsRoundStart() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.roundStart
}

// RTpropExpired returns true if RTprop hasn't been refreshed within its window.
func (e *bbrEstimator) RTpropExpired() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rtpropFilter.expired(time.Now())
}

// Reset clears all estimator state.
func (e *bbrEstimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rtpropFilter.reset()
	e.btlbwFilter.reset()
	e.rtpropUs.Store(0)
	e.btlbwBps.Store(0)
	e.delivered = 0
	e.deliveredTime = time.Time{}
	e.deliveredAtomic.Store(0)
	e.deliveredTimeNano.Store(0)
	e.roundCount = 0
	e.roundStart = false
	e.nextRoundDelivered = 0
}
