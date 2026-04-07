package transport

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// setupRawUDPPair creates a raw Conn pair (not UDPNetConn) for BBR diagnostics.
func setupRawUDPPair(t *testing.T) (client, server *Conn) {
	t.Helper()

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	clientConn, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Send a trigger packet so the listener's readLoop sees this client.
	clientConn.Write([]byte("init"))

	serverConn, err := ln.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// Drain the trigger packet on the server side.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverConn.Read(ctx)

	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	return clientConn, serverConn
}

// diagPktMeta holds per-packet delivery-rate snapshots for diagnostic tests.
// Replaces inflightPkt (which no longer stores per-packet data).
type diagPktMeta struct {
	size          int
	sentAt        time.Time
	delivered     int64
	deliveredTime time.Time
	appLimited    bool
}

// TestBBRDiagnoseSlowThroughput simulates realistic VPN conditions and
// traces BBR state to find the root cause of 5-6x speed drop.
func TestBBRDiagnoseSlowThroughput(t *testing.T) {
	// Simulate: 50 Mbps bottleneck, 80ms RTT, 0.7% loss
	const (
		bottleneckBps = 50_000_000 // 50 Mbps
		rtt           = 80 * time.Millisecond
		mss           = MaxPayloadSize // 1400 bytes
	)

	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, bbrMaxBurst)
	bbr := NewBBRState(est, ifl, p, mss)

	// Per-packet metadata (delivery-rate snapshots) stored locally.
	pktMeta := make(map[uint32]*diagPktMeta, 64)

	var seq uint32
	sentBytes := int64(0)
	ackedBytes := int64(0)

	// Pre-fill: send initial window.
	for i := 0; i < minCwndPackets; i++ {
		delivered, deliveredTime := est.DeliveredSnapshot()
		now := time.Now()
		pktMeta[seq] = &diagPktMeta{
			size: mss, sentAt: now,
			delivered: delivered, deliveredTime: deliveredTime,
		}
		ifl.OnSend(mss)
		seq++
		sentBytes += int64(mss)
	}

	// Log state at each round.
	round := 0
	for elapsed := time.Duration(0); elapsed < 5*time.Second; elapsed += rtt {
		round++
		cwnd := bbr.CwndTarget()
		phase := bbr.Phase()

		// ACK all inflight packets (simulate perfect delivery).
		acksThisRound := 0
		for ackSeq := uint32(0); ackSeq < seq; ackSeq++ {
			m, ok := pktMeta[ackSeq]
			if !ok {
				continue
			}
			delete(pktMeta, ackSeq)
			ifl.OnACK(m.size)
			ackedBytes += int64(mss)
			acksThisRound++
			bbr.OnACK(rtt, int64(mss), m.delivered, m.deliveredTime, m.sentAt, m.appLimited)
		}

		newCwnd := bbr.CwndTarget()
		pacingRate := bbr.PacingRate()
		btlbw := est.BtlBw()
		bdp := est.BDP()

		if round <= 20 || round%10 == 0 {
			t.Logf("Round %3d | phase=%-8s | cwnd=%4d→%4d | pacing=%10d B/s (%5.1f Mbps) | BtlBw=%10d | BDP=%8d | acked=%d",
				round, phase, cwnd, newCwnd,
				pacingRate, float64(pacingRate)*8/1_000_000,
				btlbw, bdp, acksThisRound)
		}

		// Send new packets up to cwnd.
		newCwndNow := bbr.CwndTarget()
		inflight := ifl.Count()
		canSend := newCwndNow - inflight
		if canSend < 0 {
			canSend = 0
		}

		for i := 0; i < canSend; i++ {
			delivered, deliveredTime := est.DeliveredSnapshot()
			now := time.Now()
			pktMeta[seq] = &diagPktMeta{
				size: mss, sentAt: now,
				delivered: delivered, deliveredTime: deliveredTime,
			}
			ifl.OnSend(mss)
			seq++
			sentBytes += int64(mss)
		}
	}

	// Check final state.
	finalPacing := bbr.PacingRate()
	finalCwnd := bbr.CwndTarget()
	finalPhase := bbr.Phase()

	t.Logf("\n=== FINAL STATE ===")
	t.Logf("Phase: %s", finalPhase)
	t.Logf("Cwnd: %d packets (%d KB)", finalCwnd, finalCwnd*mss/1024)
	t.Logf("Pacing: %d B/s (%.1f Mbps)", finalPacing, float64(finalPacing)*8/1_000_000)
	t.Logf("BtlBw: %d B/s", est.BtlBw())
	t.Logf("BDP: %d bytes", est.BDP())
	t.Logf("RTprop: %d µs", est.RTprop())
	t.Logf("Total sent: %d KB, acked: %d KB", sentBytes/1024, ackedBytes/1024)

	// The pacing rate should be close to bottleneck BW.
	// If it's < 1 Mbps something is fundamentally wrong.
	if finalPacing < 1_000_000 {
		t.Errorf("CRITICAL: pacing rate %.1f Mbps is way too low (expected ~50 Mbps)",
			float64(finalPacing)*8/1_000_000)
	}
}

// TestBBRDeliveryRateComputation verifies the per-ACK delivery rate
// calculation. A bug here would cause BtlBw=0 and pacing=0.
func TestBBRDeliveryRateComputation(t *testing.T) {
	est := newBBREstimator()

	// Simulate: send packet at T=0 with snapshot (delivered=0, deliveredTime=T0).
	// ACK arrives at T=80ms (RTT=80ms), 1400 bytes delivered.
	t0 := time.Now()

	// Snapshot at send time.
	sendDelivered := int64(0)
	sendDeliveredTime := t0

	// Wait simulated RTT.
	time.Sleep(10 * time.Millisecond) // short sleep for test speed

	// ACK arrives.
	sample := est.OnACK(
		80*time.Millisecond, // rtt
		1400,                // ackedBytes
		sendDelivered,
		sendDeliveredTime,
		t0,    // sendTime
		false, // not app-limited
	)

	t.Logf("DeliveryRate: %d B/s (%.1f Mbps)", sample.DeliveryRate, float64(sample.DeliveryRate)*8/1_000_000)
	t.Logf("BtlBw: %d B/s", est.BtlBw())
	t.Logf("RTprop: %d µs", est.RTprop())
	t.Logf("BDP: %d bytes", est.BDP())

	if sample.DeliveryRate <= 0 {
		t.Fatal("CRITICAL: delivery rate is 0 — BtlBw will never grow!")
	}
	if est.BtlBw() <= 0 {
		t.Fatal("CRITICAL: BtlBw is 0 after first ACK!")
	}
}

// TestBBRPacerInitialRate verifies the pacer doesn't bottleneck on startup.
func TestBBRPacerInitialRate(t *testing.T) {
	p := newPacer(0, bbrMaxBurst) // rate=0 means unlimited

	// With rate=0, every packet should be sendable immediately.
	for i := 0; i < 20; i++ {
		wait := p.timeToSend(1400)
		if wait > 0 {
			t.Fatalf("Packet %d: pacer blocks for %v even with rate=0", i, wait)
		}
	}

	// Now set a low rate and verify it throttles.
	p.SetRate(100_000) // 100 KB/s
	// First packet uses accumulated tokens.
	wait := p.timeToSend(1400)
	t.Logf("First packet after SetRate(100KB/s): wait=%v", wait)

	// Second packet should block.
	wait = p.timeToSend(1400)
	t.Logf("Second packet: wait=%v", wait)
	if wait <= 0 {
		t.Log("WARNING: pacer doesn't throttle at low rate")
	}
}

// TestBBRAppLimitedSamples verifies that app-limited samples don't suppress BtlBw.
func TestBBRAppLimitedSamples(t *testing.T) {
	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, bbrMaxBurst)
	bbr := NewBBRState(est, ifl, p, MaxPayloadSize)

	// First ACK: non-app-limited, good delivery rate.
	t0 := time.Now()
	delivered0, deliveredTime0 := est.DeliveredSnapshot()
	ifl.OnSend(1400)
	time.Sleep(5 * time.Millisecond)
	ifl.OnACK(1400)
	bbr.OnACK(80*time.Millisecond, 1400, delivered0, deliveredTime0, t0, false)
	btlbw1 := est.BtlBw()
	t.Logf("After non-app-limited ACK: BtlBw=%d", btlbw1)

	// Second ACK: app-limited (sender was idle). Lower delivery rate.
	t1 := time.Now()
	delivered1, deliveredTime1 := est.DeliveredSnapshot()
	ifl.OnSend(1400)
	time.Sleep(50 * time.Millisecond) // longer gap = lower delivery rate
	ifl.OnACK(1400)
	bbr.OnACK(80*time.Millisecond, 1400, delivered1, deliveredTime1, t1, true /* app-limited */)
	btlbw2 := est.BtlBw()
	t.Logf("After app-limited ACK: BtlBw=%d", btlbw2)

	// BtlBw should NOT decrease due to app-limited sample.
	if btlbw2 < btlbw1 {
		t.Errorf("BUG: BtlBw decreased from %d to %d due to app-limited sample", btlbw1, btlbw2)
	}
}

// TestBBRCwndWaitDoesNotDeadlock verifies that writePacket doesn't deadlock
// when cwnd is full. This simulates the hot path in the real VPN.
func TestBBRCwndWaitDoesNotDeadlock(t *testing.T) {
	// Create a real UDP pair.
	client, server := setupRawUDPPair(t)
	_ = server
	pair := struct{ client, server *Conn }{client, server}

	// Fill the cwnd.
	cwnd := pair.client.bbr.CwndTarget()
	t.Logf("Initial cwnd: %d", cwnd)

	data := make([]byte, 100)
	sent := 0
	for i := 0; i < cwnd; i++ {
		err := pair.client.Write(data)
		if err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
		sent++
	}
	t.Logf("Sent %d packets (cwnd full)", sent)

	// Now try to write one more — it should block until ACKs arrive.
	done := make(chan error, 1)
	go func() {
		done <- pair.client.Write(data)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write after cwnd full failed: %v", err)
		}
		t.Log("Write unblocked (ACKs arrived)")
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK: Write blocked for 3s waiting for cwnd to open")
	}
}

// TestBBRThroughputVsSimpleSend measures actual throughput through the UDP+BBR
// stack vs the theoretical maximum. This is the key diagnostic test.
func TestBBRThroughputVsSimpleSend(t *testing.T) {
	client, server := setupRawUDPPair(t)
	_ = server
	pair := struct{ client, server *Conn }{client, server}

	// Send 500 KB of data and measure throughput.
	const totalBytes = 500 * 1024
	data := make([]byte, 1400)

	// Drain receiver in background.
	received := make(chan int64, 1)
	go func() {
		var total int64
		ctx := context.Background()
		for total < totalBytes {
			rp, err := pair.server.Read(ctx)
			if err != nil || rp.data == nil {
				break
			}
			total += int64(len(rp.data))
		}
		received <- total
	}()

	start := time.Now()
	bytesSent := int64(0)
	for bytesSent < totalBytes {
		remaining := totalBytes - bytesSent
		if remaining < int64(len(data)) {
			data = data[:remaining]
		}
		if err := pair.client.Write(data); err != nil {
			t.Fatalf("Write failed after %d bytes: %v", bytesSent, err)
		}
		bytesSent += int64(len(data))
	}
	sendDuration := time.Since(start)

	select {
	case rxBytes := <-received:
		rxDuration := time.Since(start)
		sendThroughput := float64(bytesSent) * 8 / sendDuration.Seconds() / 1_000_000
		rxThroughput := float64(rxBytes) * 8 / rxDuration.Seconds() / 1_000_000
		t.Logf("Sent: %d KB in %v (%.1f Mbps)", bytesSent/1024, sendDuration, sendThroughput)
		t.Logf("Received: %d KB in %v (%.1f Mbps)", rxBytes/1024, rxDuration, rxThroughput)
		t.Logf("BBR phase: %s, cwnd: %d, pacing: %d B/s (%.1f Mbps)",
			pair.client.bbr.Phase(),
			pair.client.bbr.CwndTarget(),
			pair.client.bbr.PacingRate(),
			float64(pair.client.bbr.PacingRate())*8/1_000_000)
		t.Logf("BtlBw: %d B/s, RTprop: %d µs, BDP: %d bytes",
			pair.client.bbr.estimator.BtlBw(),
			pair.client.bbr.estimator.RTprop(),
			pair.client.bbr.estimator.BDP())
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for receiver")
	}
}

// TestBBRRealisticDeliveryRate verifies delivery rate computation with
// realistic timing (packets sent over time, ACKs arrive after RTT).
func TestBBRRealisticDeliveryRate(t *testing.T) {
	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, bbrMaxBurst)
	bbr := NewBBRState(est, ifl, p, 1400)

	const rtt = 80 * time.Millisecond
	sendTime := time.Now()

	// Per-packet metadata stored locally.
	type pktInfo struct {
		delivered     int64
		deliveredTime time.Time
		appLimited    bool
	}
	pktMeta := make(map[uint32]*pktInfo, 20)

	// Send 10 packets.
	for i := 0; i < 10; i++ {
		delivered, deliveredTime := est.DeliveredSnapshot()
		pktMeta[uint32(i)] = &pktInfo{delivered: delivered, deliveredTime: deliveredTime}
		ifl.OnSend(1400)
		_ = sendTime
	}

	// Wait simulated RTT.
	time.Sleep(rtt)

	// ACK all 10 packets.
	for i := 0; i < 10; i++ {
		m, ok := pktMeta[uint32(i)]
		if !ok {
			t.Fatalf("packet %d not in meta", i)
		}
		ifl.OnACK(1400)
		bbr.OnACK(rtt, 1400, m.delivered, m.deliveredTime, sendTime, m.appLimited)
	}

	btlbw := est.BtlBw()
	// Expected: 10 × 1400 bytes / 80ms = 175000 B/s = 1.4 Mbps
	expectedBps := int64(10 * 1400 * 1000 / 80) // ~175000
	t.Logf("BtlBw: %d B/s (%.1f Mbps), expected ~%d B/s (%.1f Mbps)",
		btlbw, float64(btlbw)*8/1e6,
		expectedBps, float64(expectedBps)*8/1e6)
	t.Logf("Phase: %s, cwnd: %d, pacing: %d B/s (%.1f Mbps)",
		bbr.Phase(), bbr.CwndTarget(),
		bbr.PacingRate(), float64(bbr.PacingRate())*8/1e6)

	// BtlBw should be roughly 175 KB/s (10 * 1400 / 0.08)
	if btlbw < expectedBps/2 {
		t.Errorf("BtlBw too low: %d < %d/2", btlbw, expectedBps)
	}
	if btlbw > expectedBps*3 {
		t.Errorf("BtlBw unrealistically high: %d > %d*3", btlbw, expectedBps)
	}

	// Now send 2nd burst at cwnd-limited rate.
	cwnd := bbr.CwndTarget()
	t.Logf("Sending 2nd burst: cwnd=%d", cwnd)
	sendTime2 := time.Now()
	pktMeta2 := make(map[uint32]*pktInfo, cwnd)
	for i := 0; i < cwnd && i < 200; i++ {
		delivered, deliveredTime := est.DeliveredSnapshot()
		pktMeta2[uint32(10+i)] = &pktInfo{delivered: delivered, deliveredTime: deliveredTime}
		ifl.OnSend(1400)
	}

	time.Sleep(rtt)

	for i := 0; i < cwnd && i < 200; i++ {
		m, ok := pktMeta2[uint32(10+i)]
		if !ok {
			continue
		}
		ifl.OnACK(1400)
		bbr.OnACK(rtt, 1400, m.delivered, m.deliveredTime, sendTime2, m.appLimited)
	}

	btlbw2 := est.BtlBw()
	t.Logf("After 2nd burst: BtlBw=%d B/s (%.1f Mbps), cwnd=%d, pacing=%.1f Mbps, phase=%s",
		btlbw2, float64(btlbw2)*8/1e6,
		bbr.CwndTarget(),
		float64(bbr.PacingRate())*8/1e6,
		bbr.Phase())

	// BtlBw should grow significantly (more packets in same RTT = higher rate).
	if btlbw2 <= btlbw {
		t.Logf("WARNING: BtlBw did not grow after larger burst: %d → %d", btlbw, btlbw2)
	}
}

// TestBBRHighRTTSimulation simulates the Russia-Kazakhstan path (RTT=80ms)
// and verifies BBR ramps up properly.
func TestBBRHighRTTSimulation(t *testing.T) {
	const (
		rtt = 80 * time.Millisecond
		mss = 1400
	)

	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, bbrMaxBurst)
	bbr := NewBBRState(est, ifl, p, mss)

	type pktInfo struct {
		sentAt        time.Time
		delivered     int64
		deliveredTime time.Time
	}
	pktMeta := make(map[uint32]*pktInfo, 128)
	var seq uint32

	// Simulate 20 round-trips of traffic.
	for round := 0; round < 20; round++ {
		// Send cwnd packets.
		cwnd := bbr.CwndTarget()
		for i := 0; i < cwnd; i++ {
			delivered, deliveredTime := est.DeliveredSnapshot()
			now := time.Now()
			pktMeta[seq] = &pktInfo{sentAt: now, delivered: delivered, deliveredTime: deliveredTime}
			ifl.OnSend(mss)
			seq++
		}

		// Simulate RTT delay.
		time.Sleep(2 * time.Millisecond) // scaled down for test speed

		// ACK all.
		for ackSeq := uint32(0); ackSeq < seq; ackSeq++ {
			m, ok := pktMeta[ackSeq]
			if !ok {
				continue
			}
			delete(pktMeta, ackSeq)
			ifl.OnACK(mss)
			bbr.OnACK(rtt, int64(mss), m.delivered, m.deliveredTime, m.sentAt, false)
		}

		t.Logf("Round %2d: phase=%-8s cwnd=%4d pacing=%.1f Mbps BtlBw=%d BDP=%d",
			round, bbr.Phase(), bbr.CwndTarget(),
			float64(bbr.PacingRate())*8/1_000_000,
			est.BtlBw(), est.BDP())
	}

	// After 20 RTTs, BBR should be in ProbeBW with a reasonable cwnd.
	if bbr.Phase() == BBRStartup {
		t.Error("BUG: still in Startup after 20 RTTs — BtlBw never plateaued")
	}
	if bbr.CwndTarget() <= minCwndPackets {
		t.Errorf("BUG: cwnd stuck at minimum %d after 20 RTTs", bbr.CwndTarget())
	}
	if bbr.PacingRate() <= 0 {
		t.Error("BUG: pacing rate is 0 after 20 RTTs")
	}
	fmt.Printf("BBR converged: cwnd=%d, pacing=%.1f Mbps\n",
		bbr.CwndTarget(), float64(bbr.PacingRate())*8/1_000_000)
}
