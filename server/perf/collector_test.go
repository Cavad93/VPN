package perf

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
	for _, s := range allStages {
		if _, ok := c.stages[s]; !ok {
			t.Errorf("stage %q missing from collector", s)
		}
	}
}

func TestTrackLatency(t *testing.T) {
	c := NewCollector()
	c.TrackLatency(StageNoiseEnc, 100*time.Microsecond)
	c.TrackLatency(StageNoiseEnc, 200*time.Microsecond)
	c.TrackLatency(StageNoiseEnc, 300*time.Microsecond)

	snap := c.Snapshot()
	st := snap.Stages[string(StageNoiseEnc)]
	if st.Latency.Count != 3 {
		t.Errorf("expected count=3, got %d", st.Latency.Count)
	}
	if st.Latency.MeanUs < 100 || st.Latency.MeanUs > 400 {
		t.Errorf("mean_us=%f out of expected range [100, 400]", st.Latency.MeanUs)
	}
	if st.Latency.MaxUs < 200 {
		t.Errorf("max_us=%f should be >= 200", st.Latency.MaxUs)
	}
}

func TestTrackPacket(t *testing.T) {
	c := NewCollector()
	c.TrackPacket(StageTunRead, 1500)
	c.TrackPacket(StageTunRead, 500)

	snap := c.Snapshot()
	st := snap.Stages[string(StageTunRead)]
	if st.Packets != 2 {
		t.Errorf("expected packets=2, got %d", st.Packets)
	}
	if st.Bytes != 2000 {
		t.Errorf("expected bytes=2000, got %d", st.Bytes)
	}
}

func TestTrackRetransmit(t *testing.T) {
	c := NewCollector()
	c.TrackRetransmit()
	c.TrackRetransmit()
	c.TrackRetransmit()

	snap := c.Snapshot()
	if snap.RetransmitCount != 3 {
		t.Errorf("expected retransmit_count=3, got %d", snap.RetransmitCount)
	}
}

func TestSetCongestion(t *testing.T) {
	c := NewCollector()
	c.SetCongestion(32, 16)

	snap := c.Snapshot()
	if snap.CongestionWindow != 32 {
		t.Errorf("expected cwnd=32, got %d", snap.CongestionWindow)
	}
	if snap.SSThresh != 16 {
		t.Errorf("expected ssthresh=16, got %d", snap.SSThresh)
	}
}

func TestTimer(t *testing.T) {
	c := NewCollector()
	done := c.Timer(StageObfsWrite)
	time.Sleep(1 * time.Millisecond)
	done()

	snap := c.Snapshot()
	st := snap.Stages[string(StageObfsWrite)]
	if st.Latency.Count != 1 {
		t.Errorf("expected count=1, got %d", st.Latency.Count)
	}
	if st.Latency.MeanUs < 500 {
		t.Errorf("mean_us=%f too low for 1ms sleep", st.Latency.MeanUs)
	}
}

func TestSessionCounters(t *testing.T) {
	c := NewCollector()
	c.ActiveSessions.Add(1)
	c.ActiveSessions.Add(1)
	c.TotalSessions.Add(2)
	c.ActiveSessions.Add(-1)

	snap := c.Snapshot()
	if snap.ActiveSessions != 1 {
		t.Errorf("expected active=1, got %d", snap.ActiveSessions)
	}
	if snap.TotalSessions != 2 {
		t.Errorf("expected total=2, got %d", snap.TotalSessions)
	}
}

func TestReset(t *testing.T) {
	c := NewCollector()
	c.TrackLatency(StageNoiseEnc, 100*time.Microsecond)
	c.TrackPacket(StageTunRead, 1000)
	c.TrackRetransmit()

	c.Reset()

	snap := c.Snapshot()
	for name, st := range snap.Stages {
		if st.Latency.Count != 0 {
			t.Errorf("stage %s: latency count=%d after reset", name, st.Latency.Count)
		}
		if st.Packets != 0 {
			t.Errorf("stage %s: packets=%d after reset", name, st.Packets)
		}
	}
	if snap.RetransmitCount != 0 {
		t.Errorf("retransmit_count=%d after reset", snap.RetransmitCount)
	}
}

func TestSnapshotJSON(t *testing.T) {
	c := NewCollector()
	c.TrackLatency(StageNoiseEnc, 50*time.Microsecond)
	c.TrackPacket(StageNoiseEnc, 1500)

	snap := c.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	var decoded Snapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded.Stages[string(StageNoiseEnc)].Packets != 1 {
		t.Error("decoded packets mismatch")
	}
}

func TestTrackUnknownStage(t *testing.T) {
	c := NewCollector()
	// Should not panic.
	c.TrackLatency("nonexistent", time.Millisecond)
	c.TrackPacket("nonexistent", 100)
}

func TestPercentiles(t *testing.T) {
	c := NewCollector()
	// Record 1000 samples: 100µs to 100ms spread.
	for i := 0; i < 500; i++ {
		c.TrackLatency(StageObfsRead, 100*time.Microsecond)
	}
	for i := 0; i < 450; i++ {
		c.TrackLatency(StageObfsRead, 1*time.Millisecond)
	}
	for i := 0; i < 50; i++ {
		c.TrackLatency(StageObfsRead, 50*time.Millisecond)
	}

	snap := c.Snapshot()
	st := snap.Stages[string(StageObfsRead)]
	if st.Latency.Count != 1000 {
		t.Fatalf("expected 1000, got %d", st.Latency.Count)
	}
	// p50 should be in the low range (100µs bucket area).
	if st.Latency.P50Us > 2000 {
		t.Errorf("p50=%f too high", st.Latency.P50Us)
	}
	// p99 should be in the high range (50ms area).
	if st.Latency.P99Us < 100 {
		t.Errorf("p99=%f too low for 50ms tail", st.Latency.P99Us)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := NewCollector()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.TrackLatency(StageNoiseEnc, time.Duration(j)*time.Microsecond)
				c.TrackPacket(StageTunRead, j)
				c.TrackRetransmit()
				c.SetCongestion(j, j/2)
			}
		}()
	}
	wg.Wait()

	snap := c.Snapshot()
	if snap.Stages[string(StageNoiseEnc)].Latency.Count != 10000 {
		t.Errorf("expected 10000, got %d", snap.Stages[string(StageNoiseEnc)].Latency.Count)
	}
	if snap.Stages[string(StageTunRead)].Packets != 10000 {
		t.Errorf("expected 10000 packets, got %d", snap.Stages[string(StageTunRead)].Packets)
	}
	if snap.RetransmitCount != 10000 {
		t.Errorf("expected 10000 retransmits, got %d", snap.RetransmitCount)
	}
}

func BenchmarkTrackLatency(b *testing.B) {
	c := NewCollector()
	d := 100 * time.Microsecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.TrackLatency(StageNoiseEnc, d)
	}
}

func BenchmarkTrackPacket(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.TrackPacket(StageTunRead, 1500)
	}
}

func TestExpandedHistogramBuckets(t *testing.T) {
	// Verify that latencies up to 30s are properly captured in the expanded
	// 30-bucket histogram (previously 20 buckets capped at ~512ms).
	c := NewCollector()
	c.TrackLatency(StageFullIngress, 100*time.Millisecond)
	c.TrackLatency(StageFullIngress, 1*time.Second)
	c.TrackLatency(StageFullIngress, 10*time.Second)
	c.TrackLatency(StageFullIngress, 30*time.Second)

	snap := c.Snapshot()
	st := snap.Stages[string(StageFullIngress)]
	if st.Latency.Count != 4 {
		t.Fatalf("expected count=4, got %d", st.Latency.Count)
	}
	// Max should reflect the 30s sample.
	if st.Latency.MaxUs < 29_000_000 {
		t.Errorf("max_us=%f should be >= 29_000_000 (30s)", st.Latency.MaxUs)
	}
	// P99 should be in the 30s range, not clamped at 512ms.
	if st.Latency.P99Us < 1_000_000 {
		t.Errorf("p99=%f too low — bucket overflow? should be >= 1_000_000 (1s)", st.Latency.P99Us)
	}
}

func TestNewStages(t *testing.T) {
	c := NewCollector()
	// Verify new stages exist and accept data.
	c.TrackLatency(StageObfsReadWait, 50*time.Millisecond)
	c.TrackLatency(StageObfsReadProc, 100*time.Microsecond)

	snap := c.Snapshot()
	if snap.Stages[string(StageObfsReadWait)].Latency.Count != 1 {
		t.Error("obfs_read_wait not tracked")
	}
	if snap.Stages[string(StageObfsReadProc)].Latency.Count != 1 {
		t.Error("obfs_read_proc not tracked")
	}
}

func TestTCPInfoSnapshot(t *testing.T) {
	c := NewCollector()
	c.TCP.RTTUs.Store(93000)
	c.TCP.RetransmitSegs.Store(42)
	c.TCP.CwndSegs.Store(10)

	snap := c.Snapshot()
	if snap.TCPInfo.RTTUs != 93000 {
		t.Errorf("expected rtt_us=93000, got %d", snap.TCPInfo.RTTUs)
	}
	if snap.TCPInfo.RetransmitSegs != 42 {
		t.Errorf("expected retransmit_segs=42, got %d", snap.TCPInfo.RetransmitSegs)
	}
	if snap.TCPInfo.CwndSegs != 10 {
		t.Errorf("expected cwnd_segs=10, got %d", snap.TCPInfo.CwndSegs)
	}
}

func BenchmarkSnapshot(b *testing.B) {
	c := NewCollector()
	for i := 0; i < 10000; i++ {
		c.TrackLatency(StageNoiseEnc, time.Duration(i)*time.Microsecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Snapshot()
	}
}
