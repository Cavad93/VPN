package transport

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBBRInstantStart compares throughput with and without SetInitialBandwidth
// on a simulated SPb→Astana path (65ms RTT, 0.5% loss).
func TestBBRInstantStart(t *testing.T) {
	profile := networkProfile{
		Name:     "SPb → Astana",
		RTT:      65 * time.Millisecond,
		LossRate: 0.005,
		JitterMs: 5,
	}

	t.Run("Without_SetInitialBandwidth_(slow_startup)", func(t *testing.T) {
		speed := runInstantStartTest(t, profile, 0, 0)
		t.Logf("Speed WITHOUT initial bandwidth: %.1f Mbps", speed)
	})

	t.Run("With_SetInitialBandwidth_100Mbps_(instant)", func(t *testing.T) {
		// Seed with 100 Mbps and estimated 65ms RTT.
		speed := runInstantStartTest(t, profile, 100_000_000/8, 65*time.Millisecond)
		t.Logf("Speed WITH initial bandwidth 100Mbps: %.1f Mbps", speed)
	})

	t.Run("With_SetInitialBandwidth_50Mbps_(conservative)", func(t *testing.T) {
		speed := runInstantStartTest(t, profile, 50_000_000/8, 65*time.Millisecond)
		t.Logf("Speed WITH initial bandwidth 50Mbps: %.1f Mbps", speed)
	})
}

func runInstantStartTest(t *testing.T, profile networkProfile, initialBw int64, initialRTT time.Duration) float64 {
	transferSize := 1 * 1024 * 1024 // 1 MB

	// Create sockets.
	serverSock, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer serverSock.Close()
	clientSock, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer clientSock.Close()

	serverAddr := serverSock.LocalAddr().(*net.UDPAddr)
	clientAddr := clientSock.LocalAddr().(*net.UDPAddr)

	// Proxy sockets for delay/loss simulation.
	proxyStoC, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer proxyStoC.Close()
	proxyCtoS, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer proxyCtoS.Close()

	proxyStoCAdr := proxyStoC.LocalAddr().(*net.UDPAddr)
	proxyCtoSAdr := proxyCtoS.LocalAddr().(*net.UDPAddr)

	proxyFwd := newLossyProxy(proxyCtoS, serverSock, proxyCtoSAdr, serverAddr, profile)
	go proxyFwd.run()
	defer proxyFwd.stop()

	proxyRev := newLossyProxy(proxyStoC, clientSock, proxyStoCAdr, clientAddr, profile)
	go proxyRev.run()
	defer proxyRev.stop()

	// Create Conn objects.
	senderConn := newConn(clientSock, proxyCtoSAdr, false)
	receiverConn := newConn(serverSock, proxyStoCAdr, false)

	// Apply initial bandwidth if requested.
	if initialBw > 0 {
		senderConn.SetInitialBandwidth(initialBw, initialRTT)
	}

	go proxyReadLoop(clientSock, senderConn)
	go proxyReadLoop(serverSock, receiverConn)

	// Receiver.
	var received atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for received.Load() < int64(transferSize) {
			data, err := receiverConn.Read(ctx)
			if err != nil {
				return
			}
			received.Add(int64(len(data)))
		}
	}()

	// Send.
	payload := make([]byte, MaxPayloadSize)
	rand.Read(payload)
	start := time.Now()
	sent := 0
	for sent < transferSize {
		chunk := MaxPayloadSize
		if transferSize-sent < chunk {
			chunk = transferSize - sent
		}
		if err := senderConn.Write(payload[:chunk]); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		sent += chunk
	}

	// Wait for receive.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Logf("Timeout! Received %d / %d bytes", received.Load(), transferSize)
	}

	elapsed := time.Since(start)
	recvBytes := received.Load()
	mbps := float64(recvBytes) * 8 / elapsed.Seconds() / 1_000_000
	cwnd := senderConn.bbr.CwndTarget()
	phase := senderConn.bbr.Phase()

	t.Logf("  Transferred: %d KB / %d KB in %v", recvBytes/1024, transferSize/1024, elapsed.Round(time.Millisecond))
	t.Logf("  Throughput:   %.1f Mbps", mbps)
	t.Logf("  BBR phase:    %s, cwnd=%d pkts", phase, cwnd)
	t.Logf("  BtlBw:        %.1f Mbps", float64(senderConn.bbr.estimator.BtlBw())*8/1_000_000)

	senderConn.Close()
	receiverConn.Close()

	return mbps
}
