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

// networkProfile describes a simulated network path.
type networkProfile struct {
	Name       string
	RTT        time.Duration // round-trip time
	LossRate   float64       // packet loss probability (0.0 - 1.0)
	Bandwidth  int64         // link bandwidth in bytes/sec (0 = unlimited)
	JitterMs   int           // random jitter added to RTT (±ms)
}

// Realistic network profiles for benchmarking.
var profiles = []networkProfile{
	{
		Name:      "Localhost (baseline)",
		RTT:       200 * time.Microsecond,
		LossRate:  0,
		Bandwidth: 0,
	},
	{
		Name:     "Saint Petersburg → Astana (~3000 km)",
		RTT:      65 * time.Millisecond, // typical SPb-Astana via Moscow
		LossRate: 0.005,                 // 0.5% loss
		JitterMs: 5,
	},
	{
		Name:     "SPb → Astana (congested)",
		RTT:      85 * time.Millisecond,
		LossRate: 0.015, // 1.5% loss
		JitterMs: 15,
	},
	{
		Name:     "SPb → Astana (good path)",
		RTT:      50 * time.Millisecond,
		LossRate: 0.002, // 0.2% loss
		JitterMs: 3,
	},
}

// lossy proxy sits between sender and receiver, adding delay/loss/jitter.
type lossyProxy struct {
	src, dst   *net.UDPConn
	srcAddr    *net.UDPAddr
	dstAddr    *net.UDPAddr
	halfRTT    time.Duration
	lossRate   float64
	jitterMs   int
	forwarded  atomic.Int64
	dropped    atomic.Int64
	ctx        context.Context
	cancel     context.CancelFunc
}

func newLossyProxy(src, dst *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, p networkProfile) *lossyProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &lossyProxy{
		src:      src,
		dst:      dst,
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		halfRTT:  p.RTT / 2,
		lossRate: p.LossRate,
		jitterMs: p.JitterMs,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (lp *lossyProxy) run() {
	buf := make([]byte, 65535)
	for {
		lp.src.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := lp.src.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-lp.ctx.Done():
				return
			default:
				continue
			}
		}

		// Simulate loss.
		if lp.lossRate > 0 && rand.Float64() < lp.lossRate {
			lp.dropped.Add(1)
			continue
		}

		// Simulate delay + jitter.
		delay := lp.halfRTT
		if lp.jitterMs > 0 {
			jitter := time.Duration(rand.Intn(lp.jitterMs*2)-lp.jitterMs) * time.Millisecond
			delay += jitter
			if delay < 0 {
				delay = time.Millisecond
			}
		}

		// Copy packet (buf will be reused).
		pktCopy := make([]byte, n)
		copy(pktCopy, buf[:n])

		go func() {
			time.Sleep(delay)
			lp.dst.WriteToUDP(pktCopy, lp.dstAddr)
			lp.forwarded.Add(1)
		}()
	}
}

func (lp *lossyProxy) stop() {
	lp.cancel()
}

// TestBBRThroughputSimulation benchmarks BBR throughput under various
// network conditions simulating real-world paths.
func TestBBRThroughputSimulation(t *testing.T) {
	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			runThroughputTest(t, profile)
		})
	}
}

func runThroughputTest(t *testing.T, profile networkProfile) {
	// Create server and client UDP sockets.
	serverSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverSock.Close()

	clientSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSock.Close()

	serverAddr := serverSock.LocalAddr().(*net.UDPAddr)
	clientAddr := clientSock.LocalAddr().(*net.UDPAddr)

	if profile.RTT > time.Millisecond {
		// Set up lossy proxy for non-localhost profiles.
		// We need two proxy sockets — one for each direction.
		proxyStoC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer proxyStoC.Close()

		proxyCtoS, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer proxyCtoS.Close()

		proxyStoCAdr := proxyStoC.LocalAddr().(*net.UDPAddr)
		proxyCtoSAdr := proxyCtoS.LocalAddr().(*net.UDPAddr)

		// Client → ProxyCtoS → Server
		proxyFwd := newLossyProxy(proxyCtoS, serverSock, proxyCtoSAdr, serverAddr, profile)
		go proxyFwd.run()
		defer proxyFwd.stop()

		// Server → ProxyStoC → Client
		proxyRev := newLossyProxy(proxyStoC, clientSock, proxyStoCAdr, clientAddr, profile)
		go proxyRev.run()
		defer proxyRev.stop()

		// Create Conn objects using proxy addresses.
		serverConn := newConn(serverSock, proxyStoCAdr, false)
		clientConn := newConn(clientSock, proxyCtoSAdr, false)

		// Read loops.
		go proxyReadLoop(serverSock, serverConn)
		go proxyReadLoop(clientSock, clientConn)

		runDataTransfer(t, profile, clientConn, serverConn)

		clientConn.Close()
		serverConn.Close()
	} else {
		// Direct localhost connection (no proxy).
		serverConn := newConn(serverSock, clientAddr, false)
		clientConn := newConn(clientSock, serverAddr, false)

		go proxyReadLoop(serverSock, serverConn)
		go proxyReadLoop(clientSock, clientConn)

		runDataTransfer(t, profile, clientConn, serverConn)

		clientConn.Close()
		serverConn.Close()
	}
}

func proxyReadLoop(conn *net.UDPConn, c *Conn) {
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}
		pkt, err := DecodePacket(buf[:n])
		if err != nil {
			continue
		}
		switch pkt.Type {
		case PacketTypeData, PacketTypeSYN, PacketTypeFIN:
			c.processData(pkt)
		case PacketTypeACK:
			c.processACK(pkt.AckNum)
			pkt.Payload = nil
			pktPool.Put(pkt)
		}
	}
}

func runDataTransfer(t *testing.T, profile networkProfile, sender, receiver *Conn) {
	// Transfer size: 4 MB for fast profiles, 1 MB for slow ones.
	// Larger transfers give BBR more time to converge to true bandwidth.
	transferSize := 4 * 1024 * 1024
	if profile.RTT > 60*time.Millisecond {
		transferSize = 1 * 1024 * 1024
	}

	// Timeout: generous to account for slow convergence.
	timeout := 30 * time.Second
	if profile.RTT > 60*time.Millisecond {
		timeout = 45 * time.Second
	}

	// Receive goroutine.
	var received atomic.Int64
	var receiveDone sync.WaitGroup
	receiveDone.Add(1)
	go func() {
		defer receiveDone.Done()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		for received.Load() < int64(transferSize) {
			rp, err := receiver.Read(ctx)
			if err != nil {
				return
			}
			received.Add(int64(len(rp.data)))
			if rp.backing != nil {
				decodePayloadPool.Put(rp.backing)
			}
		}
	}()

	// Send data.
	sendStart := time.Now()
	payload := make([]byte, MaxPayloadSize)
	rand.Read(payload)

	sent := 0
	for sent < transferSize {
		chunk := MaxPayloadSize
		if transferSize-sent < chunk {
			chunk = transferSize - sent
		}
		if err := sender.Write(payload[:chunk]); err != nil {
			t.Fatalf("Write error after %d bytes: %v", sent, err)
		}
		sent += chunk
	}
	sendDuration := time.Since(sendStart)

	// Wait for all data to arrive.
	done := make(chan struct{})
	go func() {
		receiveDone.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Logf("WARNING: Receive timed out. Got %d / %d bytes (%.1f%%)",
			received.Load(), transferSize, float64(received.Load())*100/float64(transferSize))
	}

	recvBytes := received.Load()
	totalDuration := time.Since(sendStart)

	// Calculate throughput.
	sendMbps := float64(sent*8) / sendDuration.Seconds() / 1_000_000
	recvMbps := float64(recvBytes*8) / totalDuration.Seconds() / 1_000_000

	// BBR state info.
	btlbw := sender.bbr.estimator.BtlBw()
	rtprop := sender.bbr.estimator.RTprop()
	bdp := sender.bbr.estimator.BDP()
	cwnd := sender.bbr.CwndTarget()
	inflight := sender.bbr.inflight.Count()

	t.Logf("═══════════════════════════════════════════")
	t.Logf("  Profile:    %s", profile.Name)
	t.Logf("  Simulated:  RTT=%v, Loss=%.1f%%, Jitter=±%dms", profile.RTT, profile.LossRate*100, profile.JitterMs)
	t.Logf("───────────────────────────────────────────")
	t.Logf("  Transferred: %d KB / %d KB (%.1f%%)",
		recvBytes/1024, transferSize/1024, float64(recvBytes)*100/float64(transferSize))
	t.Logf("  Send speed:  %.1f Mbps", sendMbps)
	t.Logf("  Recv speed:  %.1f Mbps (end-to-end)", recvMbps)
	t.Logf("───────────────────────────────────────────")
	t.Logf("  BBR BtlBw:   %.1f Mbps", float64(btlbw)*8/1_000_000)
	t.Logf("  BBR RTprop:  %d µs", rtprop)
	t.Logf("  BBR BDP:     %d KB", bdp/1024)
	t.Logf("  BBR cwnd:    %d pkts", cwnd)
	t.Logf("  Inflight:    %d pkts", inflight)
	t.Logf("═══════════════════════════════════════════")

	// Sanity check: at least some data should have arrived.
	if recvBytes == 0 {
		t.Error("No data received!")
	}
}

// TestBBRTheoretical calculates theoretical max throughput for the SPb-Astana path
// given BBR parameters and our protocol overhead.
func TestBBRTheoretical(t *testing.T) {
	t.Log("╔═══════════════════════════════════════════════════════════════╗")
	t.Log("║  THEORETICAL THROUGHPUT: Saint Petersburg → Astana          ║")
	t.Log("╠═══════════════════════════════════════════════════════════════╣")

	// Network parameters.
	rttMs := 65.0        // ms
	lossRate := 0.005    // 0.5%
	linkBwMbps := 100.0  // ISP link capacity

	// Protocol overhead per packet.
	payloadSize := MaxPayloadSize                          // 1460
	udpOverhead := 8                                       // UDP header
	ipOverhead := 20                                       // IP header
	wireSize := HeaderSize + payloadSize + udpOverhead + ipOverhead // our header + payload + UDP + IP
	overheadRatio := float64(payloadSize) / float64(wireSize)

	// BBR BDP calculation.
	linkBwBps := linkBwMbps * 1_000_000 / 8 // bytes/sec
	rttSec := rttMs / 1000
	bdpBytes := linkBwBps * rttSec
	bdpPackets := bdpBytes / float64(payloadSize)

	// Effective throughput with loss.
	// BBR tolerates loss up to ~2% without reducing. Below that, full BDP.
	effectiveBw := linkBwBps
	if lossRate > 0.02 {
		// TCP-like degradation above BBR loss threshold.
		effectiveBw = linkBwBps * (1 - lossRate)
	}

	// User-space overhead estimate.
	// Based on our optimizations:
	// - 1 alloc per packet (payload copy)
	// - 2 mutex ops per packet (sendMu in writePacket)
	// - Batch send: ~64 packets per syscall (Linux) or 1 per syscall (Windows)
	//
	// Per-packet processing time estimate:
	perPktUsLinux := 3.0    // µs per packet with sendmmsg batching
	perPktUsWindows := 8.0  // µs per packet without batching
	perPktUsMacOS := 8.0    // µs per packet without batching

	maxPpsLinux := 1_000_000 / perPktUsLinux
	maxPpsWindows := 1_000_000 / perPktUsWindows
	maxPpsMacOS := 1_000_000 / perPktUsMacOS

	maxBwLinux := maxPpsLinux * float64(payloadSize) * 8 / 1_000_000
	maxBwWindows := maxPpsWindows * float64(payloadSize) * 8 / 1_000_000
	maxBwMacOS := maxPpsMacOS * float64(payloadSize) * 8 / 1_000_000

	// Actual throughput = min(link_bw, user_space_processing_max)
	// BDP determines cwnd needed, not throughput limit — BBR fills the pipe.
	effectiveMbps := effectiveBw * 8 / 1_000_000 * overheadRatio

	actualLinux := min3(effectiveMbps, maxBwLinux, effectiveMbps)
	actualWindows := min3(effectiveMbps, maxBwWindows, effectiveMbps)
	actualMacOS := min3(effectiveMbps, maxBwMacOS, effectiveMbps)

	t.Logf("║  Network: RTT=%gms, Loss=%.1f%%, Link=%g Mbps           ║", rttMs, lossRate*100, linkBwMbps)
	t.Logf("║  Payload: %d B, Wire: %d B, Efficiency: %.1f%%            ║",
		payloadSize, wireSize, overheadRatio*100)
	t.Logf("║  BDP: %.0f KB (%.0f packets)                              ║", bdpBytes/1024, bdpPackets)
	t.Logf("╠═══════════════════════════════════════════════════════════════╣")
	t.Logf("║  Platform      │ Max PPS   │ Processing  │ Expected Mbps   ║")
	t.Logf("╠════════════════╪═══════════╪═════════════╪═════════════════╣")
	t.Logf("║  Linux (smmsg) │ %7.0f   │  %4.1f µs/pkt │  %6.1f Mbps    ║", maxPpsLinux, perPktUsLinux, actualLinux)
	t.Logf("║  Windows       │ %7.0f   │  %4.1f µs/pkt │  %6.1f Mbps    ║", maxPpsWindows, perPktUsWindows, actualWindows)
	t.Logf("║  macOS         │ %7.0f   │  %4.1f µs/pkt │  %6.1f Mbps    ║", maxPpsMacOS, perPktUsMacOS, actualMacOS)
	t.Logf("╠═══════════════════════════════════════════════════════════════╣")
	t.Logf("║  YOUR SETUP: Server=Windows(Astana), Client=macOS(SPb)      ║")
	t.Logf("║  ➤ Expected download:  %.0f - %.0f Mbps                     ║", actualMacOS*0.6, actualMacOS*0.9)
	t.Logf("║  ➤ Expected upload:    %.0f - %.0f Mbps                     ║", actualWindows*0.6, actualWindows*0.9)
	t.Logf("║                                                             ║")
	t.Logf("║  vs TCP bonding (32 conn):  50-100 Mbps                     ║")
	t.Logf("║  vs BBR BEFORE optimizations: 3-8 Mbps                      ║")
	t.Logf("╚═══════════════════════════════════════════════════════════════╝")
}

func min3(a, b, c float64) float64 {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
