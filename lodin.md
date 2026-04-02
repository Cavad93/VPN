# VPN Speed Optimization Log

## Baseline
- Down: 2.6 Mbps, Up: 3.3 Mbps, Ping: 84ms

## Completed Optimizations (10 cycles)

### Cycle 1: Remove DSCP CS1 marking
**File:** `server/sockopt_linux.go`
**Change:** DSCP CS1 (0x20) → Default (0x00)
**Impact:** HIGH — CS1 explicitly tells ISPs to deprioritize traffic ("lower effort" class). This was likely the single biggest cause of low throughput.

### Cycle 2: Increase TUN MTU 1420 → 1460
**File:** `server/tun_linux.go`
**Change:** Reduced safety margin from 50 bytes to 10 bytes. VPN overhead is exactly 30 bytes (mux 7 + noise 18 + obfs 5), so 1460 + 30 = 1490 fits well within 1500 Ethernet MTU.
**Impact:** MEDIUM — 2.8% more payload per packet, fewer packets for same data.

### Cycle 3: Increase socket buffers 4MB → 8MB
**Files:** `server/main.go`, `client/core.py`
**Change:** SO_RCVBUF/SO_SNDBUF from 4MB to 8MB on both server and client.
**Impact:** MEDIUM — More headroom for burst traffic. BDP for 64 Mbps × 120ms = ~960 KB, 8MB provides 8× headroom.

### Cycle 4: Add bufio.Reader + pool ObfsConn allocations
**File:** `server/transport/obfs.go`
**Change:** Added 32KB bufio.Reader for reads, pooled TLS record buffers for writes.
**Impact:** MEDIUM — Reduces read syscalls by batching small header reads. Eliminates heap allocation per outgoing TLS record.

### Cycle 5: Increase mux accept backlog 16 → 64
**File:** `server/transport/mux.go`
**Change:** `acceptCh` channel buffer from 16 to 64.
**Impact:** LOW — Prevents stream rejection under burst of new stream opens.

### Cycle 6: Client-side recv buffer + queue increase
**File:** `client/core.py`
**Change:** ObfsConn recv staging 64KB → 128KB, mux stream queue 2048 → 4096.
**Impact:** MEDIUM — Fewer recv syscalls on client, matched to 8MB socket buffer.

### Cycle 7: Add TCP_QUICKACK on server
**File:** `server/sockopt_linux.go`
**Change:** Set TCP_QUICKACK=1 on each connection.
**Impact:** MEDIUM — Eliminates 40ms delayed ACK timer, allowing faster congestion window growth.

### Cycle 8: Lock-free dataStream via atomic.Pointer
**File:** `server/main.go`
**Change:** Replaced `sync.Mutex` + `*transport.Stream` with `atomic.Pointer[transport.Stream]`.
**Impact:** LOW-MEDIUM — Eliminates mutex lock/unlock per packet on the hot TUN→client path. At 10 Mbps with 1460-byte packets, that's ~860 lock/unlock pairs per second eliminated.

### Cycle 9: Enable TCP BBR congestion control
**File:** `server/sockopt_linux.go`
**Change:** Set TCP_CONGESTION="bbr" per socket (falls back to CUBIC if unavailable).
**Impact:** HIGH — BBR probes actual bandwidth rather than relying on loss signals. On high-latency links (80-120ms), BBR typically achieves 2-5× throughput vs CUBIC because it doesn't halve the congestion window on random packet loss.

---

## Expected Impact Summary
| Optimization | Expected Improvement |
|---|---|
| Remove DSCP CS1 | +50-200% (ISP deprioritization removed) |
| TCP BBR | +100-400% on high-latency links |
| TCP_QUICKACK | +10-20% (faster window ramp) |
| Socket buffers 8MB | +20-50% (burst capacity) |
| MTU 1460 | +2-3% (payload efficiency) |
| bufio.Reader + pools | +5-15% (reduced syscalls/GC) |
| atomic.Pointer | +1-5% (lock contention removed) |
| Client recv/queue | +5-10% (fewer client syscalls) |

## Plan for Next Run
1. **Verify BBR kernel module** — Check if `tcp_bbr` is loaded on the server. If not, load it via `modprobe tcp_bbr`.
2. **Tune kernel sysctl** — `net.core.rmem_max`, `net.core.wmem_max`, `net.ipv4.tcp_rmem`, `net.ipv4.tcp_wmem` should be set to at least 8MB.
3. **Benchmark** — Run actual speedtest after deploying to see real numbers.
4. **Consider TCP_CORK** — Batch multiple mux frames into one TCP segment when possible.
5. **Consider GRO/GSO** — Enable Generic Receive/Send Offloading on TUN device.
6. **noiseConn Decrypt allocation** — Pre-allocate decrypt destination buffer to eliminate per-packet allocation.
7. **Client-side BBR** — Set TCP_CONGESTION on client socket (requires macOS equivalent).
