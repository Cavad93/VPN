# VPN Speed Optimization Log

## Baseline
- Down: 2.6 Mbps, Up: 3.3 Mbps, Ping: 84ms

## Completed Optimizations (20 cycles)

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

### Cycle 10: Zero-alloc AEAD decrypt via pre-allocated buffer
**Files:** `server/crypto/handshake.go`, `server/main.go`
**Change:** Added `DecryptTo(dst, ciphertext, ad)` method to `SessionCipher` that decrypts into a caller-provided buffer. Added 65KB `decryptBuf` field to `noiseConn`. The hot-path `noiseConn.Read` now calls `DecryptTo` instead of `Decrypt`, passing `decryptBuf` as destination. This eliminates the `make([]byte, 0, len-16)` allocation inside `aead.Open` on every received packet.
**Impact:** LOW-MEDIUM — At 10 Mbps with 1460-byte packets, eliminates ~860 heap allocations per second (~1.2 MB/s GC pressure removed). Reduces GC pause frequency and improves P99 latency.

### Cycle 11: Zero-alloc AEAD encrypt via EncryptTo
**Files:** `server/crypto/handshake.go`
**Change:** Added `encryptWithADTo(dst, ad, plaintext)` to `noiseCipherState` and `EncryptTo(dst, plaintext, ad)` to `SessionCipher` — mirrors the existing DecryptTo pattern. AEAD Seal writes ciphertext directly into a caller-provided buffer.
**Impact:** LOW-MEDIUM — Foundation for cycle 13. Eliminates the `aead.Seal(nil, ...)` allocation on every encrypt call when used with a pre-allocated destination.

### Cycle 12: ObfsConn.Read zero-copy tail
**File:** `server/transport/obfs.go`
**Change:** Replaced `tail := make([]byte, len-n); copy(tail, payload[n:])` with `c.readBuf = payload[n:]`. Safe because `readRecord` allocates a fresh buffer for each TLS record — same pattern as `consumeData` in mux.go.
**Impact:** LOW — Eliminates one allocation + copy per partial ObfsConn.Read. At high throughput (~860 packets/s at 10 Mbps), saves ~860 allocs/s when reads are partial.

### Cycle 13: noiseConn.Write — EncryptTo directly into frame buffer
**File:** `server/main.go`
**Change:** Instead of `Encrypt(p, nil)` → alloc ciphertext → copy into pool frame, now `EncryptTo(frame[2:2], p, nil)` writes ciphertext directly into the pool frame buffer at offset 2. Eliminates both the intermediate ciphertext allocation and the copy.
**Impact:** MEDIUM — Saves 2 allocations + 1 memcpy per outgoing packet. At 10 Mbps: ~860 allocs/s + ~1.2 MB/s of copies eliminated.

### Cycle 14: Increase bufio.Reader 32KB → 64KB
**File:** `server/transport/obfs.go`
**Change:** bufio.NewReaderSize from 32768 to 65536.
**Impact:** LOW — Larger read buffer means fewer read syscalls. Matches the 8MB socket buffer better — one syscall fills ~44 TLS records instead of ~22.

### Cycle 15: Mux acceptCh 16 → 64 (fix)
**File:** `server/transport/mux.go`
**Change:** `acceptCh` channel buffer from 16 to 64. Previous cycle 5 logged this but the change was not applied in current code.
**Impact:** LOW — Prevents stream rejection under burst of new stream opens.

### Cycle 16: Client _SOCK_RECV_SIZE 131072 → 262144
**File:** `client/core.py`
**Change:** Socket-level recv buffer doubled from 128KB to 256KB.
**Impact:** LOW-MEDIUM — One recv(262144) fills ~180 TLS records, reducing syscalls by ~50% vs 128KB.

### Cycle 17: Client ObfsConn.write — inline header+payload
**File:** `client/core.py`
**Change:** Replaced `_build_app_data_record(chunk)` (creates intermediate bytes object) with inline `bytearray(5+chunk_len)` + `struct.pack_into` + slice assignment. Avoids per-chunk bytes allocation and concatenation.
**Impact:** LOW — Eliminates 1 allocation per outgoing TLS record on client side.

### Cycle 18: TCP_DEFER_ACCEPT on server listener
**Files:** `server/sockopt_linux.go`, `server/sockopt_stub.go`, `server/main.go`
**Change:** Set TCP_DEFER_ACCEPT=5s on the listener socket. Kernel holds connections in SYN_RECV until the client sends data (the TLS ClientHello), eliminating one context switch per accept and silently dropping SYN-only port-scan probes.
**Impact:** LOW — Reduces accept() overhead. More impactful under port-scan traffic from Russian/Kazakh ISP probes.

### Cycle 19: Client TCP keepalive (15s idle)
**File:** `client/core.py`
**Change:** Set SO_KEEPALIVE=1, TCP_KEEPALIVE=15s (macOS) or TCP_KEEPIDLE=15s + TCP_KEEPINTVL=10s + TCP_KEEPCNT=3 (Linux). Platform-adaptive with best-effort fallback.
**Impact:** MEDIUM — Prevents ISP NAT/firewall from dropping idle VPN connections. Russian ISPs (Rostelecom, MTS) expire idle TCP entries after 60-120s; 15s keepalive probes well within this window.

### Cycle 20: Server TCP keepalive tuning (30s → 15s idle, 10s → 5s interval)
**Files:** `server/sockopt_linux.go`, `server/main.go`
**Change:** TCP_KEEPIDLE 30→15s, TCP_KEEPINTVL 10→5s. Total detection time: 15+3×5=30s (was 60s). Also updated `SetKeepAlivePeriod` from 30s to 15s.
**Impact:** LOW-MEDIUM — Detects dead connections 2× faster, freeing IP pool entries, goroutines, and memory sooner. Important for mobile clients with frequent disconnects.

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
| Zero-alloc decrypt | +2-5% (reduced GC pressure) |
| Zero-alloc encrypt (EncryptTo) | +2-5% (reduced GC pressure) |
| ObfsConn zero-copy tail | +1-2% (fewer allocs) |
| noiseConn.Write EncryptTo | +3-8% (2 allocs + 1 copy eliminated per pkt) |
| bufio.Reader 64KB | +2-5% (fewer read syscalls) |
| Client recv 256KB | +3-5% (fewer recv syscalls) |
| Client inline write | +1-3% (fewer client allocs) |
| TCP_DEFER_ACCEPT | +1-2% (faster accept, probe rejection) |
| Client TCP keepalive | stability (prevents NAT drops) |
| Server keepalive 15s | stability (faster dead conn detection) |

## Plan for Next Run
1. **Benchmark** — Deploy to server and run actual speedtest to measure cumulative effect of all 20 optimizations.
2. **Kernel sysctl tuning** — `net.core.rmem_max=16777216`, `net.core.wmem_max=16777216`, `net.ipv4.tcp_rmem="4096 1048576 16777216"`, `net.ipv4.tcp_wmem="4096 1048576 16777216"` — ensure kernel allows the 8MB socket buffers.
3. **Verify BBR kernel module** — Check if `tcp_bbr` is loaded: `lsmod | grep bbr`. If not: `modprobe tcp_bbr && echo tcp_bbr >> /etc/modules`.
4. **GRO/GSO on TUN** — Enable Generic Receive/Send Offloading on the TUN device via `ethtool -K tun0 gro on gso on` to let the kernel aggregate small packets.
5. **Client-side sendfile optimization** — Use Python `os.sendfile` or `socket.sendmsg` with SCM_RIGHTS to reduce user↔kernel copies for TUN→socket forwarding.
6. **Parallel data streams** — Open multiple mux data streams for parallel forwarding, saturating the TCP window.
7. **Write coalescing with writev** — Use `net.Buffers` (writev syscall) to send multiple mux frames in one syscall on the server.
8. **noiseConn.Read: avoid io.ReadFull for length prefix** — Read 2+frameLen in one call when bufio has enough data, avoiding the 2-call overhead.
9. **Pool TUN read buffer in routeFromTun** — Currently stack-allocated 64KB; pool it for consistency.
10. **Profile with pprof** — Run CPU and allocation profiling under load to identify remaining hot spots.
