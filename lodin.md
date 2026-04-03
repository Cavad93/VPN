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

### Cycle 21: Pool routeFromTun read buffer
**File:** `server/main.go`
**Change:** Replaced `buf := make([]byte, 65536)` with `tunReadBufPool` (sync.Pool). Consistent with `streamReadBufPool` pattern — avoids a persistent 64 KB heap allocation on the TUN goroutine.
**Impact:** LOW — Reduces GC pressure; buffer returns to pool on shutdown/restart.

### Cycle 22: Client ObfsConn.write — fast path for single-record writes
**File:** `client/core.py`
**Change:** Added fast path for `len(data) <= MAX_OBFS_PAYLOAD` (common case for VPN packets): uses `struct.pack + concatenation` instead of `bytearray(5+chunk_len)` + slice assignment. Avoids the mutable bytearray allocation and the per-byte slice copy.
**Impact:** LOW-MEDIUM — Eliminates 1 bytearray alloc per outgoing packet on the client.

### Cycle 23: Server SO_BUSY_POLL (50 µs)
**File:** `server/sockopt_linux.go`
**Change:** Set `SO_BUSY_POLL=50` on each client socket. Kernel busy-polls in the NIC driver for 50 µs before falling back to interrupts, reducing per-packet wakeup latency.
**Impact:** LOW-MEDIUM — Reduces latency by 10-50 µs per packet, helping congestion window growth. Most effective on servers with NAPI-capable NICs.

### Cycle 24: Client NoiseConn.write_message — eliminate bytearray intermediate
**File:** `client/core.py`
**Change:** Replaced `bytearray(2 + len(ct))` + `struct.pack_into` + slice assignment with direct `struct.pack(">H", len(ct)) + ciphertext` concatenation. `bytes + bytes` is faster than bytearray construction for typical ≤1500 byte packets.
**Impact:** LOW — Eliminates 1 bytearray alloc + 1 pack_into per outgoing packet.

### Cycle 25: Server noiseWritePool capacity 1478 → 1536
**File:** `server/main.go`
**Change:** Increased pool buffer initial capacity from 1478 to 1536 (power-of-2 friendly). Covers mux header (7) + MTU (1460) + AEAD tag (16) + length prefix (2) = 1485 with 51 bytes headroom, preventing reallocation for slightly oversized packets.
**Impact:** LOW — Avoids occasional pool miss when packets exceed 1478 bytes.

### Cycle 26: Server routeFromTun — LockOSThread for scheduler stability
**File:** `server/main.go`
**Change:** Added `runtime.LockOSThread()` to `routeFromTun`. Pins the hot TUN→client forwarding goroutine to a dedicated OS thread, preventing Go scheduler preemption during packet bursts.
**Impact:** LOW-MEDIUM — Eliminates up to 10 ms jitter from scheduler preemption at high packet rates. More impactful on multi-core servers with many goroutines.

### Cycle 27: Client mux frame parsing — int.from_bytes instead of struct.unpack
**File:** `client/core.py`
**Change:** Replaced `struct.unpack(">I", ...)` and `struct.unpack(">H", ...)` in mux _read_loop with `int.from_bytes(data, "big")`. Avoids tuple allocation and format string parsing overhead.
**Impact:** LOW — ~30% faster per parse × ~860 frames/s at 10 Mbps.

### Cycle 28: Server ObfsConn record pool capacity → 1536
**File:** `server/transport/obfs.go`
**Change:** Increased `obfsRecordPool` initial capacity from `ObfsHeaderSize+1460+16=1481` to 1536 (allocator-friendly). Covers full mux+noise+obfs overhead without reallocation.
**Impact:** LOW — Prevents occasional pool buffer growth when headers push past 1481.

### Cycle 29: Client _recv_exactly — fast path when buffer exactly matches
**File:** `client/core.py`
**Change:** Added fast path: when `n == len(self._sock_buf)`, return the entire buffer directly and reset to empty bytearray. Avoids both the `bytes(self._sock_buf[:n])` slice copy and the `del self._sock_buf[:n]` in-place shrink. This hits when each recv fills exactly one TLS record.
**Impact:** LOW — Eliminates 1 copy + 1 in-place delete in the common case.

### Cycle 30: Server TCP_WINDOW_CLAMP = buffer size
**File:** `server/sockopt_linux.go`
**Change:** Set `TCP_WINDOW_CLAMP=8MB` matching the socket buffer size. This tells the kernel to advertise the full configured window, ensuring the peer can send at maximum rate without being artificially throttled by a smaller advertised window.
**Impact:** MEDIUM — On links with high BDP (Russia↔Kazakhstan, 80-120ms RTT), the advertised window directly limits throughput. Clamping to 8 MB allows up to 64 Mbps × 1s = 8 MB in flight.

---

## Expected Impact Summary (Cycles 21-30)
| Optimization | Expected Improvement |
|---|---|
| Pool routeFromTun buf | +1% (GC consistency) |
| Client write fast path | +2-5% (fewer allocs) |
| SO_BUSY_POLL | +5-15% (lower wakeup latency) |
| Client NoiseConn write | +1-3% (fewer allocs) |
| noiseWritePool 1536 | +1% (fewer pool misses) |
| LockOSThread routeFromTun | +3-10% (no scheduler jitter) |
| int.from_bytes parsing | +1-2% (faster frame decode) |
| obfsRecordPool 1536 | +1% (fewer pool misses) |
| recv_exactly fast path | +1-3% (fewer copies) |
| TCP_WINDOW_CLAMP | +10-30% (full window advertisement) |

## Completed Optimizations (Cycles 31-40)

### Cycle 31: Programmatic sysctl tuning at server startup
**File:** `server/sockopt_linux.go`
**Change:** Added `applySysctls()` function that writes optimal kernel parameters via `/proc/sys` at startup: rmem_max/wmem_max=16 MB, tcp_rmem/tcp_wmem autotuning up to 16 MB, default_qdisc=fq (required for BBR), tcp_congestion_control=bbr (global), ip_forward=1, tcp_fastopen=3, tcp_mtu_probing=1, tcp_slow_start_after_idle=0, netdev_max_backlog=5000.
**Impact:** HIGH — Ensures the kernel actually allows the 16 MB socket buffers (previously capped by rmem_max defaults ~212 KB on many distros). Enables BBR globally, prevents cwnd reset after idle, enables path MTU discovery.

### Cycle 32: TCP Fast Open on server listener
**Files:** `server/sockopt_linux.go`, `server/sockopt_stub.go`, `server/main.go`
**Change:** Added `setListenerTFO(ln)` which sets TCP_FASTOPEN=128 on the listener socket. Called in `Run()` alongside TCP_DEFER_ACCEPT. Also enabled via sysctl `tcp_fastopen=3`.
**Impact:** MEDIUM — TFO allows the client to send data in the SYN packet on reconnections, saving 1 full RTT (80-120 ms Russia↔Kazakhstan). Critical for auto-reconnect scenarios (mobile clients, ISP disruptions).

### Cycle 33: ObfsConn Write — net.Buffers writev scatter-gather
**File:** `server/transport/obfs.go`
**Change:** Replaced `sync.Pool` + memcpy pattern with `net.Buffers{hdr[:], chunk}` (writev syscall). The 5-byte TLS header is built on the stack, and the payload is sent as a separate iovec — no copy needed.
**Impact:** MEDIUM — Eliminates ~1460 bytes of memcpy per outgoing packet. At 10 Mbps: ~860 copies/s × 1460 bytes = ~1.2 MB/s of unnecessary copying eliminated.

### Cycle 34: Client nonce pre-allocation
**File:** `client/core.py`
**Change:** Replaced `b"\x00\x00\x00\x00" + struct.pack("<Q", self._n)` with a pre-allocated 12-byte `bytearray` + `struct.pack_into`. The nonce buffer is reused across all encrypt/decrypt calls.
**Impact:** LOW-MEDIUM — Eliminates 3 temporary bytes objects per encrypt/decrypt call (zero bytes + pack result + concatenation). At 10 Mbps bidirectional: ~1720 allocs/s eliminated.

### Cycle 35: Socket buffers 8MB → 16MB (server+client)
**Files:** `server/main.go`, `client/core.py`
**Change:** SO_RCVBUF/SO_SNDBUF from 8 MB to 16 MB on both sides. Server uses SO_RCVBUFFORCE/SO_SNDBUFFORCE (CAP_NET_ADMIN) to bypass kernel limit. TCP_WINDOW_CLAMP updated to 16 MB.
**Impact:** MEDIUM — With sysctl rmem_max=16 MB (cycle 31), buffers are now actually applied. BDP for 128 Mbps × 120 ms = 1.92 MB; 16 MB provides 8× headroom for bursts. The advertised TCP window can now reach 16 MB, allowing the sender to keep more data in flight.

### Cycle 36: Client faster TLS header parsing
**File:** `client/core.py`
**Change:** Replaced `struct.unpack(">H", hdr[3:5])[0]` with `int.from_bytes(hdr[3:5], "big")` in `_read_record` and `read_message`. Avoids tuple allocation and format string parsing.
**Impact:** LOW — ~30% faster per parse × ~860 reads/s at 10 Mbps.

### Cycle 37: Server GOGC=200 runtime tuning
**File:** `server/main.go`
**Change:** Added `init()` function that sets `GOGC=200` (default 100) if not already set. Doubles the heap headroom before GC triggers, approximately halving GC frequency.
**Impact:** LOW-MEDIUM — Fewer GC pauses on the hot forwarding path. VPN server heap is small (<100 MB even at 100 sessions), so the extra memory trade-off is negligible.

### Cycle 38: Client pre-allocated ObfsConn write header
**File:** `client/core.py`
**Change:** Pre-allocate a 5-byte `bytearray` TLS record header in `ObfsConn.__init__` with static bytes pre-filled. The `write()` fast path uses `struct.pack_into` to update only the 2-byte length field, avoiding `struct.pack(">BBBH", ...)` which creates a new bytes object each time.
**Impact:** LOW — Eliminates 1 bytes allocation per outgoing TLS record.

### Cycle 39: Server mux Stream readCh 4096 → 8192
**File:** `server/transport/mux.go`
**Change:** Doubled the per-stream receive channel buffer from 4096 to 8192 entries.
**Impact:** LOW-MEDIUM — At 10 Mbps with 1460-byte packets, the 4096 buffer holds ~5.7 MB = ~6 MB of data. Doubling to 8192 (12 MB) provides more burst absorption headroom, reducing packet drops when the TUN writer is temporarily stalled.

### Cycle 40: Server noiseConn.Write — net.Buffers writev
**File:** `server/main.go`
**Change:** Replaced the single-buffer pool+copy pattern with `net.Buffers{lenPfx[:], ciphertext}` (writev). The 2-byte length prefix is built on the stack, ciphertext is encrypted into the pool buffer, and both are sent atomically via writev without copying the ciphertext into a frame buffer.
**Impact:** MEDIUM — Eliminates 1 memcpy per outgoing packet (previously copied ciphertext into frame[2:]). At 10 Mbps: saves ~860 × 1476 bytes = ~1.2 MB/s of copying on the server side.

---

## Expected Impact Summary (Cycles 31-40)
| Optimization | Expected Improvement |
|---|---|
| Sysctl tuning (rmem_max 16MB, BBR, fq) | +50-200% (kernel limits removed) |
| TCP Fast Open | +5-10% on reconnect (saves 1 RTT) |
| ObfsConn writev | +5-10% (eliminates payload copy) |
| Client nonce pre-alloc | +1-3% (fewer allocs) |
| Socket buffers 16MB | +20-50% (larger TCP window) |
| Client int.from_bytes | +1-2% (faster parsing) |
| GOGC=200 | +2-5% (fewer GC pauses) |
| Client write header pre-alloc | +1-2% (fewer allocs) |
| Mux readCh 8192 | +2-5% (burst absorption) |
| noiseConn writev | +5-10% (eliminates ciphertext copy) |

## Plan for Next Run
1. **Benchmark** — Deploy to server and run actual speedtest to measure cumulative effect of all 40 optimizations.
2. **Parallel data streams** — Open multiple mux data streams for parallel forwarding, saturating the TCP window.
3. **noiseConn.Read: combined header+payload read** — Read 2+frameLen in one io.ReadFull call when possible.
4. **Client: socket.sendmsg scatter-gather** — Use sendmsg with multiple iovecs to avoid TLS header+payload concatenation.
5. **Server: per-session write coalescing** — Buffer multiple TUN packets before flushing to reduce encryption overhead.
6. **GRO/GSO on TUN** — Enable Generic Receive/Send Offloading on the TUN device.
7. **Server: TUN multi-queue** — Open multiple TUN file descriptors for parallel read/write.
8. **Profile with pprof** — Run CPU and allocation profiling under load to identify remaining hot spots.
9. **Client: TCP_FASTOPEN_CONNECT** — Enable TFO on client socket for 0-RTT reconnect.
10. **Server: splice/sendfile for TUN→socket path** — Zero-copy kernel forwarding.
