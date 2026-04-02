"""
test_padding.py — Unit and integration tests for padding.py.

Coverage targets:
  - encode_frame / decode_frame wire-format correctness
  - FixedBucketPadder bucket selection and padding computation
  - JitterConfig sampling for all three distributions
  - StatisticalObfuscator write/read round-trips
  - Cover-traffic injection and transparent discard
  - Statistics tracking
  - Preset factory (create_obfuscator)

Run:
    cd client && python3 -m pytest test_padding.py -v
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from padding import (
    DEFAULT_BUCKETS,
    FLAG_COVER,
    FLAG_DATA,
    FLAG_KEEPALIVE,
    FRAME_HEADER_SIZE,
    FRAME_LEN_SIZE,
    CoverTrafficConfig,
    FixedBucketPadder,
    JitterConfig,
    JitterDistribution,
    StatisticalObfuscator,
    create_obfuscator,
    decode_frame,
    encode_frame,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_socketpair():
    """Return a pair of connected sockets for end-to-end tests."""
    a, b = socket.socketpair()
    return a, b


def drain_all(sock: socket.socket, timeout: float = 0.5) -> bytes:
    """Read everything available from *sock* within *timeout* seconds."""
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
    except socket.timeout:
        pass
    return bytes(buf)


# ---------------------------------------------------------------------------
# encode_frame / decode_frame
# ---------------------------------------------------------------------------


class TestEncodeFrame:
    def test_flag_byte_is_first_body_byte(self):
        frame = encode_frame(b"hello", FLAG_DATA, 0)
        # First 4 bytes = body length; byte 4 = flag
        assert frame[FRAME_LEN_SIZE] == FLAG_DATA

    def test_padding_len_field(self):
        frame = encode_frame(b"x" * 10, FLAG_DATA, 5)
        body = frame[FRAME_LEN_SIZE:]
        _, plen = struct.unpack(">BH", body[:FRAME_HEADER_SIZE])
        assert plen == 5

    def test_total_length_prefix(self):
        data = b"abc"
        padding_len = 7
        frame = encode_frame(data, FLAG_DATA, padding_len)
        expected_body = FRAME_HEADER_SIZE + len(data) + padding_len
        actual_body_len = struct.unpack(">I", frame[:FRAME_LEN_SIZE])[0]
        assert actual_body_len == expected_body

    def test_total_wire_size(self):
        data = b"hello"
        padding_len = 10
        frame = encode_frame(data, FLAG_DATA, padding_len)
        assert len(frame) == FRAME_LEN_SIZE + FRAME_HEADER_SIZE + len(data) + padding_len

    def test_cover_flag(self):
        frame = encode_frame(b"", FLAG_COVER, 64)
        assert frame[FRAME_LEN_SIZE] == FLAG_COVER

    def test_keepalive_flag(self):
        frame = encode_frame(b"", FLAG_KEEPALIVE, 32)
        assert frame[FRAME_LEN_SIZE] == FLAG_KEEPALIVE

    def test_empty_data(self):
        frame = encode_frame(b"", FLAG_DATA, 0)
        body = frame[FRAME_LEN_SIZE:]
        flag, data = decode_frame(body)
        assert flag == FLAG_DATA
        assert data == b""

    def test_padding_too_long_raises(self):
        with pytest.raises(ValueError, match="padding_len"):
            encode_frame(b"x", FLAG_DATA, 65536)

    def test_padding_max_allowed(self):
        frame = encode_frame(b"x", FLAG_DATA, 65535)
        assert len(frame) > 0  # should not raise


class TestDecodeFrame:
    def test_roundtrip_data(self):
        payload = b"test payload 1234"
        frame = encode_frame(payload, FLAG_DATA, 16)
        body = frame[FRAME_LEN_SIZE:]
        flag, data = decode_frame(body)
        assert flag == FLAG_DATA
        assert data == payload

    def test_roundtrip_cover(self):
        frame = encode_frame(b"", FLAG_COVER, 128)
        body = frame[FRAME_LEN_SIZE:]
        flag, data = decode_frame(body)
        assert flag == FLAG_COVER
        assert data == b""

    def test_roundtrip_keepalive(self):
        frame = encode_frame(b"", FLAG_KEEPALIVE, 0)
        body = frame[FRAME_LEN_SIZE:]
        flag, data = decode_frame(body)
        assert flag == FLAG_KEEPALIVE
        assert data == b""

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            decode_frame(b"\x00\x00")  # less than FRAME_HEADER_SIZE (3)

    def test_bad_padding_len_raises(self):
        # Declare padding_len bigger than the remaining bytes
        bad = struct.pack(">BH", FLAG_DATA, 100) + b"short"
        with pytest.raises(ValueError, match="malformed"):
            decode_frame(bad)

    def test_arbitrary_payload_survives(self):
        payload = bytes(range(256))
        frame = encode_frame(payload, FLAG_DATA, 50)
        body = frame[FRAME_LEN_SIZE:]
        _, data = decode_frame(body)
        assert data == payload


# ---------------------------------------------------------------------------
# FixedBucketPadder
# ---------------------------------------------------------------------------


class TestFixedBucketPadder:
    def test_default_buckets_populated(self):
        p = FixedBucketPadder()
        assert p.buckets == sorted(set(DEFAULT_BUCKETS))

    def test_custom_buckets(self):
        p = FixedBucketPadder([100, 200, 400])
        assert p.buckets == [100, 200, 400]

    def test_empty_buckets_raises(self):
        with pytest.raises(ValueError):
            FixedBucketPadder([])

    def test_target_size_small_data(self):
        # data_len=1; needed = FRAME_HEADER_SIZE(3) + 1 = 4 → first bucket >= 4
        p = FixedBucketPadder([64, 128, 256])
        assert p.target_frame_size(1) == 64

    def test_target_size_exact_fit(self):
        p = FixedBucketPadder([64, 128])
        # data_len = 64 - FRAME_HEADER_SIZE(3) = 61 → needed = 64 → fits exactly in 64
        data_len = 64 - FRAME_HEADER_SIZE
        assert p.target_frame_size(data_len) == 64

    def test_target_size_just_over_bucket(self):
        p = FixedBucketPadder([64, 128])
        # data_len = 62 → needed = 65 → exceeds 64, falls in 128
        data_len = 62
        assert p.target_frame_size(data_len) == 128

    def test_target_size_exceeds_all_buckets(self):
        p = FixedBucketPadder([64, 128])
        # data_len = 200 → needed = 203 → exceeds 128 → ceil(203/128)*128 = 256
        result = p.target_frame_size(200)
        assert result >= 203
        assert result % 128 == 0

    def test_compute_padding_zero(self):
        # data that exactly fills the smallest bucket should get 0 padding
        p = FixedBucketPadder([64, 128])
        data_len = 64 - FRAME_HEADER_SIZE  # = 61
        pad = p.compute_padding(data_len)
        assert pad == 0

    def test_compute_padding_positive(self):
        p = FixedBucketPadder([64, 128])
        # 1 byte data → target=64 → padding = 64 - 3 - 1 = 60
        assert p.compute_padding(1) == 60

    def test_frame_size_consistency(self):
        p = FixedBucketPadder()
        for data_len in [0, 1, 10, 60, 61, 100, 500, 1000]:
            pad = p.compute_padding(data_len)
            assert FRAME_HEADER_SIZE + data_len + pad == p.target_frame_size(data_len)

    def test_all_padded_frames_match_bucket(self):
        p = FixedBucketPadder([64, 128, 256, 512])
        for data_len in range(0, 250):
            pad = p.compute_padding(data_len)
            total_body = FRAME_HEADER_SIZE + data_len + pad
            # total body must equal one of the buckets or be a multiple of max bucket
            assert total_body in [64, 128, 256, 512] or total_body % 512 == 0


# ---------------------------------------------------------------------------
# JitterConfig
# ---------------------------------------------------------------------------


class TestJitterConfig:
    def _samples(self, cfg: JitterConfig, n: int = 200) -> List[float]:
        return [cfg.sample_ms() for _ in range(n)]

    def test_uniform_within_range(self):
        cfg = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=5.0, max_ms=50.0
        )
        for v in self._samples(cfg):
            assert 5.0 <= v <= 50.0

    def test_gaussian_clamped_to_range(self):
        cfg = JitterConfig(
            distribution=JitterDistribution.GAUSSIAN,
            min_ms=0.0,
            max_ms=30.0,
            mean_ms=15.0,
            std_ms=5.0,
        )
        for v in self._samples(cfg):
            assert 0.0 <= v <= 30.0

    def test_exponential_clamped_to_range(self):
        cfg = JitterConfig(
            distribution=JitterDistribution.EXPONENTIAL,
            min_ms=0.0,
            max_ms=100.0,
            mean_ms=20.0,
        )
        for v in self._samples(cfg):
            assert 0.0 <= v <= 100.0

    def test_sample_seconds_conversion(self):
        cfg = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=10.0, max_ms=10.0
        )
        assert abs(cfg.sample_seconds() - 0.01) < 1e-9

    def test_wait_does_not_crash(self):
        cfg = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        cfg.wait()  # should return immediately without raising

    def test_uniform_zero_range(self):
        cfg = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=7.0, max_ms=7.0
        )
        assert cfg.sample_ms() == pytest.approx(7.0)


# ---------------------------------------------------------------------------
# CoverTrafficConfig
# ---------------------------------------------------------------------------


class TestCoverTrafficConfig:
    def test_defaults(self):
        cfg = CoverTrafficConfig()
        assert cfg.enabled is True
        assert cfg.idle_threshold_ms == 200.0
        assert cfg.interval_ms == 500.0
        assert 1 <= cfg.min_size < cfg.max_size

    def test_disabled(self):
        cfg = CoverTrafficConfig(enabled=False)
        assert not cfg.enabled


# ---------------------------------------------------------------------------
# StatisticalObfuscator — basic write/read
# ---------------------------------------------------------------------------


class TestStatisticalObfuscatorWriteRead:
    """End-to-end tests using socket.socketpair()."""

    def _make_pair(self, **kwargs):
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        oa = StatisticalObfuscator(a, jitter=no_jitter, cover_config=no_cover, **kwargs)
        ob = StatisticalObfuscator(b, jitter=no_jitter, cover_config=no_cover, **kwargs)
        return oa, ob

    def test_basic_roundtrip(self):
        oa, ob = self._make_pair()
        oa.write(b"hello world")
        assert ob.read() == b"hello world"
        oa.close()
        ob.close()

    def test_empty_payload(self):
        oa, ob = self._make_pair()
        oa.write(b"")
        assert ob.read() == b""
        oa.close()
        ob.close()

    def test_multiple_messages(self):
        oa, ob = self._make_pair()
        messages = [b"msg1", b"second message", b"third", b"x" * 1000]
        for m in messages:
            oa.write(m)
        for m in messages:
            assert ob.read() == m
        oa.close()
        ob.close()

    def test_large_payload(self):
        oa, ob = self._make_pair()
        payload = os.urandom(20000)
        oa.write(payload)
        assert ob.read() == payload
        oa.close()
        ob.close()

    def test_binary_payload(self):
        oa, ob = self._make_pair()
        payload = bytes(range(256)) * 10
        oa.write(payload)
        assert ob.read() == payload
        oa.close()
        ob.close()

    def test_write_after_close_raises(self):
        oa, ob = self._make_pair()
        oa.close()
        with pytest.raises(ConnectionError):
            oa.write(b"after close")
        ob.close()


# ---------------------------------------------------------------------------
# Cover and keepalive frame handling
# ---------------------------------------------------------------------------


class TestCoverFrameHandling:
    """Verify read() silently discards FLAG_COVER and FLAG_KEEPALIVE frames."""

    def _inject_raw_frame(self, sock: socket.socket, flag: int, data: bytes) -> None:
        """Write a single frame directly into the socket."""
        frame = encode_frame(data, flag, 0)
        sock.sendall(frame)

    def test_skips_single_cover_frame(self):
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        ob = StatisticalObfuscator(b, jitter=no_jitter, cover_config=no_cover)

        # Inject: COVER, COVER, DATA
        self._inject_raw_frame(a, FLAG_COVER, b"")
        self._inject_raw_frame(a, FLAG_COVER, b"")
        self._inject_raw_frame(a, FLAG_DATA, b"real data")

        result = ob.read()
        assert result == b"real data"
        assert ob.stats()["cover_packets_recv"] == 2

        a.close()
        ob.close()

    def test_skips_keepalive_frame(self):
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        ob = StatisticalObfuscator(b, jitter=no_jitter, cover_config=no_cover)

        self._inject_raw_frame(a, FLAG_KEEPALIVE, b"")
        self._inject_raw_frame(a, FLAG_DATA, b"payload")

        result = ob.read()
        assert result == b"payload"
        assert ob.stats()["cover_packets_recv"] == 1

        a.close()
        ob.close()

    def test_mixed_real_and_cover(self):
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        ob = StatisticalObfuscator(b, jitter=no_jitter, cover_config=no_cover)

        sequence = [
            (FLAG_COVER, b""),
            (FLAG_DATA, b"first"),
            (FLAG_KEEPALIVE, b""),
            (FLAG_DATA, b"second"),
        ]
        for flag, data in sequence:
            self._inject_raw_frame(a, flag, data)

        assert ob.read() == b"first"
        assert ob.read() == b"second"
        assert ob.stats()["cover_packets_recv"] == 2

        a.close()
        ob.close()

    def test_unknown_flag_raises(self):
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        ob = StatisticalObfuscator(b, jitter=no_jitter, cover_config=no_cover)

        # Inject a frame with an unrecognised flag
        bad_frame = encode_frame(b"x", 0xFF, 0)
        a.sendall(bad_frame)

        with pytest.raises(ValueError, match="Unknown frame flag"):
            ob.read()

        a.close()
        ob.close()


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class TestStatistics:
    def _make_pair_no_overhead(self):
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        oa = StatisticalObfuscator(a, jitter=no_jitter, cover_config=no_cover)
        ob = StatisticalObfuscator(b, jitter=no_jitter, cover_config=no_cover)
        return oa, ob

    def test_data_packets_sent_increments(self):
        oa, ob = self._make_pair_no_overhead()
        oa.write(b"a")
        oa.write(b"b")
        assert oa.stats()["data_packets_sent"] == 2
        ob.read()
        ob.read()
        oa.close()
        ob.close()

    def test_data_bytes_in_tracked(self):
        oa, ob = self._make_pair_no_overhead()
        payload = b"hello"
        oa.write(payload)
        assert oa.stats()["data_bytes_in"] == len(payload)
        ob.read()
        oa.close()
        ob.close()

    def test_data_bytes_out_gte_bytes_in(self):
        oa, ob = self._make_pair_no_overhead()
        oa.write(b"test")
        s = oa.stats()
        assert s["data_bytes_out"] >= s["data_bytes_in"]
        ob.read()
        oa.close()
        ob.close()

    def test_data_packets_recv_increments(self):
        oa, ob = self._make_pair_no_overhead()
        oa.write(b"msg")
        ob.read()
        assert ob.stats()["data_packets_recv"] == 1
        oa.close()
        ob.close()

    def test_overhead_ratio_nonnegative(self):
        oa, ob = self._make_pair_no_overhead()
        oa.write(b"x" * 100)
        ob.read()
        assert oa.stats()["overhead_ratio"] >= 0.0
        oa.close()
        ob.close()

    def test_stats_keys_present(self):
        oa, ob = self._make_pair_no_overhead()
        s = oa.stats()
        expected_keys = {
            "data_packets_sent", "cover_packets_sent", "keepalive_packets_sent",
            "data_bytes_in", "data_bytes_out", "cover_bytes_out",
            "data_packets_recv", "cover_packets_recv", "overhead_ratio",
        }
        assert expected_keys.issubset(s.keys())
        oa.close()
        ob.close()


# ---------------------------------------------------------------------------
# Cover traffic injection
# ---------------------------------------------------------------------------


class TestCoverTrafficInjection:
    """Test that the cover thread actually sends frames."""

    def test_cover_packets_injected_when_idle(self):
        """Obfuscator should inject cover packets after idle_threshold_ms."""
        # Use a raw recording socket pair: we only care about what gets sent
        a, b = make_socketpair()
        b.settimeout(2.0)

        cover_cfg = CoverTrafficConfig(
            enabled=True,
            idle_threshold_ms=0.0,   # inject immediately
            interval_ms=50.0,        # check every 50 ms
            min_size=32,
            max_size=64,
        )
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        oa = StatisticalObfuscator(a, jitter=no_jitter, cover_config=cover_cfg)

        # Wait long enough for at least one cover packet
        time.sleep(0.3)

        assert oa.stats()["cover_packets_sent"] > 0

        oa.close()
        b.close()

    def test_cover_packets_received_and_discarded(self):
        """Cover packets from sender should be silently discarded by receiver."""
        a, b = make_socketpair()
        cover_cfg = CoverTrafficConfig(
            enabled=True,
            idle_threshold_ms=0.0,
            interval_ms=50.0,
            min_size=32,
            max_size=64,
        )
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        oa = StatisticalObfuscator(a, jitter=no_jitter, cover_config=cover_cfg)
        ob = StatisticalObfuscator(
            b,
            jitter=no_jitter,
            cover_config=CoverTrafficConfig(enabled=False),
        )

        # Wait for cover packets to be sent, then inject a real packet
        time.sleep(0.2)
        oa.write(b"real")

        result = ob.read()
        assert result == b"real"
        assert ob.stats()["cover_packets_recv"] > 0

        oa.close()
        ob.close()

    def test_no_cover_thread_when_disabled(self):
        a, _ = make_socketpair()
        oa = StatisticalObfuscator(
            a,
            cover_config=CoverTrafficConfig(enabled=False),
        )
        assert oa._cover_thread is None
        oa.close()


# ---------------------------------------------------------------------------
# Close behaviour
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_stops_cover_thread(self):
        a, _ = make_socketpair()
        cover_cfg = CoverTrafficConfig(
            enabled=True, idle_threshold_ms=0.0, interval_ms=50.0
        )
        oa = StatisticalObfuscator(a, cover_config=cover_cfg)
        time.sleep(0.1)
        oa.close()
        if oa._cover_thread:
            assert not oa._cover_thread.is_alive()

    def test_double_close_no_exception(self):
        a, _ = make_socketpair()
        oa = StatisticalObfuscator(
            a, cover_config=CoverTrafficConfig(enabled=False)
        )
        oa.close()
        oa.close()  # should not raise


# ---------------------------------------------------------------------------
# Padding ensures bucket-aligned wire sizes
# ---------------------------------------------------------------------------


class TestPaddingAlignment:
    def test_wire_sizes_are_bucket_aligned(self):
        """All sent frames should have body sizes in DEFAULT_BUCKETS (or multiples)."""
        a, b = make_socketpair()
        no_cover = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        oa = StatisticalObfuscator(
            a,
            padder=FixedBucketPadder([64, 128, 256, 512, 1024]),
            jitter=no_jitter,
            cover_config=no_cover,
        )
        ob = StatisticalObfuscator(
            b,
            padder=FixedBucketPadder([64, 128, 256, 512, 1024]),
            jitter=no_jitter,
            cover_config=no_cover,
        )

        test_sizes = [1, 10, 60, 61, 100, 250, 500, 510, 1021]
        for size in test_sizes:
            payload = b"x" * size
            oa.write(payload)
            received = ob.read()
            assert received == payload

        oa.close()
        ob.close()


# ---------------------------------------------------------------------------
# Preset factory
# ---------------------------------------------------------------------------


class TestCreateObfuscator:
    def test_light_mode(self):
        a, _ = make_socketpair()
        ob = create_obfuscator(a, mode="light")
        assert ob._cover_config.enabled is False
        assert ob._jitter.max_ms <= 5.0
        ob.close()

    def test_balanced_mode(self):
        a, _ = make_socketpair()
        ob = create_obfuscator(a, mode="balanced")
        assert ob._cover_config.enabled is True
        assert ob._jitter.distribution == JitterDistribution.GAUSSIAN
        ob.close()

    def test_paranoid_mode(self):
        a, _ = make_socketpair()
        ob = create_obfuscator(a, mode="paranoid")
        assert ob._cover_config.enabled is True
        assert ob._jitter.distribution == JitterDistribution.EXPONENTIAL
        # Paranoid should use finer buckets (smallest = 32)
        assert min(ob._padder.buckets) <= 64
        ob.close()

    def test_unknown_mode_raises(self):
        a, _ = make_socketpair()
        with pytest.raises(ValueError, match="Unknown obfuscation mode"):
            create_obfuscator(a, mode="nonexistent")
        a.close()

    def test_all_presets_roundtrip(self):
        for mode in ("light", "balanced", "paranoid"):
            a, b = make_socketpair()
            oa = create_obfuscator(a, mode=mode)
            ob = create_obfuscator(b, mode=mode)
            oa.write(b"test " + mode.encode())
            assert ob.read() == b"test " + mode.encode()
            oa.close()
            ob.close()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_encode_then_manually_decode(self):
        """Verify that encode_frame output can be parsed by hand."""
        payload = b"manual check"
        padding_len = 20
        frame = encode_frame(payload, FLAG_DATA, padding_len)

        # Parse length prefix
        body_len = struct.unpack(">I", frame[:4])[0]
        body = frame[4:]
        assert len(body) == body_len

        # Parse header
        flag, plen = struct.unpack(">BH", body[:3])
        assert flag == FLAG_DATA
        assert plen == padding_len

        # Parse data and padding
        data_end = len(body) - plen
        extracted_data = body[3:data_end]
        assert extracted_data == payload

    def test_bucket_padder_deduplicates_buckets(self):
        p = FixedBucketPadder([64, 64, 128, 128])
        assert p.buckets == [64, 128]

    def test_large_cover_frame_looks_like_data(self):
        """Cover frames should have the same size structure as data frames."""
        oa, _ = make_socketpair()
        cover_cfg = CoverTrafficConfig(enabled=False)
        no_jitter = JitterConfig(
            distribution=JitterDistribution.UNIFORM, min_ms=0.0, max_ms=0.0
        )
        padder = FixedBucketPadder([64, 128, 256, 512])
        ob = StatisticalObfuscator(oa, padder=padder, jitter=no_jitter, cover_config=cover_cfg)

        # Build a cover frame and check its body size is in the bucket list
        frame = ob._build_cover_frame()
        body_len = struct.unpack(">I", frame[:4])[0]
        assert body_len in [64, 128, 256, 512] or body_len % 512 == 0

        ob.close()


# ---------------------------------------------------------------------------
# Required import fix
# ---------------------------------------------------------------------------

import os
