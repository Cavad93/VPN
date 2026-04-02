"""
test_traffic_shaping.py — Unit tests for traffic_shaping.py
"""

from __future__ import annotations

import os
import random
import struct
import threading
import time
from typing import List
from unittest.mock import MagicMock, patch, call

import pytest

from traffic_shaping import (
    PADDING_HEADER_SIZE,
    TrafficProfile,
    TrafficShaper,
    ShapedConn,
    SizeBucket,
    _sample_from_buckets,
    browser_profile,
    create_shaper,
    decode_chunk,
    encode_chunk,
    idle_profile,
    streaming_profile,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    size_buckets: List[SizeBucket] | None = None,
    min_inter_ms: float = 0.0,
    max_inter_ms: float = 0.0,
    burst_count: int = 4,
    burst_pause_min_ms: float = 0.0,
    burst_pause_max_ms: float = 0.0,
    padding_probability: float = 0.0,
    max_padding_bytes: int = 0,
) -> TrafficProfile:
    if size_buckets is None:
        size_buckets = [(100, 200, 1.0)]
    return TrafficProfile(
        name="test",
        size_buckets=size_buckets,
        min_inter_chunk_ms=min_inter_ms,
        max_inter_chunk_ms=max_inter_ms,
        burst_count=burst_count,
        burst_pause_min_ms=burst_pause_min_ms,
        burst_pause_max_ms=burst_pause_max_ms,
        padding_probability=padding_probability,
        max_padding_bytes=max_padding_bytes,
    )


# ---------------------------------------------------------------------------
# _sample_from_buckets
# ---------------------------------------------------------------------------


class TestSampleFromBuckets:
    def test_single_bucket(self):
        buckets = [(100, 200, 1.0)]
        for _ in range(50):
            v = _sample_from_buckets(buckets)
            assert 100 <= v <= 200

    def test_first_bucket_hit_when_r_low(self):
        buckets = [(10, 20, 0.50), (100, 200, 1.0)]
        # Patch random.random to return 0.1 — must land in bucket 0
        with patch("traffic_shaping.random.random", return_value=0.1):
            v = _sample_from_buckets(buckets)
        assert 10 <= v <= 20

    def test_second_bucket_hit_when_r_high(self):
        buckets = [(10, 20, 0.50), (100, 200, 1.0)]
        with patch("traffic_shaping.random.random", return_value=0.8):
            v = _sample_from_buckets(buckets)
        assert 100 <= v <= 200

    def test_boundary_probability(self):
        buckets = [(1, 1, 0.5), (2, 2, 1.0)]
        # r == 0.5 should still hit the first bucket
        with patch("traffic_shaping.random.random", return_value=0.5):
            v = _sample_from_buckets(buckets)
        assert v == 1

    def test_statistical_distribution(self):
        # With two equal buckets, roughly half should be in each
        buckets = [(1, 1, 0.5), (2, 2, 1.0)]
        ones = sum(1 for _ in range(1000) if _sample_from_buckets(buckets) == 1)
        assert 350 < ones < 650, f"Expected ~500 ones, got {ones}"


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------


class TestBuiltInProfiles:
    def test_browser_profile_returns_profile(self):
        p = browser_profile()
        assert p.name == "browser"
        assert len(p.size_buckets) > 0
        assert p.size_buckets[-1][2] == 1.0

    def test_streaming_profile_returns_profile(self):
        p = streaming_profile()
        assert p.name == "streaming"
        assert p.size_buckets[-1][2] == 1.0

    def test_idle_profile_returns_profile(self):
        p = idle_profile()
        assert p.name == "idle"

    def test_browser_sample_in_range(self):
        p = browser_profile()
        for _ in range(100):
            size = p.sample_chunk_size()
            assert 64 <= size <= 16383

    def test_streaming_sample_in_range(self):
        p = streaming_profile()
        for _ in range(100):
            size = p.sample_chunk_size()
            assert 512 <= size <= 16383

    def test_idle_sample_in_range(self):
        p = idle_profile()
        for _ in range(100):
            size = p.sample_chunk_size()
            assert 32 <= size <= 512


# ---------------------------------------------------------------------------
# TrafficProfile methods
# ---------------------------------------------------------------------------


class TestTrafficProfile:
    def test_sample_inter_chunk_delay_range(self):
        p = _make_profile(min_inter_ms=10.0, max_inter_ms=20.0)
        for _ in range(50):
            d = p.sample_inter_chunk_delay()
            assert 0.010 <= d <= 0.021

    def test_sample_burst_pause_range(self):
        p = _make_profile(burst_pause_min_ms=100.0, burst_pause_max_ms=200.0)
        for _ in range(50):
            d = p.sample_burst_pause()
            assert 0.100 <= d <= 0.201

    def test_sample_padding_returns_bytes(self):
        p = _make_profile(padding_probability=1.0, max_padding_bytes=16)
        pad = p.sample_padding()
        assert isinstance(pad, bytes)
        assert 1 <= len(pad) <= 16

    def test_sample_padding_zero_probability(self):
        p = _make_profile(padding_probability=0.0)
        for _ in range(20):
            pad = p.sample_padding()
            assert pad == b""

    def test_sample_padding_full_probability(self):
        p = _make_profile(padding_probability=1.0, max_padding_bytes=8)
        for _ in range(20):
            pad = p.sample_padding()
            assert len(pad) >= 1


# ---------------------------------------------------------------------------
# encode_chunk / decode_chunk
# ---------------------------------------------------------------------------


class TestEncodeDecodeChunk:
    def test_round_trip_no_padding(self):
        data = b"hello world"
        encoded = encode_chunk(data, b"")
        assert decode_chunk(encoded) == data

    def test_round_trip_with_padding(self):
        data = b"secret payload"
        padding = b"\x00" * 32
        encoded = encode_chunk(data, padding)
        assert decode_chunk(encoded) == data

    def test_encoded_length(self):
        data = b"abc"
        padding = b"pad"
        encoded = encode_chunk(data, padding)
        assert len(encoded) == PADDING_HEADER_SIZE + len(data) + len(padding)

    def test_padding_header_value(self):
        data = b"x"
        padding = b"\xff" * 10
        encoded = encode_chunk(data, padding)
        pad_len = struct.unpack(">H", encoded[:PADDING_HEADER_SIZE])[0]
        assert pad_len == 10

    def test_empty_data_no_padding(self):
        encoded = encode_chunk(b"", b"")
        assert decode_chunk(encoded) == b""

    def test_empty_data_with_padding(self):
        encoded = encode_chunk(b"", b"XXXX")
        assert decode_chunk(encoded) == b""

    def test_decode_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            decode_chunk(b"\x00")

    def test_decode_malformed_padding_len_raises(self):
        # Claim 100 bytes of padding but provide only 2 bytes total
        bad = struct.pack(">H", 100) + b"ab"
        with pytest.raises(ValueError, match="malformed"):
            decode_chunk(bad)

    def test_encode_padding_too_long_raises(self):
        with pytest.raises(ValueError, match="Padding too long"):
            encode_chunk(b"data", b"x" * 70000)

    def test_random_data_round_trip(self):
        for _ in range(20):
            data = os.urandom(random.randint(0, 1024))
            padding = os.urandom(random.randint(0, 64))
            encoded = encode_chunk(data, padding)
            assert decode_chunk(encoded) == data


# ---------------------------------------------------------------------------
# TrafficShaper.fragment
# ---------------------------------------------------------------------------


class TestTrafficShaperFragment:
    def test_fragment_empty(self):
        shaper = TrafficShaper(_make_profile())
        assert shaper.fragment(b"") == []

    def test_fragment_smaller_than_target(self):
        # Bucket forces size >= 100; payload is 10 bytes → single chunk
        shaper = TrafficShaper(_make_profile(size_buckets=[(100, 200, 1.0)]))
        chunks = shaper.fragment(b"x" * 10)
        assert chunks == [b"x" * 10]

    def test_fragment_exact_target(self):
        # Force bucket exactly 100 bytes
        with patch("traffic_shaping.random.randint", return_value=100):
            shaper = TrafficShaper(_make_profile(size_buckets=[(100, 100, 1.0)]))
            data = b"a" * 100
            chunks = shaper.fragment(data)
        assert len(chunks) == 1
        assert b"".join(chunks) == data

    def test_fragment_multiple_chunks(self):
        # Force small bucket (10 bytes), send 35 bytes → 4 chunks
        with patch("traffic_shaping.random.randint", return_value=10):
            shaper = TrafficShaper(_make_profile(size_buckets=[(10, 10, 1.0)]))
            data = bytes(range(35))
            chunks = shaper.fragment(data)
        assert b"".join(chunks) == data
        assert len(chunks) == 4  # 10+10+10+5

    def test_fragment_reassembles_exactly(self):
        shaper = TrafficShaper(browser_profile())
        data = os.urandom(50_000)
        chunks = shaper.fragment(data)
        assert b"".join(chunks) == data
        assert len(chunks) > 1


# ---------------------------------------------------------------------------
# TrafficShaper.shape_outgoing
# ---------------------------------------------------------------------------


class TestTrafficShaperShapeOutgoing:
    def _no_pad_profile(self) -> TrafficProfile:
        return _make_profile(
            size_buckets=[(10, 10, 1.0)],
            padding_probability=0.0,
            max_padding_bytes=0,
        )

    def test_output_decodable(self):
        # With padding_probability=0, each encoded chunk has 0 padding bytes.
        shaper = TrafficShaper(self._no_pad_profile())
        data = b"hello world!"
        encoded_chunks = shaper.shape_outgoing(data)
        decoded_parts = []
        for ec in encoded_chunks:
            # padding_len header + data + 0 padding bytes
            pad_len = struct.unpack(">H", ec[:PADDING_HEADER_SIZE])[0]
            assert pad_len == 0
            decoded_parts.append(ec[PADDING_HEADER_SIZE:])
        assert b"".join(decoded_parts) == data

    def test_stats_updated(self):
        shaper = TrafficShaper(self._no_pad_profile())
        shaper.shape_outgoing(b"x" * 50)
        stats = shaper.stats()
        assert stats["total_bytes_in"] == 50
        assert stats["total_bytes_out"] >= 50
        assert stats["total_chunks"] > 0

    def test_empty_input(self):
        shaper = TrafficShaper(self._no_pad_profile())
        encoded = shaper.shape_outgoing(b"")
        assert encoded == []

    def test_overhead_with_padding(self):
        profile = _make_profile(
            size_buckets=[(1000, 1000, 1.0)],
            padding_probability=1.0,
            max_padding_bytes=32,
        )
        shaper = TrafficShaper(profile)
        data = b"x" * 3000
        encoded = shaper.shape_outgoing(data)
        stats = shaper.stats()
        assert stats["overhead_bytes"] > 0


# ---------------------------------------------------------------------------
# TrafficShaper timing / burst
# ---------------------------------------------------------------------------


class TestTrafficShaperTiming:
    def test_inter_chunk_delay_no_sleep(self):
        # Zero-delay profile — should return 0 immediately
        profile = _make_profile(
            min_inter_ms=0.0,
            max_inter_ms=0.0,
            burst_count=100,
            burst_pause_min_ms=0.0,
            burst_pause_max_ms=0.0,
        )
        shaper = TrafficShaper(profile)
        for _ in range(10):
            assert shaper.inter_chunk_delay() == pytest.approx(0.0, abs=0.001)

    def test_burst_pause_after_burst_count(self):
        profile = _make_profile(
            min_inter_ms=1.0,
            max_inter_ms=1.0,
            burst_count=3,
            burst_pause_min_ms=500.0,
            burst_pause_max_ms=500.0,
        )
        shaper = TrafficShaper(profile)
        delays = [shaper.inter_chunk_delay() for _ in range(4)]
        # Chunks 1 and 2: inter-chunk delay (0.001s each)
        assert delays[0] == pytest.approx(0.001, abs=0.0001)
        assert delays[1] == pytest.approx(0.001, abs=0.0001)
        # 3rd chunk hits burst_count=3, triggers burst pause (0.5s) and resets
        assert delays[2] == pytest.approx(0.5, abs=0.0001)
        # 4th chunk starts a new burst — inter-chunk delay again
        assert delays[3] == pytest.approx(0.001, abs=0.0001)

    def test_reset_burst_resets_counter(self):
        profile = _make_profile(
            min_inter_ms=1.0,
            max_inter_ms=1.0,
            burst_count=2,
            burst_pause_min_ms=500.0,
            burst_pause_max_ms=500.0,
        )
        shaper = TrafficShaper(profile)
        shaper.inter_chunk_delay()  # chunk 1
        shaper.reset_burst()
        d = shaper.inter_chunk_delay()  # should be inter-chunk not burst pause
        assert d == pytest.approx(0.001, abs=0.0001)

    def test_wait_inter_chunk_calls_sleep(self):
        profile = _make_profile(
            min_inter_ms=10.0,
            max_inter_ms=10.0,
            burst_count=100,
        )
        shaper = TrafficShaper(profile)
        with patch("traffic_shaping.time.sleep") as mock_sleep:
            shaper.wait_inter_chunk()
        mock_sleep.assert_called_once()
        args = mock_sleep.call_args[0]
        assert args[0] == pytest.approx(0.010, abs=0.001)


# ---------------------------------------------------------------------------
# TrafficShaper thread-safety
# ---------------------------------------------------------------------------


class TestTrafficShaperThreadSafety:
    def test_concurrent_shape_outgoing(self):
        shaper = TrafficShaper(browser_profile())
        errors = []
        results = []

        def worker():
            try:
                encoded = shaper.shape_outgoing(os.urandom(4096))
                results.append(encoded)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors in threads: {errors}"
        assert len(results) == 10


# ---------------------------------------------------------------------------
# create_shaper factory
# ---------------------------------------------------------------------------


class TestCreateShaper:
    def test_browser(self):
        s = create_shaper("browser")
        assert s.profile.name == "browser"

    def test_streaming(self):
        s = create_shaper("streaming")
        assert s.profile.name == "streaming"

    def test_idle(self):
        s = create_shaper("idle")
        assert s.profile.name == "idle"

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            create_shaper("unknown_xyz")

    def test_default_is_browser(self):
        s = create_shaper()
        assert s.profile.name == "browser"


# ---------------------------------------------------------------------------
# ShapedConn
# ---------------------------------------------------------------------------


class _FakeSocket:
    """In-memory duplex socket for testing ShapedConn."""

    def __init__(self):
        self._buf = bytearray()
        self._closed = False

    def send(self, data: bytes) -> int:
        self._buf.extend(data)
        return len(data)

    def recv(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def close(self):
        self._closed = True


class TestShapedConn:
    def _make_conn(self, **kwargs) -> tuple[ShapedConn, _FakeSocket]:
        sock = _FakeSocket()
        profile = _make_profile(
            size_buckets=[(50, 50, 1.0)],
            padding_probability=0.0,
        )
        conn = ShapedConn(sock, profile, apply_timing=False, **kwargs)
        return conn, sock

    def test_write_sends_bytes(self):
        conn, sock = self._make_conn()
        conn.write(b"hello")
        assert len(sock._buf) > 0

    def test_write_returns_input_length(self):
        conn, sock = self._make_conn()
        n = conn.write(b"hello world")
        assert n == 11

    def test_write_includes_padding_header(self):
        conn, sock = self._make_conn()
        conn.write(b"data")
        # First two bytes of wire buffer should be the padding_len header
        assert len(sock._buf) >= PADDING_HEADER_SIZE
        pad_len = struct.unpack(">H", bytes(sock._buf[:PADDING_HEADER_SIZE]))[0]
        assert pad_len == 0  # padding_probability=0.0

    def test_close_closes_underlying(self):
        conn, sock = self._make_conn()
        conn.close()
        assert sock._closed

    def test_shaper_accessible(self):
        conn, sock = self._make_conn()
        assert isinstance(conn.shaper, TrafficShaper)

    def test_write_empty_data(self):
        conn, sock = self._make_conn()
        n = conn.write(b"")
        assert n == 0
        assert len(sock._buf) == 0

    def test_write_large_data_fragmented(self):
        # Force 10-byte chunks
        sock = _FakeSocket()
        profile = _make_profile(
            size_buckets=[(10, 10, 1.0)],
            padding_probability=0.0,
        )
        conn = ShapedConn(sock, profile, apply_timing=False)
        data = b"x" * 35
        conn.write(data)
        # 4 chunks × (2 header + data_size) = 4 × (2+10) + 1 × (2+5) = 55 bytes
        # 10+10+10+5 → 3×12 + 1×7 = 43 bytes
        assert len(sock._buf) == 43

    def test_read_strips_padding(self):
        # Manually write a shaped chunk into a fake socket and read it back
        sock = _FakeSocket()
        # Write shaped data: 5 bytes data + 3 bytes padding
        data = b"hello"
        padding = b"XYZ"
        wire = encode_chunk(data, padding)
        sock._buf.extend(wire)

        profile = _make_profile(padding_probability=0.0)
        conn = ShapedConn(sock, profile, apply_timing=False)
        result = conn.read(max_size=len(data))
        assert result == data

    def test_read_zero_padding(self):
        sock = _FakeSocket()
        data = b"no padding here"
        wire = encode_chunk(data, b"")
        sock._buf.extend(wire)

        profile = _make_profile(padding_probability=0.0)
        conn = ShapedConn(sock, profile, apply_timing=False)
        result = conn.read(max_size=len(data))
        assert result == data

    def test_connection_error_on_empty_recv(self):
        class ClosedSocket:
            def send(self, data):
                return 0

            def recv(self, n):
                return b""

        profile = _make_profile(padding_probability=0.0)
        conn = ShapedConn(ClosedSocket(), profile, apply_timing=False)
        with pytest.raises(ConnectionError):
            conn.read(max_size=4)

    def test_connection_error_on_zero_send(self):
        class ClosedSocket:
            def send(self, data):
                return 0

            def recv(self, n):
                return b""

        profile = _make_profile(padding_probability=0.0)
        conn = ShapedConn(ClosedSocket(), profile, apply_timing=False)
        with pytest.raises(ConnectionError):
            conn.write(b"test")

    def test_timing_applied_between_chunks(self):
        sock = _FakeSocket()
        profile = _make_profile(
            size_buckets=[(5, 5, 1.0)],
            min_inter_ms=50.0,
            max_inter_ms=50.0,
            burst_count=100,
            padding_probability=0.0,
        )
        conn = ShapedConn(sock, profile, apply_timing=True)
        with patch("traffic_shaping.time.sleep") as mock_sleep:
            conn.write(b"x" * 15)  # 3 chunks of 5 bytes
        # sleep called between chunks 1→2 and 2→3 (not after last)
        assert mock_sleep.call_count == 2
