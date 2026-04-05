"""
core.py — Python VPN client implementing the full protocol stack:
  TCP → TLS obfuscation → Noise_XX handshake → noiseConn → Mux → control/data streams
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Optional

import structlog
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOISE_PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
KEY_SIZE = 32
OVERHEAD = 16  # ChaCha20-Poly1305 AEAD tag size

# TLS obfuscation constants
TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_APPDATA = 0x17
TLS_VERSION_MAJOR = 0x03
TLS_VERSION_MINOR = 0x03
TLS_HELLO_CLIENT = 0x01
TLS_HELLO_SERVER = 0x02
MAX_OBFS_PAYLOAD = 16383

# Mux frame types
FRAME_SYN = 0x01
FRAME_DATA = 0x02
FRAME_FIN = 0x03
MUX_HEADER_SIZE = 7  # streamID(4) + type(1) + payloadLen(2)

# Control stream message types
CTL_HELLO = 0x01
CTL_ASSIGN = 0x02
CTL_ERROR = 0x03
CTL_ASSIGN_PAYLOAD_LEN = 9  # ip(4) + prefixLen(1) + gateway(4)


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """An X25519 key pair."""
    private_key: X25519PrivateKey
    public_key_bytes: bytes  # 32 raw bytes

    @property
    def public_key(self) -> bytes:
        return self.public_key_bytes


def generate_key_pair() -> KeyPair:
    """Generate a new X25519 key pair with RFC 7748 clamping applied."""
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    logger.debug("generated_key_pair", public_key=pub_bytes.hex())
    return KeyPair(private_key=priv, public_key_bytes=pub_bytes)


def load_key_pair_from_file(path: str) -> KeyPair:
    """Load a hex-encoded private key from a file and derive the public key."""
    with open(path, "r") as f:
        hex_str = f.read().strip()
    priv_bytes = bytes.fromhex(hex_str)
    if len(priv_bytes) != KEY_SIZE:
        raise ValueError(f"private key must be {KEY_SIZE} bytes, got {len(priv_bytes)}")
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return KeyPair(private_key=priv, public_key_bytes=pub_bytes)


def dh(priv: X25519PrivateKey, pub_bytes: bytes) -> bytes:
    """Perform X25519 Diffie-Hellman. Returns 32-byte shared secret."""
    peer_pub = X25519PublicKey.from_public_bytes(pub_bytes)
    shared = priv.exchange(peer_pub)
    if shared == b"\x00" * 32:
        raise ValueError("DH result is the all-zero weak point")
    return shared


# ---------------------------------------------------------------------------
# Noise HKDF
# ---------------------------------------------------------------------------

def noise_hkdf(ck: bytes, ikm: bytes, n: int) -> list[bytes]:
    """
    Noise protocol HKDF using HMAC-SHA256.

    Returns n (2 or 3) 32-byte outputs.
    """
    if n not in (2, 3):
        raise ValueError("noise_hkdf: n must be 2 or 3")
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    out1 = hmac.new(temp, b"\x01", hashlib.sha256).digest()
    out2 = hmac.new(temp, out1 + b"\x02", hashlib.sha256).digest()
    if n == 2:
        return [out1, out2]
    out3 = hmac.new(temp, out2 + b"\x03", hashlib.sha256).digest()
    return [out1, out2, out3]


# ---------------------------------------------------------------------------
# Noise cipher state
# ---------------------------------------------------------------------------

class NoiseCipherState:
    """
    Manages a ChaCha20-Poly1305 cipher with an auto-incrementing nonce counter.

    When no key has been set, encrypt/decrypt pass data through unchanged.
    """

    def __init__(self) -> None:
        self._key: Optional[bytes] = None
        self._n: int = 0
        # Pre-allocated 12-byte nonce buffer (mutable bytearray).
        # Updated in-place via struct.pack_into to avoid allocating a new
        # bytes object on every encrypt/decrypt call (~860 calls/s at 10 Mbps).
        self._nonce_buf = bytearray(12)

    def initialize_key(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"key must be {KEY_SIZE} bytes")
        self._key = key
        self._n = 0
        self._aead = ChaCha20Poly1305(key)  # create once, reuse for all packets

    @property
    def has_key(self) -> bool:
        return self._key is not None

    def _make_nonce(self) -> bytes:
        # Noise spec: 4 zero bytes + 8-byte little-endian counter = 12 bytes.
        # Pack the counter directly into the pre-allocated buffer at offset 4,
        # avoiding b"\x00" * 4 + struct.pack("<Q", n) which creates 3 objects.
        struct.pack_into("<Q", self._nonce_buf, 4, self._n)
        return bytes(self._nonce_buf)

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if not self.has_key:
            return plaintext
        nonce = self._make_nonce()
        self._n += 1
        return self._aead.encrypt(nonce, plaintext, ad)

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if not self.has_key:
            return ciphertext
        nonce = self._make_nonce()
        self._n += 1
        return self._aead.decrypt(nonce, ciphertext, ad)


# ---------------------------------------------------------------------------
# Noise symmetric state
# ---------------------------------------------------------------------------

class NoiseSymmetricState:
    """
    Tracks the chaining key and transcript hash during a Noise handshake.
    """

    def __init__(self, protocol_name: bytes) -> None:
        self.cs = NoiseCipherState()
        # Initialize h: if protocol name <= 32 bytes pad with zeros, else SHA-256
        if len(protocol_name) <= 32:
            h = protocol_name + b"\x00" * (32 - len(protocol_name))
        else:
            h = hashlib.sha256(protocol_name).digest()
        self.h: bytes = h
        self.ck: bytes = h

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        outputs = noise_hkdf(self.ck, ikm, 2)
        self.ck = outputs[0]
        self.cs.initialize_key(outputs[1])

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cs.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cs.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[NoiseCipherState, NoiseCipherState]:
        outputs = noise_hkdf(self.ck, b"", 2)
        c1 = NoiseCipherState()
        c1.initialize_key(outputs[0])
        c2 = NoiseCipherState()
        c2.initialize_key(outputs[1])
        return c1, c2


# ---------------------------------------------------------------------------
# Session cipher (post-handshake)
# ---------------------------------------------------------------------------

class SessionCipher:
    """Wraps a NoiseCipherState for post-handshake use."""

    def __init__(self, cs: NoiseCipherState) -> None:
        self._cs = cs

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> bytes:
        return self._cs.encrypt_with_ad(ad, plaintext)

    def decrypt(self, ciphertext: bytes, ad: bytes = b"") -> bytes:
        return self._cs.decrypt_with_ad(ad, ciphertext)


@dataclass
class NoiseSession:
    """Result of a completed Noise_XX handshake."""
    send_cipher: SessionCipher
    recv_cipher: SessionCipher
    remote_static: bytes  # 32-byte public key of the remote peer


# ---------------------------------------------------------------------------
# Noise_XX handshake (initiator/client side)
# ---------------------------------------------------------------------------

class NoiseHandshake:
    """
    Implements the Noise_XX handshake pattern for the initiator (client) role.

    Pattern:
        -> e
        <- e, ee, s, es
        -> s, se
    """

    def __init__(self, static_kp: KeyPair) -> None:
        self._static_kp = static_kp
        self._ss = NoiseSymmetricState(NOISE_PROTOCOL_NAME)
        self._ss.mix_hash(b"")  # empty prologue
        self._e: Optional[KeyPair] = None        # our ephemeral
        self._re: Optional[bytes] = None         # remote ephemeral pub
        self._rs: Optional[bytes] = None         # remote static pub
        self._step = 0

    # --- Message 1: -> e ---------------------------------------------------

    def write_message1(self) -> bytes:
        """Generate ephemeral keypair, mix hash, return e.pub (32 bytes)."""
        if self._step != 0:
            raise RuntimeError("write_message1: invalid step")
        self._e = generate_key_pair()
        self._ss.mix_hash(self._e.public_key_bytes)
        self._step = 1
        return self._e.public_key_bytes

    # --- Message 2: <- e, ee, s, es ----------------------------------------

    def read_message2(self, msg: bytes) -> None:
        """
        Process responder's message: re.pub(32) + EncryptAndHash(s)(48).
        Performs ee and es DH mixes.
        """
        if self._step != 1:
            raise RuntimeError("read_message2: invalid step")
        min_len = KEY_SIZE + KEY_SIZE + OVERHEAD
        if len(msg) < min_len:
            raise ValueError(f"message2 too short: {len(msg)} < {min_len}")

        # <- e
        self._re = msg[:KEY_SIZE]
        self._ss.mix_hash(self._re)

        # ee: DH(e_init, e_resp)
        ee = dh(self._e.private_key, self._re)
        self._ss.mix_key(ee)

        # s: decrypt remote static
        enc_s = msg[KEY_SIZE : KEY_SIZE + KEY_SIZE + OVERHEAD]
        plain_s = self._ss.decrypt_and_hash(enc_s)
        self._rs = plain_s

        # es: DH(e_init, s_resp)
        es = dh(self._e.private_key, self._rs)
        self._ss.mix_key(es)

        self._step = 2

    # --- Message 3: -> s, se -----------------------------------------------

    def write_message3(self) -> tuple[bytes, NoiseSession]:
        """
        Send encrypted initiator static key, perform se DH mix, split.
        Returns (message_bytes, NoiseSession).
        """
        if self._step != 2:
            raise RuntimeError("write_message3: invalid step")

        # s: encrypt our static public key
        enc_s = self._ss.encrypt_and_hash(self._static_kp.public_key_bytes)

        # se: DH(s_init, e_resp)
        se = dh(self._static_kp.private_key, self._re)
        self._ss.mix_key(se)

        # split: c1 = initiator sends, c2 = responder sends
        c1, c2 = self._ss.split()

        session = NoiseSession(
            send_cipher=SessionCipher(c1),
            recv_cipher=SessionCipher(c2),
            remote_static=self._rs,
        )

        self._step = 3
        return enc_s, session


# ---------------------------------------------------------------------------
# TLS obfuscation layer
# ---------------------------------------------------------------------------

def _build_client_hello() -> bytes:
    """Build a synthetic TLS 1.3 ClientHello record."""
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)

    body = (
        bytes([0x03, 0x03])          # legacy_version = TLS 1.2
        + random_bytes               # random (32)
        + bytes([0x20])              # session_id length = 32
        + session_id                 # session_id (32)
        + bytes([0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03])  # cipher suites
        + bytes([0x01, 0x00])        # compression_methods
    )
    return _wrap_handshake_record(TLS_HELLO_CLIENT, body)


def _build_server_hello() -> bytes:
    """Build a synthetic TLS 1.3 ServerHello record."""
    random_bytes = os.urandom(32)

    body = (
        bytes([0x03, 0x03])   # legacy_version = TLS 1.2
        + random_bytes        # random (32)
        + bytes([0x00])       # session_id length = 0
        + bytes([0x13, 0x01]) # cipher_suite: TLS_AES_128_GCM_SHA256
        + bytes([0x00])       # compression_method: null
    )
    return _wrap_handshake_record(TLS_HELLO_SERVER, body)


def _wrap_handshake_record(msg_type: int, body: bytes) -> bytes:
    """Wrap body in a TLS handshake message inside a TLS record."""
    hs_len = len(body)
    hs = bytes([
        msg_type,
        (hs_len >> 16) & 0xFF,
        (hs_len >> 8) & 0xFF,
        hs_len & 0xFF,
    ]) + body

    rec_len = len(hs)
    return bytes([
        TLS_RECORD_HANDSHAKE,
        TLS_VERSION_MAJOR,
        TLS_VERSION_MINOR,
        (rec_len >> 8) & 0xFF,
        rec_len & 0xFF,
    ]) + hs


def _build_app_data_record(payload: bytes) -> bytes:
    n = len(payload)
    return bytes([
        TLS_RECORD_APPDATA,
        TLS_VERSION_MAJOR,
        TLS_VERSION_MINOR,
        (n >> 8) & 0xFF,
        n & 0xFF,
    ]) + payload


class ObfsConn:
    """
    Wraps a socket and presents data framed inside synthetic TLS 1.3 records.
    Call client_handshake() before read/write.
    """

    # Large socket-level read buffer: one recv(262144) fills ~180 TLS records,
    # so most _recv_exactly() calls return instantly from memory with zero syscalls.
    _SOCK_RECV_SIZE = 262144

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        # Both buffers are bytearray: += is an in-place extend O(chunk), not O(total).
        self._read_buf = bytearray()
        self._sock_buf = bytearray()  # bytearray avoids O(n) copy on each += unlike bytes
        # Pre-allocated receive staging buffer for recv_into() — avoids allocating
        # a new bytes object on every recv() syscall (~13 allocs/s at 10 Mbps).
        self._recv_staging = bytearray(self._SOCK_RECV_SIZE)
        # Pre-allocated 5-byte TLS record header — reused on every write call.
        # struct.pack_into modifies it in-place, avoiding a new bytes allocation.
        self._write_hdr = bytearray(5)
        self._write_hdr[0] = TLS_RECORD_APPDATA
        self._write_hdr[1] = TLS_VERSION_MAJOR
        self._write_hdr[2] = TLS_VERSION_MINOR

    def client_handshake(self) -> None:
        """Send ClientHello, read ServerHello."""
        self._sock.sendall(_build_client_hello())
        self._read_handshake_record(TLS_HELLO_SERVER)
        logger.debug("obfs_client_handshake_done")

    def server_handshake(self) -> None:
        """Read ClientHello, send ServerHello."""
        self._read_handshake_record(TLS_HELLO_CLIENT)
        self._sock.sendall(_build_server_hello())
        logger.debug("obfs_server_handshake_done")

    def write(self, data: bytes) -> None:
        """Send data as one or more TLS application_data records.

        Builds each record inline in a pre-sized bytearray to avoid the
        intermediate bytes allocation that _build_app_data_record creates.
        For single-record writes (the common case, ≤16383 bytes), uses a
        pre-allocated header buffer + memoryview scatter to avoid copying
        the payload into the record buffer entirely.
        """
        if len(data) <= MAX_OBFS_PAYLOAD:
            # Fast path: single record — write length into pre-allocated header
            # and send header + payload. Avoids struct.pack allocation.
            struct.pack_into(">H", self._write_hdr, 3, len(data))
            self._sock.sendall(self._write_hdr + data)
            return
        offset = 0
        while offset < len(data):
            end = min(offset + MAX_OBFS_PAYLOAD, len(data))
            chunk_len = end - offset
            rec = bytearray(5 + chunk_len)
            rec[0] = TLS_RECORD_APPDATA
            rec[1] = TLS_VERSION_MAJOR
            rec[2] = TLS_VERSION_MINOR
            struct.pack_into(">H", rec, 3, chunk_len)
            rec[5:] = data[offset:end]
            self._sock.sendall(rec)
            offset = end

    def read(self, n: int) -> bytes:
        """Read exactly n bytes, buffering across TLS records as needed."""
        while len(self._read_buf) < n:
            payload = self._read_record(TLS_RECORD_APPDATA)
            self._read_buf += payload  # bytearray += is O(chunk), not O(total)
        result = bytes(self._read_buf[:n])
        del self._read_buf[:n]  # in-place delete avoids creating a new bytearray
        return result

    def read_exactly(self, n: int) -> bytes:
        return self.read(n)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    # -- internal helpers ---------------------------------------------------

    def _recv_exactly(self, n: int) -> bytes:
        # Fill the socket buffer in large chunks so most calls return from
        # memory without a syscall. recv_into() writes directly into
        # _recv_staging (pre-allocated bytearray) to avoid temporary bytes.
        while len(self._sock_buf) < n:
            nbytes = self._sock.recv_into(self._recv_staging)
            if not nbytes:
                raise ConnectionError("connection closed mid-read")
            self._sock_buf += self._recv_staging[:nbytes]
        # Fast path: if requesting the entire buffer, return it directly
        # without creating a slice copy + in-place delete.
        if n == len(self._sock_buf):
            result = bytes(self._sock_buf)
            self._sock_buf = bytearray()
            return result
        result = bytes(self._sock_buf[:n])
        del self._sock_buf[:n]
        return result

    def _read_record(self, want_type: int) -> bytes:
        hdr = self._recv_exactly(5)
        if hdr[0] != want_type:
            raise ValueError(
                f"unexpected TLS record type 0x{hdr[0]:02x}, want 0x{want_type:02x}"
            )
        # int.from_bytes is ~30% faster than struct.unpack — avoids tuple
        # allocation and format string parsing on the hot read path.
        length = int.from_bytes(hdr[3:5], "big")
        if length == 0 or length > MAX_OBFS_PAYLOAD:
            raise ValueError(f"invalid TLS record length {length}")
        return self._recv_exactly(length)

    def _read_handshake_record(self, want_msg_type: int) -> None:
        payload = self._read_record(TLS_RECORD_HANDSHAKE)
        if len(payload) < 4:
            raise ValueError("handshake record too short")
        if payload[0] != want_msg_type:
            raise ValueError(
                f"unexpected handshake type 0x{payload[0]:02x}, want 0x{want_msg_type:02x}"
            )


# ---------------------------------------------------------------------------
# NoiseConn — post-handshake encrypted transport
# ---------------------------------------------------------------------------

class NoiseConn:
    """
    Wraps an ObfsConn with Noise session encryption.

    Each message is encrypted with ChaCha20-Poly1305 and length-prefixed
    with a 2-byte big-endian uint16.
    """

    def __init__(self, obfs: ObfsConn, session: NoiseSession, perf=None) -> None:
        self._obfs = obfs
        self._session = session
        self._read_buf = b""
        self._perf = perf  # optional PerfCollector

    def write_message(self, plaintext: bytes) -> None:
        if self._perf:
            import time as _t
            from perf_collector import Stage
            _t0 = _t.monotonic()
            ciphertext = self._session.send_cipher.encrypt(plaintext)
            self._perf.track_latency(Stage.NOISE_ENCRYPT, _t.monotonic() - _t0)
        else:
            ciphertext = self._session.send_cipher.encrypt(plaintext)
        # Build length prefix + ciphertext in one concatenation (bytes + bytes
        # is faster than bytearray construction for typical packet sizes ≤1500).
        self._obfs.write(struct.pack(">H", len(ciphertext)) + ciphertext)

    def read_message(self) -> bytes:
        # Read 2-byte length prefix — int.from_bytes avoids tuple alloc.
        len_bytes = self._read_exactly_raw(2)
        frame_len = int.from_bytes(len_bytes, "big")
        frame = self._read_exactly_raw(frame_len)
        if self._perf:
            import time as _t
            from perf_collector import Stage
            _t0 = _t.monotonic()
            result = self._session.recv_cipher.decrypt(frame)
            self._perf.track_latency(Stage.NOISE_DECRYPT, _t.monotonic() - _t0)
            return result
        return self._session.recv_cipher.decrypt(frame)

    def _read_exactly_raw(self, n: int) -> bytes:
        """Read exactly n bytes from the obfs layer."""
        return self._obfs.read(n)

    def close(self) -> None:
        self._obfs.close()

    # Expose session info
    @property
    def remote_static(self) -> bytes:
        return self._session.remote_static


# ---------------------------------------------------------------------------
# Mux stream
# ---------------------------------------------------------------------------

class MuxStream:
    """
    A virtual bidirectional stream within a ClientMux.
    Thread-safe read/write.
    """

    def __init__(self, stream_id: int, mux: "ClientMux") -> None:
        self.stream_id = stream_id
        self._mux = mux
        self._read_buf = b""
        self._read_lock = threading.Lock()
        self._closed = threading.Event()
        self._remote_fin = threading.Event()
        # Queue for incoming data chunks; bounded to provide backpressure.
        # 4096 × 1460-byte packets ≈ 6 MB — matches the 8 MB socket buffer
        # so that the reader thread can drain without stalling the TCP window.
        import queue
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=4096)

    def write(self, data: bytes) -> None:
        if self._closed.is_set():
            raise IOError("stream is closed")
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 0xFFFF]
            self._mux._write_frame(self.stream_id, FRAME_DATA, chunk)
            offset += len(chunk)

    def read(self, timeout: Optional[float] = None) -> bytes:
        """
        Read the next available data chunk.
        Returns b'' on EOF (remote FIN).
        """
        import queue
        with self._read_lock:
            if self._read_buf:
                chunk = self._read_buf
                self._read_buf = b""
                return chunk

        while True:
            try:
                data = self._queue.get(timeout=timeout if timeout is not None else 5.0)
                return data
            except queue.Empty:
                if self._remote_fin.is_set() or self._closed.is_set():
                    return b""
                raise TimeoutError("stream read timeout")

    def read_exactly(self, n: int, timeout: Optional[float] = None) -> bytes:
        """Read exactly n bytes, buffering across multiple chunks."""
        import queue
        # bytearray accumulation is O(chunk) not O(total); no intermediate copies.
        buf = bytearray()
        pending = bytearray(self._read_buf)  # carry over any buffered tail
        self._read_buf = b""
        while len(buf) < n:
            if pending:
                need = n - len(buf)
                if len(pending) <= need:
                    buf += pending
                    pending = bytearray()
                else:
                    buf += pending[:need]
                    pending = pending[need:]
                continue
            try:
                data = self._queue.get(timeout=timeout if timeout is not None else 5.0)
                if data == b"":
                    raise EOFError("stream closed before read_exactly completed")
                pending = bytearray(data)
            except queue.Empty:
                if self._remote_fin.is_set() or self._closed.is_set():
                    raise EOFError("stream closed before read_exactly completed")
                raise TimeoutError("stream read_exactly timeout")
        # Save any unconsumed tail back to _read_buf
        if pending:
            self._read_buf = bytes(pending)
        return bytes(buf)

    def close(self) -> None:
        if not self._closed.is_set():
            self._closed.set()
            try:
                self._mux._write_frame(self.stream_id, FRAME_FIN, b"")
            except Exception:
                pass
            self._mux._remove_stream(self.stream_id)

    def _deliver(self, data: bytes) -> None:
        """Called by the mux read loop to deliver incoming data."""
        self._queue.put(data)

    def _signal_fin(self) -> None:
        """Called by the mux read loop when the remote sends FIN."""
        self._remote_fin.set()
        self._queue.put(b"")  # unblock any blocking read


# ---------------------------------------------------------------------------
# Client-side Mux
# ---------------------------------------------------------------------------

class ClientMux:
    """
    Stream multiplexer for the client side.
    Client uses even stream IDs starting at 2.
    """

    def __init__(self, noise_conn: NoiseConn) -> None:
        self._conn = noise_conn
        self._streams: dict[int, MuxStream] = {}
        self._streams_lock = threading.Lock()
        self._next_id = 2  # client uses even IDs
        self._write_lock = threading.Lock()
        self._closed = threading.Event()
        # Start the read loop
        self._reader_thread = threading.Thread(
            target=self._read_loop, daemon=True, name="mux-reader"
        )
        self._reader_thread.start()

    def open_stream(self) -> MuxStream:
        """Open a new outbound stream and send SYN."""
        with self._streams_lock:
            sid = self._next_id
            self._next_id += 2
            stream = MuxStream(sid, self)
            self._streams[sid] = stream
        self._write_frame(sid, FRAME_SYN, b"")
        logger.debug("mux_open_stream", stream_id=sid)
        return stream

    def close(self) -> None:
        self._closed.set()
        with self._streams_lock:
            for stream in list(self._streams.values()):
                try:
                    stream._signal_fin()
                except Exception:
                    pass
            self._streams.clear()
        try:
            self._conn.close()
        except Exception:
            pass

    def _write_frame(self, stream_id: int, frame_type: int, payload: bytes) -> None:
        # Build 7-byte mux header + payload in a single pre-sized bytearray to
        # avoid three separate struct.pack calls and the hdr+payload concatenation.
        frame = bytearray(7 + len(payload))
        struct.pack_into(">IbH", frame, 0, stream_id, frame_type, len(payload))
        frame[7:] = payload
        with self._write_lock:
            self._conn.write_message(bytes(frame))

    def _remove_stream(self, stream_id: int) -> None:
        with self._streams_lock:
            self._streams.pop(stream_id, None)

    def _read_loop(self) -> None:
        """Background thread: read mux frames and dispatch to streams."""
        import socket as _socket
        while not self._closed.is_set():
            try:
                frame_data = self._conn.read_message()
            except (_socket.timeout, TimeoutError):
                # Transient read timeout — not a connection error, keep going.
                continue
            except Exception as exc:
                logger.warning("mux_read_loop_error", error=str(exc))
                self._closed.set()
                # Signal all streams
                with self._streams_lock:
                    for stream in list(self._streams.values()):
                        stream._signal_fin()
                break

            if len(frame_data) < MUX_HEADER_SIZE:
                logger.warning("mux_short_frame", length=len(frame_data))
                continue

            # int.from_bytes is ~30% faster than struct.unpack for fixed-width
            # big-endian integers — avoids tuple allocation and format parsing.
            stream_id = int.from_bytes(frame_data[0:4], "big")
            frame_type = frame_data[4]
            payload_len = int.from_bytes(frame_data[5:7], "big")
            payload = frame_data[7:7 + payload_len]

            with self._streams_lock:
                stream = self._streams.get(stream_id)

            if frame_type == FRAME_SYN:
                # Server opened a stream (odd ID) — create and register it
                if stream is None:
                    new_stream = MuxStream(stream_id, self)
                    with self._streams_lock:
                        self._streams[stream_id] = new_stream
                    logger.debug("mux_accepted_stream", stream_id=stream_id)

            elif frame_type == FRAME_DATA:
                if stream is not None and payload:
                    stream._deliver(payload)

            elif frame_type == FRAME_FIN:
                if stream is not None:
                    stream._signal_fin()
                    self._remove_stream(stream_id)


# ---------------------------------------------------------------------------
# Route info
# ---------------------------------------------------------------------------

@dataclass
class RouteInfo:
    """IP assignment from the VPN server."""
    assigned_ip: str        # e.g. "10.8.0.2"
    prefix_len: int         # e.g. 24
    gateway: str            # e.g. "10.8.0.1"
    server_public_key: bytes  # 32-byte server static public key

    @property
    def cidr(self) -> str:
        """Return CIDR notation for the assigned address, e.g. '10.8.0.2/24'."""
        return f"{self.assigned_ip}/{self.prefix_len}"

    @property
    def network(self) -> ipaddress.IPv4Network:
        """Return the IPv4Network for the assigned subnet."""
        return ipaddress.IPv4Network(f"{self.assigned_ip}/{self.prefix_len}", strict=False)


# ---------------------------------------------------------------------------
# VPN configuration
# ---------------------------------------------------------------------------

@dataclass
class VPNConfig:
    """Configuration for the VPN client."""
    server_addr: str           # host:port, e.g. "1.2.3.4:443"
    private_key_file: Optional[str] = None   # path to hex private key file
    key_pair: Optional[KeyPair] = None       # or provide directly
    connect_timeout: float = 30.0
    read_timeout: float = 60.0
    transport: str = "udp"      # "tcp" or "udp" (user-space BBR on server)


# ---------------------------------------------------------------------------
# VPN client
# ---------------------------------------------------------------------------

class VPNClient:
    """
    Full-stack VPN client.

    Protocol:
      TCP → ObfsConn (TLS obfuscation) → Noise_XX handshake →
      NoiseConn → ClientMux → control stream (IP assignment) →
      data stream (raw IP packets)
    """

    def __init__(self, config: VPNConfig, perf=None) -> None:
        self._config = config
        self._sock: Optional[socket.socket] = None
        self._obfs: Optional[ObfsConn] = None
        self._noise_conn: Optional[NoiseConn] = None
        self._mux: Optional[ClientMux] = None
        self._data_stream: Optional[MuxStream] = None
        self._route_info: Optional[RouteInfo] = None
        self._connected = threading.Event()
        self._log = logger.bind(server=config.server_addr)
        self._perf = perf  # optional PerfCollector instance

    def connect(self) -> RouteInfo:
        """
        Perform the full connection sequence and return the assigned route info.
        """
        kp = self._load_key_pair()

        host, port = self._parse_addr(self._config.server_addr)
        self._log.info("vpn_connecting", host=host, port=port,
                       transport=self._config.transport)

        # 1. Transport connection (TCP or UDP)
        if self._config.transport == "udp":
            self._sock = self._connect_udp(host, int(port))
        else:
            self._sock = self._connect_tcp(host, int(port))

        # 2. TLS obfuscation
        self._obfs = ObfsConn(self._sock)
        self._obfs.client_handshake()
        self._log.debug("obfs_handshake_done")

        # 3. Noise_XX handshake
        if self._perf:
            import time as _t
            _hs_start = _t.monotonic()
        session = self._do_noise_handshake(kp)
        if self._perf:
            from perf_collector import Stage
            self._perf.track_latency(Stage.HANDSHAKE, _t.monotonic() - _hs_start)
        self._log.info("noise_handshake_done",
                       remote_key=session.remote_static.hex())

        # 4. Post-handshake encrypted transport
        self._noise_conn = NoiseConn(self._obfs, session, perf=self._perf)

        # 5. Mux
        self._mux = ClientMux(self._noise_conn)

        # 6. Control stream: request IP
        route = self._do_control_stream()
        route = RouteInfo(
            assigned_ip=route.assigned_ip,
            prefix_len=route.prefix_len,
            gateway=route.gateway,
            server_public_key=session.remote_static,
        )
        self._route_info = route
        self._log.info("vpn_connected", cidr=route.cidr, gateway=route.gateway)

        # 7. Open data stream
        self._data_stream = self._mux.open_stream()
        self._connected.set()

        return route

    def disconnect(self) -> None:
        """Close all layers gracefully."""
        self._connected.clear()
        if self._data_stream:
            try:
                self._data_stream.close()
            except Exception:
                pass
        if self._mux:
            try:
                self._mux.close()
            except Exception:
                pass
        self._sock = None
        self._obfs = None
        self._noise_conn = None
        self._mux = None
        self._data_stream = None
        self._log.info("vpn_disconnected")

    def send_packet(self, pkt: bytes) -> None:
        """Send a raw IP packet over the data stream."""
        if not self._connected.is_set() or self._data_stream is None:
            raise IOError("VPN not connected")
        self._data_stream.write(pkt)
        if self._perf:
            from perf_collector import Stage
            self._perf.track_packet(Stage.TUN_WRITE, len(pkt))

    def recv_packet(self) -> bytes:
        """Receive a raw IP packet from the data stream."""
        if not self._connected.is_set() or self._data_stream is None:
            raise IOError("VPN not connected")
        data = self._data_stream.read()
        if self._perf:
            from perf_collector import Stage
            self._perf.track_packet(Stage.TUN_READ, len(data))
        return data

    # -- internal helpers ---------------------------------------------------

    def _load_key_pair(self) -> KeyPair:
        if self._config.key_pair is not None:
            return self._config.key_pair
        if self._config.private_key_file is not None:
            return load_key_pair_from_file(self._config.private_key_file)
        return generate_key_pair()

    def _connect_tcp(self, host: str, port: int):
        """Establish a TCP connection with tuned socket options."""
        sock = socket.create_connection(
            (host, port), timeout=self._config.connect_timeout
        )
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        _BUF_SIZE = 2 * 1024 * 1024
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            import platform
            if platform.system() == "Darwin":
                TCP_KEEPALIVE = 0x10
                sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 15)
            else:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except (AttributeError, OSError):
            pass
        sock.settimeout(None)
        self._log.debug("tcp_connected")
        return sock

    def _connect_udp(self, host: str, port: int):
        """Establish a reliable UDP connection (server runs user-space BBR)."""
        from reliable_udp import connect_udp
        conn = connect_udp(host, port, timeout=self._config.connect_timeout)
        self._log.debug("udp_connected")
        return conn

    def _do_noise_handshake(self, kp: KeyPair) -> NoiseSession:
        hs = NoiseHandshake(kp)

        # WriteMessage1: -> e (32 bytes)
        msg1 = hs.write_message1()
        self._send_handshake_msg(msg1)

        # ReadMessage2: <- e, ee, s, es
        msg2 = self._recv_handshake_msg()
        hs.read_message2(msg2)

        # WriteMessage3: -> s, se
        msg3, session = hs.write_message3()
        self._send_handshake_msg(msg3)

        return session

    def _send_handshake_msg(self, msg: bytes) -> None:
        """Send a length-prefixed handshake message over the obfs layer."""
        prefix = struct.pack(">H", len(msg))
        self._obfs.write(prefix + msg)

    def _recv_handshake_msg(self) -> bytes:
        """Receive a length-prefixed handshake message from the obfs layer."""
        len_bytes = self._obfs.read(2)
        length = struct.unpack(">H", len_bytes)[0]
        return self._obfs.read(length)

    def _do_control_stream(self) -> RouteInfo:
        """Open control stream, send ctlHello, parse ctlAssign response."""
        ctl = self._mux.open_stream()
        try:
            # Send ctlHello
            ctl.write(bytes([CTL_HELLO]))

            # Read response: ctlAssign(1) + ip(4) + prefixLen(1) + gateway(4) = 10 bytes
            resp = ctl.read_exactly(1 + CTL_ASSIGN_PAYLOAD_LEN)

            if resp[0] == CTL_ERROR:
                raise IOError("server returned ctlError on control stream")
            if resp[0] != CTL_ASSIGN:
                raise IOError(f"unexpected control response 0x{resp[0]:02x}")

            ip_bytes = resp[1:5]
            prefix_len = resp[5]
            gw_bytes = resp[6:10]

            assigned_ip = socket.inet_ntoa(ip_bytes)
            gateway = socket.inet_ntoa(gw_bytes)

            self._log.info("ip_assigned",
                           ip=assigned_ip, prefix_len=prefix_len, gateway=gateway)
            return RouteInfo(
                assigned_ip=assigned_ip,
                prefix_len=prefix_len,
                gateway=gateway,
                server_public_key=b"",  # filled in connect()
            )
        finally:
            ctl.close()

    @staticmethod
    def _parse_addr(addr: str) -> tuple[str, int]:
        """Parse 'host:port' string. Supports IPv6 brackets."""
        if addr.startswith("["):
            # IPv6: [::1]:443
            bracket_end = addr.index("]")
            host = addr[1:bracket_end]
            rest = addr[bracket_end + 1:]
            if not rest.startswith(":"):
                raise ValueError(f"invalid address: {addr!r}")
            port = int(rest[1:])
        elif ":" in addr:
            parts = addr.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1])
        else:
            raise ValueError(f"invalid address (no port): {addr!r}")
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range: {port}")
        return host, port
