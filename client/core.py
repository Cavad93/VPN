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
TLS_RECORD_CCS = 0x14  # ChangeCipherSpec (middlebox compat, RFC 8446 §5.1)
TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_APPDATA = 0x17
TLS_VERSION_MAJOR = 0x03
TLS_VERSION_MINOR = 0x03
TLS_HELLO_CLIENT = 0x01
TLS_HELLO_SERVER = 0x02
MAX_OBFS_PAYLOAD = 16383

# Mux frame types
FRAME_SYN  = 0x01
FRAME_DATA = 0x02
FRAME_FIN  = 0x03
FRAME_PING = 0x04  # keepalive; streamID=0, length=0, no payload
MUX_HEADER_SIZE = 7  # streamID(4) + type(1) + payloadLen(2)

# How often the mux sends a keepalive ping.
# Must be < noiseConn read deadline on server (60s) divided by 2.
MUX_KEEPALIVE_INTERVAL: float = 15.0  # seconds

# Control stream message types
CTL_HELLO      = 0x01
CTL_ASSIGN     = 0x02
# CTL_SECONDARY is the first byte sent on a secondary (bonded) control stream.
# It tells the server to attach this connection to an existing primary session
# identified by the 4-byte assigned IP that immediately follows this byte.
# The server responds with CTL_ASSIGN (0x02) on success.
# Wire: open stream → write CTL_SECONDARY(1) + assigned_ip(4) → read CTL_ASSIGN(1)
CTL_SECONDARY  = 0x03
CTL_ERROR      = 0xFF  # server→client error (e.g. IP pool exhaustion)
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

def _compute_knock_tag(psk: bytes, random_bytes: bytes) -> bytes:
    """Compute HMAC-SHA256(psk, random) for Reality-style port knocking."""
    return hmac.new(psk, random_bytes, hashlib.sha256).digest()


def _build_client_hello(knock_key: Optional[bytes] = None) -> bytes:
    """Build a synthetic TLS 1.3 ClientHello record.

    If knock_key is provided (32 bytes), session_id is set to
    HMAC-SHA256(knock_key, random) for relay port-knock authentication.
    """
    random_bytes = os.urandom(32)
    if knock_key is not None:
        session_id = _compute_knock_tag(knock_key, random_bytes)
    else:
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

    def __init__(self, sock: socket.socket, knock_key: Optional[bytes] = None) -> None:
        self._sock = sock
        self._knock_key = knock_key  # 32-byte PSK for relay port knocking, or None
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
        self._sock.sendall(_build_client_hello(self._knock_key))
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
        while True:
            hdr = self._recv_exactly(5)
            # Skip ChangeCipherSpec records (TLS 1.3 middlebox compat,
            # RFC 8446 §5.1). The server sends CCS after ServerHello.
            if hdr[0] == TLS_RECORD_CCS:
                length = int.from_bytes(hdr[3:5], "big")
                if 0 < length <= MAX_OBFS_PAYLOAD:
                    self._recv_exactly(length)  # discard CCS payload
                continue
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
        # Pre-allocated 2-byte header buffer — reused on every write_message call
        # to avoid the struct.pack(">H", ...) allocation on the hot send path.
        # struct.pack_into writes in-place; no new bytes object is created.
        self._len_hdr = bytearray(2)

    def write_message(self, plaintext: bytes) -> None:
        if self._perf:
            import time as _t
            from perf_collector import Stage
            _t0 = _t.monotonic()
            ciphertext = self._session.send_cipher.encrypt(plaintext)
            self._perf.track_latency(Stage.NOISE_ENCRYPT, _t.monotonic() - _t0)
        else:
            ciphertext = self._session.send_cipher.encrypt(plaintext)
        # Build length-prefixed frame in a single bytearray (1 alloc + 1 copy).
        # Original: pack(">H",...) + ciphertext = 2 allocs + 2 copies.
        # New: bytearray(2+n), pack_into header in-place, slice-assign payload.
        n = len(ciphertext)
        frame = bytearray(2 + n)
        frame[0] = n >> 8
        frame[1] = n & 0xFF
        frame[2:] = ciphertext
        self._obfs.write(frame)

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
        # Start the keepalive loop — prevents server's noiseConn.Read deadline
        # from firing and keeps NAT/firewall state tables alive.
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop, daemon=True, name="mux-keepalive"
        )
        self._keepalive_thread.start()

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

    def _keepalive_loop(self) -> None:
        """Background thread: send a FramePing every MUX_KEEPALIVE_INTERVAL seconds.

        This prevents the server's noiseConn.Read deadline (60 s) from triggering
        on idle connections (e.g. user not browsing) and keeps NAT/firewall UDP/TCP
        state tables alive.  The thread exits when the mux is closed.
        """
        while not self._closed.wait(timeout=MUX_KEEPALIVE_INTERVAL):
            try:
                # streamID=0 is the sentinel for keepalive (no real stream).
                self._write_frame(0, FRAME_PING, b"")
            except Exception:
                return  # connection dead; _read_loop will do the cleanup

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

            # Keepalive ping from server: just continue.  Receiving this frame
            # is sufficient — it proves the connection is alive.
            if frame_type == FRAME_PING:
                continue

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
    # bond_count: number of parallel TCP connections for download bonding.
    # With 0.7% packet loss (Russia↔Kazakhstan), a single TCP connection is
    # throttled to ~1-2 Mbps (CUBIC) or ~5-8 Mbps (BBR). N connections each
    # have an independent congestion window, so aggregate download ≈ N × rate.
    # The server round-robins download packets across all bonded streams
    # (streamBond in main.go). Recommended: 4-8 for CIS routes; 1 for LAN.
    bond_count: int = 1
    # knock_key: 32-byte PSK for relay port knocking (Reality-style HMAC in
    # session_id). Must match the relay's -knock-key. None = no knock.
    knock_key: Optional[bytes] = None


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
        # --- Download bonding state (populated when bond_count > 1) ---
        # Secondary connections each have their own TCP socket, ObfsConn,
        # NoiseConn, ClientMux, and data stream.  The server round-robins
        # download packets across all bonded streams (streamBond), so the
        # client must be able to receive from any of them.
        self._bond_muxes: list = []        # ClientMux for each secondary conn
        self._bond_data_streams: list = [] # MuxStream for each secondary conn
        # _recv_q is non-None only when bond_count > 1.  Background threads
        # for every stream (primary + secondaries) push packets here.
        # recv_packet() reads from this queue instead of blocking on
        # _data_stream.read() directly.
        self._recv_q: Optional[object] = None  # queue.SimpleQueue[bytes]
        self._bond_closed = threading.Event()  # set by disconnect() to stop reader threads
        # --- Upload bonding state (populated when bond_count > 1) ---
        # send_packet() round-robins upload packets across _send_streams so that
        # each bonded TCP connection carries an equal share of outgoing traffic.
        # Each stream has its own independent TCP congestion window, giving
        # aggregate upload bandwidth ≈ N × per-connection rate under packet loss.
        # Empty list → single-stream path (_data_stream used directly).
        self._send_streams: list = []   # [primary_stream] + secondary_streams
        self._send_idx: int = 0         # monotonically increasing; mod len(_send_streams)
        self._send_lock = threading.Lock()  # protects _send_streams list mutations

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

        # 2. TLS obfuscation (with optional port-knock)
        self._obfs = ObfsConn(self._sock, knock_key=self._config.knock_key)
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

        # 8. Download bonding: establish secondary connections when bond_count > 1.
        #
        # Each secondary connection adds an independent TCP congestion window.
        # The server (streamBond / routeFromTun) round-robins download packets
        # across primary + all secondary data streams.  With N connections and
        # 0.7% packet loss (Russia↔Kazakhstan), aggregate download ≈ N × rate:
        #   1 conn  @ 0.7% loss, BBR → ~5-8 Mbps
        #   8 conns @ 0.7% loss, BBR → ~40-60 Mbps aggregate
        #
        # Implementation: all streams (primary + secondaries) are read by
        # background daemon threads that push packets into _recv_q.
        # recv_packet() blocks on _recv_q instead of a single stream.
        if self._config.bond_count > 1:
            import queue as _queue
            self._recv_q = _queue.SimpleQueue()
            self._bond_closed.clear()

            # Background reader for the PRIMARY data stream.
            threading.Thread(
                target=self._bond_reader_thread,
                args=(self._data_stream,),
                daemon=True,
                name="vpn-bond-reader-primary",
            ).start()

            # Secondary connections (bond_count - 1 additional connections).
            ip4_bytes = socket.inet_aton(route.assigned_ip)
            for i in range(self._config.bond_count - 1):
                try:
                    self._attach_secondary_conn(host, port, kp, ip4_bytes)
                except Exception as exc:
                    self._log.warning("secondary_conn_failed",
                                      index=i + 1, err=str(exc))

            # Build upload round-robin list: primary first, then secondaries.
            # Includes only successfully attached streams.
            self._send_streams = [self._data_stream] + list(self._bond_data_streams)
            self._send_idx = 0

            self._log.info("bond_established",
                           total_conns=1 + len(self._bond_muxes),
                           upload_streams=len(self._send_streams))

        return route

    def disconnect(self) -> None:
        """Close all layers gracefully, including all bonded secondary connections."""
        self._connected.clear()

        # Signal bond reader threads to stop (they'll also stop when streams FIN).
        self._bond_closed.set()

        # Close secondary connections first (data streams + muxes).
        for ds in self._bond_data_streams:
            try:
                ds.close()
            except Exception:
                pass
        for mux in self._bond_muxes:
            try:
                mux.close()
            except Exception:
                pass
        self._bond_data_streams = []
        self._bond_muxes = []
        self._recv_q = None
        self._send_streams = []
        self._send_idx = 0

        # Close primary connection.
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

    def _remove_dead_send_stream(self, dead: "MuxStream") -> None:
        """Remove a failed stream from the upload round-robin list.

        Thread-safe: uses _send_lock.  No-op if the stream has already been
        removed by a concurrent caller.
        """
        with self._send_lock:
            updated = [s for s in self._send_streams if s is not dead]
            if len(updated) < len(self._send_streams):
                self._send_streams = updated
                self._log.warning("bond_send_stream_removed",
                                  remaining=len(updated))

    def send_packet(self, pkt: bytes) -> None:
        """Send a raw IP packet, round-robining across all bonded streams.

        When bond_count == 1 (default), writes directly to _data_stream —
        zero overhead, identical to the pre-bonding behaviour.

        When bond_count > 1, round-robins upload packets across _send_streams
        (primary + all successfully attached secondary streams).  Each stream
        has its own independent TCP congestion window, so aggregate upload
        throughput under packet loss ≈ N × per-connection rate.

        Graceful failover: if a stream write fails (dead connection), the
        stream is removed from _send_streams and the packet is retried on the
        next available stream.  If all streams fail, IOError is raised so the
        caller (AutoReconnect) can trigger a reconnect.

        Thread safety: _send_idx is incremented as a single Python int
        assignment, which is atomic under CPython's GIL.  Mutations of
        _send_streams are serialised through _send_lock; the list reference
        itself is replaced atomically, so readers that captured an old
        reference still iterate a consistent snapshot.
        """
        if not self._connected.is_set() or self._data_stream is None:
            raise IOError("VPN not connected")
        streams = self._send_streams
        if not streams:
            # Single-connection path (bond_count == 1): no round-robin overhead.
            self._data_stream.write(pkt)
        else:
            # Upload bonding: round-robin with graceful failover.
            # Try at most len(streams) candidates so we don't loop forever if
            # every stream dies in rapid succession.
            max_attempts = len(streams)
            for attempt in range(max_attempts):
                streams = self._send_streams
                if not streams:
                    raise IOError("All bonded send streams have failed")
                idx = self._send_idx % len(streams)
                self._send_idx += 1
                stream = streams[idx]
                try:
                    stream.write(pkt)
                    break  # success
                except Exception as exc:
                    self._log.warning("bond_stream_write_failed",
                                      attempt=attempt + 1, err=str(exc))
                    self._remove_dead_send_stream(stream)
            else:
                raise IOError("All bonded send streams have failed")
        if self._perf:
            from perf_collector import Stage
            self._perf.track_packet(Stage.TUN_WRITE, len(pkt))

    def recv_packet(self) -> bytes:
        """Receive a raw IP packet from any bonded data stream.

        When bond_count == 1 (default), reads directly from _data_stream —
        identical to the pre-bonding behaviour.

        When bond_count > 1, reads from _recv_q, which is fed by background
        reader threads for every bonded stream (primary + secondaries).  The
        server round-robins download packets across all bonded connections, so
        packets can arrive on any stream; the queue serialises them into a
        single receive path for the caller.
        """
        if not self._connected.is_set() or self._data_stream is None:
            raise IOError("VPN not connected")
        if self._recv_q is not None:
            # Bonded mode: block until any reader thread deposits a packet.
            data = self._recv_q.get()  # type: ignore[union-attr]
        else:
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
        """Establish a TCP connection with tuned socket options.

        Socket options mirror what the server applies in setForcedSocketBuffers()
        (sockopt_linux.go) to ensure symmetric performance in both directions.
        """
        sock = socket.create_connection(
            (host, port), timeout=self._config.connect_timeout
        )
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # 4 MB buffers — matches the server's setForcedSocketBuffers(4 MB).
        # For download (server→client): SO_RCVBUF determines how much
        # unread data the kernel can buffer before stalling the TCP window.
        # At 30 Mbps × 100 ms RTT the BDP is 3.75 MB; 2 MB (old value) caps
        # download at ~20 Mbps. 4 MB allows full 30+ Mbps on high-latency links.
        _BUF_SIZE = 4 * 1024 * 1024
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            import platform
            _sys = platform.system()
            if _sys == "Darwin":
                TCP_KEEPALIVE = 0x10
                sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 15)
            else:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except (AttributeError, OSError):
            pass
        # --- Linux-only optimisations (mirroring sockopt_linux.go) ---
        # TCP_QUICKACK (Linux ≥ 2.4.4, value 12): disable 40 ms delayed-ACK.
        #
        # Root cause of download < upload asymmetry:
        #   Upload: server has TCP_QUICKACK=1 → sends ACKs immediately →
        #           upload cwnd grows fast.
        #   Download (before fix): client had NO TCP_QUICKACK → delayed ACKs
        #           (up to 40 ms) → server's cwnd opens slowly → download stalls.
        #
        # With TCP_QUICKACK on client: ACKs for incoming (download) packets are
        # sent immediately, allowing the server's congestion window to grow at
        # the same rate as the client's upload window does. At 100 ms RTT,
        # delayed ACKs effectively add 40 % overhead to every download RTT.
        #
        # TCP_CONGESTION="bbr" (Linux ≥ 2.6.13, value 13): use BBR congestion
        # control for upload. The server already runs BBR; having CUBIC on the
        # client causes the two CCs to interact badly on lossy links.
        #
        # TCP_NOTSENT_LOWAT=16384 (Linux ≥ 3.12, value 73): limit unsent data
        # in the kernel send buffer to 16 KB. On packet loss, only 16 KB is
        # retransmitted instead of megabytes — reduces upload tail latency on
        # lossy links (e.g. 0.7 % loss Russia↔Kazakhstan) by 5–10×.
        try:
            _TCP_QUICKACK = getattr(socket, "TCP_QUICKACK", 12)
            sock.setsockopt(socket.IPPROTO_TCP, _TCP_QUICKACK, 1)
        except OSError:
            pass  # not available on macOS / Windows — silently skip
        try:
            _TCP_CONGESTION = getattr(socket, "TCP_CONGESTION", 13)
            sock.setsockopt(socket.IPPROTO_TCP, _TCP_CONGESTION, b"bbr")
        except OSError:
            pass  # not available on macOS / Windows / kernels without BBR
        try:
            _TCP_NOTSENT_LOWAT = getattr(socket, "TCP_NOTSENT_LOWAT", 73)
            sock.setsockopt(socket.IPPROTO_TCP, _TCP_NOTSENT_LOWAT, 16384)
        except OSError:
            pass  # not available on macOS / Windows or older kernels
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
        """Perform Noise_XX handshake on the primary obfs connection (self._obfs)."""
        return self._do_noise_handshake_on(self._obfs, kp)

    def _do_noise_handshake_on(self, obfs: ObfsConn, kp: KeyPair) -> NoiseSession:
        """Perform Noise_XX handshake on an arbitrary ObfsConn.

        Used for both primary and secondary connections so that secondary
        connections can reuse the same key pair without touching self._obfs.
        """
        hs = NoiseHandshake(kp)

        # WriteMessage1: -> e (32 bytes)
        msg1 = hs.write_message1()
        obfs.write(struct.pack(">H", len(msg1)) + msg1)

        # ReadMessage2: <- e, ee, s, es
        len_b = obfs.read(2)
        msg2 = obfs.read(struct.unpack(">H", len_b)[0])
        hs.read_message2(msg2)

        # WriteMessage3: -> s, se
        msg3, session = hs.write_message3()
        obfs.write(struct.pack(">H", len(msg3)) + msg3)

        return session

    def _bond_reader_thread(self, stream: MuxStream) -> None:
        """Background daemon thread: reads download packets from a bonded data
        stream and puts them into _recv_q.

        The thread exits when:
          - The stream closes (read() returns b"" / empty bytes on EOF)
          - _bond_closed is set (disconnect() called) — detected via the
            stream's FIN signal triggered by mux.close()
          - Any unexpected exception (broken connection)
        """
        while not self._bond_closed.is_set():
            try:
                # Timeout=2s allows _bond_closed check to run periodically
                # without blocking the thread forever during idle connections.
                pkt = stream.read(timeout=2.0)
                if not pkt:
                    break  # EOF: remote FIN or stream closed
                if self._recv_q is not None:
                    self._recv_q.put(pkt)  # type: ignore[union-attr]
            except TimeoutError:
                continue  # idle — retry
            except Exception:
                break  # broken connection: exit silently

    def _attach_secondary_conn(
        self,
        host: str,
        port: int,
        kp: KeyPair,
        assigned_ip_bytes: bytes,
    ) -> None:
        """Establish one secondary TCP connection for download bonding.

        Wire protocol (mirrors server's runSecondaryConn in main.go):
          1. Full TCP → ObfsConn → Noise_XX handshake (same key pair)
          2. Open control stream (mux stream ID=2)
          3. Write CTL_SECONDARY (1 byte) + assigned_ip (4 bytes big-endian)
          4. Read CTL_ASSIGN (1 byte) from server — confirms attachment
          5. Close control stream
          6. Open data stream (mux stream ID=4)
          7. Start _bond_reader_thread for this data stream

        The server adds the data stream to its streamBond for this session,
        so download packets are now round-robined across all bonded connections.
        """
        sock = self._connect_tcp(host, port)

        obfs = ObfsConn(sock, knock_key=self._config.knock_key)
        obfs.client_handshake()

        session = self._do_noise_handshake_on(obfs, kp)
        nc = NoiseConn(obfs, session)
        mux = ClientMux(nc)

        # Control stream: announce secondary attachment
        ctl = mux.open_stream()
        try:
            ctl.write(bytes([CTL_SECONDARY]) + assigned_ip_bytes)
            resp = ctl.read_exactly(1, timeout=10.0)
            if resp[0] != CTL_ASSIGN:
                raise IOError(
                    f"secondary: unexpected response 0x{resp[0]:02x} "
                    f"(expected CTL_ASSIGN 0x{CTL_ASSIGN:02x})"
                )
        finally:
            ctl.close()

        # Open data stream — server's AcceptStream() picks it up and registers
        # it in cs.bond for round-robin download forwarding.
        ds = mux.open_stream()

        self._bond_muxes.append(mux)
        self._bond_data_streams.append(ds)

        t = threading.Thread(
            target=self._bond_reader_thread,
            args=(ds,),
            daemon=True,
            name=f"vpn-bond-reader-{len(self._bond_muxes)}",
        )
        t.start()
        self._log.info("secondary_conn_attached",
                       bond=len(self._bond_muxes) + 1)  # +1 for primary

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
