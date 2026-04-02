"""
sni_spoof.py — SNI (Server Name Indication) spoofing for Anti-DPI obfuscation.

Makes VPN traffic appear as connections to legitimate popular HTTPS websites
by embedding a real-looking Server Name Indication extension in the TLS
ClientHello. Deep Packet Inspection systems that see this traffic believe
it is coming from a normal browser visiting YouTube, Cloudflare, etc.

This module provides:

1. A curated pool of high-traffic HTTPS domains rotated per-connection.
2. Proper TLS 1.3 ClientHello construction with a Chrome-like extension set:
   - SNI (0x0000) with the spoofed hostname
   - Supported Versions (0x002b) advertising TLS 1.3 + 1.2
   - Supported Groups (0x000a) with X25519, P-256, P-384
   - EC Point Formats (0x000b)
   - ALPN (0x0010) with h2 / http/1.1
   - Signature Algorithms (0x000d)
   - Session Ticket (0x0023)
   - Renegotiation Info (0xff01)
3. ``SNISpoofConn`` — drop-in replacement for ``ObfsConn`` that sends a
   SNI-enhanced ClientHello while keeping the same read/write/close API.
4. ``DomainSelector`` for round-robin, random, or fixed domain rotation.

Wire format is identical to ``ObfsConn`` — only the ClientHello body is
enriched with extensions; application data records are unchanged.

Usage::

    import socket
    from sni_spoof import SNIConfig, create_sni_conn, RotationPolicy

    sock = socket.create_connection(("93.184.216.34", 443))
    conn = create_sni_conn(sock, SNIConfig(rotation_policy=RotationPolicy.RANDOM))
    conn.client_handshake()
    conn.write(b"secret payload")
    data = conn.read(len(b"secret payload"))
    conn.close()
"""

from __future__ import annotations

import os
import random
import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TLS wire-format constants (shared with core.py / obfs.go)
# ---------------------------------------------------------------------------

TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_APPDATA = 0x17
TLS_VERSION_MAJOR = 0x03
TLS_VERSION_MINOR = 0x03
TLS_HELLO_CLIENT = 0x01
TLS_HELLO_SERVER = 0x02
MAX_OBFS_PAYLOAD = 16383

# TLS extension type codes (RFC 8446 §4.2)
EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_RENEGOTIATION_INFO = 0xFF01

# ---------------------------------------------------------------------------
# Cipher suites — Chrome 120 TLS fingerprint
# ---------------------------------------------------------------------------

CHROME_CIPHER_SUITES: list[int] = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0x00FF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
]

# ---------------------------------------------------------------------------
# Domain pool — popular high-traffic HTTPS sites
# ---------------------------------------------------------------------------

DOMAIN_POOL: list[str] = [
    "www.youtube.com",
    "www.google.com",
    "www.cloudflare.com",
    "www.googleapis.com",
    "fonts.googleapis.com",
    "ssl.gstatic.com",
    "www.gstatic.com",
    "accounts.google.com",
    "www.instagram.com",
    "www.facebook.com",
    "static.cdninstagram.com",
    "www.apple.com",
    "cdn.apple.com",
    "swdist.apple.com",
    "www.microsoft.com",
    "login.microsoftonline.com",
    "www.office.com",
    "outlook.live.com",
    "www.github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "www.netflix.com",
    "assets.nflxext.com",
    "www.twitch.tv",
    "static.twitchsvc.net",
    "cdn.cloudflare.com",
    "ajax.cloudflare.com",
    "www.amazon.com",
    "images.amazon.com",
    "www.bing.com",
]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class RotationPolicy(str, Enum):
    """Domain rotation strategy used by DomainSelector."""

    RANDOM = "random"       # pick a random domain each time
    SEQUENTIAL = "sequential"  # cycle through the list in order
    FIXED = "fixed"         # always use the same domain


@dataclass
class SNIConfig:
    """Configuration for SNI spoofing.

    Attributes:
        domains: List of hostnames to rotate through.
        rotation_policy: How the next domain is selected.
        fixed_domain: Domain used when policy is FIXED (defaults to the first
            entry in ``domains`` if not set).
        alpn_protocols: ALPN protocol list embedded in the ClientHello.
        include_session_ticket: Whether to include the Session Ticket extension.
    """

    domains: list[str] = field(default_factory=lambda: list(DOMAIN_POOL))
    rotation_policy: RotationPolicy = RotationPolicy.RANDOM
    fixed_domain: Optional[str] = None
    alpn_protocols: list[str] = field(default_factory=lambda: ["h2", "http/1.1"])
    include_session_ticket: bool = True

    def validate(self) -> None:
        """Raise ValueError if the configuration is invalid."""
        if not self.domains:
            raise ValueError("SNIConfig.domains must not be empty")
        if self.rotation_policy == RotationPolicy.FIXED:
            domain = self.fixed_domain or self.domains[0]
            if not domain:
                raise ValueError("fixed_domain must be set when policy is FIXED")
        for proto in self.alpn_protocols:
            if not proto:
                raise ValueError("alpn_protocols entries must not be empty")


# ---------------------------------------------------------------------------
# Domain selector
# ---------------------------------------------------------------------------


class DomainSelector:
    """Returns the next SNI hostname according to the configured policy.

    Thread-safe for sequential and random policies; fixed is inherently safe.
    """

    def __init__(self, config: SNIConfig) -> None:
        config.validate()
        self._config = config
        self._index = 0

    def next_domain(self) -> str:
        """Return the next domain to use as SNI."""
        policy = self._config.rotation_policy
        if policy == RotationPolicy.FIXED:
            return self._config.fixed_domain or self._config.domains[0]
        elif policy == RotationPolicy.SEQUENTIAL:
            domain = self._config.domains[self._index % len(self._config.domains)]
            self._index += 1
            return domain
        else:  # RANDOM
            return random.choice(self._config.domains)


# ---------------------------------------------------------------------------
# TLS extension builders
# ---------------------------------------------------------------------------


def _encode_ext(ext_type: int, data: bytes) -> bytes:
    """Wrap *data* in a TLS extension entry: type(2) + length(2) + data."""
    return struct.pack(">HH", ext_type, len(data)) + data


def build_sni_extension(hostname: str) -> bytes:
    """Build a TLS SNI extension (RFC 6066 §3) for *hostname*.

    Wire layout::

        server_name_list_length  2 B  (big-endian)
        name_type                1 B  (0 = host_name)
        name_length              2 B  (big-endian)
        name                     N B  (ASCII)
    """
    name_bytes = hostname.encode("ascii")
    # name entry: type(1) + length(2) + name
    name_entry = struct.pack(">BH", 0x00, len(name_bytes)) + name_bytes
    # list: length(2) + entry
    name_list = struct.pack(">H", len(name_entry)) + name_entry
    return _encode_ext(EXT_SNI, name_list)


def build_supported_versions_extension() -> bytes:
    """Build Supported Versions extension advertising TLS 1.3 and TLS 1.2."""
    # Client hello format: versions_length(1) + [version(2) ...]
    versions = bytes([0x03, 0x04, 0x03, 0x03])  # TLS 1.3, TLS 1.2
    data = struct.pack(">B", len(versions)) + versions
    return _encode_ext(EXT_SUPPORTED_VERSIONS, data)


def build_supported_groups_extension() -> bytes:
    """Build Supported Groups extension with common ECDH curves."""
    groups = struct.pack(
        ">6H",
        0x001D,  # x25519
        0x0017,  # secp256r1 (P-256)
        0x0018,  # secp384r1 (P-384)
        0x0019,  # secp521r1 (P-521)
        0x0100,  # ffdhe2048
        0x0101,  # ffdhe3072
    )
    data = struct.pack(">H", len(groups)) + groups
    return _encode_ext(EXT_SUPPORTED_GROUPS, data)


def build_ec_point_formats_extension() -> bytes:
    """Build EC Point Formats extension (uncompressed only)."""
    formats = bytes([0x01, 0x00])  # length=1, uncompressed
    return _encode_ext(EXT_EC_POINT_FORMATS, formats)


def build_alpn_extension(protocols: list[str]) -> bytes:
    """Build ALPN extension (RFC 7301) for *protocols*."""
    entries = b""
    for proto in protocols:
        encoded = proto.encode("ascii")
        entries += struct.pack(">B", len(encoded)) + encoded
    data = struct.pack(">H", len(entries)) + entries
    return _encode_ext(EXT_ALPN, data)


def build_signature_algorithms_extension() -> bytes:
    """Build Signature Algorithms extension with modern schemes."""
    schemes = struct.pack(
        ">8H",
        0x0403,  # ecdsa_secp256r1_sha256
        0x0503,  # ecdsa_secp384r1_sha384
        0x0603,  # ecdsa_secp521r1_sha512
        0x0804,  # rsa_pss_rsae_sha256
        0x0805,  # rsa_pss_rsae_sha384
        0x0806,  # rsa_pss_rsae_sha512
        0x0401,  # rsa_pkcs1_sha256
        0x0501,  # rsa_pkcs1_sha384
    )
    data = struct.pack(">H", len(schemes)) + schemes
    return _encode_ext(EXT_SIGNATURE_ALGORITHMS, data)


def build_session_ticket_extension() -> bytes:
    """Build an empty Session Ticket extension (request a new ticket)."""
    return _encode_ext(EXT_SESSION_TICKET, b"")


def build_renegotiation_info_extension() -> bytes:
    """Build Renegotiation Info extension with empty RI data (initial handshake)."""
    return _encode_ext(EXT_RENEGOTIATION_INFO, bytes([0x00]))


# ---------------------------------------------------------------------------
# ClientHello builder
# ---------------------------------------------------------------------------


def build_client_hello(sni: str, alpn_protocols: Optional[list[str]] = None,
                       include_session_ticket: bool = True) -> bytes:
    """Build a TLS 1.3 ClientHello record with SNI and Chrome-like extensions.

    Args:
        sni: Hostname to embed in the SNI extension.
        alpn_protocols: ALPN protocols to advertise (default: h2, http/1.1).
        include_session_ticket: Whether to include the session ticket extension.

    Returns:
        Complete TLS record bytes ready to send over a TCP connection.
    """
    if alpn_protocols is None:
        alpn_protocols = ["h2", "http/1.1"]

    random_bytes = os.urandom(32)
    session_id = os.urandom(32)

    # Cipher suites: 2-byte length prefix + list of 2-byte values
    cipher_bytes = b"".join(struct.pack(">H", cs) for cs in CHROME_CIPHER_SUITES)
    cipher_block = struct.pack(">H", len(cipher_bytes)) + cipher_bytes

    # Extensions
    exts = (
        build_sni_extension(sni)
        + build_supported_versions_extension()
        + build_supported_groups_extension()
        + build_ec_point_formats_extension()
        + build_alpn_extension(alpn_protocols)
        + build_signature_algorithms_extension()
        + build_renegotiation_info_extension()
    )
    if include_session_ticket:
        exts += build_session_ticket_extension()

    exts_block = struct.pack(">H", len(exts)) + exts

    body = (
        bytes([0x03, 0x03])  # legacy_version = TLS 1.2
        + random_bytes        # random[32]
        + bytes([0x20])       # session_id length = 32
        + session_id          # session_id[32]
        + cipher_block        # cipher suites
        + bytes([0x01, 0x00]) # compression_methods: length=1, null
        + exts_block          # extensions
    )

    return _wrap_handshake_record(TLS_HELLO_CLIENT, body)


def parse_server_hello(data: bytes) -> dict:
    """Parse the body of a synthetic ServerHello for diagnostic purposes.

    Extracts the legacy_version, random bytes, session_id, and selected
    cipher suite.  Unknown or missing extensions are silently ignored.

    Args:
        data: Raw bytes of the TLS handshake record (including TLS header).

    Returns:
        Dict with keys: ``version``, ``random``, ``session_id``, ``cipher_suite``.

    Raises:
        ValueError: If the data is too short or has an unexpected record type.
    """
    if len(data) < 5:
        raise ValueError("server hello too short")
    if data[0] != TLS_RECORD_HANDSHAKE:
        raise ValueError(f"expected handshake record, got 0x{data[0]:02x}")

    rec_len = struct.unpack(">H", data[3:5])[0]
    if len(data) < 5 + rec_len:
        raise ValueError("truncated server hello record")

    hs = data[5: 5 + rec_len]
    if len(hs) < 4:
        raise ValueError("handshake message too short")
    if hs[0] != TLS_HELLO_SERVER:
        raise ValueError(f"expected ServerHello (0x02), got 0x{hs[0]:02x}")

    body = hs[4:]  # skip msg_type + 3-byte length
    if len(body) < 35:
        raise ValueError("ServerHello body too short")

    version = struct.unpack(">H", body[0:2])[0]
    random_val = body[2:34]
    session_id_len = body[34]
    offset = 35 + session_id_len
    session_id_val = body[35:offset]

    cipher_suite: Optional[int] = None
    if len(body) >= offset + 2:
        cipher_suite = struct.unpack(">H", body[offset: offset + 2])[0]

    return {
        "version": version,
        "random": random_val,
        "session_id": session_id_val,
        "cipher_suite": cipher_suite,
    }


# ---------------------------------------------------------------------------
# Internal TLS record helpers (mirrors core.py helpers)
# ---------------------------------------------------------------------------


def _wrap_handshake_record(msg_type: int, body: bytes) -> bytes:
    """Wrap *body* in a TLS handshake message inside a TLS record."""
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
    """Wrap *payload* in a TLS application_data record."""
    n = len(payload)
    return bytes([
        TLS_RECORD_APPDATA,
        TLS_VERSION_MAJOR,
        TLS_VERSION_MINOR,
        (n >> 8) & 0xFF,
        n & 0xFF,
    ]) + payload


def _build_server_hello() -> bytes:
    """Build a synthetic TLS 1.3 ServerHello record (used by the responder)."""
    random_bytes = os.urandom(32)
    body = (
        bytes([0x03, 0x03])    # legacy_version = TLS 1.2
        + random_bytes          # random[32]
        + bytes([0x00])         # session_id length = 0
        + bytes([0x13, 0x01])   # cipher_suite: TLS_AES_128_GCM_SHA256
        + bytes([0x00])         # compression_method: null
    )
    return _wrap_handshake_record(TLS_HELLO_SERVER, body)


# ---------------------------------------------------------------------------
# SNISpoofConn
# ---------------------------------------------------------------------------


class SNISpoofConn:
    """Drop-in replacement for ``ObfsConn`` that sends a SNI-enhanced ClientHello.

    Compatible interface:
    - ``client_handshake()`` — send SNI-bearing ClientHello, read ServerHello
    - ``server_handshake()`` — read ClientHello (any variant), send ServerHello
    - ``write(data)`` — send data as TLS application_data records
    - ``read(n)`` — read exactly *n* bytes, buffering across records
    - ``close()`` — close the underlying socket
    """

    def __init__(self, sock: socket.socket, config: Optional[SNIConfig] = None) -> None:
        self._sock = sock
        self._config = config or SNIConfig()
        self._selector = DomainSelector(self._config)
        self._read_buf = b""
        self._active_sni: Optional[str] = None

    @property
    def active_sni(self) -> Optional[str]:
        """The SNI hostname used in the most recent ClientHello."""
        return self._active_sni

    def client_handshake(self) -> None:
        """Send a SNI-enhanced ClientHello and read the ServerHello."""
        sni = self._selector.next_domain()
        self._active_sni = sni
        hello = build_client_hello(
            sni=sni,
            alpn_protocols=self._config.alpn_protocols,
            include_session_ticket=self._config.include_session_ticket,
        )
        self._sock.sendall(hello)
        self._read_handshake_record(TLS_HELLO_SERVER)
        logger.debug("sni_client_handshake_done", sni=sni)

    def server_handshake(self) -> None:
        """Read any ClientHello (plain or SNI-enhanced) and send a ServerHello."""
        self._read_handshake_record(TLS_HELLO_CLIENT)
        self._sock.sendall(_build_server_hello())
        logger.debug("sni_server_handshake_done")

    def write(self, data: bytes) -> None:
        """Send *data* as one or more TLS application_data records."""
        offset = 0
        while offset < len(data):
            chunk = data[offset: offset + MAX_OBFS_PAYLOAD]
            self._sock.sendall(_build_app_data_record(chunk))
            offset += len(chunk)

    def read(self, n: int) -> bytes:
        """Read exactly *n* bytes, buffering across TLS records as needed."""
        while len(self._read_buf) < n:
            payload = self._read_record(TLS_RECORD_APPDATA)
            self._read_buf += payload
        result = self._read_buf[:n]
        self._read_buf = self._read_buf[n:]
        return result

    def read_exactly(self, n: int) -> bytes:
        """Alias for read(n) for compatibility with ObfsConn."""
        return self.read(n)

    def close(self) -> None:
        """Close the underlying socket."""
        try:
            self._sock.close()
        except OSError:
            pass

    # -- internal helpers ---------------------------------------------------

    def _recv_exactly(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed mid-read")
            buf += chunk
        return buf

    def _read_record(self, want_type: int) -> bytes:
        hdr = self._recv_exactly(5)
        if hdr[0] != want_type:
            raise ValueError(
                f"unexpected TLS record type 0x{hdr[0]:02x}, want 0x{want_type:02x}"
            )
        length = struct.unpack(">H", hdr[3:5])[0]
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
# Factory function
# ---------------------------------------------------------------------------


def create_sni_conn(sock: socket.socket,
                    config: Optional[SNIConfig] = None) -> SNISpoofConn:
    """Create an :class:`SNISpoofConn` with the given configuration.

    Args:
        sock: Connected socket to wrap.
        config: SNI spoofing configuration.  Uses defaults if omitted.

    Returns:
        An :class:`SNISpoofConn` ready for ``client_handshake()`` or
        ``server_handshake()``.
    """
    return SNISpoofConn(sock, config or SNIConfig())
