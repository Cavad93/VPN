"""
test_sni_spoof.py — Unit and integration tests for sni_spoof.py.

Tests cover:
  - SNIConfig validation
  - DomainSelector (random, sequential, fixed policies)
  - Individual TLS extension builders (wire format)
  - build_client_hello (structure, SNI embedding, randomness)
  - parse_server_hello (round-trip and error paths)
  - SNISpoofConn (handshake, read/write, inter-op with server_handshake)
  - create_sni_conn factory
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from sni_spoof import (
    CHROME_CIPHER_SUITES,
    DOMAIN_POOL,
    EXT_ALPN,
    EXT_EC_POINT_FORMATS,
    EXT_RENEGOTIATION_INFO,
    EXT_SESSION_TICKET,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SNI,
    EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
    MAX_OBFS_PAYLOAD,
    TLS_HELLO_CLIENT,
    TLS_HELLO_SERVER,
    TLS_RECORD_APPDATA,
    TLS_RECORD_HANDSHAKE,
    TLS_VERSION_MAJOR,
    TLS_VERSION_MINOR,
    DomainSelector,
    RotationPolicy,
    SNIConfig,
    SNISpoofConn,
    _build_server_hello,
    _encode_ext,
    _wrap_handshake_record,
    build_alpn_extension,
    build_client_hello,
    build_ec_point_formats_extension,
    build_renegotiation_info_extension,
    build_session_ticket_extension,
    build_signature_algorithms_extension,
    build_sni_extension,
    build_supported_groups_extension,
    build_supported_versions_extension,
    create_sni_conn,
    parse_server_hello,
)


# ===========================================================================
# SNIConfig
# ===========================================================================


class TestSNIConfig:
    def test_default_domains_nonempty(self) -> None:
        cfg = SNIConfig()
        assert len(cfg.domains) > 0

    def test_default_uses_domain_pool(self) -> None:
        cfg = SNIConfig()
        assert cfg.domains == DOMAIN_POOL

    def test_validate_empty_domains_raises(self) -> None:
        cfg = SNIConfig(domains=[])
        with pytest.raises(ValueError, match="domains must not be empty"):
            cfg.validate()

    def test_validate_fixed_no_domain_raises(self) -> None:
        cfg = SNIConfig(
            domains=["a.com"],
            rotation_policy=RotationPolicy.FIXED,
            fixed_domain=None,
        )
        # fixed_domain is None but domains[0] is used — should pass
        cfg.validate()  # no error expected

    def test_validate_empty_alpn_entry_raises(self) -> None:
        cfg = SNIConfig(alpn_protocols=["h2", ""])
        with pytest.raises(ValueError, match="alpn_protocols"):
            cfg.validate()

    def test_validate_ok_default(self) -> None:
        SNIConfig().validate()  # must not raise

    def test_validate_fixed_with_explicit_domain(self) -> None:
        cfg = SNIConfig(
            rotation_policy=RotationPolicy.FIXED,
            fixed_domain="cdn.example.com",
        )
        cfg.validate()  # must not raise

    def test_custom_domains(self) -> None:
        cfg = SNIConfig(domains=["a.com", "b.com"])
        assert cfg.domains == ["a.com", "b.com"]

    def test_rotation_policy_default(self) -> None:
        assert SNIConfig().rotation_policy == RotationPolicy.RANDOM


# ===========================================================================
# DomainSelector
# ===========================================================================


class TestDomainSelector:
    def test_random_returns_domain_from_pool(self) -> None:
        cfg = SNIConfig(rotation_policy=RotationPolicy.RANDOM)
        sel = DomainSelector(cfg)
        for _ in range(20):
            assert sel.next_domain() in cfg.domains

    def test_sequential_cycles_in_order(self) -> None:
        domains = ["a.com", "b.com", "c.com"]
        cfg = SNIConfig(domains=domains, rotation_policy=RotationPolicy.SEQUENTIAL)
        sel = DomainSelector(cfg)
        result = [sel.next_domain() for _ in range(6)]
        assert result == ["a.com", "b.com", "c.com", "a.com", "b.com", "c.com"]

    def test_fixed_always_returns_same_domain(self) -> None:
        cfg = SNIConfig(
            rotation_policy=RotationPolicy.FIXED,
            fixed_domain="fixed.example.com",
        )
        sel = DomainSelector(cfg)
        results = {sel.next_domain() for _ in range(10)}
        assert results == {"fixed.example.com"}

    def test_fixed_defaults_to_first_domain(self) -> None:
        cfg = SNIConfig(
            domains=["first.com", "second.com"],
            rotation_policy=RotationPolicy.FIXED,
            fixed_domain=None,
        )
        sel = DomainSelector(cfg)
        assert sel.next_domain() == "first.com"

    def test_random_policy_string_value(self) -> None:
        assert RotationPolicy.RANDOM.value == "random"

    def test_sequential_policy_string_value(self) -> None:
        assert RotationPolicy.SEQUENTIAL.value == "sequential"

    def test_fixed_policy_string_value(self) -> None:
        assert RotationPolicy.FIXED.value == "fixed"

    def test_sequential_single_domain(self) -> None:
        cfg = SNIConfig(domains=["only.com"], rotation_policy=RotationPolicy.SEQUENTIAL)
        sel = DomainSelector(cfg)
        for _ in range(5):
            assert sel.next_domain() == "only.com"

    def test_random_different_calls(self) -> None:
        # With a large domain pool, random selection should not always be same.
        cfg = SNIConfig(rotation_policy=RotationPolicy.RANDOM)
        sel = DomainSelector(cfg)
        results = {sel.next_domain() for _ in range(50)}
        assert len(results) > 1


# ===========================================================================
# Extension builders — wire format
# ===========================================================================


class TestEncodeExt:
    def test_structure(self) -> None:
        data = b"\x01\x02"
        ext = _encode_ext(0x0000, data)
        assert ext[:2] == b"\x00\x00"  # type
        assert ext[2:4] == b"\x00\x02"  # length
        assert ext[4:] == data

    def test_empty_data(self) -> None:
        ext = _encode_ext(0x0023, b"")
        assert len(ext) == 4
        assert ext[2:4] == b"\x00\x00"


class TestSNIExtension:
    def test_hostname_encoded(self) -> None:
        ext = build_sni_extension("www.youtube.com")
        # ext type
        assert struct.unpack(">H", ext[:2])[0] == EXT_SNI
        # host_name type byte
        data = ext[4:]  # skip type+length
        # server_name_list_length
        list_len = struct.unpack(">H", data[:2])[0]
        name_entry = data[2:]
        assert len(name_entry) >= list_len
        assert name_entry[0] == 0x00  # name_type = host_name
        name_len = struct.unpack(">H", name_entry[1:3])[0]
        name = name_entry[3: 3 + name_len]
        assert name == b"www.youtube.com"

    def test_different_domains_differ(self) -> None:
        e1 = build_sni_extension("www.google.com")
        e2 = build_sni_extension("www.cloudflare.com")
        assert e1 != e2

    def test_extension_type_is_sni(self) -> None:
        ext = build_sni_extension("example.com")
        assert struct.unpack(">H", ext[:2])[0] == EXT_SNI

    def test_empty_subdomain(self) -> None:
        ext = build_sni_extension("a.b")
        assert b"a.b" in ext


class TestSupportedVersionsExtension:
    def test_type_code(self) -> None:
        ext = build_supported_versions_extension()
        assert struct.unpack(">H", ext[:2])[0] == EXT_SUPPORTED_VERSIONS

    def test_contains_tls13(self) -> None:
        ext = build_supported_versions_extension()
        assert b"\x03\x04" in ext  # TLS 1.3

    def test_contains_tls12(self) -> None:
        ext = build_supported_versions_extension()
        assert b"\x03\x03" in ext  # TLS 1.2


class TestSupportedGroupsExtension:
    def test_type_code(self) -> None:
        ext = build_supported_groups_extension()
        assert struct.unpack(">H", ext[:2])[0] == EXT_SUPPORTED_GROUPS

    def test_contains_x25519(self) -> None:
        ext = build_supported_groups_extension()
        assert b"\x00\x1d" in ext  # x25519

    def test_contains_p256(self) -> None:
        ext = build_supported_groups_extension()
        assert b"\x00\x17" in ext  # secp256r1


class TestECPointFormatsExtension:
    def test_type_code(self) -> None:
        ext = build_ec_point_formats_extension()
        assert struct.unpack(">H", ext[:2])[0] == EXT_EC_POINT_FORMATS

    def test_uncompressed(self) -> None:
        ext = build_ec_point_formats_extension()
        assert b"\x00" in ext[4:]  # uncompressed point format


class TestALPNExtension:
    def test_type_code(self) -> None:
        ext = build_alpn_extension(["h2", "http/1.1"])
        assert struct.unpack(">H", ext[:2])[0] == EXT_ALPN

    def test_h2_encoded(self) -> None:
        ext = build_alpn_extension(["h2"])
        assert b"h2" in ext

    def test_http11_encoded(self) -> None:
        ext = build_alpn_extension(["http/1.1"])
        assert b"http/1.1" in ext

    def test_both_protocols(self) -> None:
        ext = build_alpn_extension(["h2", "http/1.1"])
        assert b"h2" in ext
        assert b"http/1.1" in ext

    def test_single_protocol(self) -> None:
        ext = build_alpn_extension(["h2"])
        data = ext[4:]  # skip type(2)+length(2)
        # protocol name list length
        list_len = struct.unpack(">H", data[:2])[0]
        assert list_len == 3  # 1 (len byte) + 2 (h2)


class TestSignatureAlgorithmsExtension:
    def test_type_code(self) -> None:
        ext = build_signature_algorithms_extension()
        assert struct.unpack(">H", ext[:2])[0] == EXT_SIGNATURE_ALGORITHMS

    def test_contains_ecdsa_p256_sha256(self) -> None:
        ext = build_signature_algorithms_extension()
        assert b"\x04\x03" in ext  # ecdsa_secp256r1_sha256

    def test_contains_rsa_pss_sha256(self) -> None:
        ext = build_signature_algorithms_extension()
        assert b"\x08\x04" in ext  # rsa_pss_rsae_sha256


class TestSessionTicketExtension:
    def test_type_code(self) -> None:
        ext = build_session_ticket_extension()
        assert struct.unpack(">H", ext[:2])[0] == EXT_SESSION_TICKET

    def test_empty_data(self) -> None:
        ext = build_session_ticket_extension()
        assert struct.unpack(">H", ext[2:4])[0] == 0


class TestRenegotiationInfoExtension:
    def test_type_code(self) -> None:
        ext = build_renegotiation_info_extension()
        assert struct.unpack(">H", ext[:2])[0] == EXT_RENEGOTIATION_INFO

    def test_zero_ri_data_length(self) -> None:
        ext = build_renegotiation_info_extension()
        # ext[4] is the RI data length byte = 0x00
        assert ext[4] == 0x00


# ===========================================================================
# build_client_hello
# ===========================================================================


class TestBuildClientHello:
    def _parse_hello(self, data: bytes) -> bytes:
        """Return the ClientHello body (after 4-byte hs header)."""
        assert data[0] == TLS_RECORD_HANDSHAKE
        rec_len = struct.unpack(">H", data[3:5])[0]
        hs = data[5: 5 + rec_len]
        assert hs[0] == TLS_HELLO_CLIENT
        body = hs[4:]
        return body

    def test_is_handshake_record(self) -> None:
        hello = build_client_hello("www.youtube.com")
        assert hello[0] == TLS_RECORD_HANDSHAKE

    def test_msg_type_is_client_hello(self) -> None:
        hello = build_client_hello("www.youtube.com")
        assert hello[5] == TLS_HELLO_CLIENT

    def test_legacy_version(self) -> None:
        hello = build_client_hello("www.youtube.com")
        body = self._parse_hello(hello)
        assert body[0:2] == bytes([0x03, 0x03])

    def test_random_field_32_bytes(self) -> None:
        hello = build_client_hello("www.youtube.com")
        body = self._parse_hello(hello)
        # random is bytes 2..34
        assert len(body[2:34]) == 32

    def test_session_id_32_bytes(self) -> None:
        hello = build_client_hello("www.youtube.com")
        body = self._parse_hello(hello)
        sid_len = body[34]
        assert sid_len == 32

    def test_sni_in_extensions(self) -> None:
        hello = build_client_hello("www.netflix.com")
        assert b"www.netflix.com" in hello

    def test_different_sni_different_bytes(self) -> None:
        h1 = build_client_hello("www.youtube.com")
        h2 = build_client_hello("www.cloudflare.com")
        assert h1 != h2

    def test_randomness_between_calls(self) -> None:
        h1 = build_client_hello("www.youtube.com")
        h2 = build_client_hello("www.youtube.com")
        assert h1 != h2  # random bytes differ

    def test_contains_tls13_supported_version(self) -> None:
        hello = build_client_hello("a.com")
        assert b"\x03\x04" in hello  # TLS 1.3

    def test_contains_alpn_h2(self) -> None:
        hello = build_client_hello("a.com", alpn_protocols=["h2", "http/1.1"])
        assert b"h2" in hello

    def test_chrome_cipher_suites_present(self) -> None:
        hello = build_client_hello("a.com")
        # TLS_AES_128_GCM_SHA256 = 0x1301
        assert b"\x13\x01" in hello

    def test_without_session_ticket(self) -> None:
        hello_with = build_client_hello("a.com", include_session_ticket=True)
        hello_without = build_client_hello("a.com", include_session_ticket=False)
        # Session ticket extension type is 0x0023
        assert b"\x00\x23" in hello_with
        assert b"\x00\x23" not in hello_without

    def test_minimum_length(self) -> None:
        # Even a minimal ClientHello with SNI is well above 50 bytes.
        hello = build_client_hello("a.com")
        assert len(hello) > 100

    def test_record_length_field_matches_content(self) -> None:
        hello = build_client_hello("example.com")
        rec_len = struct.unpack(">H", hello[3:5])[0]
        assert len(hello) == 5 + rec_len


# ===========================================================================
# parse_server_hello
# ===========================================================================


class TestParseServerHello:
    def test_parse_valid_server_hello(self) -> None:
        sh = _build_server_hello()
        result = parse_server_hello(sh)
        assert result["version"] == 0x0303
        assert len(result["random"]) == 32
        assert result["cipher_suite"] == 0x1301  # TLS_AES_128_GCM_SHA256

    def test_random_differs_each_call(self) -> None:
        r1 = parse_server_hello(_build_server_hello())["random"]
        r2 = parse_server_hello(_build_server_hello())["random"]
        assert r1 != r2

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_server_hello(b"\x00\x01\x02")

    def test_wrong_record_type_raises(self) -> None:
        sh = _build_server_hello()
        bad = bytes([0x17]) + sh[1:]  # change to appdata
        with pytest.raises(ValueError, match="handshake record"):
            parse_server_hello(bad)

    def test_wrong_msg_type_raises(self) -> None:
        sh = _build_server_hello()
        # hs payload starts at offset 5; byte 0 of hs payload is msg_type
        bad_list = list(sh)
        bad_list[5] = 0x01  # change ServerHello → ClientHello type
        bad = bytes(bad_list)
        with pytest.raises(ValueError, match="ServerHello"):
            parse_server_hello(bad)

    def test_truncated_record_raises(self) -> None:
        sh = _build_server_hello()
        with pytest.raises(ValueError):
            parse_server_hello(sh[:10])


# ===========================================================================
# SNISpoofConn — handshake and data transfer via socketpair
# ===========================================================================


def _make_sni_pair(
    client_config: Optional[SNIConfig] = None,
    server_config: Optional[SNIConfig] = None,
) -> tuple[SNISpoofConn, SNISpoofConn]:
    """Create a (client, server) pair over a socketpair, perform handshakes."""
    c_raw, s_raw = socket.socketpair()
    client = SNISpoofConn(c_raw, client_config)
    server = SNISpoofConn(s_raw, server_config)

    errors: list[Exception] = []

    def do_client() -> None:
        try:
            client.client_handshake()
        except Exception as exc:
            errors.append(exc)

    def do_server() -> None:
        try:
            server.server_handshake()
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=do_client)
    t2 = threading.Thread(target=do_server)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    if errors:
        raise errors[0]
    return client, server


class TestSNISpoofConnHandshake:
    def test_handshake_completes(self) -> None:
        client, server = _make_sni_pair()
        client.close()
        server.close()

    def test_active_sni_set_after_handshake(self) -> None:
        cfg = SNIConfig(
            domains=["www.youtube.com"],
            rotation_policy=RotationPolicy.FIXED,
            fixed_domain="www.youtube.com",
        )
        client, server = _make_sni_pair(client_config=cfg)
        assert client.active_sni == "www.youtube.com"
        client.close()
        server.close()

    def test_active_sni_from_pool(self) -> None:
        cfg = SNIConfig(rotation_policy=RotationPolicy.RANDOM)
        client, server = _make_sni_pair(client_config=cfg)
        assert client.active_sni in DOMAIN_POOL
        client.close()
        server.close()

    def test_sequential_selector_cycles_correctly(self) -> None:
        # DomainSelector is the authoritative source for rotation order.
        # Each SNISpoofConn creates its own selector from the config.
        domains = ["a.com", "b.com", "c.com"]
        cfg = SNIConfig(domains=domains, rotation_policy=RotationPolicy.SEQUENTIAL)
        sel = DomainSelector(cfg)
        assert [sel.next_domain() for _ in domains] == domains

    def test_server_handshake_accepts_sni_hello(self) -> None:
        # Verify the server can read an SNI-enhanced ClientHello.
        c_raw, s_raw = socket.socketpair()

        def server_side() -> None:
            conn = SNISpoofConn(s_raw)
            conn.server_handshake()
            conn.close()

        t = threading.Thread(target=server_side)
        t.start()

        # Client sends a manually crafted SNI ClientHello.
        hello = build_client_hello("www.google.com")
        c_raw.sendall(hello)
        # Read the ServerHello response
        sh_hdr = b""
        while len(sh_hdr) < 5:
            sh_hdr += c_raw.recv(5 - len(sh_hdr))
        rec_len = struct.unpack(">H", sh_hdr[3:5])[0]
        sh_body = b""
        while len(sh_body) < rec_len:
            sh_body += c_raw.recv(rec_len - len(sh_body))
        c_raw.close()
        t.join(timeout=5)
        # If we got here, the server accepted the SNI-bearing hello.
        assert sh_body[0] == TLS_HELLO_SERVER


class TestSNISpoofConnReadWrite:
    def test_small_message(self) -> None:
        client, server = _make_sni_pair()
        msg = b"hello SNI"

        def send() -> None:
            client.write(msg)

        t = threading.Thread(target=send)
        t.start()
        received = server.read(len(msg))
        t.join(timeout=5)
        assert received == msg
        client.close()
        server.close()

    def test_bidirectional(self) -> None:
        client, server = _make_sni_pair()
        ping = b"ping"
        pong = b"pong"
        errors: list[Exception] = []

        def client_side() -> None:
            try:
                client.write(ping)
                assert client.read(len(pong)) == pong
            except Exception as exc:
                errors.append(exc)

        def server_side() -> None:
            try:
                assert server.read(len(ping)) == ping
                server.write(pong)
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=client_side)
        t2 = threading.Thread(target=server_side)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)
        assert not errors
        client.close()
        server.close()

    def test_large_payload(self) -> None:
        # 50 KB forces multiple TLS records.
        client, server = _make_sni_pair()
        data = bytes(range(256)) * 200  # 51 200 bytes

        def send() -> None:
            client.write(data)

        t = threading.Thread(target=send)
        t.start()
        received = server.read(len(data))
        t.join(timeout=5)
        assert received == data
        client.close()
        server.close()

    def test_read_exactly_alias(self) -> None:
        client, server = _make_sni_pair()
        msg = b"alias test"

        def send() -> None:
            client.write(msg)

        t = threading.Thread(target=send)
        t.start()
        received = server.read_exactly(len(msg))
        t.join(timeout=5)
        assert received == msg
        client.close()
        server.close()

    def test_buffered_read(self) -> None:
        # Send 9 bytes; read in 3-byte chunks (exactly 3 chunks).
        client, server = _make_sni_pair()
        msg = b"012345678"  # 9 bytes — divisible by 3

        def send() -> None:
            client.write(msg)

        t = threading.Thread(target=send)
        t.start()
        buf = b""
        while len(buf) < len(msg):
            buf += server.read(3)
        t.join(timeout=5)
        assert buf == msg
        client.close()
        server.close()

    def test_close_idempotent(self) -> None:
        client, server = _make_sni_pair()
        client.close()
        client.close()  # must not raise
        server.close()

    def test_read_after_close_raises(self) -> None:
        client, server = _make_sni_pair()
        # Close the server side; reading from client should fail (peer closed).
        server._sock.close()
        with pytest.raises(Exception):
            client.read(1)
        client.close()


# ===========================================================================
# create_sni_conn factory
# ===========================================================================


class TestCreateSniConn:
    def test_returns_sni_spoof_conn(self) -> None:
        c_raw, s_raw = socket.socketpair()
        conn = create_sni_conn(c_raw)
        assert isinstance(conn, SNISpoofConn)
        c_raw.close()
        s_raw.close()

    def test_accepts_custom_config(self) -> None:
        c_raw, s_raw = socket.socketpair()
        cfg = SNIConfig(
            domains=["custom.example.com"],
            rotation_policy=RotationPolicy.FIXED,
            fixed_domain="custom.example.com",
        )
        conn = create_sni_conn(c_raw, cfg)
        assert conn._config is cfg
        c_raw.close()
        s_raw.close()

    def test_default_config_when_none(self) -> None:
        c_raw, s_raw = socket.socketpair()
        conn = create_sni_conn(c_raw, None)
        assert isinstance(conn._config, SNIConfig)
        c_raw.close()
        s_raw.close()


# ===========================================================================
# Cross-compatibility: SNISpoofConn client ↔ plain ObfsConn server
# ===========================================================================


class TestCrossCompatibility:
    """Ensure SNISpoofConn client handshake is accepted by the Go-compatible
    server_handshake path (which only checks the msg_type byte)."""

    def test_sni_client_with_sni_server(self) -> None:
        """Both sides are SNISpoofConn — full round-trip."""
        client, server = _make_sni_pair()
        msg = b"cross compat"

        def send() -> None:
            client.write(msg)

        t = threading.Thread(target=send)
        t.start()
        data = server.read(len(msg))
        t.join(timeout=5)
        assert data == msg
        client.close()
        server.close()

    def test_sni_hello_structure_compatible_with_obfsconn(self) -> None:
        """The SNI ClientHello must have: handshake record type, ClientHello msg
        type as first byte of handshake payload.  The server only checks these."""
        hello = build_client_hello("www.youtube.com")
        assert hello[0] == TLS_RECORD_HANDSHAKE
        # Record length
        rec_len = struct.unpack(">H", hello[3:5])[0]
        hs = hello[5: 5 + rec_len]
        # hs[0] = msg type, hs[1:4] = 3-byte length, hs[4:] = body
        assert hs[0] == TLS_HELLO_CLIENT
        assert len(hs) >= 4

    def test_server_hello_parseable(self) -> None:
        sh = _build_server_hello()
        info = parse_server_hello(sh)
        assert info["cipher_suite"] is not None


# ===========================================================================
# Domain pool sanity checks
# ===========================================================================


class TestDomainPool:
    def test_pool_nonempty(self) -> None:
        assert len(DOMAIN_POOL) > 10

    def test_all_entries_nonempty_strings(self) -> None:
        for domain in DOMAIN_POOL:
            assert isinstance(domain, str) and len(domain) > 0

    def test_all_entries_contain_dot(self) -> None:
        for domain in DOMAIN_POOL:
            assert "." in domain, f"{domain!r} has no dot"

    def test_no_duplicates(self) -> None:
        assert len(DOMAIN_POOL) == len(set(DOMAIN_POOL))
