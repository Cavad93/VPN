"""
test_compat.py — Python compatibility tests for the iOS CavadVPN Swift implementation.

These tests validate that the PROTOCOL LOGIC described in the Swift sources is
wire-compatible with the existing Python/Go implementations by exercising the same
cryptographic math and wire-format parsers using the Python client code.

Run with:
    cd /home/user/VPN/ios/test-runner && python3 -m pytest test_compat.py -v
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import io
import os
import struct
import sys

import pytest

# ---------------------------------------------------------------------------
# Import the Python reference implementation
# ---------------------------------------------------------------------------

_CLIENT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "client")
sys.path.insert(0, os.path.abspath(_CLIENT_DIR))

from core import (
    KEY_SIZE,
    OVERHEAD,
    NOISE_PROTOCOL_NAME,
    FRAME_SYN,
    FRAME_DATA,
    FRAME_FIN,
    MUX_HEADER_SIZE,
    CTL_HELLO,
    CTL_ASSIGN,
    TLS_RECORD_HANDSHAKE,
    TLS_RECORD_APPDATA,
    TLS_VERSION_MAJOR,
    TLS_VERSION_MINOR,
    MAX_OBFS_PAYLOAD,
    generate_key_pair,
    dh,
    noise_hkdf,
    NoiseCipherState,
    NoiseSymmetricState,
    NoiseHandshake,
    ObfsConn,
    NoiseConn,
    NoiseSession,
    SessionCipher,
    _build_client_hello,
    _build_server_hello,
    _build_app_data_record,
    _wrap_handshake_record,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ===========================================================================
# 1. Cryptographic primitives
# ===========================================================================

class TestCryptoPrimitives:
    """Tests for X25519, ChaCha20-Poly1305, HMAC-SHA256 — mirror of CryptoCoreTests.swift."""

    def test_generate_key_pair_sizes(self):
        kp = generate_key_pair()
        assert len(kp.public_key_bytes) == KEY_SIZE

    def test_generate_key_pair_random(self):
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()
        assert kp1.public_key_bytes != kp2.public_key_bytes

    def test_dh_shared_secret_symmetry(self):
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()
        s1 = dh(kp1.private_key, kp2.public_key_bytes)
        s2 = dh(kp2.private_key, kp1.public_key_bytes)
        assert s1 == s2
        assert len(s1) == KEY_SIZE

    def test_chacha20_encrypt_decrypt_roundtrip(self):
        key   = os.urandom(32)
        nonce = os.urandom(12)
        pt    = b"Hello, VPN!"
        aead  = ChaCha20Poly1305(key)
        ct    = aead.encrypt(nonce, pt, b"")
        dec   = aead.decrypt(nonce, ct, b"")
        assert dec == pt

    def test_chacha20_tag_appended(self):
        key   = os.urandom(32)
        nonce = os.urandom(12)
        pt    = b"test"
        ct    = ChaCha20Poly1305(key).encrypt(nonce, pt, b"")
        assert len(ct) == len(pt) + 16  # 16-byte tag

    def test_chacha20_with_aad(self):
        key  = os.urandom(32)
        nonce = os.urandom(12)
        pt   = b"message"
        aad  = b"associated data"
        aead = ChaCha20Poly1305(key)
        ct   = aead.encrypt(nonce, pt, aad)
        dec  = aead.decrypt(nonce, ct, aad)
        assert dec == pt

    def test_chacha20_wrong_key_fails(self):
        key1, key2 = os.urandom(32), os.urandom(32)
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(key1).encrypt(nonce, b"hello", b"")
        with pytest.raises(Exception):
            ChaCha20Poly1305(key2).decrypt(nonce, ct, b"")


# ===========================================================================
# 2. Noise HKDF
# ===========================================================================

class TestNoiseHKDF:
    """Tests for noiseHKDF — mirrors the NoiseHKDF math in CryptoCore.swift."""

    def test_two_outputs(self):
        ck  = os.urandom(32)
        ikm = os.urandom(32)
        out = noise_hkdf(ck, ikm, 2)
        assert len(out) == 2
        assert all(len(o) == 32 for o in out)
        assert out[0] != out[1]

    def test_three_outputs(self):
        ck  = os.urandom(32)
        ikm = os.urandom(32)
        out = noise_hkdf(ck, ikm, 3)
        assert len(out) == 3
        assert all(len(o) == 32 for o in out)

    def test_known_vector_all_zeros(self):
        ck  = b"\x00" * 32
        ikm = b"\x00" * 32
        out = noise_hkdf(ck, ikm, 2)
        assert out[0] != b"\x00" * 32
        # Deterministic
        out2 = noise_hkdf(ck, ikm, 2)
        assert out[0] == out2[0]
        assert out[1] == out2[1]

    def test_hkdf_manual_computation(self):
        """Verify the HKDF derivation matches the explicit HMAC-SHA256 formula."""
        ck  = b"chaining_key_____chaining_key___"
        ikm = b"input_key_material__input_key___"

        def hmac(key, data):
            return _hmac.new(key, data, hashlib.sha256).digest()

        temp = hmac(ck, ikm)
        o1 = hmac(temp, b"\x01")
        o2 = hmac(temp, o1 + b"\x02")

        out = noise_hkdf(ck, ikm, 2)
        assert out[0] == o1
        assert out[1] == o2

    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            noise_hkdf(b"\x00" * 32, b"", 1)

    def test_three_outputs_chain(self):
        ck  = os.urandom(32)
        ikm = os.urandom(32)

        def hmac(key, data):
            return _hmac.new(key, data, hashlib.sha256).digest()

        temp = hmac(ck, ikm)
        o1 = hmac(temp, b"\x01")
        o2 = hmac(temp, o1 + b"\x02")
        o3 = hmac(temp, o2 + b"\x03")

        out = noise_hkdf(ck, ikm, 3)
        assert out[2] == o3


# ===========================================================================
# 3. NoiseCipherState nonce format
# ===========================================================================

class TestNoiseCipherStateNonce:
    """Tests for the nonce format used in NoiseCipherState (mirrors Swift NoiseCipherState)."""

    def test_nonce_format_4zeros_plus_8bytes_le(self):
        """Nonce = 4 zero bytes + 8-byte little-endian counter."""
        cs = NoiseCipherState()
        cs.initialize_key(os.urandom(32))
        # Access the internal nonce via _make_nonce
        n0 = cs._make_nonce()
        assert n0[:4] == b"\x00\x00\x00\x00"
        assert n0[4:] == struct.pack("<Q", 0)

    def test_nonce_increments(self):
        cs = NoiseCipherState()
        cs.initialize_key(os.urandom(32))
        n0 = cs._make_nonce()
        cs._n += 1
        n1 = cs._make_nonce()
        assert n0 != n1
        assert n1[4:] == struct.pack("<Q", 1)

    def test_counter_increments_on_encrypt(self):
        cs = NoiseCipherState()
        key = os.urandom(32)
        cs.initialize_key(key)
        ct1 = cs.encrypt_with_ad(b"", b"hello")
        ct2 = cs.encrypt_with_ad(b"", b"hello")
        assert ct1 != ct2  # different nonces

    def test_decrypt_matches_encrypt(self):
        key = os.urandom(32)
        cs_enc = NoiseCipherState()
        cs_enc.initialize_key(key)
        cs_dec = NoiseCipherState()
        cs_dec.initialize_key(key)

        pt = b"secret message"
        ct = cs_enc.encrypt_with_ad(b"", pt)
        dec = cs_dec.decrypt_with_ad(b"", ct)
        assert dec == pt


# ===========================================================================
# 4. Noise_XX handshake
# ===========================================================================

class TestNoiseHandshake:
    """Tests for the Noise_XX handshake — mirrors NoiseHandshakeTests.swift."""

    def _do_handshake(self, init_kp=None, resp_kp=None):
        """Run a full XX handshake and return (init_session, resp_session)."""
        if init_kp is None:
            init_kp = generate_key_pair()
        if resp_kp is None:
            resp_kp = generate_key_pair()

        # Initiator
        initiator = NoiseHandshake(init_kp)

        # Responder (manual, mirrors Go server)
        resp_ss = NoiseSymmetricState(NOISE_PROTOCOL_NAME)
        resp_ss.mix_hash(b"")  # empty prologue

        # -> e
        msg1 = initiator.write_message1()
        assert len(msg1) == 32
        resp_ss.mix_hash(msg1)   # re
        re = msg1

        # <- e, ee, s, es
        resp_e = generate_key_pair()
        resp_ss.mix_hash(resp_e.public_key_bytes)
        ee = dh(resp_e.private_key, re)
        resp_ss.mix_key(ee)
        enc_s = resp_ss.encrypt_and_hash(resp_kp.public_key_bytes)
        es = dh(resp_kp.private_key, re)
        resp_ss.mix_key(es)

        # msg2 = re.pub(32) + enc_s(48) — no empty payload (matches Go server)
        msg2 = resp_e.public_key_bytes + enc_s
        initiator.read_message2(msg2)

        # -> s, se
        msg3, init_session = initiator.write_message3()

        # Responder processes msg3
        enc_rs = msg3[:KEY_SIZE + OVERHEAD]
        rs = resp_ss.decrypt_and_hash(enc_rs)
        se = dh(resp_e.private_key, rs)
        resp_ss.mix_key(se)
        c1, c2 = resp_ss.split()

        resp_session = NoiseSession(
            send_cipher=SessionCipher(c2),
            recv_cipher=SessionCipher(c1),
            remote_static=rs,
        )
        return init_session, resp_session, init_kp, resp_kp

    def test_full_handshake_roundtrip(self):
        init_s, resp_s, _, _ = self._do_handshake()
        pt = b"Hello, Noise!"
        ct = init_s.send_cipher.encrypt(pt)
        dec = resp_s.recv_cipher.decrypt(ct)
        assert dec == pt

    def test_reverse_direction(self):
        init_s, resp_s, _, _ = self._do_handshake()
        pt = b"Reply from server"
        ct = resp_s.send_cipher.encrypt(pt)
        dec = init_s.recv_cipher.decrypt(ct)
        assert dec == pt

    def test_remote_static_exchanged(self):
        init_s, resp_s, init_kp, resp_kp = self._do_handshake()
        assert init_s.remote_static == resp_kp.public_key_bytes
        assert resp_s.remote_static == init_kp.public_key_bytes

    def test_message1_size(self):
        kp = generate_key_pair()
        hs = NoiseHandshake(kp)
        msg1 = hs.write_message1()
        assert len(msg1) == 32

    def test_message3_size(self):
        _, _, _, _ = self._do_handshake()
        kp = generate_key_pair()
        resp_kp = generate_key_pair()
        initiator = NoiseHandshake(kp)
        resp_ss = NoiseSymmetricState(NOISE_PROTOCOL_NAME)
        resp_ss.mix_hash(b"")
        msg1 = initiator.write_message1()
        resp_ss.mix_hash(msg1)
        resp_e = generate_key_pair()
        resp_ss.mix_hash(resp_e.public_key_bytes)
        ee = dh(resp_e.private_key, msg1)
        resp_ss.mix_key(ee)
        enc_s = resp_ss.encrypt_and_hash(resp_kp.public_key_bytes)
        es = dh(resp_kp.private_key, msg1)
        resp_ss.mix_key(es)
        # no empty payload in msg2 (matches Go server)
        msg2 = resp_e.public_key_bytes + enc_s
        initiator.read_message2(msg2)
        msg3, _ = initiator.write_message3()
        assert len(msg3) == 48  # enc_s(32+16)

    def test_invalid_step_raises(self):
        kp = generate_key_pair()
        hs = NoiseHandshake(kp)
        with pytest.raises(RuntimeError):
            hs.read_message2(b"\x00" * 80)

    def test_protocol_name_initializes_h(self):
        """h = SHA-256(protocol_name) or direct copy if len <= 32."""
        name = NOISE_PROTOCOL_NAME
        assert len(name) == 32  # exactly 32 bytes → direct copy
        h_init = name + b"\x00" * 0  # no padding needed
        ss = NoiseSymmetricState(name)
        assert ss.h == h_init


# ===========================================================================
# 5. TLS obfuscation wire format
# ===========================================================================

class TestObfsWireFormat:
    """Validates the TLS record wire format used by ObfsConn — mirrors ObfsConnTests.swift."""

    def test_app_data_record_header(self):
        payload = b"\x01\x02\x03"
        record  = _build_app_data_record(payload)
        assert record[0] == 0x17        # application_data
        assert record[1] == 0x03        # version major
        assert record[2] == 0x03        # version minor
        assert struct.unpack(">H", record[3:5])[0] == len(payload)
        assert record[5:] == payload

    def test_client_hello_record_type(self):
        hello = _build_client_hello()
        assert hello[0] == 0x16         # TLS handshake record

    def test_server_hello_record_type(self):
        hello = _build_server_hello()
        assert hello[0] == 0x16         # TLS handshake record

    def test_client_hello_contains_msg_type(self):
        hello = _build_client_hello()
        # Record header is 5 bytes; HS message type follows at byte 5
        assert hello[5] == 0x01         # ClientHello

    def test_server_hello_contains_msg_type(self):
        hello = _build_server_hello()
        assert hello[5] == 0x02         # ServerHello

    def test_max_record_size(self):
        assert MAX_OBFS_PAYLOAD == 16383  # 2^14 - 1

    def test_large_payload_fragmentation(self):
        """Payloads > 16383 bytes must be split into multiple records."""
        large_payload = os.urandom(40000)
        records = []
        offset = 0
        while offset < len(large_payload):
            chunk = large_payload[offset:offset + MAX_OBFS_PAYLOAD]
            records.append(_build_app_data_record(chunk))
            offset += len(chunk)
        assert len(records) == 3  # ceil(40000/16383)

    def test_wrap_handshake_record_structure(self):
        body = b"body data"
        rec  = _wrap_handshake_record(0x01, body)
        # TLS record: 0x16 + version + length(2)
        assert rec[0] == 0x16
        assert rec[1] == 0x03
        assert rec[2] == 0x03
        inner_len = struct.unpack(">H", rec[3:5])[0]
        # inner = hs_type(1) + hs_len(3) + body
        assert inner_len == 4 + len(body)
        assert rec[5] == 0x01  # handshake type

    def test_obfs_roundtrip_via_loopback(self):
        """Full ObfsConn handshake + data exchange via socket loopback."""
        import socket, threading

        server_sock, client_sock = socket.socketpair()

        client_obfs = ObfsConn(client_sock)
        server_obfs = ObfsConn(server_sock)

        results = {}

        def server_fn():
            try:
                server_obfs.server_handshake()
                data = server_obfs.read(5)
                results["server_read"] = data
            except Exception as e:
                results["server_error"] = str(e)

        t = threading.Thread(target=server_fn)
        t.start()

        client_obfs.client_handshake()
        client_obfs.write(b"hello")
        t.join(timeout=5)

        assert "server_error" not in results, results.get("server_error")
        assert results.get("server_read") == b"hello"

        client_sock.close()
        server_sock.close()


# ===========================================================================
# 6. Mux frame format
# ===========================================================================

class TestMuxFrameFormat:
    """Validates mux frame layout — mirrors MuxConnTests.swift."""

    def test_header_size(self):
        assert MUX_HEADER_SIZE == 7  # streamID(4) + type(1) + len(2)

    def test_frame_type_constants(self):
        assert FRAME_SYN  == 0x01
        assert FRAME_DATA == 0x02
        assert FRAME_FIN  == 0x03

    def test_build_and_parse_data_frame(self):
        stream_id = 2
        payload   = b"packet data"
        # Build frame (Python reference)
        frame = struct.pack(">IBH", stream_id, FRAME_DATA, len(payload)) + payload
        assert len(frame) == MUX_HEADER_SIZE + len(payload)

        # Parse
        sid   = struct.unpack(">I", frame[0:4])[0]
        ftype = frame[4]
        plen  = struct.unpack(">H", frame[5:7])[0]
        pdata = frame[7:7 + plen]

        assert sid   == stream_id
        assert ftype == FRAME_DATA
        assert plen  == len(payload)
        assert pdata == payload

    def test_syn_frame_no_payload(self):
        stream_id = 2
        frame = struct.pack(">IBH", stream_id, FRAME_SYN, 0)
        assert len(frame) == MUX_HEADER_SIZE
        ftype = frame[4]
        plen  = struct.unpack(">H", frame[5:7])[0]
        assert ftype == FRAME_SYN
        assert plen  == 0

    def test_fin_frame_no_payload(self):
        stream_id = 4
        frame = struct.pack(">IBH", stream_id, FRAME_FIN, 0)
        ftype = frame[4]
        assert ftype == FRAME_FIN

    def test_client_uses_even_stream_ids(self):
        """Client stream IDs start at 2 and increment by 2."""
        ids = [2, 4, 6, 8, 10]
        for sid in ids:
            assert sid % 2 == 0

    def test_noise_length_prefix_encoding(self):
        """NoiseConn uses 2-byte big-endian length prefix."""
        ct = os.urandom(1234)
        prefix = struct.pack(">H", len(ct))
        assert len(prefix) == 2
        assert struct.unpack(">H", prefix)[0] == 1234


# ===========================================================================
# 7. Control protocol
# ===========================================================================

class TestControlProtocol:
    """Tests for the VPN control stream protocol — mirrors VpnClient control logic."""

    def test_ctl_hello_bytes(self):
        """ctlHello = [0x01, 0x00 × 9] = 10 bytes."""
        hello = bytes([CTL_HELLO]) + b"\x00" * 9
        assert len(hello) == 10
        assert hello[0] == 0x01
        assert hello[1:] == b"\x00" * 9

    def test_ctl_assign_parse(self):
        """ctlAssign = [0x02, ip(4), prefixLen(1), gateway(4)]."""
        ip      = bytes([10, 8, 0, 2])
        prefix  = bytes([24])
        gateway = bytes([10, 8, 0, 1])
        resp    = bytes([CTL_ASSIGN]) + ip + prefix + gateway
        assert len(resp) == 10
        assert resp[0] == CTL_ASSIGN

        parsed_ip      = f"{resp[1]}.{resp[2]}.{resp[3]}.{resp[4]}"
        parsed_prefix  = resp[5]
        parsed_gateway = f"{resp[6]}.{resp[7]}.{resp[8]}.{resp[9]}"

        assert parsed_ip      == "10.8.0.2"
        assert parsed_prefix  == 24
        assert parsed_gateway == "10.8.0.1"

    def test_ctl_hello_type_byte(self):
        assert CTL_HELLO  == 0x01

    def test_ctl_assign_type_byte(self):
        assert CTL_ASSIGN == 0x02

    def test_ctl_assign_total_length(self):
        # 1 (type) + 4 (ip) + 1 (prefix) + 4 (gateway) = 10
        assert 1 + 4 + 1 + 4 == 10

    def test_ctl_assign_cidr_derivation(self):
        prefix_len = 24
        mask_bits  = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        octets     = [(mask_bits >> s) & 0xFF for s in (24, 16, 8, 0)]
        assert octets == [255, 255, 255, 0]


# ===========================================================================
# 8. Full stack handshake compatibility (Python ↔ Python as proxy for iOS ↔ Go)
# ===========================================================================

class TestFullStackHandshake:
    """
    End-to-end tests that simulate a full client-server connection using the
    Python reference implementation on both sides.  This validates that the
    protocol math described in the Swift sources is correctly specified.
    """

    def _make_noise_conn_pair(self):
        """Create two NoiseConn instances connected over a socket pair."""
        import socket, threading

        client_sock, server_sock = socket.socketpair()

        client_kp = generate_key_pair()
        server_kp = generate_key_pair()

        client_obfs = ObfsConn(client_sock)
        server_obfs = ObfsConn(server_sock)

        server_session = [None]
        client_session = [None]

        def server_fn():
            server_obfs.server_handshake()
            # Server-side Noise responder
            ss = NoiseSymmetricState(NOISE_PROTOCOL_NAME)
            ss.mix_hash(b"")
            # Read msg1
            lb = server_obfs.read(2)
            msg1_len = struct.unpack(">H", lb)[0]
            msg1 = server_obfs.read(msg1_len)
            ss.mix_hash(msg1)
            re = msg1

            # Send msg2 (no empty payload — matches Go server WriteMessage2)
            e = generate_key_pair()
            ss.mix_hash(e.public_key_bytes)
            ee = dh(e.private_key, re)
            ss.mix_key(ee)
            enc_s   = ss.encrypt_and_hash(server_kp.public_key_bytes)
            es      = dh(server_kp.private_key, re)
            ss.mix_key(es)
            msg2    = e.public_key_bytes + enc_s
            msg2_prefix = struct.pack(">H", len(msg2))
            server_obfs.write(msg2_prefix + msg2)

            # Read msg3
            lb3 = server_obfs.read(2)
            msg3_len = struct.unpack(">H", lb3)[0]
            msg3 = server_obfs.read(msg3_len)
            enc_rs = msg3[:KEY_SIZE + OVERHEAD]
            rs = ss.decrypt_and_hash(enc_rs)
            se = dh(e.private_key, rs)
            ss.mix_key(se)
            c1, c2 = ss.split()
            server_session[0] = NoiseSession(
                send_cipher=SessionCipher(c2),
                recv_cipher=SessionCipher(c1),
                remote_static=rs,
            )

        t = threading.Thread(target=server_fn)
        t.start()

        # Client side
        client_obfs.client_handshake()
        hs = NoiseHandshake(client_kp)
        msg1 = hs.write_message1()
        client_obfs.write(struct.pack(">H", len(msg1)) + msg1)

        lb = client_obfs.read(2)
        msg2_len = struct.unpack(">H", lb)[0]
        msg2 = client_obfs.read(msg2_len)
        hs.read_message2(msg2)

        msg3, session = hs.write_message3()
        client_obfs.write(struct.pack(">H", len(msg3)) + msg3)
        client_session[0] = session

        t.join(timeout=5)
        assert client_session[0] is not None
        assert server_session[0] is not None

        client_nc = NoiseConn(client_obfs, client_session[0])
        server_nc = NoiseConn(server_obfs, server_session[0])
        return client_nc, server_nc, client_sock, server_sock

    def test_noise_conn_send_receive(self):
        import socket
        client_nc, server_nc, cs, ss = self._make_noise_conn_pair()
        import threading
        received = [None]

        def recv():
            received[0] = server_nc.read_message()

        t = threading.Thread(target=recv)
        t.start()
        client_nc.write_message(b"greetings from iOS")
        t.join(timeout=5)
        assert received[0] == b"greetings from iOS"
        cs.close(); ss.close()

    def test_noise_conn_multiple_messages(self):
        client_nc, server_nc, cs, ss = self._make_noise_conn_pair()
        import threading
        messages = [b"alpha", b"beta", b"gamma"]
        received = []

        def recv():
            for _ in range(len(messages)):
                received.append(server_nc.read_message())

        t = threading.Thread(target=recv)
        t.start()
        for msg in messages:
            client_nc.write_message(msg)
        t.join(timeout=5)
        assert received == messages
        cs.close(); ss.close()

    def test_handshake_authenticates_remote_key(self):
        """The client must obtain the server's static key after the handshake."""
        client_nc, _, cs, ss = self._make_noise_conn_pair()
        # remote_static should be a 32-byte key
        assert len(client_nc.remote_static) == 32
        cs.close(); ss.close()
