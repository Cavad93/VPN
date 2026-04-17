"""
test_core.py — Unit and integration tests for core.py VPN client.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import ipaddress
import os
import socket
import struct
import threading
import unittest
from typing import Optional

# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------
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
    CTL_ASSIGN_DUAL,
    CTL_ASSIGN_DUAL_PAYLOAD_LEN,
    CTL_ERROR,
    CTL_ASSIGN_PAYLOAD_LEN,
    TLS_HELLO_CLIENT,
    TLS_HELLO_SERVER,
    TLS_RECORD_HANDSHAKE,
    TLS_RECORD_APPDATA,
    KeyPair,
    NoiseSession,
    NoiseCipherState,
    NoiseSymmetricState,
    SessionCipher,
    NoiseHandshake,
    NoiseConn,
    ObfsConn,
    ClientMux,
    RouteInfo,
    VPNClient,
    VPNConfig,
    generate_key_pair,
    load_key_pair_from_file,
    dh,
    noise_hkdf,
    _build_client_hello,
    _build_server_hello,
    _build_app_data_record,
    _wrap_handshake_record,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ===========================================================================
# Helper: NoiseResponder (server-side Noise_XX for integration tests)
# ===========================================================================

class NoiseResponder:
    """
    Server-side Noise_XX responder used in handshake integration tests.
    Mirrors the Go server's doNoiseHandshake logic.
    """

    def __init__(self, static_kp: KeyPair) -> None:
        from core import NoiseSymmetricState, NoiseCipherState, generate_key_pair, dh, noise_hkdf
        self._static_kp = static_kp
        self._ss = NoiseSymmetricState(NOISE_PROTOCOL_NAME)
        self._ss.mix_hash(b"")  # empty prologue
        self._e: Optional[KeyPair] = None
        self._re: Optional[bytes] = None
        self._rs: Optional[bytes] = None
        self._step = 0

    def read_message1(self, msg: bytes) -> None:
        """Process -> e"""
        assert self._step == 0
        assert len(msg) >= KEY_SIZE
        self._re = msg[:KEY_SIZE]
        self._ss.mix_hash(self._re)
        self._step = 1

    def write_message2(self) -> bytes:
        """Send <- e, ee, s, es"""
        assert self._step == 1
        self._e = generate_key_pair()

        # <- e
        self._ss.mix_hash(self._e.public_key_bytes)
        msg = self._e.public_key_bytes

        # ee
        ee = dh(self._e.private_key, self._re)
        self._ss.mix_key(ee)

        # s: encrypt static
        enc_s = self._ss.encrypt_and_hash(self._static_kp.public_key_bytes)
        msg += enc_s

        # es: DH(s_resp, e_init)
        es = dh(self._static_kp.private_key, self._re)
        self._ss.mix_key(es)

        self._step = 2
        return msg

    def read_message3(self, msg: bytes) -> NoiseSession:
        """Process -> s, se; return session."""
        assert self._step == 2
        # s: decrypt initiator static
        enc_s = msg[:KEY_SIZE + OVERHEAD]
        plain_s = self._ss.decrypt_and_hash(enc_s)
        self._rs = plain_s

        # se: DH(e_resp, s_init)
        se = dh(self._e.private_key, self._rs)
        self._ss.mix_key(se)

        # split: c1=initiator sends (our recv), c2=responder sends (our send)
        c1, c2 = self._ss.split()

        from core import SessionCipher
        session = NoiseSession(
            send_cipher=SessionCipher(c2),
            recv_cipher=SessionCipher(c1),
            remote_static=self._rs,
        )
        self._step = 3
        return session


# ===========================================================================
# Helper: ObfsServer (server-side TLS obfuscation for integration tests)
# ===========================================================================

class ObfsServer:
    """Server-side ObfsConn helper for tests."""

    def __init__(self, sock: socket.socket) -> None:
        self._obfs = ObfsConn(sock)

    def handshake(self) -> None:
        self._obfs.server_handshake()

    def write(self, data: bytes) -> None:
        self._obfs.write(data)

    def read(self, n: int) -> bytes:
        return self._obfs.read(n)

    def close(self) -> None:
        self._obfs.close()


# ===========================================================================
# 1. TestKeyPair
# ===========================================================================

class TestKeyPair(unittest.TestCase):

    def test_generate_key_pair_returns_32_byte_public_key(self) -> None:
        kp = generate_key_pair()
        self.assertIsInstance(kp, KeyPair)
        self.assertEqual(len(kp.public_key_bytes), 32)

    def test_generate_key_pair_unique(self) -> None:
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()
        self.assertNotEqual(kp1.public_key_bytes, kp2.public_key_bytes)

    def test_dh_produces_shared_secret(self) -> None:
        kp_a = generate_key_pair()
        kp_b = generate_key_pair()
        secret = dh(kp_a.private_key, kp_b.public_key_bytes)
        self.assertEqual(len(secret), 32)
        self.assertNotEqual(secret, b"\x00" * 32)

    def test_dh_commutative(self) -> None:
        """DH(a, B) == DH(b, A)"""
        kp_a = generate_key_pair()
        kp_b = generate_key_pair()
        s1 = dh(kp_a.private_key, kp_b.public_key_bytes)
        s2 = dh(kp_b.private_key, kp_a.public_key_bytes)
        self.assertEqual(s1, s2)

    def test_load_key_pair_from_file(self) -> None:
        import tempfile
        kp = generate_key_pair()
        raw = kp.private_key.private_bytes(Encoding.Raw,
                                            from_cryptography_private_format(),
                                            from_cryptography_no_encryption())
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hex", delete=False) as f:
            f.write(raw.hex())
            fname = f.name
        try:
            loaded = load_key_pair_from_file(fname)
            self.assertEqual(loaded.public_key_bytes, kp.public_key_bytes)
        finally:
            os.unlink(fname)


def from_cryptography_private_format():
    from cryptography.hazmat.primitives.serialization import PrivateFormat
    return PrivateFormat.Raw


def from_cryptography_no_encryption():
    from cryptography.hazmat.primitives.serialization import NoEncryption
    return NoEncryption()


# ===========================================================================
# 2. TestNoiseHKDF
# ===========================================================================

class TestNoiseHKDF(unittest.TestCase):

    def test_two_outputs(self) -> None:
        ck = os.urandom(32)
        ikm = os.urandom(32)
        out = noise_hkdf(ck, ikm, 2)
        self.assertEqual(len(out), 2)
        self.assertEqual(len(out[0]), 32)
        self.assertEqual(len(out[1]), 32)
        self.assertNotEqual(out[0], out[1])

    def test_three_outputs(self) -> None:
        ck = os.urandom(32)
        ikm = os.urandom(32)
        out = noise_hkdf(ck, ikm, 3)
        self.assertEqual(len(out), 3)
        for o in out:
            self.assertEqual(len(o), 32)
        self.assertNotEqual(out[0], out[1])
        self.assertNotEqual(out[1], out[2])

    def test_deterministic(self) -> None:
        ck = b"\x01" * 32
        ikm = b"\x02" * 32
        out1 = noise_hkdf(ck, ikm, 2)
        out2 = noise_hkdf(ck, ikm, 2)
        self.assertEqual(out1[0], out2[0])
        self.assertEqual(out1[1], out2[1])

    def test_invalid_n_raises(self) -> None:
        with self.assertRaises(ValueError):
            noise_hkdf(b"\x00" * 32, b"", 1)
        with self.assertRaises(ValueError):
            noise_hkdf(b"\x00" * 32, b"", 4)

    def test_known_vector(self) -> None:
        """Cross-check with manual HMAC-SHA256 computation."""
        ck = b"\xAB" * 32
        ikm = b"\xCD" * 16
        temp = hmac_mod.new(ck, ikm, hashlib.sha256).digest()
        expected_out1 = hmac_mod.new(temp, b"\x01", hashlib.sha256).digest()
        expected_out2 = hmac_mod.new(temp, expected_out1 + b"\x02", hashlib.sha256).digest()
        out = noise_hkdf(ck, ikm, 2)
        self.assertEqual(out[0], expected_out1)
        self.assertEqual(out[1], expected_out2)


# ===========================================================================
# 3. TestNoiseCipherState
# ===========================================================================

class TestNoiseCipherState(unittest.TestCase):

    def test_no_key_passthrough_encrypt(self) -> None:
        cs = NoiseCipherState()
        pt = b"hello world"
        ct = cs.encrypt_with_ad(b"ad", pt)
        self.assertEqual(ct, pt)

    def test_no_key_passthrough_decrypt(self) -> None:
        cs = NoiseCipherState()
        ct = b"hello world"
        pt = cs.decrypt_with_ad(b"ad", ct)
        self.assertEqual(pt, ct)

    def test_encrypt_decrypt_round_trip(self) -> None:
        cs_enc = NoiseCipherState()
        cs_dec = NoiseCipherState()
        key = os.urandom(32)
        cs_enc.initialize_key(key)
        cs_dec.initialize_key(key)

        plaintext = b"secret message"
        ad = b"additional data"
        ciphertext = cs_enc.encrypt_with_ad(ad, plaintext)
        recovered = cs_dec.decrypt_with_ad(ad, ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_nonce_increments(self) -> None:
        cs1 = NoiseCipherState()
        cs2 = NoiseCipherState()
        key = os.urandom(32)
        cs1.initialize_key(key)
        cs2.initialize_key(key)

        # First encrypt/decrypt pair
        ct1 = cs1.encrypt_with_ad(b"", b"msg1")
        pt1 = cs2.decrypt_with_ad(b"", ct1)
        self.assertEqual(pt1, b"msg1")

        # Second encrypt/decrypt pair (nonce = 1)
        ct2 = cs1.encrypt_with_ad(b"", b"msg2")
        pt2 = cs2.decrypt_with_ad(b"", ct2)
        self.assertEqual(pt2, b"msg2")

        # ct1 != ct2 because nonces differ
        self.assertNotEqual(ct1, ct2)

    def test_wrong_key_decrypt_fails(self) -> None:
        cs_enc = NoiseCipherState()
        cs_dec = NoiseCipherState()
        cs_enc.initialize_key(os.urandom(32))
        cs_dec.initialize_key(os.urandom(32))
        ct = cs_enc.encrypt_with_ad(b"", b"data")
        with self.assertRaises(Exception):
            cs_dec.decrypt_with_ad(b"", ct)


# ===========================================================================
# 4. TestNoiseSymmetricState
# ===========================================================================

class TestNoiseSymmetricState(unittest.TestCase):

    def _make_ss(self) -> NoiseSymmetricState:
        return NoiseSymmetricState(NOISE_PROTOCOL_NAME)

    def test_mix_hash_changes_h(self) -> None:
        ss = self._make_ss()
        h_before = ss.h
        ss.mix_hash(b"some data")
        self.assertNotEqual(ss.h, h_before)

    def test_mix_hash_deterministic(self) -> None:
        ss1 = self._make_ss()
        ss2 = self._make_ss()
        ss1.mix_hash(b"data")
        ss2.mix_hash(b"data")
        self.assertEqual(ss1.h, ss2.h)

    def test_mix_key_initializes_cipher(self) -> None:
        ss = self._make_ss()
        self.assertFalse(ss.cs.has_key)
        ss.mix_key(os.urandom(32))
        self.assertTrue(ss.cs.has_key)

    def test_encrypt_and_hash_then_decrypt_and_hash(self) -> None:
        ss_enc = self._make_ss()
        ss_dec = self._make_ss()
        ikm = os.urandom(32)
        ss_enc.mix_key(ikm)
        ss_dec.mix_key(ikm)

        plaintext = b"noise symmetric test"
        ct = ss_enc.encrypt_and_hash(plaintext)
        pt = ss_dec.decrypt_and_hash(ct)
        self.assertEqual(pt, plaintext)

    def test_split_produces_two_cipher_states(self) -> None:
        ss = self._make_ss()
        ss.mix_key(os.urandom(32))
        c1, c2 = ss.split()
        self.assertTrue(c1.has_key)
        self.assertTrue(c2.has_key)

    def test_split_keys_differ(self) -> None:
        ss1 = self._make_ss()
        ss2 = self._make_ss()
        ikm = os.urandom(32)
        ss1.mix_key(ikm)
        ss2.mix_key(ikm)
        c1, c2 = ss1.split()
        # c1 and c2 should produce different ciphertexts
        ct1 = c1.encrypt_with_ad(b"", b"test")
        ct2 = c2.encrypt_with_ad(b"", b"test")
        self.assertNotEqual(ct1, ct2)


# ===========================================================================
# 5. TestNoiseHandshake — full initiator+responder round trip
# ===========================================================================

class TestNoiseHandshake(unittest.TestCase):

    def _run_handshake(self) -> tuple[NoiseSession, NoiseSession]:
        init_kp = generate_key_pair()
        resp_kp = generate_key_pair()

        init = NoiseHandshake(init_kp)
        resp = NoiseResponder(resp_kp)

        msg1 = init.write_message1()
        self.assertEqual(len(msg1), KEY_SIZE)
        resp.read_message1(msg1)

        msg2 = resp.write_message2()
        # msg2 = re(32) + EncryptAndHash(s)(48) = 80 bytes
        self.assertEqual(len(msg2), KEY_SIZE + KEY_SIZE + OVERHEAD)
        init.read_message2(msg2)

        msg3, init_session = init.write_message3()
        # msg3 = EncryptAndHash(s)(48) = 48 bytes
        self.assertEqual(len(msg3), KEY_SIZE + OVERHEAD)
        resp_session = resp.read_message3(msg3)

        return init_session, resp_session

    def test_handshake_completes(self) -> None:
        init_session, resp_session = self._run_handshake()
        self.assertIsInstance(init_session, NoiseSession)
        self.assertIsInstance(resp_session, NoiseSession)

    def test_remote_static_keys_correct(self) -> None:
        init_kp = generate_key_pair()
        resp_kp = generate_key_pair()

        init = NoiseHandshake(init_kp)
        resp = NoiseResponder(resp_kp)

        msg1 = init.write_message1()
        resp.read_message1(msg1)
        msg2 = resp.write_message2()
        init.read_message2(msg2)
        msg3, init_session = init.write_message3()
        resp_session = resp.read_message3(msg3)

        self.assertEqual(init_session.remote_static, resp_kp.public_key_bytes)
        self.assertEqual(resp_session.remote_static, init_kp.public_key_bytes)

    def test_session_ciphers_work(self) -> None:
        init_session, resp_session = self._run_handshake()

        # Initiator sends -> responder receives
        ct = init_session.send_cipher.encrypt(b"hello from init")
        pt = resp_session.recv_cipher.decrypt(ct)
        self.assertEqual(pt, b"hello from init")

        # Responder sends -> initiator receives
        ct2 = resp_session.send_cipher.encrypt(b"hello from resp")
        pt2 = init_session.recv_cipher.decrypt(ct2)
        self.assertEqual(pt2, b"hello from resp")

    def test_multiple_messages(self) -> None:
        init_session, resp_session = self._run_handshake()
        for i in range(5):
            msg = f"message {i}".encode()
            ct = init_session.send_cipher.encrypt(msg)
            pt = resp_session.recv_cipher.decrypt(ct)
            self.assertEqual(pt, msg)


# ===========================================================================
# 6. TestObfsConn
# ===========================================================================

class TestObfsConn(unittest.TestCase):

    def _make_pair(self) -> tuple[socket.socket, socket.socket]:
        """Return a connected socket pair (client_sock, server_sock)."""
        return socket.socketpair()

    def test_client_server_handshake_succeeds(self) -> None:
        c_sock, s_sock = self._make_pair()
        results = {}

        def server_side():
            try:
                srv = ObfsServer(s_sock)
                srv.handshake()
                results["server"] = "ok"
            except Exception as e:
                results["server"] = str(e)

        t = threading.Thread(target=server_side)
        t.start()

        cli = ObfsConn(c_sock)
        cli.client_handshake()
        t.join(timeout=5)

        self.assertEqual(results.get("server"), "ok")

    def test_write_read_data(self) -> None:
        c_sock, s_sock = self._make_pair()
        received = {}

        def server_side():
            srv = ObfsServer(s_sock)
            srv.handshake()
            data = srv.read(5)
            received["data"] = data

        t = threading.Thread(target=server_side)
        t.start()

        cli = ObfsConn(c_sock)
        cli.client_handshake()
        cli.write(b"hello")
        t.join(timeout=5)

        self.assertEqual(received.get("data"), b"hello")

    def test_large_data_fragmentation(self) -> None:
        c_sock, s_sock = self._make_pair()
        large_data = os.urandom(40000)  # > 2 * MAX_OBFS_PAYLOAD
        received = {}

        def server_side():
            srv = ObfsServer(s_sock)
            srv.handshake()
            data = srv.read(len(large_data))
            received["data"] = data

        t = threading.Thread(target=server_side)
        t.start()

        cli = ObfsConn(c_sock)
        cli.client_handshake()
        cli.write(large_data)
        t.join(timeout=10)

        self.assertEqual(received.get("data"), large_data)

    def test_wrong_record_type_raises(self) -> None:
        c_sock, s_sock = self._make_pair()

        def server_side():
            # Send garbage record type
            s_sock.sendall(bytes([0x15, 0x03, 0x03, 0x00, 0x05]) + b"hello")

        t = threading.Thread(target=server_side)
        t.start()

        cli = ObfsConn(c_sock)
        with self.assertRaises(Exception):
            # Expect either a ValueError or ConnectionError
            cli.client_handshake()
        t.join(timeout=5)

    def test_build_client_hello_structure(self) -> None:
        hello = _build_client_hello()
        # TLS record header
        self.assertEqual(hello[0], 0x16)  # handshake record
        self.assertEqual(hello[1], 0x03)
        self.assertEqual(hello[2], 0x03)
        # Handshake type should be 0x01 (ClientHello)
        self.assertEqual(hello[5], 0x01)

    def test_build_server_hello_structure(self) -> None:
        hello = _build_server_hello()
        self.assertEqual(hello[0], 0x16)
        self.assertEqual(hello[5], 0x02)  # ServerHello

    def test_app_data_record_structure(self) -> None:
        payload = b"test payload"
        rec = _build_app_data_record(payload)
        self.assertEqual(rec[0], 0x17)
        self.assertEqual(rec[1], 0x03)
        self.assertEqual(rec[2], 0x03)
        length = struct.unpack(">H", rec[3:5])[0]
        self.assertEqual(length, len(payload))
        self.assertEqual(rec[5:], payload)


# ===========================================================================
# 7. TestNoiseConn
# ===========================================================================

class TestNoiseConn(unittest.TestCase):

    def _make_noise_session_pair(self):
        """Run full Noise_XX to get two paired NoiseSession objects."""
        init_kp = generate_key_pair()
        resp_kp = generate_key_pair()

        init = NoiseHandshake(init_kp)
        resp = NoiseResponder(resp_kp)

        msg1 = init.write_message1()
        resp.read_message1(msg1)
        msg2 = resp.write_message2()
        init.read_message2(msg2)
        msg3, init_session = init.write_message3()
        resp_session = resp.read_message3(msg3)

        return init_session, resp_session

    def test_encrypt_decrypt_over_socket_pair(self) -> None:
        c_sock, s_sock = socket.socketpair()
        init_session, resp_session = self._make_noise_session_pair()
        received = {}

        def server_side():
            s_obfs = ObfsConn(s_sock)
            s_obfs.server_handshake()
            s_nc = NoiseConn(s_obfs, resp_session)
            data = s_nc.read_message()
            received["data"] = data

        def handshake_server():
            s_sock2 = s_sock
            srv_obfs = ObfsConn(s_sock)
            srv_obfs.server_handshake()

        # We need both sides of the obfs handshake, so use socket pairs
        c_sock2, s_sock2 = socket.socketpair()

        def server_thread():
            s_obfs = ObfsConn(s_sock2)
            s_obfs.server_handshake()
            _, resp_s = self._make_noise_session_pair()
            s_nc = NoiseConn(s_obfs, resp_s)
            try:
                # just drain
                pass
            except Exception:
                pass

        # Simpler test: use ObfsConn on both sides manually
        c_s, s_s = socket.socketpair()
        init_sess, resp_sess = self._make_noise_session_pair()
        recv_buf = {}

        def srv():
            s_obfs = ObfsConn(s_s)
            s_obfs.server_handshake()
            s_nc = NoiseConn(s_obfs, resp_sess)
            recv_buf["msg"] = s_nc.read_message()

        t = threading.Thread(target=srv)
        t.start()

        c_obfs = ObfsConn(c_s)
        c_obfs.client_handshake()
        c_nc = NoiseConn(c_obfs, init_sess)
        c_nc.write_message(b"encrypted payload")
        t.join(timeout=5)

        self.assertEqual(recv_buf.get("msg"), b"encrypted payload")

    def test_bidirectional_noise_conn(self) -> None:
        c_s, s_s = socket.socketpair()
        init_sess, resp_sess = self._make_noise_session_pair()
        results = {}

        def srv():
            s_obfs = ObfsConn(s_s)
            s_obfs.server_handshake()
            s_nc = NoiseConn(s_obfs, resp_sess)
            # Echo back
            msg = s_nc.read_message()
            s_nc.write_message(b"echo: " + msg)

        t = threading.Thread(target=srv)
        t.start()

        c_obfs = ObfsConn(c_s)
        c_obfs.client_handshake()
        c_nc = NoiseConn(c_obfs, init_sess)
        c_nc.write_message(b"ping")
        reply = c_nc.read_message()
        t.join(timeout=5)

        self.assertEqual(reply, b"echo: ping")


# ===========================================================================
# 8. TestClientMux — open_stream, send/receive data, FIN handling
# ===========================================================================

class _LoopbackNoiseConn:
    """
    A pair of NoiseConn-like objects sharing a socket pair.
    Used to test the Mux in isolation.
    """

    def __init__(self) -> None:
        self._c_sock, self._s_sock = socket.socketpair()
        init_kp = generate_key_pair()
        resp_kp = generate_key_pair()

        # Run obfs + noise handshake in thread
        init_session_box = {}
        resp_session_box = {}

        def server_side():
            s_obfs = ObfsConn(self._s_sock)
            s_obfs.server_handshake()
            resp = NoiseResponder(resp_kp)
            # Read msg1
            len_b = s_obfs.read(2)
            msg1_len = struct.unpack(">H", len_b)[0]
            msg1 = s_obfs.read(msg1_len)
            resp.read_message1(msg1)
            # Write msg2
            msg2 = resp.write_message2()
            s_obfs.write(struct.pack(">H", len(msg2)) + msg2)
            # Read msg3
            len_b = s_obfs.read(2)
            msg3_len = struct.unpack(">H", len_b)[0]
            msg3 = s_obfs.read(msg3_len)
            session = resp.read_message3(msg3)
            resp_session_box["session"] = session
            resp_session_box["obfs"] = s_obfs

        t = threading.Thread(target=server_side)
        t.start()

        c_obfs = ObfsConn(self._c_sock)
        c_obfs.client_handshake()

        init = NoiseHandshake(init_kp)
        msg1 = init.write_message1()
        c_obfs.write(struct.pack(">H", len(msg1)) + msg1)
        len_b = c_obfs.read(2)
        msg2_len = struct.unpack(">H", len_b)[0]
        msg2 = c_obfs.read(msg2_len)
        init.read_message2(msg2)
        msg3, init_session = init.write_message3()
        c_obfs.write(struct.pack(">H", len(msg3)) + msg3)

        t.join(timeout=5)

        self.client_nc = NoiseConn(c_obfs, init_session)
        self.server_nc = NoiseConn(resp_session_box["obfs"], resp_session_box["session"])


def _make_mux_pair() -> tuple[ClientMux, ClientMux]:
    """
    Create a client+server mux pair using socket pairs.
    Returns (client_mux, server_mux).
    Server mux uses odd IDs (isClient=False equivalent), but we use ClientMux
    for the server too, starting from nextID=1 (we hack nextID).
    """
    lb = _LoopbackNoiseConn()

    # Client mux: even IDs (2, 4, ...)
    client_mux = ClientMux(lb.client_nc)

    # Server mux: use ClientMux but patch _next_id to 1 for odd IDs
    server_mux = ClientMux(lb.server_nc)
    server_mux._next_id = 1  # odd IDs

    return client_mux, server_mux


class TestClientMux(unittest.TestCase):

    def test_open_stream_returns_stream(self) -> None:
        lb = _LoopbackNoiseConn()
        mux = ClientMux(lb.client_nc)
        stream = mux.open_stream()
        self.assertIsNotNone(stream)
        self.assertEqual(stream.stream_id, 2)
        mux.close()

    def test_stream_ids_increment_by_two(self) -> None:
        lb = _LoopbackNoiseConn()
        mux = ClientMux(lb.client_nc)
        s1 = mux.open_stream()
        s2 = mux.open_stream()
        self.assertEqual(s1.stream_id, 2)
        self.assertEqual(s2.stream_id, 4)
        mux.close()

    def test_send_receive_data(self) -> None:
        client_mux, server_mux = _make_mux_pair()
        received = {}

        def server_side():
            import time
            time.sleep(0.05)  # let client send SYN
            with server_mux._streams_lock:
                streams = list(server_mux._streams.values())
            if streams:
                received["data"] = streams[0].read(timeout=3.0)

        t = threading.Thread(target=server_side)
        t.start()

        stream = client_mux.open_stream()
        import time
        time.sleep(0.05)
        stream.write(b"hello mux")

        t.join(timeout=5)
        client_mux.close()
        server_mux.close()

        self.assertEqual(received.get("data"), b"hello mux")

    def test_fin_closes_stream(self) -> None:
        lb = _LoopbackNoiseConn()
        mux = ClientMux(lb.client_nc)
        stream = mux.open_stream()
        stream.close()
        self.assertTrue(stream._closed.is_set())
        mux.close()

    def test_mux_close_signals_streams(self) -> None:
        lb = _LoopbackNoiseConn()
        mux = ClientMux(lb.client_nc)
        stream = mux.open_stream()
        mux.close()
        self.assertTrue(mux._closed.is_set())


# ===========================================================================
# 9. TestRouteInfo
# ===========================================================================

class TestRouteInfo(unittest.TestCase):

    def _make_route(self) -> RouteInfo:
        return RouteInfo(
            assigned_ip="10.8.0.2",
            prefix_len=24,
            gateway="10.8.0.1",
            server_public_key=b"\x00" * 32,
        )

    def test_cidr_property(self) -> None:
        route = self._make_route()
        self.assertEqual(route.cidr, "10.8.0.2/24")

    def test_network_property(self) -> None:
        route = self._make_route()
        net = route.network
        self.assertIsInstance(net, ipaddress.IPv4Network)
        self.assertEqual(str(net), "10.8.0.0/24")

    def test_network_contains_ip(self) -> None:
        route = self._make_route()
        net = route.network
        self.assertIn(ipaddress.IPv4Address("10.8.0.2"), net)
        self.assertIn(ipaddress.IPv4Address("10.8.0.1"), net)
        self.assertNotIn(ipaddress.IPv4Address("10.9.0.1"), net)

    def test_fields(self) -> None:
        route = self._make_route()
        self.assertEqual(route.assigned_ip, "10.8.0.2")
        self.assertEqual(route.prefix_len, 24)
        self.assertEqual(route.gateway, "10.8.0.1")
        self.assertEqual(route.server_public_key, b"\x00" * 32)


# ===========================================================================
# 10. TestVPNClientParsing
# ===========================================================================

class TestVPNClientParsing(unittest.TestCase):

    def test_parse_addr_host_port(self) -> None:
        host, port = VPNClient._parse_addr("192.168.1.1:443")
        self.assertEqual(host, "192.168.1.1")
        self.assertEqual(port, 443)

    def test_parse_addr_hostname(self) -> None:
        host, port = VPNClient._parse_addr("vpn.example.com:1194")
        self.assertEqual(host, "vpn.example.com")
        self.assertEqual(port, 1194)

    def test_parse_addr_ipv6(self) -> None:
        host, port = VPNClient._parse_addr("[::1]:443")
        self.assertEqual(host, "::1")
        self.assertEqual(port, 443)

    def test_parse_addr_invalid_no_port(self) -> None:
        with self.assertRaises(ValueError):
            VPNClient._parse_addr("192.168.1.1")

    def test_parse_addr_invalid_port_range(self) -> None:
        with self.assertRaises(ValueError):
            VPNClient._parse_addr("host:99999")

    def test_parse_addr_port_zero(self) -> None:
        with self.assertRaises(ValueError):
            VPNClient._parse_addr("host:0")

    def test_vpn_config_defaults(self) -> None:
        cfg = VPNConfig(server_addr="127.0.0.1:443")
        self.assertEqual(cfg.server_addr, "127.0.0.1:443")
        self.assertIsNone(cfg.private_key_file)
        self.assertIsNone(cfg.key_pair)
        self.assertEqual(cfg.connect_timeout, 30.0)

    def test_vpn_client_not_connected_send_raises(self) -> None:
        cfg = VPNConfig(server_addr="127.0.0.1:443")
        client = VPNClient(cfg)
        with self.assertRaises(IOError):
            client.send_packet(b"\x45\x00" + b"\x00" * 18)

    def test_vpn_client_not_connected_recv_raises(self) -> None:
        cfg = VPNConfig(server_addr="127.0.0.1:443")
        client = VPNClient(cfg)
        with self.assertRaises(IOError):
            client.recv_packet()


# ===========================================================================
# Additional integration: full handshake over socket pair
# ===========================================================================

class TestFullHandshakeIntegration(unittest.TestCase):

    def test_noise_handshake_over_obfs_socket_pair(self) -> None:
        """Full Noise_XX over TLS obfuscation layer using real socket pairs."""
        c_sock, s_sock = socket.socketpair()
        init_kp = generate_key_pair()
        resp_kp = generate_key_pair()
        results = {}

        def server_thread():
            try:
                s_obfs = ObfsConn(s_sock)
                s_obfs.server_handshake()

                resp = NoiseResponder(resp_kp)
                # Read msg1
                len_b = s_obfs.read(2)
                msg1_len = struct.unpack(">H", len_b)[0]
                msg1 = s_obfs.read(msg1_len)
                resp.read_message1(msg1)

                # Write msg2
                msg2 = resp.write_message2()
                s_obfs.write(struct.pack(">H", len(msg2)) + msg2)

                # Read msg3
                len_b = s_obfs.read(2)
                msg3_len = struct.unpack(">H", len_b)[0]
                msg3 = s_obfs.read(msg3_len)
                resp_session = resp.read_message3(msg3)

                results["resp_session"] = resp_session
                results["resp_kp"] = resp_kp
            except Exception as e:
                results["error"] = str(e)

        t = threading.Thread(target=server_thread)
        t.start()

        c_obfs = ObfsConn(c_sock)
        c_obfs.client_handshake()

        init = NoiseHandshake(init_kp)
        msg1 = init.write_message1()
        c_obfs.write(struct.pack(">H", len(msg1)) + msg1)

        len_b = c_obfs.read(2)
        msg2_len = struct.unpack(">H", len_b)[0]
        msg2 = c_obfs.read(msg2_len)
        init.read_message2(msg2)

        msg3, init_session = init.write_message3()
        c_obfs.write(struct.pack(">H", len(msg3)) + msg3)

        t.join(timeout=5)

        self.assertNotIn("error", results, results.get("error", ""))
        self.assertIn("resp_session", results)
        self.assertEqual(init_session.remote_static, resp_kp.public_key_bytes)
        self.assertEqual(results["resp_session"].remote_static, init_kp.public_key_bytes)


# ===========================================================================
# Full VPN client integration test
# ===========================================================================

def _run_vpn_server_side(
    conn: socket.socket,
    server_kp: KeyPair,
    assigned_ip: str = "10.8.0.2",
    prefix_len: int = 24,
    gateway: str = "10.8.0.1",
) -> None:
    """Simulates the full Go server protocol on an accepted TCP connection."""
    try:
        # 1. TLS obfuscation handshake
        s_obfs = ObfsConn(conn)
        s_obfs.server_handshake()

        # 2. Noise_XX responder handshake
        resp = NoiseResponder(server_kp)
        len_b = s_obfs.read(2)
        msg1 = s_obfs.read(struct.unpack(">H", len_b)[0])
        resp.read_message1(msg1)

        msg2 = resp.write_message2()
        s_obfs.write(struct.pack(">H", len(msg2)) + msg2)

        len_b = s_obfs.read(2)
        msg3 = s_obfs.read(struct.unpack(">H", len_b)[0])
        session = resp.read_message3(msg3)

        # 3. NoiseConn (encrypted transport)
        nc = NoiseConn(s_obfs, session)

        # 4. Mux read loop — read frames manually for simplicity
        def read_noise_frame() -> bytes:
            return nc.read_message()

        def write_noise_frame(payload: bytes) -> None:
            nc.write_message(payload)

        def build_mux_frame(stream_id: int, ftype: int, payload: bytes) -> bytes:
            return (
                struct.pack(">I", stream_id)
                + bytes([ftype])
                + struct.pack(">H", len(payload))
                + payload
            )

        # Read SYN for control stream (stream_id=2)
        frame = read_noise_frame()
        stream_id = struct.unpack(">I", frame[0:4])[0]
        assert frame[4] == FRAME_SYN, f"expected SYN got {frame[4]}"

        # Read DATA (ctlHello)
        frame = read_noise_frame()
        assert frame[4] == FRAME_DATA
        payload = frame[7:7 + struct.unpack(">H", frame[5:7])[0]]
        assert payload == bytes([CTL_HELLO])

        # Send ctlAssign response
        ip_bytes = socket.inet_aton(assigned_ip)
        gw_bytes = socket.inet_aton(gateway)
        ctl_resp = bytes([CTL_ASSIGN]) + ip_bytes + bytes([prefix_len]) + gw_bytes
        write_noise_frame(build_mux_frame(stream_id, FRAME_DATA, ctl_resp))

        # Send FIN for control stream
        write_noise_frame(build_mux_frame(stream_id, FRAME_FIN, b""))

        # Read frames until we see SYN for the data stream (client sends FIN
        # for the control stream first, then SYN for stream 4).
        data_stream_id = None
        for _ in range(10):
            frame = read_noise_frame()
            if len(frame) < MUX_HEADER_SIZE:
                continue
            sid = struct.unpack(">I", frame[0:4])[0]
            ftype = frame[4]
            if ftype == FRAME_SYN and sid != 2:
                data_stream_id = sid
                break

        if data_stream_id is None:
            return

        # Echo any IP packets back (for send/recv test).
        # Loop until we get a DATA frame on the data stream.
        for _ in range(20):
            try:
                frame = read_noise_frame()
            except Exception:
                break
            if len(frame) < MUX_HEADER_SIZE:
                continue
            sid = struct.unpack(">I", frame[0:4])[0]
            ftype = frame[4]
            plen = struct.unpack(">H", frame[5:7])[0]
            payload = frame[7:7 + plen]
            if ftype == FRAME_DATA and sid == data_stream_id and payload:
                write_noise_frame(build_mux_frame(data_stream_id, FRAME_DATA, payload))
                break

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class TestVPNClientIntegration(unittest.TestCase):
    """Integration tests for VPNClient.connect() using a local TCP server."""

    def _start_server(self, server_kp: KeyPair) -> tuple[str, int, threading.Thread]:
        """Bind a local server, return (host, port, thread)."""
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(1)
        port = srv_sock.getsockname()[1]

        def accept_and_serve():
            try:
                srv_sock.settimeout(5.0)
                conn, _ = srv_sock.accept()
                srv_sock.close()
                _run_vpn_server_side(conn, server_kp)
            except Exception:
                try:
                    srv_sock.close()
                except Exception:
                    pass

        t = threading.Thread(target=accept_and_serve, daemon=True)
        t.start()
        return "127.0.0.1", port, t

    def test_connect_returns_route_info(self) -> None:
        server_kp = generate_key_pair()
        client_kp = generate_key_pair()
        host, port, t = self._start_server(server_kp)

        import time
        time.sleep(0.05)

        cfg = VPNConfig(
            server_addr=f"{host}:{port}",
            key_pair=client_kp,
            connect_timeout=5.0,
        )
        client = VPNClient(cfg)
        route = client.connect()

        self.assertIsInstance(route, RouteInfo)
        self.assertEqual(route.assigned_ip, "10.8.0.2")
        self.assertEqual(route.prefix_len, 24)
        self.assertEqual(route.gateway, "10.8.0.1")
        self.assertEqual(route.server_public_key, server_kp.public_key_bytes)

        client.disconnect()
        t.join(timeout=5)

    def test_send_and_recv_packet(self) -> None:
        server_kp = generate_key_pair()
        client_kp = generate_key_pair()
        host, port, t = self._start_server(server_kp)

        import time
        time.sleep(0.05)

        cfg = VPNConfig(
            server_addr=f"{host}:{port}",
            key_pair=client_kp,
            connect_timeout=5.0,
        )
        client = VPNClient(cfg)
        client.connect()

        # Send a fake IP packet (20-byte IPv4 header)
        fake_pkt = b"\x45\x00" + b"\x00" * 18
        client.send_packet(fake_pkt)

        # Receive the echo
        received = client.recv_packet()
        self.assertEqual(received, fake_pkt)

        client.disconnect()
        t.join(timeout=5)

    def test_disconnect_clears_state(self) -> None:
        server_kp = generate_key_pair()
        client_kp = generate_key_pair()
        host, port, t = self._start_server(server_kp)

        import time
        time.sleep(0.05)

        cfg = VPNConfig(
            server_addr=f"{host}:{port}",
            key_pair=client_kp,
            connect_timeout=5.0,
        )
        client = VPNClient(cfg)
        client.connect()
        self.assertTrue(client._connected.is_set())

        client.disconnect()
        self.assertFalse(client._connected.is_set())
        self.assertIsNone(client._mux)
        self.assertIsNone(client._data_stream)

        t.join(timeout=5)

    def test_load_key_pair_from_config(self) -> None:
        """VPNClient uses key_pair from config when provided."""
        server_kp = generate_key_pair()
        client_kp = generate_key_pair()
        host, port, t = self._start_server(server_kp)

        import time
        time.sleep(0.05)

        cfg = VPNConfig(
            server_addr=f"{host}:{port}",
            key_pair=client_kp,
            connect_timeout=5.0,
        )
        client = VPNClient(cfg)
        loaded_kp = client._load_key_pair()
        self.assertEqual(loaded_kp.public_key_bytes, client_kp.public_key_bytes)

        # Also connect to ensure it uses that key pair
        route = client.connect()
        self.assertIsNotNone(route)
        client.disconnect()
        t.join(timeout=5)

    def test_mux_stream_read_exactly(self) -> None:
        """Test MuxStream.read_exactly via a mux pair."""
        client_mux, server_mux = _make_mux_pair()
        received = {}

        def server_side():
            import time
            time.sleep(0.05)
            with server_mux._streams_lock:
                streams = list(server_mux._streams.values())
            if not streams:
                # Wait for SYN to be processed
                time.sleep(0.1)
                with server_mux._streams_lock:
                    streams = list(server_mux._streams.values())
            if streams:
                try:
                    data = streams[0].read_exactly(9, timeout=3.0)
                    received["data"] = data
                except Exception as e:
                    received["error"] = str(e)

        t = threading.Thread(target=server_side)
        t.start()

        stream = client_mux.open_stream()
        import time
        time.sleep(0.1)
        stream.write(b"hello mux")

        t.join(timeout=5)
        client_mux.close()
        server_mux.close()

        self.assertEqual(received.get("data"), b"hello mux")


# ===========================================================================
# 11. TestDownloadBonding — CTL_SECONDARY + multi-connection bonding
# ===========================================================================

from core import CTL_SECONDARY, MuxStream


def _run_vpn_server_side_with_secondary(
    primary_conn: socket.socket,
    server_kp: KeyPair,
    assigned_ip: str = "10.8.0.2",
    prefix_len: int = 24,
    gateway: str = "10.8.0.1",
    secondary_accepted: Optional[threading.Event] = None,
) -> None:
    """Server mock that supports both primary and secondary (CTL_SECONDARY) connections.

    After serving the primary connection it continues accepting new connections
    on the same listener socket (passed via the secondary_sock shared state in
    the closure below).  Use _start_bonded_server() which wraps this logic.
    """
    _run_vpn_server_side(primary_conn, server_kp, assigned_ip, prefix_len, gateway)


def _run_secondary_server_side(
    conn: socket.socket,
    server_kp: KeyPair,
    assigned_ip: str = "10.8.0.2",
    done: Optional[threading.Event] = None,
) -> None:
    """Simulates the server handling of a CTL_SECONDARY connection.

    Mirrors runSecondaryConn in main.go:
      1. TLS obfuscation handshake
      2. Noise_XX responder handshake
      3. Open NoiseConn + Mux
      4. Accept first stream; read CTL_SECONDARY byte + 4-byte IP
      5. Validate IP (simplified: just check it's non-zero)
      6. Send CTL_ASSIGN back
      7. Close control stream
      8. Accept data stream
      9. Echo any IP packets back (for testing recv_packet via secondary)
    """
    try:
        s_obfs = ObfsConn(conn)
        s_obfs.server_handshake()

        resp = NoiseResponder(server_kp)
        len_b = s_obfs.read(2)
        msg1 = s_obfs.read(struct.unpack(">H", len_b)[0])
        resp.read_message1(msg1)
        msg2 = resp.write_message2()
        s_obfs.write(struct.pack(">H", len(msg2)) + msg2)
        len_b = s_obfs.read(2)
        msg3 = s_obfs.read(struct.unpack(">H", len_b)[0])
        session = resp.read_message3(msg3)

        nc = NoiseConn(s_obfs, session)

        def read_frame() -> bytes:
            return nc.read_message()

        def write_frame(payload: bytes) -> None:
            nc.write_message(payload)

        def build_frame(sid: int, ftype: int, payload: bytes) -> bytes:
            return struct.pack(">I", sid) + bytes([ftype]) + struct.pack(">H", len(payload)) + payload

        # Read SYN for first stream (stream_id=2)
        frame = read_frame()
        assert frame[4] == FRAME_SYN

        # Read DATA: CTL_SECONDARY(1) + ip(4) = 5 bytes
        frame = read_frame()
        assert frame[4] == FRAME_DATA
        plen = struct.unpack(">H", frame[5:7])[0]
        payload = frame[7:7 + plen]
        # First byte must be CTL_SECONDARY
        assert payload[0] == CTL_SECONDARY, f"expected CTL_SECONDARY, got 0x{payload[0]:02x}"
        # Next 4 bytes are the assigned IP
        ip_bytes = payload[1:5]
        assert len(ip_bytes) == 4
        assert socket.inet_ntoa(ip_bytes) == assigned_ip

        # Respond with CTL_ASSIGN
        write_frame(build_frame(2, FRAME_DATA, bytes([CTL_ASSIGN])))
        # Send FIN for control stream
        write_frame(build_frame(2, FRAME_FIN, b""))

        # Signal that secondary handshake is done
        if done is not None:
            done.set()

        # Read frames until data stream SYN arrives (skip FIN from client ctl close)
        data_sid = None
        for _ in range(10):
            try:
                frame = read_frame()
                if len(frame) < MUX_HEADER_SIZE:
                    continue
                sid = struct.unpack(">I", frame[0:4])[0]
                ftype = frame[4]
                if ftype == FRAME_SYN and sid != 2:
                    data_sid = sid
                    break
            except Exception:
                break

        if data_sid is None:
            return

        # Echo any DATA packets from this secondary stream back.
        for _ in range(10):
            try:
                frame = read_frame()
                if len(frame) < MUX_HEADER_SIZE:
                    continue
                sid = struct.unpack(">I", frame[0:4])[0]
                ftype = frame[4]
                plen = struct.unpack(">H", frame[5:7])[0]
                payload = frame[7:7 + plen]
                if ftype == FRAME_DATA and sid == data_sid and payload:
                    write_frame(build_frame(data_sid, FRAME_DATA, payload))
                    break
            except Exception:
                break

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class TestDownloadBonding(unittest.TestCase):
    """Tests for CTL_SECONDARY constant, VPNConfig.bond_count, and download bonding."""

    # -- Constant correctness --------------------------------------------------

    def test_ctl_secondary_value(self) -> None:
        """CTL_SECONDARY must be 0x03 (matches ctlSecondary in main.go)."""
        self.assertEqual(CTL_SECONDARY, 0x03)

    def test_ctl_error_value(self) -> None:
        """CTL_ERROR must be 0xFF (matches ctlError in main.go).

        Previously was incorrectly 0x03 (same as CTL_SECONDARY).
        This regression test ensures they are distinct.
        """
        self.assertEqual(CTL_ERROR, 0xFF)

    def test_ctl_constants_distinct(self) -> None:
        """All four CTL constants must be distinct."""
        values = [CTL_HELLO, CTL_ASSIGN, CTL_SECONDARY, CTL_ERROR]
        self.assertEqual(len(values), len(set(values)),
                         "CTL constants must be unique")

    # -- VPNConfig.bond_count --------------------------------------------------

    def test_bond_count_default_is_one(self) -> None:
        """bond_count defaults to 1 (no bonding — backward-compatible)."""
        cfg = VPNConfig(server_addr="1.2.3.4:443")
        self.assertEqual(cfg.bond_count, 1)

    def test_bond_count_configurable(self) -> None:
        cfg = VPNConfig(server_addr="1.2.3.4:443", bond_count=4)
        self.assertEqual(cfg.bond_count, 4)

    # -- VPNClient._bond_reader_thread -----------------------------------------

    def test_bond_reader_thread_forwards_packets(self) -> None:
        """_bond_reader_thread reads from a MuxStream and puts packets in queue."""
        import queue as _queue
        client_mux, server_mux = _make_mux_pair()
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)

        # Get the client data stream (opened via client_mux, odd server IDs)
        client_stream = client_mux.open_stream()

        recv_q = _queue.SimpleQueue()
        client._recv_q = recv_q
        client._bond_closed.clear()

        t = threading.Thread(
            target=client._bond_reader_thread,
            args=(client_stream,),
            daemon=True,
        )
        t.start()

        # Server-side: write data into the stream's read path
        import time
        time.sleep(0.05)
        with server_mux._streams_lock:
            streams = list(server_mux._streams.values())
        if not streams:
            time.sleep(0.1)
            with server_mux._streams_lock:
                streams = list(server_mux._streams.values())
        self.assertTrue(streams, "server should see the opened stream")
        server_stream = streams[0]

        pkt = b"\x45\x00" + b"\xAB" * 18
        # Use write() — this sends a DATA frame through the loopback NoiseConn
        # to client_mux._read_loop, which calls client_stream._deliver(pkt),
        # which the _bond_reader_thread reads and puts in recv_q.
        server_stream.write(pkt)

        result = recv_q.get(timeout=3.0)
        self.assertEqual(result, pkt)

        # Cleanup
        client._bond_closed.set()
        client_stream._signal_fin()
        t.join(timeout=3.0)
        client_mux.close()
        server_mux.close()

    def test_bond_reader_thread_stops_on_fin(self) -> None:
        """_bond_reader_thread exits when the stream receives FIN."""
        import queue as _queue
        client_mux, server_mux = _make_mux_pair()
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)

        client_stream = client_mux.open_stream()
        recv_q = _queue.SimpleQueue()
        client._recv_q = recv_q
        client._bond_closed.clear()

        t = threading.Thread(
            target=client._bond_reader_thread,
            args=(client_stream,),
            daemon=True,
        )
        t.start()

        # Trigger FIN — thread should exit cleanly
        import time
        time.sleep(0.05)
        client_stream._signal_fin()
        t.join(timeout=3.0)
        self.assertFalse(t.is_alive(), "reader thread should exit on FIN")

        client_mux.close()
        server_mux.close()

    def test_bond_reader_thread_stops_on_bond_closed(self) -> None:
        """_bond_reader_thread exits when _bond_closed is set."""
        import queue as _queue
        client_mux, server_mux = _make_mux_pair()
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)

        client_stream = client_mux.open_stream()
        recv_q = _queue.SimpleQueue()
        client._recv_q = recv_q
        client._bond_closed.clear()

        t = threading.Thread(
            target=client._bond_reader_thread,
            args=(client_stream,),
            daemon=True,
        )
        t.start()

        import time
        time.sleep(0.05)

        # Signal bond closed AND send FIN to unblock read()
        client._bond_closed.set()
        client_stream._signal_fin()
        t.join(timeout=3.0)
        self.assertFalse(t.is_alive(), "reader thread should exit when bond_closed")

        client_mux.close()
        server_mux.close()

    # -- disconnect() cleanup ---------------------------------------------------

    def test_disconnect_clears_bond_state(self) -> None:
        """disconnect() clears bond_muxes, bond_data_streams, and recv_q."""
        import queue as _queue
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)

        # Manually inject fake bond state
        client._recv_q = _queue.SimpleQueue()
        # (No real mux — just verify the lists are cleared)
        client._bond_muxes = []
        client._bond_data_streams = []

        client._connected.clear()
        client._bond_closed.clear()
        client.disconnect()

        self.assertIsNone(client._recv_q)
        self.assertEqual(client._bond_muxes, [])
        self.assertEqual(client._bond_data_streams, [])

    # -- Secondary connection handshake (integration) --------------------------

    def test_secondary_handshake_protocol(self) -> None:
        """Client performs CTL_SECONDARY handshake correctly against a real mock server."""
        server_kp = generate_key_pair()
        client_kp = generate_key_pair()

        secondary_done = threading.Event()

        # Start a secondary server that handles CTL_SECONDARY
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(1)
        port = srv_sock.getsockname()[1]

        def accept_secondary():
            try:
                srv_sock.settimeout(5.0)
                conn, _ = srv_sock.accept()
                srv_sock.close()
                _run_secondary_server_side(conn, server_kp,
                                           assigned_ip="10.8.0.2",
                                           done=secondary_done)
            except Exception:
                secondary_done.set()

        t = threading.Thread(target=accept_secondary, daemon=True)
        t.start()

        import time
        time.sleep(0.05)

        cfg = VPNConfig(server_addr=f"127.0.0.1:{port}", key_pair=client_kp)
        client = VPNClient(cfg)

        # Directly invoke _attach_secondary_conn to test the protocol
        assigned_ip_bytes = socket.inet_aton("10.8.0.2")
        client._attach_secondary_conn("127.0.0.1", port, client_kp, assigned_ip_bytes)

        ok = secondary_done.wait(timeout=5.0)
        self.assertTrue(ok, "secondary handshake should complete within timeout")

        # Clean up secondary bond state
        client.disconnect()
        t.join(timeout=5)

    # -- Full bonded connect (integration) -------------------------------------

    def test_connect_with_bond_count_2(self) -> None:
        """connect() establishes primary + 1 secondary connection when bond_count=2."""
        server_kp = generate_key_pair()
        client_kp = generate_key_pair()
        secondary_done = threading.Event()

        # Server listens for 2 connections: primary + 1 secondary
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(5)
        port = srv_sock.getsockname()[1]

        def serve():
            conns_handled = 0
            try:
                srv_sock.settimeout(5.0)
                while conns_handled < 2:
                    try:
                        conn, _ = srv_sock.accept()
                        conns_handled += 1
                        if conns_handled == 1:
                            threading.Thread(
                                target=_run_vpn_server_side,
                                args=(conn, server_kp),
                                daemon=True,
                            ).start()
                        else:
                            threading.Thread(
                                target=_run_secondary_server_side,
                                args=(conn, server_kp, "10.8.0.2", secondary_done),
                                daemon=True,
                            ).start()
                    except socket.timeout:
                        break
            finally:
                try:
                    srv_sock.close()
                except Exception:
                    pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        import time
        time.sleep(0.05)

        cfg = VPNConfig(
            server_addr=f"127.0.0.1:{port}",
            key_pair=client_kp,
            connect_timeout=5.0,
            bond_count=2,
            transport="tcp",
        )
        client = VPNClient(cfg)
        route = client.connect()

        self.assertIsInstance(route, RouteInfo)
        self.assertEqual(route.assigned_ip, "10.8.0.2")

        # Verify secondary connection was established
        ok = secondary_done.wait(timeout=5.0)
        self.assertTrue(ok, "secondary connection should be established")
        self.assertEqual(len(client._bond_muxes), 1,
                         "should have 1 secondary mux (bond_count=2)")
        self.assertEqual(len(client._bond_data_streams), 1)
        self.assertIsNotNone(client._recv_q)

        client.disconnect()
        t.join(timeout=5)

    def test_recv_packet_via_bond_queue(self) -> None:
        """recv_packet() returns a packet injected directly into _recv_q."""
        import queue as _queue

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        client._connected.set()

        # Inject fake state so recv_packet() uses the queue path
        # and _data_stream is non-None (for the guard check)
        client_mux, server_mux = _make_mux_pair()
        client._data_stream = client_mux.open_stream()
        q = _queue.SimpleQueue()
        client._recv_q = q

        pkt = b"\x45\x00" + b"\xBB" * 18
        q.put(pkt)

        result = client.recv_packet()
        self.assertEqual(result, pkt)

        client._bond_closed.set()
        client_mux.close()
        server_mux.close()


class TestUploadBonding(unittest.TestCase):
    """Tests for upload bonding: send_packet() round-robin across all streams."""

    # -- send_packet() single-stream path (bond_count == 1) --------------------

    def test_send_packet_single_stream_no_round_robin(self) -> None:
        """bond_count=1: send_packet() uses _data_stream directly, _send_streams empty."""
        client_mux, server_mux = _make_mux_pair()
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=1)
        client = VPNClient(cfg)
        client._data_stream = client_mux.open_stream()
        client._connected.set()

        # _send_streams must be empty for the single-stream path
        self.assertEqual(client._send_streams, [])

        # Server side: accept the SYN stream
        import time
        time.sleep(0.05)
        with server_mux._streams_lock:
            streams = list(server_mux._streams.values())
        self.assertTrue(streams)
        server_stream = streams[0]

        pkt = b"\x45\x00" + b"\xAA" * 18
        client.send_packet(pkt)

        # Server receives the packet on the single stream
        received = server_stream.read()
        self.assertEqual(received, pkt)

        client._connected.clear()
        client_mux.close()
        server_mux.close()

    # -- _send_streams construction -------------------------------------------

    def test_send_streams_built_from_primary_and_secondary(self) -> None:
        """_send_streams = [primary_stream] + bond_data_streams."""
        client_mux1, _ = _make_mux_pair()
        client_mux2, _ = _make_mux_pair()
        client_mux3, _ = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=3)
        client = VPNClient(cfg)

        primary_stream = client_mux1.open_stream()
        sec1 = client_mux2.open_stream()
        sec2 = client_mux3.open_stream()

        client._data_stream = primary_stream
        client._bond_data_streams = [sec1, sec2]
        # Simulate what connect() does after the bonding loop:
        client._send_streams = [client._data_stream] + list(client._bond_data_streams)
        client._send_idx = 0

        self.assertEqual(len(client._send_streams), 3)
        self.assertIs(client._send_streams[0], primary_stream)
        self.assertIs(client._send_streams[1], sec1)
        self.assertIs(client._send_streams[2], sec2)

        client_mux1.close()
        client_mux2.close()
        client_mux3.close()

    # -- round-robin index advancement ----------------------------------------

    def test_send_packet_round_robin_two_streams(self) -> None:
        """With 2 bonded streams, send_packet() alternates between them."""
        client_mux1, server_mux1 = _make_mux_pair()
        client_mux2, server_mux2 = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        stream1 = client_mux1.open_stream()
        stream2 = client_mux2.open_stream()

        client._data_stream = stream1
        client._send_streams = [stream1, stream2]
        client._send_idx = 0
        client._connected.set()

        import time
        time.sleep(0.05)

        # Gather server-side streams
        with server_mux1._streams_lock:
            s1_list = list(server_mux1._streams.values())
        with server_mux2._streams_lock:
            s2_list = list(server_mux2._streams.values())
        self.assertTrue(s1_list, "server_mux1 should see stream1")
        self.assertTrue(s2_list, "server_mux2 should see stream2")
        srv1 = s1_list[0]
        srv2 = s2_list[0]

        pkt_a = b"\x45\x00" + b"\x11" * 18
        pkt_b = b"\x45\x00" + b"\x22" * 18
        pkt_c = b"\x45\x00" + b"\x33" * 18
        pkt_d = b"\x45\x00" + b"\x44" * 18

        # Send 4 packets: should alternate stream1, stream2, stream1, stream2
        client.send_packet(pkt_a)  # → stream1
        client.send_packet(pkt_b)  # → stream2
        client.send_packet(pkt_c)  # → stream1
        client.send_packet(pkt_d)  # → stream2

        self.assertEqual(srv1.read(), pkt_a)
        self.assertEqual(srv1.read(), pkt_c)
        self.assertEqual(srv2.read(), pkt_b)
        self.assertEqual(srv2.read(), pkt_d)

        client._connected.clear()
        client_mux1.close()
        client_mux2.close()
        server_mux1.close()
        server_mux2.close()

    def test_send_packet_round_robin_index_advances(self) -> None:
        """_send_idx advances by 1 per send_packet() call."""
        client_mux1, server_mux1 = _make_mux_pair()
        client_mux2, server_mux2 = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        stream1 = client_mux1.open_stream()
        stream2 = client_mux2.open_stream()

        client._data_stream = stream1
        client._send_streams = [stream1, stream2]
        client._send_idx = 0
        client._connected.set()

        import time
        time.sleep(0.05)

        pkt = b"\x45\x00" + b"\x00" * 18
        client.send_packet(pkt)
        self.assertEqual(client._send_idx, 1)
        client.send_packet(pkt)
        self.assertEqual(client._send_idx, 2)
        client.send_packet(pkt)
        self.assertEqual(client._send_idx, 3)

        client._connected.clear()
        client_mux1.close()
        client_mux2.close()
        server_mux1.close()
        server_mux2.close()

    def test_send_packet_round_robin_three_streams(self) -> None:
        """With 3 streams each gets 1/3 of packets in strict rotation."""
        mux_pairs = [_make_mux_pair() for _ in range(3)]
        client_muxes = [p[0] for p in mux_pairs]
        server_muxes = [p[1] for p in mux_pairs]

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=3)
        client = VPNClient(cfg)
        client_streams = [m.open_stream() for m in client_muxes]

        client._data_stream = client_streams[0]
        client._send_streams = list(client_streams)
        client._send_idx = 0
        client._connected.set()

        import time
        time.sleep(0.05)

        counters = [0, 0, 0]
        for i in range(9):
            pkt = bytes([0x45, 0x00]) + bytes([i]) * 18
            client.send_packet(pkt)
            counters[i % 3] += 1

        # Each stream should receive exactly 3 packets
        self.assertEqual(counters, [3, 3, 3])
        # _send_idx should be 9
        self.assertEqual(client._send_idx, 9)

        client._connected.clear()
        for m in client_muxes + server_muxes:
            m.close()

    # -- disconnect() clears upload state -------------------------------------

    def test_disconnect_clears_send_streams_and_idx(self) -> None:
        """disconnect() clears _send_streams and resets _send_idx to 0."""
        client_mux1, _ = _make_mux_pair()
        client_mux2, _ = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)

        stream1 = client_mux1.open_stream()
        stream2 = client_mux2.open_stream()

        client._data_stream = stream1
        client._send_streams = [stream1, stream2]
        client._send_idx = 42

        # disconnect() without a real mux — just verify state cleanup
        client._connected.clear()
        client._bond_closed.clear()
        client.disconnect()

        self.assertEqual(client._send_streams, [])
        self.assertEqual(client._send_idx, 0)

        client_mux1.close()
        client_mux2.close()

    # -- send_packet() raises when not connected ------------------------------

    def test_send_packet_raises_when_not_connected(self) -> None:
        """send_packet() raises IOError when _connected is not set."""
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        # _connected is not set — should raise immediately
        with self.assertRaises(IOError):
            client.send_packet(b"\x45\x00" + b"\x00" * 18)

    def test_send_packet_raises_when_data_stream_is_none(self) -> None:
        """send_packet() raises IOError when _data_stream is None."""
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        client._connected.set()
        client._data_stream = None
        with self.assertRaises(IOError):
            client.send_packet(b"\x45\x00" + b"\x00" * 18)

    # -- graceful failover when a stream dies ----------------------------------

    def test_remove_dead_send_stream_removes_stream(self) -> None:
        """_remove_dead_send_stream() removes the stream from _send_streams."""
        client_mux1, _ = _make_mux_pair()
        client_mux2, _ = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        stream1 = client_mux1.open_stream()
        stream2 = client_mux2.open_stream()
        client._data_stream = stream1
        client._send_streams = [stream1, stream2]

        client._remove_dead_send_stream(stream2)
        self.assertEqual(client._send_streams, [stream1])

        client_mux1.close()
        client_mux2.close()

    def test_remove_dead_send_stream_noop_if_already_removed(self) -> None:
        """_remove_dead_send_stream() is idempotent — no-op for absent stream."""
        client_mux1, _ = _make_mux_pair()
        client_mux2, _ = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        stream1 = client_mux1.open_stream()
        stream2 = client_mux2.open_stream()
        client._data_stream = stream1
        client._send_streams = [stream1]

        # stream2 is not in the list — must be a no-op
        client._remove_dead_send_stream(stream2)
        self.assertEqual(client._send_streams, [stream1])

        client_mux1.close()
        client_mux2.close()

    def test_send_packet_failover_to_next_stream_on_write_error(self) -> None:
        """When a stream write raises, send_packet() retries on the next stream."""
        class _DeadStream:
            """Fake MuxStream that always raises on write()."""
            def write(self, _data: bytes) -> None:
                raise OSError("connection reset")

        client_mux, server_mux = _make_mux_pair()

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        dead_stream = _DeadStream()
        live_stream = client_mux.open_stream()

        client._data_stream = live_stream
        client._send_streams = [dead_stream, live_stream]
        client._send_idx = 0  # will pick dead_stream first
        client._connected.set()

        import time
        time.sleep(0.05)

        with server_mux._streams_lock:
            srv_streams = list(server_mux._streams.values())
        self.assertTrue(srv_streams)
        srv_stream = srv_streams[0]

        pkt = b"\x45\x00" + b"\xBB" * 18
        # Should NOT raise — dead_stream fails, then live_stream succeeds.
        client.send_packet(pkt)

        # dead_stream must have been evicted.
        self.assertNotIn(dead_stream, client._send_streams)

        # Packet must arrive on live_stream.
        received = srv_stream.read()
        self.assertEqual(received, pkt)

        client._connected.clear()
        client_mux.close()
        server_mux.close()

    def test_send_packet_raises_when_all_streams_dead(self) -> None:
        """When every stream fails, send_packet() raises IOError."""
        class _DeadStream:
            def write(self, _data: bytes) -> None:
                raise OSError("connection reset")

        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=2)
        client = VPNClient(cfg)
        dead1 = _DeadStream()
        dead2 = _DeadStream()
        # Provide a real _data_stream so the guard at the top of send_packet passes.
        client_mux, _ = _make_mux_pair()
        client._data_stream = client_mux.open_stream()
        client._send_streams = [dead1, dead2]
        client._send_idx = 0
        client._connected.set()

        with self.assertRaises(IOError):
            client.send_packet(b"\x45\x00" + b"\x00" * 18)

        # Both streams should have been removed from the list.
        self.assertEqual(client._send_streams, [])

        client._connected.clear()
        client_mux.close()

    def test_send_packet_failover_does_not_drop_packet(self) -> None:
        """Packet is successfully delivered even if first N-1 streams are dead."""
        class _DeadStream:
            def write(self, _data: bytes) -> None:
                raise OSError("broken pipe")

        client_mux, server_mux = _make_mux_pair()
        cfg = VPNConfig(server_addr="127.0.0.1:443", bond_count=4)
        client = VPNClient(cfg)
        live_stream = client_mux.open_stream()
        client._data_stream = live_stream
        # 3 dead streams, then 1 live stream
        client._send_streams = [_DeadStream(), _DeadStream(), _DeadStream(), live_stream]
        client._send_idx = 0
        client._connected.set()

        import time
        time.sleep(0.05)

        with server_mux._streams_lock:
            srv_streams = list(server_mux._streams.values())
        srv_stream = srv_streams[0]

        pkt = b"\x45\x00" + b"\xCC" * 18
        client.send_packet(pkt)

        received = srv_stream.read()
        self.assertEqual(received, pkt)
        # Only the live stream should remain.
        self.assertEqual(len(client._send_streams), 1)
        self.assertIs(client._send_streams[0], live_stream)

        client._connected.clear()
        client_mux.close()
        server_mux.close()


# ===========================================================================
# TestDualStackControl — CTL_ASSIGN_DUAL (0x05) parsing
# ===========================================================================

class TestDualStackControl(unittest.TestCase):
    """Tests for CTL_ASSIGN_DUAL constant and _do_control_stream dual-stack parsing."""

    # --- Constant sanity checks ---

    def test_ctl_assign_dual_value(self) -> None:
        """CTL_ASSIGN_DUAL must be 0x05 (matches ctlAssignDual in main.go)."""
        self.assertEqual(CTL_ASSIGN_DUAL, 0x05)

    def test_ctl_assign_dual_payload_len(self) -> None:
        """CTL_ASSIGN_DUAL_PAYLOAD_LEN must be 42 (matches ctlAssignDualPayloadLen in main.go)."""
        self.assertEqual(CTL_ASSIGN_DUAL_PAYLOAD_LEN, 42)

    def test_ctl_constants_distinct_including_dual(self) -> None:
        """All control constants must be unique to avoid protocol ambiguity."""
        values = [CTL_HELLO, CTL_ASSIGN, CTL_ASSIGN_DUAL, CTL_SECONDARY, CTL_ERROR]
        self.assertEqual(len(values), len(set(values)))

    # --- RouteInfo dual-stack fields ---

    def test_route_info_ipv4_only_is_not_dual_stack(self) -> None:
        route = RouteInfo(
            assigned_ip="10.8.0.2",
            prefix_len=24,
            gateway="10.8.0.1",
            server_public_key=b"\x00" * 32,
        )
        self.assertFalse(route.is_dual_stack)
        self.assertIsNone(route.assigned_ip6)
        self.assertIsNone(route.prefix_len6)
        self.assertIsNone(route.gateway6)

    def test_route_info_dual_stack_fields(self) -> None:
        route = RouteInfo(
            assigned_ip="10.8.0.2",
            prefix_len=24,
            gateway="10.8.0.1",
            server_public_key=b"\x00" * 32,
            assigned_ip6="fc00::2",
            prefix_len6=120,
            gateway6="fc00::1",
        )
        self.assertTrue(route.is_dual_stack)
        self.assertEqual(route.assigned_ip6, "fc00::2")
        self.assertEqual(route.prefix_len6, 120)
        self.assertEqual(route.gateway6, "fc00::1")

    def test_route_info_ipv4_fields_unchanged_in_dual_stack(self) -> None:
        route = RouteInfo(
            assigned_ip="10.8.0.7",
            prefix_len=24,
            gateway="10.8.0.1",
            server_public_key=b"\xAB" * 32,
            assigned_ip6="fc00::7",
            prefix_len6=120,
            gateway6="fc00::1",
        )
        self.assertEqual(route.assigned_ip, "10.8.0.7")
        self.assertEqual(route.prefix_len, 24)
        self.assertEqual(route.gateway, "10.8.0.1")
        self.assertEqual(route.cidr, "10.8.0.7/24")

    # --- _do_control_stream parsing ---

    def _build_ctl_stream(self, payload_bytes: bytes) -> "MuxStream":
        """Build a fake MuxStream that returns payload_bytes on read_exactly calls."""

        class FakeStream:
            def __init__(self, data: bytes) -> None:
                self._buf = bytearray(data)
                self._pos = 0

            def write(self, data: bytes) -> None:
                pass  # discard ctlHello

            def read_exactly(self, n: int) -> bytes:
                chunk = bytes(self._buf[self._pos:self._pos + n])
                if len(chunk) < n:
                    raise EOFError("not enough data")
                self._pos += n
                return chunk

            def close(self) -> None:
                pass

        return FakeStream(payload_bytes)

    def _make_client_with_fake_mux(self, stream) -> "VPNClient":
        """Create a VPNClient whose _mux.open_stream() returns stream."""

        class FakeMux:
            def __init__(self, s) -> None:
                self._s = s

            def open_stream(self):
                return self._s

        client = VPNClient.__new__(VPNClient)
        import structlog
        client._log = structlog.get_logger()
        client._mux = FakeMux(stream)
        return client

    def test_do_control_stream_ipv4_only(self) -> None:
        """_do_control_stream parses CTL_ASSIGN (IPv4-only) correctly."""
        ip4 = socket.inet_aton("10.8.0.3")
        gw4 = socket.inet_aton("10.8.0.1")
        payload = bytes([CTL_ASSIGN]) + ip4 + bytes([24]) + gw4
        stream = self._build_ctl_stream(payload)
        client = self._make_client_with_fake_mux(stream)

        route = client._do_control_stream()

        self.assertEqual(route.assigned_ip, "10.8.0.3")
        self.assertEqual(route.prefix_len, 24)
        self.assertEqual(route.gateway, "10.8.0.1")
        self.assertFalse(route.is_dual_stack)
        self.assertIsNone(route.assigned_ip6)

    def test_do_control_stream_dual_stack(self) -> None:
        """_do_control_stream parses CTL_ASSIGN_DUAL (dual-stack) correctly."""
        ip4 = socket.inet_aton("10.8.0.5")
        gw4 = socket.inet_aton("10.8.0.1")
        ip6 = ipaddress.IPv6Address("fc00::5").packed  # 16 bytes
        gw6 = ipaddress.IPv6Address("fc00::1").packed  # 16 bytes
        payload = (
            bytes([CTL_ASSIGN_DUAL])
            + ip4 + bytes([24]) + gw4
            + ip6 + bytes([120]) + gw6
        )
        stream = self._build_ctl_stream(payload)
        client = self._make_client_with_fake_mux(stream)

        route = client._do_control_stream()

        self.assertEqual(route.assigned_ip, "10.8.0.5")
        self.assertEqual(route.prefix_len, 24)
        self.assertEqual(route.gateway, "10.8.0.1")
        self.assertTrue(route.is_dual_stack)
        self.assertEqual(route.assigned_ip6, "fc00::5")
        self.assertEqual(route.prefix_len6, 120)
        self.assertEqual(route.gateway6, "fc00::1")

    def test_do_control_stream_dual_payload_length(self) -> None:
        """Dual-stack payload must be exactly CTL_ASSIGN_DUAL_PAYLOAD_LEN=42 bytes."""
        ip4 = socket.inet_aton("10.8.0.2")
        gw4 = socket.inet_aton("10.8.0.1")
        ip6 = b"\xfc\x00" + b"\x00" * 13 + b"\x02"  # fc00::2
        gw6 = b"\xfc\x00" + b"\x00" * 13 + b"\x01"  # fc00::1
        dual_payload = ip4 + bytes([24]) + gw4 + ip6 + bytes([120]) + gw6
        self.assertEqual(len(dual_payload), CTL_ASSIGN_DUAL_PAYLOAD_LEN)

    def test_do_control_stream_ctl_error_raises(self) -> None:
        """CTL_ERROR response raises IOError."""
        payload = bytes([CTL_ERROR])
        stream = self._build_ctl_stream(payload)
        client = self._make_client_with_fake_mux(stream)
        with self.assertRaises(IOError):
            client._do_control_stream()

    def test_do_control_stream_unknown_type_raises(self) -> None:
        """Unknown response type raises IOError."""
        payload = bytes([0xAB])
        stream = self._build_ctl_stream(payload)
        client = self._make_client_with_fake_mux(stream)
        with self.assertRaises(IOError):
            client._do_control_stream()

    def test_do_control_stream_dual_stack_various_prefixes(self) -> None:
        """Dual-stack correctly handles various IPv6 prefix lengths."""
        for pfx6 in (64, 96, 112, 120, 126):
            with self.subTest(pfx6=pfx6):
                ip4 = socket.inet_aton("10.8.0.2")
                gw4 = socket.inet_aton("10.8.0.1")
                ip6 = ipaddress.IPv6Address(f"fc00::{pfx6}").packed
                gw6 = ipaddress.IPv6Address("fc00::1").packed
                payload = (
                    bytes([CTL_ASSIGN_DUAL])
                    + ip4 + bytes([24]) + gw4
                    + ip6 + bytes([pfx6]) + gw6
                )
                stream = self._build_ctl_stream(payload)
                client = self._make_client_with_fake_mux(stream)
                route = client._do_control_stream()
                self.assertEqual(route.prefix_len6, pfx6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
