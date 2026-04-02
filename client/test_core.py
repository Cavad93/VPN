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


if __name__ == "__main__":
    unittest.main(verbosity=2)
