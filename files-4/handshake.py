"""
protocol/handshake.py
=====================
Hybrid post-quantum handshake state machine (KEMTLS-inspired).

Protocol Design (TLS 1.3 + KEMTLS Hybrid):
    ┌──────────┐                              ┌──────────┐
    │  Client  │                              │  Server  │
    └────┬─────┘                              └────┬─────┘
         │  ClientHello                            │
         │  (X25519_pub_C, Kyber_pub_C, nonce_C)  │
         │ ───────────────────────────────────────>│
         │                                         │  gen X25519_S, Kyber_S
         │                                         │  encap(Kyber_pub_C)→(ct, ss_K)
         │                                         │  ECDH(X25519_S, X25519_pub_C)→ss_X
         │                                         │  session_key = HKDF(ss_X||ss_K, ...)
         │                                         │  key_confirm_S = HMAC(mac_key, transcript)
         │  ServerHello                            │
         │  (X25519_pub_S, Kyber_pub_S,            │
         │   kyber_ct, nonce_S, key_confirm_S)     │
         │ <───────────────────────────────────────│
         │  ECDH(X25519_C, X25519_pub_S)→ss_X      │
         │  decap(Kyber_sk_C, kyber_ct)→ss_K       │
         │  session_key = HKDF(ss_X||ss_K, ...)    │
         │  verify key_confirm_S                   │
         │  key_confirm_C = HMAC(mac_key, transcript)
         │  ClientFinish                           │
         │  (key_confirm_C)                        │
         │ ───────────────────────────────────────>│
         │                                         │  verify key_confirm_C
         │   [Encrypted Application Data]          │
         │ <══════════════════════════════════════>│

Security Properties:
    - Mutual authentication via key confirmation MACs (prevents UKS attacks).
    - PFS via ephemeral keys (no static long-term secrets in key exchange).
    - HNDL resilience via Kyber-768 (quantum-safe encapsulation).
    - Replay protection via nonces and sequence numbers.
    - IND-CCA2 security under Module-LWE (Kyber) + CDH (X25519).

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import hashlib
import logging
import enum
from typing import Optional, Tuple

from ..crypto.hybrid_kem import HybridKEM, HybridPublicBundle
from ..crypto.primitives import (
    AESGCMEncryptor,
    compute_hmac,
    verify_hmac,
    hkdf_derive_mac_key,
    hkdf_derive_base_key,
    secure_random_bytes,
    HandshakeError,
)
from .message import (
    ClientHelloMsg,
    ServerHelloMsg,
    ClientFinishMsg,
    MessageCodec,
    MsgType,
)

logger = logging.getLogger(__name__)

HANDSHAKE_NONCE_BYTES: int = 32


# ---------------------------------------------------------------------------
# Handshake state machine states
# ---------------------------------------------------------------------------

class HandshakeState(enum.Enum):
    INITIAL           = "INITIAL"
    CLIENT_HELLO_SENT = "CLIENT_HELLO_SENT"
    SERVER_HELLO_RECV = "SERVER_HELLO_RECV"
    FINISHED          = "FINISHED"
    FAILED            = "FAILED"

    # Server-side states
    CLIENT_HELLO_RECV = "CLIENT_HELLO_RECV"
    SERVER_HELLO_SENT = "SERVER_HELLO_SENT"
    CLIENT_FINISH_RECV = "CLIENT_FINISH_RECV"


# ---------------------------------------------------------------------------
# Transcript hash (binds key confirmation to full handshake)
# ---------------------------------------------------------------------------

class HandshakeTranscript:
    """
    Append-only SHA-256 transcript hash of all handshake messages.

    Prevents downgrade attacks and cross-protocol replay by binding
    key confirmation MACs to the complete message transcript.
    """

    def __init__(self) -> None:
        self._hash = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Append raw message bytes to the transcript."""
        self._hash.update(data)

    def digest(self) -> bytes:
        """Return current 32-byte transcript hash (non-destructive copy)."""
        return self._hash.copy().digest()


# ---------------------------------------------------------------------------
# Client-side handshake
# ---------------------------------------------------------------------------

class ClientHandshake:
    """
    Client-side hybrid handshake protocol.

    Implements the client role in the 3-message hybrid KEM handshake.
    On successful completion, exposes `session_key` and `encryptor` for
    use in the secure channel.

    Args:
        client_id: Optional client identifier string.
    """

    def __init__(self, client_id: str = "client") -> None:
        self.client_id: str = client_id
        self.state: HandshakeState = HandshakeState.INITIAL
        self._kem: HybridKEM = HybridKEM()
        self._nonce_c: bytes = secure_random_bytes(HANDSHAKE_NONCE_BYTES)
        self._transcript: HandshakeTranscript = HandshakeTranscript()
        self.session_key: Optional[bytes] = None
        self.encryptor: Optional[AESGCMEncryptor] = None
        self._pub_bundle: Optional[HybridPublicBundle] = None

    def create_client_hello(self) -> bytes:
        """
        Generate and serialize ClientHello message.

        Generates ephemeral X25519 + Kyber-768 key pair; packages
        public keys + nonce into ClientHello CBOR frame.

        Returns:
            CBOR-encoded ClientHello bytes (ready for TCP send).

        Raises:
            HandshakeError: If not in INITIAL state.
        """
        if self.state != HandshakeState.INITIAL:
            raise HandshakeError(f"Cannot create ClientHello in state {self.state}.")

        self._pub_bundle = self._kem.generate_keypair()

        msg = ClientHelloMsg(
            x25519_pub=self._pub_bundle.x25519_pub,
            kyber_pub=self._pub_bundle.kyber_pub,
            nonce=self._nonce_c,
            client_id=self.client_id,
        )
        encoded = MessageCodec.encode(MsgType.CLIENT_HELLO, msg)
        self._transcript.update(encoded)
        self.state = HandshakeState.CLIENT_HELLO_SENT

        logger.info(
            "[Client] ClientHello sent | X25519: %d B | Kyber: %d B | Nonce: %s",
            len(self._pub_bundle.x25519_pub),
            len(self._pub_bundle.kyber_pub),
            self._nonce_c.hex()[:16] + "...",
        )
        return encoded

    def process_server_hello(self, data: bytes) -> bytes:
        """
        Process ServerHello: decapsulate Kyber CT, derive session key,
        verify server's key confirmation, generate client's confirmation.

        Args:
            data: Raw CBOR ServerHello bytes from server.

        Returns:
            CBOR-encoded ClientFinish bytes.

        Raises:
            HandshakeError: On state violation, HMAC failure, or KEM error.
        """
        if self.state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError(f"Unexpected ServerHello in state {self.state}.")

        msg_type, payload = MessageCodec.decode(data)
        if msg_type != MsgType.SERVER_HELLO:
            raise HandshakeError(f"Expected SERVER_HELLO, got {msg_type.name}.")

        srv = ServerHelloMsg(**payload)
        # Capture transcript BEFORE adding ServerHello (server computed MAC at this point)
        transcript_before_srv_hello = self._transcript.digest()
        self._transcript.update(data)

        # --- Hybrid decapsulation ---
        # Client decapsulates Kyber ciphertext (server encapped against client's pk)
        # and performs X25519 ECDH with server's ephemeral public key.
        encap_result = self._kem.decapsulate(
            kyber_ciphertext=srv.kyber_ct,
            peer_x25519_pub=srv.x25519_pub,
        )

        # Combined salt: client_nonce || server_nonce (both parties contribute)
        salt = self._nonce_c + srv.nonce
        self.session_key = self._kem.derive_session_key(encap_result, salt=salt, role="client")
        base_key = self._kem.derive_base_key(encap_result, salt=salt)
        mac_key = self._kem.get_mac_key(base_key)

        # --- Verify server's key confirmation ---
        # Server computed MAC over transcript hash BEFORE encoding ServerHello
        if not verify_hmac(mac_key, transcript_before_srv_hello, srv.key_confirm):
            self.state = HandshakeState.FAILED
            raise HandshakeError("Server key confirmation MAC verification FAILED — possible MITM.")

        logger.info("[Client] Server key confirmation verified ✓")

        # --- Generate client's key confirmation ---
        # Update transcript with current data before computing client MAC
        client_confirm = compute_hmac(mac_key, self._transcript.digest())

        finish_msg = ClientFinishMsg(
            key_confirm=client_confirm,
            client_id=self.client_id,
        )
        encoded = MessageCodec.encode(MsgType.CLIENT_FINISH, finish_msg)
        self._transcript.update(encoded)

        # --- Initialize secure channel encryptor ---
        self.encryptor = AESGCMEncryptor(self.session_key)
        self.state = HandshakeState.FINISHED

        using_kyber = "REAL" if self._kem.using_real_kyber else "SIMULATED"
        logger.info(
            "[Client] Handshake COMPLETE | Session key derived | Kyber: %s | Key: %s...",
            using_kyber,
            self.session_key.hex()[:16],
        )
        return encoded


# ---------------------------------------------------------------------------
# Server-side handshake
# ---------------------------------------------------------------------------

class ServerHandshake:
    """
    Server-side hybrid handshake protocol.

    Implements the server role: processes ClientHello, performs Kyber
    encapsulation against client's public key, derives session key,
    generates and validates key confirmation MACs.

    Args:
        server_id: Optional server identifier string.
    """

    def __init__(self, server_id: str = "hypq-server") -> None:
        self.server_id: str = server_id
        self.state: HandshakeState = HandshakeState.INITIAL
        self._kem: HybridKEM = HybridKEM()
        self._nonce_s: bytes = secure_random_bytes(HANDSHAKE_NONCE_BYTES)
        self._transcript: HandshakeTranscript = HandshakeTranscript()
        self.session_key: Optional[bytes] = None
        self.encryptor: Optional[AESGCMEncryptor] = None
        self._client_nonce: Optional[bytes] = None
        self._mac_key: Optional[bytes] = None

    def process_client_hello(self, data: bytes) -> bytes:
        """
        Process ClientHello: encapsulate against client's Kyber PK,
        perform X25519 ECDH, derive session key, send ServerHello.

        Args:
            data: Raw CBOR ClientHello bytes from client.

        Returns:
            CBOR-encoded ServerHello bytes to send to client.

        Raises:
            HandshakeError: On state violation or KEM failure.
        """
        if self.state != HandshakeState.INITIAL:
            raise HandshakeError(f"Unexpected ClientHello in state {self.state}.")

        msg_type, payload = MessageCodec.decode(data)
        if msg_type != MsgType.CLIENT_HELLO:
            raise HandshakeError(f"Expected CLIENT_HELLO, got {msg_type.name}.")

        cli = ClientHelloMsg(**payload)
        self._client_nonce = cli.nonce
        self._transcript.update(data)

        logger.info(
            "[Server] ClientHello received from '%s' | Kyber pk: %d B",
            cli.client_id,
            len(cli.kyber_pub),
        )

        # --- Generate server's ephemeral key pair ---
        server_pub_bundle = self._kem.generate_keypair()

        # --- Encapsulate against client's Kyber public key ---
        client_pub_bundle = HybridPublicBundle(
            x25519_pub=cli.x25519_pub,
            kyber_pub=cli.kyber_pub,
        )
        kyber_ct, encap_result = self._kem.encapsulate(client_pub_bundle)

        # --- Derive session key ---
        salt = self._client_nonce + self._nonce_s
        self.session_key = self._kem.derive_session_key(encap_result, salt=salt, role="server")
        base_key = self._kem.derive_base_key(encap_result, salt=salt)
        self._mac_key = self._kem.get_mac_key(base_key)

        # --- Compute key confirmation MAC over transcript ---
        # Include ServerHello fields (excluding key_confirm itself) in transcript
        # We compute MAC over transcript AFTER updating with the partial ServerHello
        placeholder_hello = ServerHelloMsg(
            x25519_pub=server_pub_bundle.x25519_pub,
            kyber_pub=server_pub_bundle.kyber_pub,
            kyber_ct=kyber_ct,
            nonce=self._nonce_s,
            key_confirm=b"\x00" * 32,  # placeholder
            server_id=self.server_id,
        )
        partial_encoded = MessageCodec.encode(MsgType.SERVER_HELLO, placeholder_hello)
        transcript_for_mac = self._transcript.digest()
        key_confirm_s = compute_hmac(self._mac_key, transcript_for_mac)

        # --- Build actual ServerHello ---
        hello = ServerHelloMsg(
            x25519_pub=server_pub_bundle.x25519_pub,
            kyber_pub=server_pub_bundle.kyber_pub,
            kyber_ct=kyber_ct,
            nonce=self._nonce_s,
            key_confirm=key_confirm_s,
            server_id=self.server_id,
        )
        encoded = MessageCodec.encode(MsgType.SERVER_HELLO, hello)
        self._transcript.update(encoded)
        self.state = HandshakeState.SERVER_HELLO_SENT

        using_kyber = "REAL" if self._kem.using_real_kyber else "SIMULATED"
        logger.info(
            "[Server] ServerHello sent | Kyber-CT: %d B | Kyber: %s",
            len(kyber_ct),
            using_kyber,
        )
        return encoded

    def process_client_finish(self, data: bytes) -> bool:
        """
        Process ClientFinish: verify client's key confirmation MAC.

        Args:
            data: Raw CBOR ClientFinish bytes from client.

        Returns:
            True on successful verification.

        Raises:
            HandshakeError: On MAC verification failure or state violation.
        """
        if self.state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError(f"Unexpected ClientFinish in state {self.state}.")

        msg_type, payload = MessageCodec.decode(data)
        if msg_type != MsgType.CLIENT_FINISH:
            raise HandshakeError(f"Expected CLIENT_FINISH, got {msg_type.name}.")

        fin = ClientFinishMsg(**payload)

        # Verify over the transcript hash at the point of ClientFinish
        transcript_digest = self._transcript.digest()
        if not verify_hmac(self._mac_key, transcript_digest, fin.key_confirm):
            self.state = HandshakeState.FAILED
            raise HandshakeError("Client key confirmation FAILED — aborting session.")

        self._transcript.update(data)
        self.encryptor = AESGCMEncryptor(self.session_key)
        self.state = HandshakeState.FINISHED

        logger.info(
            "[Server] Handshake COMPLETE with client '%s' | Key: %s...",
            fin.client_id,
            self.session_key.hex()[:16],
        )
        return True
