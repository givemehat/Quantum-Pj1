"""
crypto/primitives.py
====================
Low-level cryptographic primitives for HyPQ-Mess.

Implements AES-256-GCM authenticated encryption and HKDF-SHA256
key derivation following NIST SP 800-56C Rev. 2 recommendations.
All operations use the `cryptography` library for side-channel
resistance and constant-time guarantees.

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_KEY_BYTES: int = 32  # AES-256
GCM_NONCE_BYTES: int = 12  # 96-bit nonce (NIST recommended)
GCM_TAG_BYTES: int = 16  # 128-bit authentication tag
HKDF_HASH = hashes.SHA256  # Hash function for HKDF
REPLAY_WINDOW_SIZE: int = 64  # Anti-replay window (bitmask, 64 slots)
MAX_SEQ_GAP: int = 32  # Maximum acceptable sequence gap


# ---------------------------------------------------------------------------
# Secure RNG helpers
# ---------------------------------------------------------------------------


def secure_random_bytes(n: int) -> bytes:
    """
    Generate `n` cryptographically secure random bytes.

    Uses os.urandom (backed by getrandom(2) on Linux / CryptGenRandom
    on Windows), which is CSPRNG-quality as per NIST SP 800-90A.

    Args:
        n: Number of bytes to generate.

    Returns:
        Cryptographically secure random bytes.
    """
    return os.urandom(n)


def generate_nonce() -> bytes:
    """Generate a 96-bit AES-GCM nonce (NIST SP 800-38D §8.2.2)."""
    return secure_random_bytes(GCM_NONCE_BYTES)


# ---------------------------------------------------------------------------
# HKDF Key Derivation
# ---------------------------------------------------------------------------


def hkdf_derive(
    ikm: bytes,
    length: int = AES_KEY_BYTES,
    salt: Optional[bytes] = None,
    info: bytes = b"HyPQ-Mess-v1",
) -> bytes:
    """
    Derive a key using HKDF-SHA256 (RFC 5869).

    Implements the "concatenation KDF" pattern for hybrid key exchange:
        HKDF(salt, X25519_secret || Kyber_shared, info) → session_key

    Security:
        - IND-CCA2 security inherited from Kyber shared secret.
        - Domain separation via `info` label prevents cross-protocol attacks.

    Args:
        ikm   : Input keying material (concatenated secrets for hybrid KEM).
        length: Output key length in bytes (default 32 for AES-256).
        salt  : Optional random salt (recommended; use server nonce).
        info  : Context/label for domain separation.

    Returns:
        Derived key of `length` bytes.

    Raises:
        ValueError: If length exceeds HKDF output limit.
    """
    if length > 255 * 32:
        raise ValueError(f"Requested key length {length} exceeds HKDF-SHA256 limit.")

    hkdf = HKDF(
        algorithm=HKDF_HASH(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def hkdf_derive_session_key(
    x25519_secret: bytes,
    kyber_shared: bytes,
    salt: bytes,
    role: str = "client",
) -> bytes:
    """
    Derive the session AES-256-GCM key from hybrid KEM secrets.

    Produces two keys from a single base derivation:
        base_key = HKDF-SHA256(X25519||Kyber, salt, "HyPQ-Mess|base")
        enc_key  = HKDF-Expand(base_key, "HyPQ-Mess|enc|<role>")

    The role ("client"/"server") creates directional encryption keys
    for bidirectional channel security, while the base_key is shared
    and used for MAC key confirmation.

    Args:
        x25519_secret: 32-byte X25519 shared secret.
        kyber_shared : Kyber-768 shared secret (32 bytes).
        salt         : Random salt (from handshake nonce exchange).
        role         : "client" or "server" for directional keys.

    Returns:
        32-byte AES-256-GCM session key.
    """
    ikm = x25519_secret + kyber_shared
    # First derive a role-independent base key
    base_key = hkdf_derive(
        ikm=ikm, length=AES_KEY_BYTES, salt=salt, info=b"HyPQ-Mess|base|v1"
    )
    # Then derive role-specific encryption key
    enc_info = f"HyPQ-Mess|enc|{role}|v1".encode()
    hkdf_expand = HKDFExpand(algorithm=HKDF_HASH(), length=AES_KEY_BYTES, info=enc_info)
    return hkdf_expand.derive(base_key)


def hkdf_derive_base_key(
    x25519_secret: bytes,
    kyber_shared: bytes,
    salt: bytes,
) -> bytes:
    """
    Derive role-independent base key used for MAC key confirmation.

    Both client and server derive the SAME base key, enabling symmetric
    HMAC verification during the Finished handshake phase.

    Args:
        x25519_secret: 32-byte X25519 shared secret.
        kyber_shared : Kyber shared secret.
        salt         : Handshake salt (nonce_C || nonce_S).

    Returns:
        32-byte shared base key.
    """
    ikm = x25519_secret + kyber_shared
    return hkdf_derive(
        ikm=ikm, length=AES_KEY_BYTES, salt=salt, info=b"HyPQ-Mess|base|v1"
    )


def hkdf_derive_mac_key(session_key: bytes, purpose: str = "confirm") -> bytes:
    """
    Derive a MAC confirmation key from the session key using HKDF-Expand.

    Used during handshake Finished phase for mutual key confirmation,
    preventing unknown key-share (UKS) attacks.

    Args:
        session_key: 32-byte session key.
        purpose    : Label differentiating MAC key from enc key.

    Returns:
        32-byte HMAC-SHA256 key for key confirmation.
    """
    info = f"HyPQ-Mess|mac|{purpose}".encode()
    hkdf_expand = HKDFExpand(
        algorithm=HKDF_HASH(),
        length=AES_KEY_BYTES,
        info=info,
    )
    return hkdf_expand.derive(session_key)


# ---------------------------------------------------------------------------
# HMAC for Key Confirmation
# ---------------------------------------------------------------------------


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 for key confirmation messages.

    Args:
        key : 32-byte HMAC key.
        data: Arbitrary data to authenticate.

    Returns:
        32-byte HMAC tag.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """
    Constant-time HMAC verification (prevents timing oracles).

    Args:
        key : 32-byte HMAC key.
        data: Data to verify.
        tag : Expected HMAC tag.

    Returns:
        True if tag is valid, False otherwise.
    """
    expected = compute_hmac(key, data)
    # secrets.compare_digest is constant-time for equal-length byte strings
    return secrets.compare_digest(expected, tag)


# ---------------------------------------------------------------------------
# AES-256-GCM Authenticated Encryption
# ---------------------------------------------------------------------------


@dataclass
class EncryptedMessage:
    """
    Container for AES-256-GCM ciphertext with associated metadata.

    Fields:
        nonce      : 96-bit GCM nonce (never reused per key).
        ciphertext : Encrypted payload (includes 128-bit auth tag).
        sequence   : Monotonically increasing message sequence number.
        timestamp  : Unix timestamp (microseconds) for replay detection.
    """

    nonce: bytes
    ciphertext: bytes
    sequence: int
    timestamp: int


class AESGCMEncryptor:
    """
    AES-256-GCM authenticated encryption engine.

    Provides IND-CPA + INT-CTXT security (authenticated encryption).
    Each instance maintains a monotonic sequence counter and replay
    detection window to prevent replay attacks.

    Security Properties:
        - Confidentiality  : AES-256 in GCM mode (IND-CPA secure).
        - Integrity/Auth   : GCM authentication tag (INT-CTXT secure).
        - Replay Protection: Sequence + timestamp window (64-slot bitmask).
        - Forward Secrecy  : Ephemeral session keys; no key reuse across sessions.

    Note:
        AES-GCM nonces MUST be unique per key. This class generates
        random 96-bit nonces via os.urandom, providing 2^48 safety
        margin before collision probability reaches 2^-32 (NIST §8.3).

    Args:
        key: 32-byte AES-256 session key.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != AES_KEY_BYTES:
            raise ValueError(
                f"AES-256 requires exactly {AES_KEY_BYTES} bytes; got {len(key)}."
            )
        self._aesgcm: AESGCM = AESGCM(key)
        self._sequence: int = 0
        self._recv_seq: int = -1
        self._replay_window: int = 0  # 64-bit bitmask

    def encrypt(
        self, plaintext: bytes, aad: Optional[bytes] = None
    ) -> EncryptedMessage:
        """
        Encrypt plaintext with AES-256-GCM.

        The sequence number is embedded in AAD (Additional Authenticated
        Data) to bind it cryptographically to the ciphertext, preventing
        message reordering attacks.

        Args:
            plaintext: Arbitrary-length message bytes.
            aad      : Optional additional authenticated data (not encrypted).

        Returns:
            EncryptedMessage with nonce, ciphertext, sequence, timestamp.
        """
        nonce = generate_nonce()
        seq = self._sequence
        self._sequence += 1
        ts = int(time.time() * 1_000_000)  # microsecond precision

        # Bind sequence + timestamp into AAD for replay protection
        seq_aad = struct.pack(">QQ", seq, ts)
        full_aad = seq_aad + (aad or b"")

        ciphertext = self._aesgcm.encrypt(nonce, plaintext, full_aad)
        return EncryptedMessage(
            nonce=nonce,
            ciphertext=ciphertext,
            sequence=seq,
            timestamp=ts,
        )

    def decrypt(
        self,
        msg: EncryptedMessage,
        aad: Optional[bytes] = None,
        max_age_seconds: float = 30.0,
    ) -> bytes:
        """
        Decrypt and authenticate an EncryptedMessage.

        Performs replay detection before decryption to prevent
        chosen-ciphertext attacks via the replay oracle.

        Args:
            msg            : EncryptedMessage to decrypt.
            aad            : Optional AAD (must match encryption AAD).
            max_age_seconds: Maximum message age for timestamp check.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ReplayAttackError : Detected replay or out-of-window sequence.
            ValueError        : Authentication tag mismatch (tampered message).
            MessageExpiredError: Message timestamp too old.
        """
        # Timestamp freshness check
        now_us = int(time.time() * 1_000_000)
        age_us = now_us - msg.timestamp
        if age_us < 0 or age_us > max_age_seconds * 1_000_000:
            raise MessageExpiredError(
                f"Message age {age_us/1e6:.2f}s exceeds {max_age_seconds}s window."
            )

        # Replay window check
        self._check_replay(msg.sequence)

        seq_aad = struct.pack(">QQ", msg.sequence, msg.timestamp)
        full_aad = seq_aad + (aad or b"")

        try:
            plaintext = self._aesgcm.decrypt(msg.nonce, msg.ciphertext, full_aad)
        except Exception as exc:
            raise ValueError(f"AES-GCM authentication failed: {exc}") from exc

        # Update replay window only after successful decryption
        self._update_replay_window(msg.sequence)
        return plaintext

    def _check_replay(self, seq: int) -> None:
        """Check if sequence is within the replay window (raises on replay)."""
        diff = seq - self._recv_seq
        if diff <= -REPLAY_WINDOW_SIZE:
            raise ReplayAttackError(f"Sequence {seq} outside replay window (too old).")
        if diff > 0:
            return  # Future sequence: tentatively OK
        bit = 1 << (-diff)
        if self._replay_window & bit:
            raise ReplayAttackError(f"Replayed sequence number: {seq}.")

    def _update_replay_window(self, seq: int) -> None:
        """Update replay window bitmask after successful decryption."""
        diff = seq - self._recv_seq
        if diff > 0:
            # Advance window
            shift = min(diff, REPLAY_WINDOW_SIZE)
            self._replay_window = (self._replay_window << shift) | 1
            self._recv_seq = seq
        else:
            bit = 1 << (-diff)
            self._replay_window |= bit


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class ReplayAttackError(Exception):
    """Raised when a replayed or out-of-window message is detected."""


class MessageExpiredError(Exception):
    """Raised when message timestamp exceeds the freshness window."""


class HandshakeError(Exception):
    """Raised when the hybrid handshake protocol fails."""
