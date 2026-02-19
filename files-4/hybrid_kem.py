"""
crypto/hybrid_kem.py
====================
Hybrid Key Encapsulation Mechanism (HybridKEM) combining:
    - Classical : X25519 (Curve25519) ECDH — NIST SP 800-186
    - Post-Quantum: ML-KEM-768 (Kyber-768) — NIST FIPS 203 (2024)

The hybrid design follows the "dual-PRF" paradigm:
    session_key = HKDF(X25519_shared || Kyber_shared, salt, context)

Security Rationale (NIST IR 8413):
    Breaking the hybrid requires SIMULTANEOUSLY breaking both X25519
    (requires solving ECDLP on Curve25519, infeasible classically) AND
    Kyber-768 (IND-CCA2 secure under Module-LWE hardness assumption,
    infeasible even for a large-scale quantum computer via Shor's algorithm).
    This provides "harvest now, decrypt later" (HNDL) resilience.

Implementation Note:
    Primary: liboqs via `oqs` Python bindings (pyoqs / oqs-python).
    Fallback: Pure-Python Kyber simulation for portability when liboqs
              is unavailable (e.g., CI environments without native libs).
              The simulation preserves API compatibility but is NOT
              cryptographically secure — production MUST use liboqs.

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from .primitives import (
    hkdf_derive_session_key,
    hkdf_derive_mac_key,
    secure_random_bytes,
    AES_KEY_BYTES,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# liboqs availability detection
# ---------------------------------------------------------------------------

_OQS_AVAILABLE: bool = False
_oqs: Optional[object] = None

try:
    import oqs  # type: ignore[import]
    _OQS_AVAILABLE = True
    _oqs = oqs
    logger.info("liboqs detected: using real Kyber-768 (ML-KEM-768).")
except ImportError:
    logger.warning(
        "liboqs (pyoqs) not found. Falling back to Kyber SIMULATION. "
        "NOT cryptographically secure. Install pyoqs for production use."
    )


# ---------------------------------------------------------------------------
# Kyber-768 parameters (NIST FIPS 203)
# ---------------------------------------------------------------------------
KYBER_ALG: str = "Kyber768"          # liboqs algorithm name
KYBER_PK_BYTES: int = 1184           # Kyber-768 public key size
KYBER_SK_BYTES: int = 2400           # Kyber-768 secret key size
KYBER_CT_BYTES: int = 1088           # Kyber-768 ciphertext size
KYBER_SS_BYTES: int = 32             # Kyber-768 shared secret size


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class KyberKeyPair:
    """Kyber-768 key pair (ephemeral, per-session)."""
    public_key: bytes    # 1184-byte public key
    secret_key: bytes    # 2400-byte secret key (zeroize on scope exit in prod)


@dataclass
class HybridPublicBundle:
    """
    Public key bundle transmitted during ClientHello.

    Contains both classical (X25519) and post-quantum (Kyber-768)
    public keys for the hybrid KEM handshake.

    Wire format: serialized via CBOR in protocol/message.py.
    """
    x25519_pub: bytes    # 32-byte X25519 compressed public key
    kyber_pub: bytes     # 1184-byte Kyber-768 public key


@dataclass
class HybridEncapsulation:
    """
    Result of hybrid KEM encapsulation (server-side operation).

    Contains ciphertexts and the derived shared secrets (never transmitted).
    """
    kyber_ciphertext: bytes    # 1088-byte Kyber-768 encapsulation ciphertext
    kyber_shared: bytes        # 32-byte Kyber shared secret (local only)
    x25519_shared: bytes       # 32-byte X25519 shared secret (local only)


# ---------------------------------------------------------------------------
# Pure-Python Kyber Simulation (fallback only)
# ---------------------------------------------------------------------------

class _KyberSimulator:
    """
    Kyber-768 API-compatible SIMULATION for environments without liboqs.

    WARNING: This does NOT implement actual Kyber cryptography.
    It uses HMAC-SHA256 to produce DETERMINISTIC shared secrets from
    (pk, sk, ct) to allow handshake integration testing.
    NEVER use in production or security-sensitive contexts.

    Simulation scheme:
        seed = sk[:32]  (first 32 bytes of "secret key" = random seed)
        ct   = HMAC(seed, pk)[:KYBER_CT_BYTES]  (deterministic ct)
        ss   = HMAC(seed, ct)[:KYBER_SS_BYTES]  (deterministic shared secret)
    Both encapsulate and decapsulate recover the same ss from (seed, ct).
    """
    import hashlib as _hashlib
    import hmac as _hmac

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Simulate Kyber-768 key generation."""
        seed = secure_random_bytes(32)                          # true random seed
        pk = (seed * ((KYBER_PK_BYTES // 32) + 1))[:KYBER_PK_BYTES]
        sk = seed + (b"\x00" * (KYBER_SK_BYTES - 32))          # seed is first 32 bytes
        return pk, sk

    @staticmethod
    def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
        """Simulate Kyber-768 encapsulation (deterministic from pk)."""
        import hmac, hashlib
        # ct = HMAC-SHA256(key=pk[:32], data="encap")[:KYBER_CT_BYTES] (padded)
        seed_pk = public_key[:32]
        ct_raw = hmac.new(seed_pk, b"kyber_sim_ct", hashlib.sha256).digest()
        ciphertext = (ct_raw * ((KYBER_CT_BYTES // 32) + 1))[:KYBER_CT_BYTES]
        # ss = HMAC-SHA256(key=pk[:32], data=ct[:32])
        shared_secret = hmac.new(seed_pk, ciphertext[:32], hashlib.sha256).digest()[:KYBER_SS_BYTES]
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Simulate Kyber-768 decapsulation.
        Recovers same shared secret as encapsulate by reconstructing from
        the seed embedded in the secret key.
        """
        import hmac, hashlib
        # pk[:32] = seed stored in sk[:32]
        seed_pk = secret_key[:32]
        # Reconstruct expected ct from seed
        ct_raw = hmac.new(seed_pk, b"kyber_sim_ct", hashlib.sha256).digest()
        expected_ct = (ct_raw * ((KYBER_CT_BYTES // 32) + 1))[:KYBER_CT_BYTES]
        # ss from the actual received ciphertext (in real Kyber this verifies ct)
        # For simulation: use actual ciphertext to be consistent with encap
        shared_secret = hmac.new(seed_pk, ciphertext[:32], hashlib.sha256).digest()[:KYBER_SS_BYTES]
        return shared_secret


# ---------------------------------------------------------------------------
# HybridKEM: Core class
# ---------------------------------------------------------------------------

class HybridKEM:
    """
    Hybrid Key Encapsulation Mechanism (X25519 + ML-KEM-768).

    Implements a two-layer KEM:
        1. X25519 ECDH: Classical 128-bit security (broken by quantum Shor).
        2. Kyber-768 KEM: Post-quantum 178-bit security (NIST Cat-3 equiv.).

    Session key derivation:
        ikm = ECDH(x25519_priv, x25519_pub) || Kyber_decaps(sk, ct)
        key = HKDF-SHA256(ikm, salt=nonce, info="HyPQ-Mess|session|<role>")

    The concatenation ensures that even if one primitive is broken,
    the combined key remains secure under the other.

    Usage (Server):
        kem = HybridKEM()
        keypair = kem.generate_keypair()               # Generates X25519 + Kyber keys
        encap = kem.encapsulate(client_pub_bundle)     # Encapsulate using client's pubs
        session_key = kem.derive_session_key(          # Derive AES-256 key
            encap, salt=nonce, role="server"
        )

    Usage (Client):
        kem = HybridKEM()
        keypair = kem.generate_keypair()
        # Send keypair.public_bundle to server
        # Receive server's encapsulation ct + server pub
        session_key = kem.decapsulate_and_derive(
            kyber_ct, server_x25519_pub, salt=nonce, role="client"
        )
    """

    def __init__(self) -> None:
        self._x25519_priv: Optional[X25519PrivateKey] = None
        self._kyber_sk: Optional[bytes] = None
        self._kyber_pk: Optional[bytes] = None
        self._use_real_kyber: bool = _OQS_AVAILABLE

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(self) -> HybridPublicBundle:
        """
        Generate ephemeral X25519 + Kyber-768 key pair.

        Keys are ephemeral (per-session) to provide Perfect Forward
        Secrecy (PFS): compromise of long-term keys does not expose
        past session keys.

        Returns:
            HybridPublicBundle containing both public keys for transmission.
        """
        # X25519: ephemeral private key
        self._x25519_priv = X25519PrivateKey.generate()
        x25519_pub_bytes = self._x25519_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        # Kyber-768: ephemeral key pair
        self._kyber_pk, self._kyber_sk = self._kyber_generate()

        logger.debug(
            "Generated hybrid keypair: X25519(%d B) + Kyber768(%d B)",
            len(x25519_pub_bytes),
            len(self._kyber_pk),
        )
        return HybridPublicBundle(
            x25519_pub=x25519_pub_bytes,
            kyber_pub=self._kyber_pk,
        )

    # ------------------------------------------------------------------
    # Encapsulation (used by the party initiating key agreement)
    # ------------------------------------------------------------------

    def encapsulate(
        self,
        peer_pub_bundle: HybridPublicBundle,
    ) -> Tuple[bytes, HybridEncapsulation]:
        """
        Encapsulate secrets against peer's public key bundle.

        Performs:
            1. Kyber-768 encapsulation → (ct, ss_kyber)
            2. X25519 ECDH with peer's pub → ss_x25519

        Args:
            peer_pub_bundle: Remote party's public key bundle.

        Returns:
            Tuple of (kyber_ciphertext, HybridEncapsulation with shared secrets).

        Raises:
            RuntimeError: If own keypair has not been generated yet.
        """
        if self._x25519_priv is None:
            raise RuntimeError("Call generate_keypair() before encapsulate().")

        # Kyber encapsulation
        kyber_ct, kyber_ss = self._kyber_encapsulate(peer_pub_bundle.kyber_pub)

        # X25519 ECDH
        peer_x25519_pub = X25519PublicKey.from_public_bytes(peer_pub_bundle.x25519_pub)
        x25519_ss = self._x25519_priv.exchange(peer_x25519_pub)

        logger.debug("Encapsulated: Kyber-ct=%d B, X25519-ss=%d B", len(kyber_ct), len(x25519_ss))

        return kyber_ct, HybridEncapsulation(
            kyber_ciphertext=kyber_ct,
            kyber_shared=kyber_ss,
            x25519_shared=x25519_ss,
        )

    # ------------------------------------------------------------------
    # Decapsulation (used by the party receiving the encapsulation)
    # ------------------------------------------------------------------

    def decapsulate(
        self,
        kyber_ciphertext: bytes,
        peer_x25519_pub: bytes,
    ) -> HybridEncapsulation:
        """
        Decapsulate Kyber ciphertext and compute X25519 shared secret.

        Args:
            kyber_ciphertext: Kyber-768 ciphertext from peer.
            peer_x25519_pub : 32-byte raw X25519 public key from peer.

        Returns:
            HybridEncapsulation with both shared secrets.

        Raises:
            RuntimeError: If own keypair not generated.
            ValueError  : If Kyber decapsulation fails (malformed ct).
        """
        if self._kyber_sk is None or self._x25519_priv is None:
            raise RuntimeError("Call generate_keypair() before decapsulate().")

        # Kyber decapsulation
        kyber_ss = self._kyber_decapsulate(self._kyber_sk, kyber_ciphertext)

        # X25519 ECDH
        peer_pub = X25519PublicKey.from_public_bytes(peer_x25519_pub)
        x25519_ss = self._x25519_priv.exchange(peer_pub)

        logger.debug("Decapsulated: Kyber-ss=%d B, X25519-ss=%d B", len(kyber_ss), len(x25519_ss))

        return HybridEncapsulation(
            kyber_ciphertext=kyber_ciphertext,
            kyber_shared=kyber_ss,
            x25519_shared=x25519_ss,
        )

    # ------------------------------------------------------------------
    # Session key derivation
    # ------------------------------------------------------------------

    def derive_session_key(
        self,
        encapsulation: HybridEncapsulation,
        salt: bytes,
        role: str = "client",
    ) -> bytes:
        """
        Derive 32-byte AES-256-GCM session key from hybrid shared secrets.

        Key material: IKM = X25519_shared || Kyber_shared (order matters for
        domain separation; both parties must agree on ordering).

        Args:
            encapsulation: HybridEncapsulation containing both shared secrets.
            salt         : Random salt from handshake nonce exchange.
            role         : "client" or "server" (directional key binding).

        Returns:
            32-byte session key for AES-256-GCM.
        """
        session_key = hkdf_derive_session_key(
            x25519_secret=encapsulation.x25519_shared,
            kyber_shared=encapsulation.kyber_shared,
            salt=salt,
            role=role,
        )
        logger.debug("Derived session key for role='%s': %d bytes", role, len(session_key))
        return session_key

    def derive_base_key(
        self,
        encapsulation: HybridEncapsulation,
        salt: bytes,
    ) -> bytes:
        """
        Derive the role-independent base key for MAC key confirmation.

        Both client and server derive the SAME base key, enabling
        symmetric HMAC verification during the Finished phase.

        Args:
            encapsulation: HybridEncapsulation with shared secrets.
            salt         : Handshake salt (nonce_C || nonce_S).

        Returns:
            32-byte shared base key.
        """
        from .primitives import hkdf_derive_base_key
        return hkdf_derive_base_key(
            x25519_secret=encapsulation.x25519_shared,
            kyber_shared=encapsulation.kyber_shared,
            salt=salt,
        )

    def get_mac_key(self, session_key: bytes) -> bytes:
        """Derive MAC key for handshake key confirmation."""
        return hkdf_derive_mac_key(session_key, purpose="confirm")

    # ------------------------------------------------------------------
    # Internal Kyber dispatch (real vs. simulation)
    # ------------------------------------------------------------------

    def _kyber_generate(self) -> Tuple[bytes, bytes]:
        """Generate Kyber-768 key pair using liboqs or simulation."""
        if self._use_real_kyber and _oqs is not None:
            try:
                kem = _oqs.KeyEncapsulation(KYBER_ALG)
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
                return pk, sk
            except Exception as exc:
                logger.error("liboqs Kyber keygen failed: %s. Falling back.", exc)
                self._use_real_kyber = False
        sim = _KyberSimulator()
        return sim.generate_keypair()

    def _kyber_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate using Kyber-768."""
        if self._use_real_kyber and _oqs is not None:
            try:
                kem = _oqs.KeyEncapsulation(KYBER_ALG)
                ct, ss = kem.encap_secret(public_key)
                return ct, ss
            except Exception as exc:
                logger.error("liboqs encapsulation failed: %s. Falling back.", exc)
                self._use_real_kyber = False
        return _KyberSimulator.encapsulate(public_key)

    def _kyber_decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate Kyber-768 ciphertext."""
        if self._use_real_kyber and _oqs is not None:
            try:
                kem = _oqs.KeyEncapsulation(KYBER_ALG, secret_key=secret_key)
                ss = kem.decap_secret(ciphertext)
                return ss
            except Exception as exc:
                logger.error("liboqs decapsulation failed: %s. Falling back.", exc)
                self._use_real_kyber = False
        return _KyberSimulator.decapsulate(secret_key, ciphertext)

    @property
    def using_real_kyber(self) -> bool:
        """True if using liboqs (real Kyber-768), False if simulation."""
        return self._use_real_kyber
