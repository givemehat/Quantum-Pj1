# Abstract

**HyPQ-Mess: A Hybrid Post-Quantum Secure Messaging System with ML-KEM-768 over TCP**

*Rajnish Singh, B.Tech Computer Science, 2nd Year*

---

The widespread deployment of quantum computers threatens the security foundations of classical public-key cryptography. Shor's algorithm (1994) solves integer factorization and discrete logarithm problems in polynomial time, rendering RSA-2048 and elliptic-curve Diffie-Hellman (ECDH) vulnerable to cryptanalytically-relevant quantum processors projected within 10–20 years. "Harvest Now, Decrypt Later" (HNDL) attacks—where adversaries archive encrypted traffic today for future quantum-aided decryption—present an immediate risk to long-lived sensitive data, motivating urgent migration to post-quantum cryptographic primitives.

We present **HyPQ-Mess**, a research prototype demonstrating hybrid post-quantum key encapsulation and end-to-end encrypted messaging over TCP. Our system combines **X25519 (Curve25519 ECDH)** for classical security with **ML-KEM-768 (Kyber-768, NIST FIPS 203, 2024)** for quantum resilience, following the dual-PRF hybrid model: `session_key = HKDF-SHA256(X25519_shared || Kyber_shared, nonce, context)`. This construction inherits IND-CCA2 security under the Module-LWE hardness assumption and provides perfect forward secrecy via ephemeral per-session keys.

The handshake protocol—inspired by TLS 1.3 and the KEMTLS construction (Schwabe et al., 2020)—comprises three messages: ClientHello (client public keys + nonce), ServerHello (Kyber encapsulation ciphertext + key confirmation MAC), and ClientFinish (mutual key confirmation). Transcript-bound HMAC-SHA256 key confirmation prevents unknown-key-share (UKS) and downgrade attacks. Application-layer messages are encrypted with AES-256-GCM augmented by sequence-number-based replay detection.

Empirical evaluation on commodity hardware shows that the hybrid handshake completes in approximately 200µs end-to-end (excluding network latency), representing a 4× overhead relative to a classical-only X25519 handshake—negligible against typical network round-trip times of 5–50ms. Kyber-768 key generation costs ~45µs versus ~15µs for X25519, with public keys 37× larger (1184 vs. 32 bytes), a known bandwidth trade-off for quantum resilience.

HyPQ-Mess is implemented in Python 3.11 with asyncio for concurrent multi-client relay, Rich CLI, CBOR serialization, and a modular architecture enabling extension to QUIC transport, Dilithium digital signatures, and AI-based anomaly detection on handshake logs. The project aligns with IETF PQ-TLS hybrid KEM drafts and serves as a pedagogical reference for post-quantum migration in secure messaging protocols.

**Keywords**: Post-Quantum Cryptography, ML-KEM, Kyber, Hybrid Key Exchange, TLS 1.3, HNDL, End-to-End Encryption, Forward Secrecy, KEMTLS.

---

*Target Venues*: IEEE Student Conference on Research and Development (SCOReD) | arXiv:cs.CR | IETF PQ-TLS Working Group
