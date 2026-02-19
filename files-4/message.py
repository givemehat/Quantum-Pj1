"""
protocol/message.py
===================
CBOR-based message serialization for HyPQ-Mess wire protocol.

Uses RFC 8949 CBOR (Concise Binary Object Representation) for compact,
schema-less binary encoding — approximately 20-30% smaller than JSON
for binary-heavy payloads like cryptographic keys and ciphertexts.

Message Types:
    CLIENT_HELLO  (0x01): Client public keys + nonce
    SERVER_HELLO  (0x02): Server public keys + Kyber CT + nonce + KeyConfirm
    CLIENT_FINISH (0x03): Client key confirmation MAC
    ENCRYPTED_MSG (0x10): AES-GCM encrypted application data
    ERROR         (0xFF): Protocol error notification

Wire Format (each field is CBOR-encoded):
    {
        "type"    : <uint8 message type>,
        "version" : <uint8 protocol version>,
        "payload" : <map of type-specific fields>
    }

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import enum
import base64
try:
    import cbor2
    _USE_CBOR = True
except ImportError:
    import json as _json
    _USE_CBOR = False


class _CborFallback:
    """JSON-based fallback when cbor2 is unavailable.
    Bytes values are base64-encoded since JSON cannot handle raw bytes."""
    @staticmethod
    def _encode_val(v):
        if isinstance(v, bytes):
            return {"__b64__": base64.b64encode(v).decode()}
        if isinstance(v, dict):
            return {k: _CborFallback._encode_val(vv) for k, vv in v.items()}
        if isinstance(v, list):
            return [_CborFallback._encode_val(i) for i in v]
        return v

    @staticmethod
    def _decode_val(v):
        if isinstance(v, dict):
            if "__b64__" in v:
                return base64.b64decode(v["__b64__"])
            return {k: _CborFallback._decode_val(vv) for k, vv in v.items()}
        if isinstance(v, list):
            return [_CborFallback._decode_val(i) for i in v]
        return v

    @staticmethod
    def dumps(obj):
        return _json.dumps(_CborFallback._encode_val(obj)).encode()

    @staticmethod
    def loads(data):
        return _CborFallback._decode_val(_json.loads(data))

if not _USE_CBOR:
    cbor2 = _CborFallback()
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
PROTOCOL_VERSION: int = 1
MAX_MESSAGE_BYTES: int = 65_536   # 64 KiB hard limit per message


# ---------------------------------------------------------------------------
# Message type registry
# ---------------------------------------------------------------------------

class MsgType(enum.IntEnum):
    CLIENT_HELLO  = 0x01
    SERVER_HELLO  = 0x02
    CLIENT_FINISH = 0x03
    ENCRYPTED_MSG = 0x10
    PING          = 0x20
    PONG          = 0x21
    ERROR         = 0xFF


# ---------------------------------------------------------------------------
# Message dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ClientHelloMsg:
    """
    Phase 1 of hybrid handshake (client → server).

    Fields:
        x25519_pub : Client's ephemeral X25519 public key (32 bytes).
        kyber_pub  : Client's ephemeral Kyber-768 public key (1184 bytes).
        nonce      : 32-byte random client nonce (for salt in HKDF).
        client_id  : Optional client identifier string.
    """
    x25519_pub: bytes
    kyber_pub: bytes
    nonce: bytes
    client_id: str = "anonymous"


@dataclass
class ServerHelloMsg:
    """
    Phase 2 of hybrid handshake (server → client).

    Fields:
        x25519_pub    : Server's ephemeral X25519 public key (32 bytes).
        kyber_pub     : Server's Kyber-768 public key (1184 bytes).
        kyber_ct      : Kyber-768 encapsulation ciphertext of client's key (1088 bytes).
        nonce         : 32-byte random server nonce.
        key_confirm   : HMAC-SHA256 MAC for key confirmation (32 bytes).
        server_id     : Server identifier.
    """
    x25519_pub: bytes
    kyber_pub: bytes
    kyber_ct: bytes
    nonce: bytes
    key_confirm: bytes
    server_id: str = "hypq-mess-server"


@dataclass
class ClientFinishMsg:
    """
    Phase 3 of hybrid handshake (client → server).

    Provides mutual authentication: client proves it derived the same
    session key by computing HMAC over the transcript hash.

    Fields:
        key_confirm  : Client's HMAC-SHA256 key confirmation (32 bytes).
        client_id    : Client identifier.
    """
    key_confirm: bytes
    client_id: str = "anonymous"


@dataclass
class EncryptedMsgFrame:
    """
    Application data message (bidirectional after handshake).

    Fields:
        nonce      : AES-GCM 96-bit nonce (12 bytes).
        ciphertext : AES-256-GCM ciphertext + 16-byte auth tag.
        sequence   : Monotonic sequence number (anti-replay).
        timestamp  : Unix microsecond timestamp (anti-replay).
        sender_id  : Plaintext sender identifier (authenticated via GCM AAD).
    """
    nonce: bytes
    ciphertext: bytes
    sequence: int
    timestamp: int
    sender_id: str = "unknown"


@dataclass
class ErrorMsg:
    """Protocol error message."""
    code: int
    description: str


# ---------------------------------------------------------------------------
# Serializer / Deserializer
# ---------------------------------------------------------------------------

class MessageCodec:
    """
    CBOR-based encoder/decoder for HyPQ-Mess wire protocol messages.

    Encoding format:
        cbor({
            "t": <MsgType int>,
            "v": <protocol version int>,
            "p": <payload dict>
        })

    The compact single-char keys ("t", "v", "p") reduce wire overhead
    on high-frequency messaging paths.
    """

    @staticmethod
    def encode(msg_type: MsgType, payload: Any) -> bytes:
        """
        Encode a message into CBOR bytes.

        Args:
            msg_type: One of the MsgType enum values.
            payload : Message dataclass (will be converted to dict).

        Returns:
            CBOR-encoded bytes ready for transmission.

        Raises:
            ValueError: If encoded message exceeds MAX_MESSAGE_BYTES.
        """
        if hasattr(payload, "__dataclass_fields__"):
            payload_dict = asdict(payload)
        elif isinstance(payload, dict):
            payload_dict = payload
        else:
            payload_dict = {"data": payload}

        envelope = {
            "t": int(msg_type),
            "v": PROTOCOL_VERSION,
            "p": payload_dict,
        }
        encoded = cbor2.dumps(envelope)
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise ValueError(
                f"Encoded message {len(encoded)} B exceeds limit {MAX_MESSAGE_BYTES} B."
            )
        return encoded

    @staticmethod
    def decode(data: bytes) -> tuple[MsgType, dict]:
        """
        Decode CBOR bytes into (MsgType, payload_dict).

        Args:
            data: Raw CBOR bytes from network.

        Returns:
            Tuple of (MsgType, payload as dict).

        Raises:
            ValueError      : Malformed CBOR or unknown message type.
            VersionMismatch : Incompatible protocol version.
        """
        try:
            envelope = cbor2.loads(data)
        except Exception as exc:
            raise ValueError(f"CBOR decode failed: {exc}") from exc

        version = envelope.get("v", 0)
        if version != PROTOCOL_VERSION:
            raise VersionMismatchError(
                f"Protocol version mismatch: expected {PROTOCOL_VERSION}, got {version}."
            )

        try:
            msg_type = MsgType(envelope["t"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Unknown message type: {exc}") from exc

        payload = envelope.get("p", {})
        return msg_type, payload

    @staticmethod
    def encode_encrypted(frame: EncryptedMsgFrame) -> bytes:
        """Convenience encoder for encrypted application messages."""
        return MessageCodec.encode(MsgType.ENCRYPTED_MSG, frame)

    @staticmethod
    def decode_encrypted(data: bytes) -> EncryptedMsgFrame:
        """Convenience decoder for encrypted application messages."""
        msg_type, payload = MessageCodec.decode(data)
        if msg_type != MsgType.ENCRYPTED_MSG:
            raise ValueError(f"Expected ENCRYPTED_MSG, got {msg_type.name}.")
        return EncryptedMsgFrame(**payload)


# ---------------------------------------------------------------------------
# Length-prefixed framing for TCP streams
# ---------------------------------------------------------------------------

def frame_message(data: bytes) -> bytes:
    """
    Prepend a 4-byte big-endian length prefix for TCP stream framing.

    TCP is a stream protocol; length-prefixed framing ensures receivers
    can correctly delimit message boundaries.

    Args:
        data: Encoded message bytes.

    Returns:
        4-byte length prefix + message bytes.
    """
    import struct
    return struct.pack(">I", len(data)) + data


def parse_length_prefix(header: bytes) -> int:
    """
    Parse 4-byte length prefix from TCP frame header.

    Args:
        header: Exactly 4 bytes.

    Returns:
        Message body length in bytes.

    Raises:
        ValueError: If header is not exactly 4 bytes.
    """
    import struct
    if len(header) != 4:
        raise ValueError(f"Expected 4-byte header, got {len(header)}.")
    (length,) = struct.unpack(">I", header)
    if length > MAX_MESSAGE_BYTES:
        raise ValueError(f"Claimed message length {length} B exceeds limit.")
    return length


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class VersionMismatchError(Exception):
    """Raised when protocol version does not match."""
