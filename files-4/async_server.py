"""
server/async_server.py
======================
Asynchronous multi-client TCP server for HyPQ-Mess.

Architecture:
    - asyncio-based event loop (single-threaded, no GIL contention).
    - Per-client session: isolated HybridKEM + AESGCMEncryptor instances.
    - Relay mode: server decrypts → re-encrypts per recipient session key.
    - Session registry: thread-safe dict guarded by asyncio.Lock.

Security:
    - Each client session has an independent ephemeral session key.
    - Server never stores plaintext messages; relay is decrypt-then-reencrypt.
    - Failed handshakes are logged and connections dropped immediately.

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from ..crypto.primitives import AESGCMEncryptor, EncryptedMessage
from ..protocol.handshake import ServerHandshake, HandshakeState
from ..protocol.message import (
    MessageCodec, MsgType, EncryptedMsgFrame,
    frame_message, parse_length_prefix,
)

logger = logging.getLogger(__name__)

HEADER_BYTES: int = 4      # 4-byte length prefix
READ_TIMEOUT: float = 30.0  # seconds before idle disconnect


# ---------------------------------------------------------------------------
# Per-client session state
# ---------------------------------------------------------------------------

@dataclass
class ClientSession:
    """
    Encapsulates all state for a single connected client.

    Fields:
        client_id  : Negotiated client identifier.
        encryptor  : AES-GCM engine for this session.
        writer     : asyncio StreamWriter for sending data.
        connected_at: Unix timestamp of connection establishment.
        messages_sent: Count of application messages sent to this client.
    """
    client_id: str
    encryptor: AESGCMEncryptor
    writer: asyncio.StreamWriter
    connected_at: float = field(default_factory=time.time)
    messages_sent: int = 0
    messages_recv: int = 0


# ---------------------------------------------------------------------------
# HyPQ-Mess Async Server
# ---------------------------------------------------------------------------

class HyPQServer:
    """
    Hybrid Post-Quantum Secure Messaging Server.

    Accepts multiple simultaneous TCP clients, performs the hybrid
    handshake with each, and relays encrypted messages between them.

    Usage:
        server = HyPQServer(host="0.0.0.0", port=8080)
        asyncio.run(server.start())

    Args:
        host     : Bind address (default "0.0.0.0").
        port     : TCP port (default 8080).
        server_id: Server identifier in handshake.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        server_id: str = "hypq-mess-server",
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.server_id: str = server_id
        self._sessions: Dict[str, ClientSession] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._start_time: float = 0.0
        self._total_connections: int = 0

    async def start(self) -> None:
        """Start the server and listen for connections."""
        self._start_time = time.time()
        server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )
        addr = server.sockets[0].getsockname()
        logger.info("=" * 60)
        logger.info("HyPQ-Mess Server listening on %s:%s", addr[0], addr[1])
        logger.info("Hybrid KEM: X25519 + Kyber-768 | Encryption: AES-256-GCM")
        logger.info("=" * 60)

        async with server:
            await server.serve_forever()

    # ------------------------------------------------------------------
    # Per-client handler
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle a new client connection: handshake → relay loop.

        Each client gets an isolated coroutine. Exceptions cause clean
        disconnect without affecting other sessions.
        """
        peer = writer.get_extra_info("peername")
        logger.info("[Server] New connection from %s", peer)
        self._total_connections += 1

        handshake = ServerHandshake(server_id=self.server_id)
        session: Optional[ClientSession] = None

        try:
            # --- Phase 1: Receive ClientHello ---
            client_hello_raw = await self._read_frame(reader)
            server_hello_raw = handshake.process_client_hello(client_hello_raw)
            await self._write_frame(writer, server_hello_raw)

            # --- Phase 2: Receive ClientFinish ---
            client_finish_raw = await self._read_frame(reader)
            handshake.process_client_finish(client_finish_raw)

            if handshake.state != HandshakeState.FINISHED:
                raise ConnectionError("Handshake did not complete.")

            # Extract client_id from finish message (decoded in handshake)
            _, finish_payload = MessageCodec.decode(client_finish_raw)
            client_id = finish_payload.get("client_id", f"client_{self._total_connections}")

            # --- Register session ---
            session = ClientSession(
                client_id=client_id,
                encryptor=handshake.encryptor,
                writer=writer,
            )
            async with self._lock:
                if client_id in self._sessions:
                    client_id = f"{client_id}_{self._total_connections}"
                    session.client_id = client_id
                self._sessions[client_id] = session

            logger.info("[Server] Client '%s' authenticated | Session established", client_id)
            await self._broadcast_system(f"'{client_id}' joined the channel.", exclude=client_id)

            # --- Message relay loop ---
            await self._relay_loop(reader, session)

        except asyncio.TimeoutError:
            logger.warning("[Server] Timeout from %s", peer)
        except ConnectionError as exc:
            logger.warning("[Server] Connection error from %s: %s", peer, exc)
        except Exception as exc:
            logger.error("[Server] Unexpected error from %s: %s", peer, exc, exc_info=True)
        finally:
            if session:
                async with self._lock:
                    self._sessions.pop(session.client_id, None)
                logger.info("[Server] Client '%s' disconnected", session.client_id if session else peer)
                await self._broadcast_system(
                    f"'{session.client_id}' left the channel.",
                    exclude=session.client_id if session else "",
                )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _relay_loop(
        self,
        reader: asyncio.StreamReader,
        sender_session: ClientSession,
    ) -> None:
        """
        Receive encrypted messages from one client and relay to all others.

        Server-side relay:
            1. Decrypt with sender's session key.
            2. Re-encrypt with each recipient's session key.
            3. Transmit to each recipient.

        This ensures per-session key isolation: clients cannot decrypt
        each other's traffic even if they share the relay server.
        """
        while True:
            try:
                raw = await asyncio.wait_for(
                    self._read_frame(reader), timeout=READ_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.info("[Server] Client '%s' idle timeout.", sender_session.client_id)
                break
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break

            msg_type, payload = MessageCodec.decode(raw)

            if msg_type == MsgType.ENCRYPTED_MSG:
                frame = EncryptedMsgFrame(**payload)
                enc_msg = EncryptedMessage(
                    nonce=frame.nonce,
                    ciphertext=frame.ciphertext,
                    sequence=frame.sequence,
                    timestamp=frame.timestamp,
                )
                try:
                    plaintext = sender_session.encryptor.decrypt(enc_msg)
                    sender_session.messages_recv += 1
                except Exception as exc:
                    logger.warning(
                        "[Server] Decryption failed from '%s': %s",
                        sender_session.client_id, exc
                    )
                    continue

                logger.debug(
                    "[Server] Relaying %d bytes from '%s' to %d peers",
                    len(plaintext), sender_session.client_id, len(self._sessions) - 1
                )

                # Relay to all other connected clients
                async with self._lock:
                    recipients = [
                        s for cid, s in self._sessions.items()
                        if cid != sender_session.client_id
                    ]

                for recipient in recipients:
                    try:
                        enc_out = recipient.encryptor.encrypt(
                            plaintext,
                            aad=sender_session.client_id.encode(),
                        )
                        out_frame = EncryptedMsgFrame(
                            nonce=enc_out.nonce,
                            ciphertext=enc_out.ciphertext,
                            sequence=enc_out.sequence,
                            timestamp=enc_out.timestamp,
                            sender_id=sender_session.client_id,
                        )
                        out_raw = MessageCodec.encode(MsgType.ENCRYPTED_MSG, out_frame)
                        await self._write_frame(recipient.writer, out_raw)
                        recipient.messages_sent += 1
                    except Exception as exc:
                        logger.warning(
                            "[Server] Failed to relay to '%s': %s",
                            recipient.client_id, exc
                        )

            elif msg_type == MsgType.PING:
                pong = MessageCodec.encode(MsgType.PONG, {"ts": int(time.time() * 1000)})
                await self._write_frame(sender_session.writer, pong)

    async def _broadcast_system(self, message: str, exclude: str = "") -> None:
        """Encrypt and broadcast a plaintext system message to all clients."""
        async with self._lock:
            sessions = list(self._sessions.items())
        for cid, session in sessions:
            if cid == exclude:
                continue
            try:
                enc = session.encryptor.encrypt(f"[SYSTEM] {message}".encode())
                frame = EncryptedMsgFrame(
                    nonce=enc.nonce,
                    ciphertext=enc.ciphertext,
                    sequence=enc.sequence,
                    timestamp=enc.timestamp,
                    sender_id="SYSTEM",
                )
                raw = MessageCodec.encode(MsgType.ENCRYPTED_MSG, frame)
                await self._write_frame(session.writer, raw)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # TCP framing helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> bytes:
        """Read one length-prefixed frame from the stream."""
        header = await reader.readexactly(HEADER_BYTES)
        length = parse_length_prefix(header)
        return await reader.readexactly(length)

    @staticmethod
    async def _write_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
        """Write one length-prefixed frame to the stream."""
        writer.write(frame_message(data))
        await writer.drain()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return server status metrics."""
        return {
            "uptime_seconds": time.time() - self._start_time,
            "active_sessions": len(self._sessions),
            "total_connections": self._total_connections,
            "clients": list(self._sessions.keys()),
        }
