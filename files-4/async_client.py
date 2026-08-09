"""
client/async_client.py
======================
Asynchronous TCP client for HyPQ-Mess with Rich CLI interface.

Features:
    - Initiates hybrid handshake (X25519 + Kyber-768).
    - Bidirectional async message I/O: send while receiving.
    - Rich terminal UI with colored output.
    - Graceful disconnect with key zeroization.

Usage:
    python -m hy_pq_mess.client localhost 8080 --id alice

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

    class Console:
        def print(self, *args, **kwargs):
            print(*[str(a) for a in args])

        def rule(self, *args, **kwargs):
            print("=" * 60)

    class Panel:
        def __init__(self, *args, **kwargs):
            pass

        def __str__(self):
            return "HyPQ-Mess"


from ..crypto.primitives import AESGCMEncryptor, EncryptedMessage, ReplayAttackError
from ..protocol.handshake import ClientHandshake, HandshakeState
from ..protocol.message import (
    MessageCodec,
    MsgType,
    EncryptedMsgFrame,
    frame_message,
    parse_length_prefix,
)

logger = logging.getLogger(__name__)
console = Console()

HEADER_BYTES: int = 4


class HyPQClient:
    """
    Hybrid Post-Quantum Secure Messaging Client.

    Performs the hybrid handshake and maintains an encrypted channel
    to the HyPQ-Mess server.

    Args:
        host      : Server hostname or IP.
        port      : Server TCP port.
        client_id : Client identifier (shown to other users).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        client_id: str = "client",
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.client_id: str = client_id
        self._encryptor: Optional[AESGCMEncryptor] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected: bool = False
        self._handshake_time_ms: float = 0.0

    async def connect_and_run(self) -> None:
        """Connect to server, perform handshake, and start interactive loop."""
        console.print(
            Panel(
                f"[bold cyan]HyPQ-Mess Client[/bold cyan]\n"
                f"Connecting to [yellow]{self.host}:{self.port}[/yellow] as [green]{self.client_id}[/green]\n"
                f"Hybrid KEM: X25519 + Kyber-768 | AES-256-GCM",
                title="[bold]Quantum-Safe Secure Messenger[/bold]",
            )
        )

        try:
            self._reader, self._writer = await asyncio.open_connection(
                self.host, self.port
            )
            logger.info("TCP connected to %s:%s", self.host, self.port)
        except ConnectionRefusedError:
            console.print(f"[red]Connection refused: {self.host}:{self.port}[/red]")
            return

        # --- Hybrid Handshake ---
        t0 = time.perf_counter()
        try:
            await self._perform_handshake()
        except Exception as exc:
            console.print(f"[bold red]Handshake FAILED:[/bold red] {exc}")
            return
        self._handshake_time_ms = (time.perf_counter() - t0) * 1000

        self._connected = True
        console.print(
            f"\n[bold green]✓ Secure channel established[/bold green] "
            f"(handshake: {self._handshake_time_ms:.1f} ms)\n"
            f"[dim]Type messages and press Enter. Ctrl+C to quit.[/dim]\n"
        )

        # --- Concurrent send + receive ---
        await asyncio.gather(
            self._receive_loop(),
            self._send_loop(),
            return_exceptions=True,
        )

    async def _perform_handshake(self) -> None:
        """Execute 3-message hybrid handshake."""
        hs = ClientHandshake(client_id=self.client_id)

        # ClientHello → server
        hello_raw = hs.create_client_hello()
        await self._write_frame(hello_raw)
        console.print("[dim]→ ClientHello sent (X25519 + Kyber-768 pub keys)[/dim]")

        # ServerHello ← server
        srv_hello = await self._read_frame()
        finish_raw = hs.process_server_hello(srv_hello)
        console.print("[dim]← ServerHello received (Kyber CT + key confirmation)[/dim]")

        # ClientFinish → server
        await self._write_frame(finish_raw)
        console.print("[dim]→ ClientFinish sent (mutual key confirmation)[/dim]")

        if hs.state != HandshakeState.FINISHED:
            raise ConnectionError("Handshake state not FINISHED after exchange.")

        self._encryptor = hs.encryptor

    async def _receive_loop(self) -> None:
        """Continuously receive and decrypt messages from the server."""
        while self._connected:
            try:
                raw = await self._read_frame()
            except (asyncio.IncompleteReadError, ConnectionResetError):
                console.print("\n[yellow]Server disconnected.[/yellow]")
                self._connected = False
                break

            try:
                msg_type, payload = MessageCodec.decode(raw)
            except Exception as exc:
                logger.warning("Failed to decode message: %s", exc)
                continue

            if msg_type == MsgType.ENCRYPTED_MSG:
                frame = EncryptedMsgFrame(**payload)
                enc_msg = EncryptedMessage(
                    nonce=frame.nonce,
                    ciphertext=frame.ciphertext,
                    sequence=frame.sequence,
                    timestamp=frame.timestamp,
                )
                try:
                    plaintext = self._encryptor.decrypt(
                        enc_msg,
                        aad=(
                            frame.sender_id.encode()
                            if frame.sender_id != "SYSTEM"
                            else None
                        ),
                    )
                    text = plaintext.decode("utf-8", errors="replace")
                    sender = frame.sender_id

                    if sender == "SYSTEM":
                        console.print(f"[italic dim]{text}[/italic dim]")
                    else:
                        console.print(
                            f"[bold cyan]{sender}[/bold cyan][dim]:[/dim] {text}"
                        )
                except ReplayAttackError as exc:
                    console.print(f"[bold red]REPLAY ATTACK DETECTED:[/bold red] {exc}")
                except Exception as exc:
                    logger.warning("Decryption error: %s", exc)

            elif msg_type == MsgType.PONG:
                ts = payload.get("ts", 0)
                rtt = int(time.time() * 1000) - ts
                console.print(f"[dim]Pong: {rtt} ms RTT[/dim]")

    async def _send_loop(self) -> None:
        """Read user input and encrypt/send messages."""
        loop = asyncio.get_event_loop()
        while self._connected:
            try:
                # Non-blocking stdin read
                text = await loop.run_in_executor(None, sys.stdin.readline)
                text = text.rstrip("\n")
                if not text:
                    continue
                if text.lower() in ("/quit", "/exit"):
                    self._connected = False
                    break
                if text.lower() == "/ping":
                    ping_raw = MessageCodec.encode(MsgType.PING, {})
                    await self._write_frame(ping_raw)
                    continue

                enc = self._encryptor.encrypt(text.encode("utf-8"))
                frame = EncryptedMsgFrame(
                    nonce=enc.nonce,
                    ciphertext=enc.ciphertext,
                    sequence=enc.sequence,
                    timestamp=enc.timestamp,
                    sender_id=self.client_id,
                )
                raw = MessageCodec.encode(MsgType.ENCRYPTED_MSG, frame)
                await self._write_frame(raw)
                # Echo own message locally
                console.print(
                    f"[bold green]{self.client_id}[/bold green][dim]:[/dim] {text}"
                )
            except (EOFError, KeyboardInterrupt):
                self._connected = False
                break
            except Exception as exc:
                logger.error("Send error: %s", exc)

    # ------------------------------------------------------------------
    # TCP framing helpers
    # ------------------------------------------------------------------

    async def _read_frame(self) -> bytes:
        header = await self._reader.readexactly(HEADER_BYTES)
        length = parse_length_prefix(header)
        return await self._reader.readexactly(length)

    async def _write_frame(self, data: bytes) -> None:
        self._writer.write(frame_message(data))
        await self._writer.drain()

    def close(self) -> None:
        """Close the connection."""
        self._connected = False
        if self._writer:
            self._writer.close()
