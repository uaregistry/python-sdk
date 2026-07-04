"""The raw EPP-over-TLS transport: a TLS socket plus RFC 5734 framing (each message is
prefixed with a 4-byte big-endian total length that INCLUDES the 4 header bytes). Knows
nothing about EPP semantics — it ships and receives byte frames.

Byte counts use the UTF-8 *encoded* length (never the character count), so multibyte
(Cyrillic / IDN) payloads are framed correctly.
"""

from __future__ import annotations

import socket
import ssl
import struct
from abc import ABC, abstractmethod
from typing import Optional

from .config import Config
from .exceptions import ConnectionException

_MAX_FRAME = 1_048_576  # 1 MiB guard against a runaway length prefix


class Transport(ABC):
    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def is_open(self) -> bool: ...

    @abstractmethod
    def write_frame(self, xml: str) -> None: ...

    @abstractmethod
    def read_frame(self) -> str: ...

    @abstractmethod
    def close(self) -> None: ...


class Connection(Transport):
    def __init__(self, config: Config) -> None:
        self._config = config
        self._sock: Optional[ssl.SSLSocket] = None

    def _context(self) -> ssl.SSLContext:
        # PROTOCOL_TLS_CLIENT defaults to check_hostname=True + CERT_REQUIRED (secure).
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # EPP runs over modern TLS; refuse anything below 1.2.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        cfg = self._config
        if cfg.ca_file is not None:
            ctx.load_verify_locations(cfg.ca_file)
        if not cfg.verify_peer:
            # check_hostname must be cleared BEFORE lowering verify_mode.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif not cfg.verify_peer_name:
            ctx.check_hostname = False
        if cfg.client_cert is not None:
            ctx.load_cert_chain(cfg.client_cert, cfg.client_key, cfg.client_key_passphrase)
        return ctx

    def open(self) -> None:
        cfg = self._config
        try:
            raw = socket.create_connection((cfg.host, cfg.port), timeout=cfg.connect_timeout)
        except OSError as exc:
            raise ConnectionException("Cannot connect to %s:%d — %s" % (cfg.host, cfg.port, exc))
        try:
            self._sock = self._context().wrap_socket(raw, server_hostname=cfg.host)
        except (ssl.SSLError, OSError) as exc:
            raw.close()
            raise ConnectionException("TLS handshake with %s:%d failed — %s" % (cfg.host, cfg.port, exc))
        self._sock.settimeout(max(1.0, float(cfg.read_timeout)))

    def is_open(self) -> bool:
        return self._sock is not None

    def write_frame(self, xml: str) -> None:
        if self._sock is None:
            raise ConnectionException("Not connected")
        body = xml.encode("utf-8")
        payload = struct.pack("!I", len(body) + 4) + body
        try:
            self._sock.sendall(payload)
        except socket.timeout:
            raise ConnectionException("Write timed out")
        except OSError as exc:
            raise ConnectionException("Write failed (connection closed?): %s" % exc)

    def read_frame(self) -> str:
        (length,) = struct.unpack("!I", self._read_bytes(4))
        if length < 4 or length > _MAX_FRAME:
            raise ConnectionException("Invalid EPP frame length: %d" % length)
        return self._read_bytes(length - 4).decode("utf-8")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _read_bytes(self, n: int) -> bytes:
        if n == 0:
            return b""
        if self._sock is None:
            raise ConnectionException("Not connected")
        chunks = []
        got = 0
        while got < n:
            try:
                chunk = self._sock.recv(n - got)
            except socket.timeout:
                raise ConnectionException("Read timed out")
            except OSError as exc:
                raise ConnectionException("Connection error while reading: %s" % exc)
            if chunk == b"":
                raise ConnectionException("Connection closed while reading")
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)
