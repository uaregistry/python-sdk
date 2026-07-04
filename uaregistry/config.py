"""Immutable connection settings for a UARegistry EPP session.

The public endpoint is strict RFC EPP over TLS (host ``uaregistry.com``, port 700) and
needs NO client certificate. The optional ``client_cert`` / ``client_key`` /
``client_key_passphrase`` are only used if your endpoint requires mutual TLS. When
``obj_uris`` / ``ext_uris`` are left ``None`` the client logs in advertising exactly the
services the server greeting offers, so it is never rejected for an unsupported service.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Dict, List, Optional


@dataclass
class Config:
    host: str
    clid: str
    password: str
    port: int = 700
    lang: str = "en"
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    verify_peer: bool = True
    verify_peer_name: bool = True
    #: CA bundle that signs the SERVER certificate (private-CA / self-signed endpoint).
    ca_file: Optional[str] = None
    #: Your (registrar) client certificate — only when mutual TLS is required. PEM path.
    client_cert: Optional[str] = None
    #: Your client private key. PEM path. May be omitted when bundled in ``client_cert``.
    client_key: Optional[str] = None
    #: Passphrase for an encrypted client private key, if any.
    client_key_passphrase: Optional[str] = None
    #: Override the login objURIs; ``None`` = use the greeting's.
    obj_uris: Optional[List[str]] = None
    #: Override the login extURIs; ``None`` = use the greeting's.
    ext_uris: Optional[List[str]] = None
    #: Prefix for auto-generated client transaction ids (clTRID).
    cltrid_prefix: str = "UAR-SDK"

    @classmethod
    def from_dict(cls, values: Dict[str, Any]) -> "Config":
        """Build a Config from a plain dict (keys match the field names)."""
        allowed = {f.name for f in fields(cls)}
        unknown = set(values) - allowed
        if unknown:
            raise TypeError("Config.from_dict: unknown keys: " + ", ".join(sorted(unknown)))
        return cls(**values)
