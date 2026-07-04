"""Exception hierarchy raised by the SDK.

Catch :class:`EppException` to handle any SDK failure; catch the subclasses to
distinguish a transport problem from a command rejection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .response import Response


class EppException(RuntimeError):
    """Base class for every exception thrown by the SDK."""


class ConnectionException(EppException):
    """A transport-level problem (connect/read/write/TLS/framing)."""


class ConfigException(EppException):
    """The client was misconfigured (empty host / clID / password, etc.)."""


class CommandException(EppException):
    """The server answered with an EPP error result code (>= 2000).

    The code and the full parsed response are attached so the caller can branch.
    """

    def __init__(self, epp_code: int, message: str, response: "Optional[Response]" = None) -> None:
        super().__init__(message)
        self.epp_code = epp_code
        self.response = response


class AuthenticationException(CommandException):
    """Login failed (bad clID/password, or an authentication-class result code)."""
