"""EPP client for the UARegistry service. Open a connection, log in, then reach the object
commands through the resource properties — ``client.domain``, ``.contact``, ``.host``,
``.poll``. Each command returns a :class:`Response`. By default any EPP error code (>= 2000)
is raised as a :class:`CommandException`; call ``throw_on_failure(False)`` to inspect codes
yourself instead.

    client = Client(Config(host="uaregistry.com", clid="UAR0001", password="..."))
    client.connect()
    client.login()
    avail = client.domain.check(["example.com.ua"]).availability()
    client.logout()
    client.disconnect()
"""

from __future__ import annotations

import os
import re
import time
from functools import cached_property
from typing import Optional, Union

from . import namespaces as ns
from .commands import Contact, Domain, Host, Poll
from .config import Config
from .exceptions import (
    AuthenticationException,
    CommandException,
    ConfigException,
    ConnectionException,
)
from .frame import Frame
from .response import Response
from .transport import Connection, Transport

try:  # Optional logging via the standard library; any logging.Logger works.
    import logging

    _Logger = logging.Logger
except ImportError:  # pragma: no cover
    _Logger = object  # type: ignore

_REDACT = re.compile(r"(<(?:[\w.-]+:)?(?:pw|newPW)>)(.*?)(</(?:[\w.-]+:)?(?:pw|newPW)>)", re.S)


class Client:
    def __init__(self, config: Config, connection: Optional[Transport] = None,
                 logger: "Optional[_Logger]" = None) -> None:
        self._config = config
        self._connection: Transport = connection if connection is not None else Connection(config)
        self._logger = logger
        self._greeting: Optional[Response] = None
        self._logged_in = False
        self._throw = True
        self._trid_counter = 0
        # Per-process component of the client transaction id (clTRID): ids from one process
        # share a stable middle segment and stay unique across concurrent processes.
        self._process_token = str(os.getpid())

    @classmethod
    def connect_and_login(cls, config: Config) -> "Client":
        client = cls(config)
        client.connect()
        client.login()
        return client

    def throw_on_failure(self, throw: bool = True) -> "Client":
        """Toggle automatic CommandException raising on EPP error codes."""
        self._throw = throw
        return self

    def set_logger(self, logger: "Optional[_Logger]") -> "Client":
        """Attach (or clear) a logger; passwords/authInfo are masked before logging."""
        self._logger = logger
        return self

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.disconnect()

    def __del__(self) -> None:
        try:
            self._connection.close()
        except Exception:  # pragma: no cover — never raise from a finaliser
            pass

    # --- session ---------------------------------------------------------------

    def connect(self) -> Response:
        """Open the TLS socket and read the unsolicited <greeting>."""
        if self._config.host == "":
            raise ConfigException("Config: host must not be empty")
        if not self._connection.is_open():
            self._connection.open()
        raw = self._connection.read_frame()
        self._log_debug("EPP << greeting", raw)
        self._greeting = Response.from_xml(raw)
        return self._greeting

    @property
    def greeting(self) -> Optional[Response]:
        return self._greeting

    def hello(self) -> Response:
        """Send <hello>; the server replies with a fresh <greeting>."""
        self._connection.write_frame(
            '<?xml version="1.0" encoding="UTF-8"?><epp xmlns="%s"><hello/></epp>' % ns.EPP
        )
        self._greeting = Response.from_xml(self._connection.read_frame())
        return self._greeting

    def login(self, new_password: Optional[str] = None) -> Response:
        """Authenticate. Advertises exactly the services the greeting offered (never rejected
        for an unsupported service) unless Config.obj_uris / ext_uris override them.

        Pass ``new_password`` to rotate the EPP password during login (RFC 5730 <newPW>)."""
        if self._config.clid == "" or self._config.password == "":
            raise ConfigException(
                "login requires a non-empty clID and password (clID %s, password %s) — check your config"
                % ("set" if self._config.clid else "EMPTY", "set" if self._config.password else "EMPTY")
            )
        if self._greeting is None:
            self.connect()

        greeting_obj = self._greeting.service_obj_uris() if self._greeting else []
        greeting_ext = self._greeting.service_ext_uris() if self._greeting else []
        obj_uris = self._config.obj_uris or (greeting_obj or ns.DEFAULT_OBJ_URIS)
        ext_uris = self._config.ext_uris if self._config.ext_uris is not None else (greeting_ext or ns.DEFAULT_EXT_URIS)
        # The epp-1.0 base URI is not an object service and is never listed in <login>.
        obj_uris = [u for u in obj_uris if u != ns.EPP]

        frame = self.frame()
        login = frame.verb("login")
        frame.epp(login, "clID", self._config.clid)
        frame.epp(login, "pw", self._config.password)
        if new_password is not None:
            frame.epp(login, "newPW", new_password)
        options = frame.epp(login, "options")
        frame.epp(options, "version", "1.0")
        frame.epp(options, "lang", self._config.lang)
        svcs = frame.epp(login, "svcs")
        for uri in obj_uris:
            frame.epp(svcs, "objURI", uri)
        if ext_uris:
            svc_ext = frame.epp(svcs, "svcExtension")
            for uri in ext_uris:
                frame.epp(svc_ext, "extURI", uri)

        response = self._transact(frame.to_xml())
        if response.code() != 1000:
            raise AuthenticationException(
                response.code(),
                "Login failed (EPP %d): %s" % (response.code(), response.message() or "no message"),
                response,
            )
        self._logged_in = True
        return response

    def logout(self) -> Response:
        frame = self.frame()
        frame.verb("logout")
        response = self._transact(frame.to_xml())  # 1500; the server then closes the link
        self._logged_in = False
        return response

    def disconnect(self) -> None:
        self._connection.close()
        self._logged_in = False

    def is_connected(self) -> bool:
        return self._connection.is_open()

    def is_logged_in(self) -> bool:
        return self._logged_in

    # --- resource handlers -----------------------------------------------------

    @cached_property
    def domain(self) -> Domain:
        return Domain(self)

    @cached_property
    def contact(self) -> Contact:
        return Contact(self)

    @cached_property
    def host(self) -> Host:
        return Host(self)

    @cached_property
    def poll(self) -> Poll:
        return Poll(self)

    def balance(self) -> Response:
        """Query the registrar account balance (creditLimit / balance / availableCredit)."""
        frame = self.frame()
        frame.ns(frame.verb("info"), ns.UAREG_BALANCE, "balance:info")
        return self.request(frame)

    # --- low-level -------------------------------------------------------------

    def frame(self) -> Frame:
        """A new command frame with an auto-generated clTRID already stamped."""
        return Frame.command(self._next_cltrid())

    def request(self, frame: Union[Frame, str]) -> Response:
        """Send a frame (a :class:`Frame` or raw XML string) and return the parsed response.
        Raises CommandException on an EPP error code unless throw_on_failure(False) is set."""
        xml = frame.to_xml() if isinstance(frame, Frame) else frame
        response = self._transact(xml)
        if self._throw and not response.is_success():
            raise CommandException(
                response.code(),
                "EPP %d: %s" % (response.code(), response.message() or "command failed"),
                response,
            )
        return response

    # --- internals -------------------------------------------------------------

    def _transact(self, xml: str) -> Response:
        if not self._connection.is_open():
            raise ConnectionException("Not connected — call connect() first")
        self._log_debug("EPP >> request", self._redact(xml))
        self._connection.write_frame(xml)
        raw = self._connection.read_frame()
        self._log_debug("EPP << response", self._redact(raw))
        response = Response.from_xml(raw)
        if self._logger is not None:
            level = "info" if response.is_success() else "warning"
            getattr(self._logger, level)(
                "EPP result %d (svTRID=%s clTRID=%s)",
                response.code(), response.sv_trid(), response.cl_trid(),
            )
        return response

    def _log_debug(self, msg: str, frame: str) -> None:
        if self._logger is not None:
            self._logger.debug("%s %s", msg, frame)

    @staticmethod
    def _redact(xml: str) -> str:
        """Mask passwords / authInfo (any namespace) before a frame is logged."""
        return _REDACT.sub(r"\1***\3", xml)

    def _next_cltrid(self) -> str:
        self._trid_counter += 1
        # A client transaction id that is easy to correlate in logs: prefix, a UTC timestamp,
        # the per-process token and a monotonic counter.
        return "%s-%s-%s-%04d" % (
            self._config.cltrid_prefix,
            time.strftime("%Y%m%d%H%M%S", time.gmtime()),
            self._process_token,
            self._trid_counter,
        )
