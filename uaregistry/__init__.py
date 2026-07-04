"""UARegistry EPP SDK (Python).

A small, dependency-free client for the UARegistry EPP service — standard RFC 5730-5734
EPP over TLS on port 700. Speaks the wire protocol directly (no framework, no server code).

    from uaregistry import Client, Config

    client = Client(Config(host="uaregistry.com", clid="UAR0001", password="secret"))
    client.connect()
    client.login()
    print(client.domain.check(["example.com.ua"]).availability())
    client.logout()
    client.disconnect()
"""

from . import namespaces as Namespaces
from .client import Client
from .commands import Contact, Domain, Host, Poll
from .config import Config
from .exceptions import (
    AuthenticationException,
    CommandException,
    ConfigException,
    ConnectionException,
    EppException,
)
from .frame import Frame
from .response import Response
from .result_code import ResultCode
from .transport import Connection, Transport

__version__ = "1.0.0"

__all__ = [
    "Client",
    "Config",
    "Frame",
    "Response",
    "ResultCode",
    "Namespaces",
    "Transport",
    "Connection",
    "Domain",
    "Contact",
    "Host",
    "Poll",
    "EppException",
    "ConnectionException",
    "ConfigException",
    "CommandException",
    "AuthenticationException",
    "__version__",
]
