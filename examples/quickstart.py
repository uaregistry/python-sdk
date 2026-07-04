"""Minimal end-to-end example. Requires a live endpoint + credentials.

    python examples/quickstart.py
"""

import logging
import sys

# Run from the repo without installing: make the package importable.
sys.path.insert(0, __file__.rsplit("examples", 1)[0])

from uaregistry import Client, Config
from uaregistry.exceptions import CommandException, EppException

logging.basicConfig(level=logging.INFO)

config = Config(
    host="uaregistry.com",
    clid="UAR0001",
    password="your-secret",
    port=700,             # default; override only if the endpoint moves
    lang="uk",            # localized result messages (en | uk | ua | ru)
    # ca_file="/path/to/ca.pem",   # for a private-CA / self-signed endpoint
)

client = Client(config, logger=logging.getLogger("epp"))
try:
    client.connect()      # TLS + read <greeting>
    client.login()

    avail = client.domain.check(["example.com.ua"]).availability()
    print("availability:", avail)

    info = client.domain.info("example.com.ua")
    print("exDate:", info.value("exDate"))

    bal = client.balance().balance()
    print("balance:", bal)

    msg = client.poll.request()
    if msg.message_id() is not None:
        print("poll:", msg.message())
        client.poll.ack(msg.message_id())

    client.logout()
except CommandException as exc:
    print("EPP error %d: %s" % (exc.epp_code, exc))
except EppException as exc:
    print("SDK error:", exc)
finally:
    client.disconnect()
