# UARegistry EPP SDK (Python)

A small, **dependency-free** Python client for the **UARegistry** EPP service — standard
**RFC 5730–5734** EPP over **TLS on port 700**. It speaks the wire protocol directly
(no framework, no server-side code), so you can drop it into any Python 3.8+ project.
Every command frame is standard, schema-valid EPP.

- TLS transport with correct RFC 5734 framing (4-byte length prefix, UTF-8 byte-safe).
- Session: `connect` / `login` / `logout`, with the login services taken from the server
  greeting automatically (never rejected for an unsupported service).
- Full object commands: **domain**, **contact**, **host** (check / info / create / update /
  delete / transfer / renew), plus **poll** and **balance**.
- Extensions: **secDNS** (RFC 5910), **RGP restore** (RFC 3915), and the UARegistry native
  **.ua trademark licence**.
- Clean `Response` objects (result code, message, availability map, value getters) and typed
  exceptions.

## Install

```bash
pip install git+https://github.com/uaregistry/python-sdk
```

Or pin a released tag:

```bash
pip install "uaregistry @ git+https://github.com/uaregistry/python-sdk@v1.0.0"
```

No packaging at all? Copy the `uaregistry/` package folder next to your code and
`import uaregistry`. The SDK requires only the Python standard library
(`ssl`, `socket`, `xml.etree`).

## Quick start

```python
from uaregistry import Client, Config
from uaregistry.exceptions import EppException

client = Client(Config(
    host="uaregistry.com",
    clid="UAR0001",
    password="your-secret",
    port=700,                # default; override only if the endpoint moves
    lang="uk",               # localized result messages: en | uk | ua | ru
    # ca_file="/path/to/ca.pem",   # for a private-CA / self-signed endpoint
))

try:
    client.connect()          # TLS + read <greeting>
    client.login()

    avail = client.domain.check(["example.com.ua"]).availability()
    #  => {"example.com.ua": True}

    info = client.domain.info("example.com.ua")
    print(info.value("exDate"))

    client.logout()
except EppException as exc:
    print("EPP error:", exc)
finally:
    client.disconnect()
```

`Client` is also a context manager (`with Client(cfg) as client: ...`) that disconnects on exit.

## TLS notes

| Scenario | Config |
|---|---|
| Public, browser-trusted cert | defaults (`verify_peer=True`, `verify_peer_name=True`) |
| Private-CA / self-signed endpoint | set `ca_file` to the CA `.pem` |
| Hostname mismatch (dev) | `verify_peer_name=False` |
| Mutual-TLS endpoint | `client_cert` + `client_key` (+ `client_key_passphrase` if the key is encrypted) |

The public endpoint on `uaregistry.com:700` is strict RFC EPP and needs **no client
certificate** — auth is clID + password (over TLS) with an IP allowlist.

## Commands

```python
# Session
client.connect(); client.login(); client.logout(); client.disconnect()
client.login("new-password")          # rotate the EPP password during login
client.hello()                        # re-read the greeting / keep-alive

# Domain
client.domain.check(["a.com.ua", "b.com.ua"])
client.domain.info("a.com.ua", "pw")
client.domain.create("a.com.ua",
    years=1, registrant="C1", contacts={"admin": "C1", "tech": "C2"},
    nameservers=["ns1.x.ua", "ns2.x.ua"], auth_info="pw",
    license="TM-123",                                        # second-level .ua only
    sec_dns={"ds_data": [{"key_tag": 12345, "alg": 8, "digest_type": 2, "digest": "ABCD..."}]})
client.domain.update("a.com.ua",
    add={"ns": ["ns3.x.ua"], "statuses": ["clientHold"]},
    rem={"statuses": ["clientHold"]},
    chg={"registrant": "C9", "auth_info": "newpw"},
    # DNSSEC (RFC 5910): sec_dns={"add": {"ds_data": [...]}, "rem_all": True, "max_sig_life": 1209600}
)
client.domain.renew("a.com.ua", "2027-01-15", 1)
client.domain.restore("a.com.ua")     # RGP restore (op="request")
client.domain.delete("a.com.ua")
client.domain.transfer("request", "a.com.ua", "pw", 1)

# Contact
client.contact.check(["c1"])
client.contact.info("c1", "pw")
client.contact.create("c1", name="ACME", city="Kyiv", cc="UA", email="a@b.ua", auth_info="pw",
    # postal_infos=[{"type": "int", ...}, {"type": "loc", ...}],   # int + localized
    # disclose={"flag": False, "addr": ["int"], "voice": True},    # RFC 5733 privacy
)
client.contact.update("c1", chg={"email": "new@b.ua"},
    add_statuses=["clientUpdateProhibited"])
client.contact.delete("c1")
client.contact.transfer("request", "c1", "pw")

# Host
client.host.check(["ns1.x.ua"])
client.host.info("ns1.x.ua")
client.host.create("ns1.x.ua", ["203.0.113.10", "2001:db8::1"])  # v4/v6 auto-detected
client.host.update("ns1.x.ua", add_addresses=["203.0.113.11"])
client.host.delete("ns1.x.ua")

# Poll & balance
msg = client.poll.request()           # 1301 with a message, 1300 when empty
if msg.message_id() is not None:      # message_count() = how many remain
    client.poll.ack(msg.message_id())
b = client.balance().balance()        # {"creditLimit": ..., "balance": ..., "availableCredit": ...}
```

## Responses

Every command returns a `Response`:

```python
r.code()            # int EPP result code (1000, 1001, 2303, ...)
r.is_success()      # True for 1xxx
r.is_pending()      # True for 1001 (registry resolves via a poll message)
r.message()         # human-readable <msg>
r.message_lang()    # "en" | "uk" | "ua" | "ru"
r.availability()    # {name: bool} for *:check
r.statuses()        # ["ok"] or ["clientHold", ...]
r.value("exDate")   # first element with that local name
r.values("ns")      # all elements with that local name
r.balance()         # {"creditLimit": ..., "balance": ..., "availableCredit": ...} or None
r.prices()          # {"renewal": {"value": ..., "currency": "UAH"}, ...}
r.license()         # .ua trademark/licence number, or None
r.rgp_status()      # ["redemptionPeriod"], ...
r.transfer_status() # "pending" | "serverApproved" | ... or None
r.ds_records()      # [{"keyTag":..,"alg":..,"digestType":..,"digest":..}, ...]
r.key_records()     # [{"flags":..,"protocol":..,"alg":..,"pubKey":..}, ...]
r.is_signed()       # bool: any DNSSEC data present
r.message_id()      # poll: id to pass to poll().ack(); message_count() = queue size
r.error_reasons()   # extra <extValue><reason> text on a failed command
r.sv_trid()         # server transaction id
r.raw               # the raw XML
r.root              # the parsed ElementTree root, for anything bespoke
```

## Error handling

By default any EPP error code (>= 2000) raises `CommandException` (with `.epp_code` and
`.response`). Login failures raise `AuthenticationException`; transport problems raise
`ConnectionException`. All extend `EppException`.

```python
from uaregistry.exceptions import CommandException
from uaregistry import ResultCode

try:
    client.domain.create("taken.com.ua", years=1, registrant="C1",
                          contacts={"admin": "C1", "tech": "C2"}, nameservers=["ns1.x.ua"])
except CommandException as exc:
    if exc.epp_code == ResultCode.OBJECT_EXISTS:   # 2302
        ...

# Prefer branching on codes yourself?
client.throw_on_failure(False)
resp = client.domain.info("maybe.com.ua")
if resp.code() == ResultCode.OBJECT_DOES_NOT_EXIST:
    ...
```

## Custom frames

Anything the high-level API doesn't cover can be built with `Frame` and sent raw:

```python
from uaregistry import Frame, Namespaces

frame = Frame.command("my-trid-1")
check = frame.ns(frame.verb("check"), Namespaces.DOMAIN, "domain:check")
frame.ns(check, Namespaces.DOMAIN, "domain:name", "x.com.ua")
resp = client.request(frame)          # or client.request(raw_xml_string)
```

## Testing

A no-dependency offline self-test (frame building + response parsing, no server, no network):

```bash
python tests/offline_test.py
```

## License

MIT — see [LICENSE](LICENSE).
