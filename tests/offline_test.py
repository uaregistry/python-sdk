"""Offline self-test: exercises frame building and response parsing with a fake in-memory
transport — no server, no network.

    python tests/offline_test.py
"""

import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uaregistry import Client, Config, Namespaces
from uaregistry.exceptions import (
    AuthenticationException,
    CommandException,
    ConfigException,
)
from uaregistry.transport import Transport

_passed = 0
_failed = 0


def check(label, ok):
    global _passed, _failed
    print(("  ok  " if ok else " FAIL ") + label)
    if ok:
        _passed += 1
    else:
        _failed += 1


class FakeTransport(Transport):
    """Records what was written and replays queued responses."""

    def __init__(self):
        self.written = []
        self.queue = []
        self._open = False

    def open(self):
        self._open = True

    def is_open(self):
        return self._open

    def write_frame(self, xml):
        self.written.append(xml)

    def read_frame(self):
        if not self.queue:
            raise RuntimeError("FakeTransport: no queued response")
        return self.queue.pop(0)

    def close(self):
        self._open = False


GREETING = (
    '<?xml version="1.0" encoding="UTF-8"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><greeting>'
    "<svID>UARegistry EPP</svID><svDate>2026-07-04T00:00:00Z</svDate><svcMenu><version>1.0</version>"
    "<lang>en</lang><lang>uk</lang>"
    "<objURI>urn:ietf:params:xml:ns:contact-1.0</objURI><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>"
    "<objURI>urn:ietf:params:xml:ns:host-1.0</objURI>"
    "<svcExtension><extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI><extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>"
    '<extURI>http://uaregistry.com/epp/uaregistry-1.0</extURI><extURI>http://uaregistry.com/epp/balance-1.0</extURI>'
    "</svcExtension></svcMenu></greeting></epp>"
)


def OK(code=1000, msg="ok", lang="en"):
    return (
        '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
        '<result code="%d"><msg lang="%s">%s</msg></result>'
        "<trID><clTRID>C1</clTRID><svTRID>UA-1</svTRID></trID></response></epp>" % (code, lang, msg)
    )


def make_client(responses):
    fake = FakeTransport()
    fake.queue = list(responses)
    client = Client(Config(host="epp.example", clid="UAR0001", password="secret"), fake)
    return client, fake


def local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse(xml):
    return ET.fromstring(xml)


def all_local(root, name):
    return [e for e in root.iter() if local(e.tag) == name]


def first_local(root, name):
    for e in root.iter():
        if local(e.tag) == name:
            return e
    return None


def text_of(root, name):
    e = first_local(root, name)
    return e.text if e is not None else None


# --------------------------------------------------------------------------
# Session / login
# --------------------------------------------------------------------------
print("session: connect + login (services from greeting)")
client, fake = make_client([GREETING, OK()])
greeting = client.connect()
check("greeting parsed", greeting.is_greeting())
check("greeting objURIs", "urn:ietf:params:xml:ns:domain-1.0" in greeting.service_obj_uris())
client.login()
login_frame = parse(fake.written[0])
check("login clID", text_of(login_frame, "clID") == "UAR0001")
check("login pw", text_of(login_frame, "pw") == "secret")
check("login version 1.0", text_of(login_frame, "version") == "1.0")
check("login advertises domain objURI", any(
    e.text == Namespaces.DOMAIN for e in all_local(login_frame, "objURI")))
check("login advertises balance extURI", any(
    e.text == Namespaces.UAREG_BALANCE for e in all_local(login_frame, "extURI")))
check("login does not advertise the epp base URI", all(
    e.text != Namespaces.EPP for e in all_local(login_frame, "objURI")))

print("session: password rotation via newPW")
client, fake = make_client([GREETING, OK()])
client.connect()
client.login("new-secret-1")
check("login carries newPW", text_of(parse(fake.written[0]), "newPW") == "new-secret-1")

print("clTRID format: prefix-timestamp-pid-counter")
client, fake = make_client([GREETING, OK(), OK()])
client.connect()
client.domain.check(["a.com.ua"])
client.domain.check(["b.com.ua"])
t1 = parse(fake.written[0]).find(".//{urn:ietf:params:xml:ns:epp-1.0}clTRID").text
t2 = parse(fake.written[1]).find(".//{urn:ietf:params:xml:ns:epp-1.0}clTRID").text
import re as _re
check("clTRID shape UAR-SDK-<ts>-<pid>-0001", bool(_re.match(r"^UAR-SDK-\d{14}-\d+-0001$", t1)))
check("clTRID counter increments", t2.endswith("-0002"))
check("clTRID pid segment stable across a session", t1.split("-")[-2] == t2.split("-")[-2])

# --------------------------------------------------------------------------
# Domain
# --------------------------------------------------------------------------
print("domain: check / info / create")
client, fake = make_client([GREETING, OK(), OK(), OK()])
client.connect()
client.domain.check(["x.com.ua", "y.com.ua"])
dc = parse(fake.written[0])
check("domain:check has 2 names", len(all_local(dc, "name")) == 2)
check("domain:check element is in domain-1.0 ns",
      any(e.tag == "{%s}check" % Namespaces.DOMAIN for e in dc.iter()))

client.domain.info("x.com.ua", "authpw", hosts="all")
di = parse(fake.written[1])
check("domain:info hosts attr", first_local(di, "name").get("hosts") == "all")
check("domain:info authInfo pw", text_of(di, "pw") == "authpw")

client.domain.create("x.com.ua", years=1, registrant="REG1",
                     contacts={"admin": "ADM1", "tech": "TEC1"},
                     nameservers=["ns1.x.ua", "ns2.x.ua"], auth_info="secret1",
                     license="TM-1", sec_dns={"ds_data": [
                         {"key_tag": 12345, "alg": 8, "digest_type": 2, "digest": "AB" * 32}]})
cr = parse(fake.written[2])
check("create period unit=y", first_local(cr, "period").get("unit") == "y")
check("create 2 hostObj", len(all_local(cr, "hostObj")) == 2)
check("create 2 contacts", len(all_local(cr, "contact")) == 2)
check("create authInfo pw", text_of(cr, "pw") == "secret1")
check("create secDNS keyTag", text_of(cr, "keyTag") == "12345")
check("create uareg license", text_of(cr, "license") == "TM-1")

print("domain: create without authInfo still emits an empty <pw/>")
client, fake = make_client([GREETING, OK()])
client.connect()
client.domain.create("noauth.com.ua", years=1, registrant="REG1",
                     contacts={"admin": "A1", "tech": "T1"}, nameservers=["ns1.x.ua"])
na = parse(fake.written[0])
pw = first_local(na, "pw")
check("authInfo-less create has a <pw> element", pw is not None)
check("authInfo-less create <pw> is empty", (pw.text or "") == "")

print("domain: create with empty secDNS emits no childless secDNS:create")
client, fake = make_client([GREETING, OK()])
client.connect()
client.domain.create("nosec.com.ua", years=1, registrant="REG1",
                     contacts={"admin": "A1", "tech": "T1"}, nameservers=["ns1.x.ua"], sec_dns={})
check("empty secDNS -> no secDNS:create", first_local(parse(fake.written[0]), "create") is not None
      and len([e for e in parse(fake.written[0]).iter() if e.tag == "{%s}create" % Namespaces.SECDNS]) == 0)

print("domain: update deltas + secDNS + restore")
client, fake = make_client([GREETING, OK(), OK()])
client.connect()
client.domain.update("x.com.ua",
                     add={"ns": ["ns3.x.ua"], "statuses": ["clientHold"]},
                     rem={"statuses": ["clientHold"]},
                     chg={"registrant": "REG9", "auth_info": "newpw12345"},
                     sec_dns={"add": {"ds_data": [{"key_tag": 22, "alg": 8, "digest_type": 2, "digest": "bb" * 32}]},
                              "rem_all": True, "max_sig_life": 1209600})
up = parse(fake.written[0])
check("update add block present", first_local(up, "add") is not None)
check("update chg registrant", text_of(up, "registrant") == "REG9")
check("update secDNS rem all=true", any(local(e.tag) == "all" and e.text == "true" for e in up.iter()))
check("update secDNS add keyTag=22", text_of(up, "keyTag") == "22")
check("update secDNS maxSigLife", text_of(up, "maxSigLife") == "1209600")

client.domain.restore("x.com.ua")
rs = parse(fake.written[1])
check("restore rgp op=request", first_local(rs, "restore").get("op") == "request")

print("domain: renew / delete / transfer")
client, fake = make_client([GREETING, OK(), OK(), OK()])
client.connect()
client.domain.renew("x.com.ua", "2027-01-15", 2)
rn = parse(fake.written[0])
check("renew curExpDate", text_of(rn, "curExpDate") == "2027-01-15")
check("renew period 2", text_of(rn, "period") == "2")
client.domain.delete("x.com.ua")
check("delete has name", text_of(parse(fake.written[1]), "name") == "x.com.ua")
client.domain.transfer("request", "x.com.ua", "pw", 1)
tr = parse(fake.written[2])
check("transfer op=request", first_local(tr, "transfer").get("op") == "request")
check("transfer authInfo pw", text_of(tr, "pw") == "pw")

# --------------------------------------------------------------------------
# Contact
# --------------------------------------------------------------------------
print("contact: create (int+loc postalInfo + disclose)")
client, fake = make_client([GREETING, OK()])
client.connect()
client.contact.create("CID1", postal_infos=[
    {"type": "int", "name": "Test Person", "street": ["1 A St"], "city": "Kyiv", "cc": "UA"},
    {"type": "loc", "name": "Тест Особа", "city": "Київ", "cc": "UA"}],
    email="a@b.ua", auth_info="pw",
    disclose={"flag": False, "addr": ["int"], "voice": True, "email": True})
cc = parse(fake.written[0])
check("contact 2 postalInfo blocks", len(all_local(cc, "postalInfo")) == 2)
check("contact int name", any(local(e.tag) == "name" and e.text == "Test Person" for e in cc.iter()))
check("contact loc Cyrillic name preserved", any(
    local(e.tag) == "name" and e.text == "Тест Особа" for e in cc.iter()))
check("contact disclose flag=0", first_local(cc, "disclose").get("flag") == "0")

print("contact: create without email raises ValueError")
client, fake = make_client([GREETING])
client.connect()
try:
    client.contact.create("CID2", name="X", city="Kyiv", cc="UA")
    check("empty email raises", False)
except ValueError:
    check("empty email raises ValueError", True)

print("contact: update collapses multiple statuses into one add/rem block")
client, fake = make_client([GREETING, OK()])
client.connect()
client.contact.update("CID1",
                      add_statuses=["clientUpdateProhibited", "clientDeleteProhibited"],
                      rem_statuses=["clientTransferProhibited"],
                      chg={"email": "new@b.ua"})
cu = parse(fake.written[0])
check("contact update single add block", len(all_local(cu, "add")) == 1)
check("contact update 2 statuses in add", len([e for e in all_local(cu, "status")
      if e.get("s") in ("clientUpdateProhibited", "clientDeleteProhibited")]) == 2)
check("contact update chg email", any(local(e.tag) == "email" and e.text == "new@b.ua" for e in cu.iter()))

print("contact: check / info / delete / transfer")
client, fake = make_client([GREETING, OK(), OK(), OK(), OK()])
client.connect()
client.contact.check(["C1", "C2"])
check("contact:check 2 ids", len(all_local(parse(fake.written[0]), "id")) == 2)
client.contact.info("C1", "pw")
check("contact:info authInfo", text_of(parse(fake.written[1]), "pw") == "pw")
client.contact.delete("C1")
check("contact:delete id", text_of(parse(fake.written[2]), "id") == "C1")
client.contact.transfer("request", "C1", "pw")
check("contact:transfer op", first_local(parse(fake.written[3]), "transfer").get("op") == "request")

# --------------------------------------------------------------------------
# Host
# --------------------------------------------------------------------------
print("host: create v4+v6 auto-detect / update / delete-force")
client, fake = make_client([GREETING, OK(), OK(), OK()])
client.connect()
client.host.create("ns1.x.ua", ["192.0.2.1", "2001:db8::1"])
hc = parse(fake.written[0])
addrs = all_local(hc, "addr")
check("host v4 detected", any(a.text == "192.0.2.1" and a.get("ip") == "v4" for a in addrs))
check("host v6 detected", any(a.text == "2001:db8::1" and a.get("ip") == "v6" for a in addrs))
client.host.update("ns1.x.ua", add_addresses=["192.0.2.9"], rem_statuses=["clientUpdateProhibited"],
                   new_name="ns2.x.ua")
hu = parse(fake.written[1])
check("host update add block", first_local(hu, "add") is not None)
check("host update chg new name", any(local(e.tag) == "name" and e.text == "ns2.x.ua" for e in hu.iter()))
client.host.delete("ns1.x.ua", force=True)
check("host delete force uareg:deleteNS", first_local(parse(fake.written[2]), "deleteNS") is not None)

# --------------------------------------------------------------------------
# Poll + balance
# --------------------------------------------------------------------------
print("poll: request / ack")
client, fake = make_client([GREETING, OK(), OK()])
client.connect()
client.poll.request()
check("poll op=req", first_local(parse(fake.written[0]), "poll").get("op") == "req")
client.poll.ack("42")
pa = parse(fake.written[1])
check("poll op=ack", first_local(pa, "poll").get("op") == "ack")
check("poll msgID", first_local(pa, "poll").get("msgID") == "42")

print("balance: info")
client, fake = make_client([GREETING, OK()])
client.connect()
client.balance()
check("balance:info element in balance-1.0 ns",
      any(e.tag == "{%s}info" % Namespaces.UAREG_BALANCE for e in parse(fake.written[0]).iter()))

# --------------------------------------------------------------------------
# XML escaping
# --------------------------------------------------------------------------
print("frame: XML escaping (special chars + Cyrillic, single-escaped)")
client, fake = make_client([GREETING, OK()])
client.connect()
client.contact.create("C&<1", name="A & B <Ltd>", city="Львів", cc="UA", email='a"b@x.ua')
raw = fake.written[0]
check("ampersand escaped once", "&amp;" in raw and "&amp;amp;" not in raw)
check("angle brackets escaped", "&lt;Ltd&gt;" in raw)
check("Cyrillic preserved", "Львів" in raw)
# The escaped frame must still parse back cleanly.
esc = parse(raw)
check("escaped id round-trips", text_of(esc, "id") == "C&<1")

# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------
print("response: result code / message / lang / trIDs")
from uaregistry import Response
r = Response.from_xml(OK(1000, "Команду виконано успішно", "uk"))
check("code 1000", r.code() == 1000)
check("isSuccess", r.is_success())
check("message text", r.message() == "Команду виконано успішно")
check("messageLang uk", r.message_lang() == "uk")
check("svTRID", r.sv_trid() == "UA-1")
check("clTRID", r.cl_trid() == "C1")

print("response: availability (domain:check)")
avail_xml = (
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
    '<result code="1000"><msg>ok</msg></result><resData>'
    '<domain:chkData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    '<domain:cd><domain:name avail="1">free.com.ua</domain:name></domain:cd>'
    '<domain:cd><domain:name avail="0">taken.com.ua</domain:name></domain:cd>'
    "</domain:chkData></resData><trID><svTRID>UA-2</svTRID></trID></response></epp>"
)
av = Response.from_xml(avail_xml).availability()
check("avail free=True", av.get("free.com.ua") is True)
check("avail taken=False", av.get("taken.com.ua") is False)

print("response: balance / prices / licence / statuses")
info_xml = (
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
    '<result code="1000"><msg>ok</msg></result><resData>'
    '<domain:infData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>x.com.ua</domain:name><domain:status s=\"ok\"/>"
    "<domain:exDate>2027-01-01T00:00:00Z</domain:exDate></domain:infData></resData>"
    '<extension><uareg:infData xmlns:uareg="http://uaregistry.com/epp/uaregistry-1.0">'
    "<uareg:license>TM-777</uareg:license>"
    '<uareg:priceData><uareg:price operation="renewal" currency="UAH">180.00</uareg:price></uareg:priceData>'
    "</uareg:infData></extension><trID><svTRID>UA-3</svTRID></trID></response></epp>"
)
ri = Response.from_xml(info_xml)
check("value exDate", ri.value("exDate") == "2027-01-01T00:00:00Z")
check("statuses ok", ri.statuses() == ["ok"])
check("license", ri.license() == "TM-777")
check("prices renewal value", ri.prices().get("renewal", {}).get("value") == "180.00")
check("prices renewal currency", ri.prices().get("renewal", {}).get("currency") == "UAH")

bal_xml = (
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
    '<result code="1000"><msg>ok</msg></result><resData>'
    '<balance:infData xmlns:balance="http://uaregistry.com/epp/balance-1.0">'
    "<balance:creditLimit>1000.00</balance:creditLimit><balance:balance>250.50</balance:balance>"
    "<balance:availableCredit>1250.50</balance:availableCredit></balance:infData></resData>"
    "<trID><svTRID>UA-4</svTRID></trID></response></epp>"
)
b = Response.from_xml(bal_xml).balance()
check("balance creditLimit", b["creditLimit"] == "1000.00")
check("balance availableCredit", b["availableCredit"] == "1250.50")
check("non-balance response -> balance None", Response.from_xml(OK()).balance() is None)

print("response: secDNS read-back (nested keyData not leaked into keyRecords)")
sec_xml = (
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
    '<result code="1000"><msg>ok</msg></result>'
    '<extension><secDNS:infData xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">'
    "<secDNS:dsData><secDNS:keyTag>12345</secDNS:keyTag><secDNS:alg>13</secDNS:alg>"
    "<secDNS:digestType>2</secDNS:digestType><secDNS:digest>ABCDEF0123</secDNS:digest>"
    "<secDNS:keyData><secDNS:flags>256</secDNS:flags><secDNS:protocol>3</secDNS:protocol>"
    "<secDNS:alg>13</secDNS:alg><secDNS:pubKey>nested</secDNS:pubKey></secDNS:keyData></secDNS:dsData>"
    "<secDNS:keyData><secDNS:flags>257</secDNS:flags><secDNS:protocol>3</secDNS:protocol>"
    "<secDNS:alg>13</secDNS:alg><secDNS:pubKey>toplevel</secDNS:pubKey></secDNS:keyData>"
    "</secDNS:infData></extension><trID><svTRID>UA-5</svTRID></trID></response></epp>"
)
rs = Response.from_xml(sec_xml)
check("dsRecords count 1", len(rs.ds_records()) == 1)
check("dsRecords keyTag", rs.ds_records()[0]["keyTag"] == 12345)
check("keyRecords only top-level", len(rs.key_records()) == 1 and rs.key_records()[0]["pubKey"] == "toplevel")
check("isSigned", rs.is_signed() is True)

print("response: poll message id/count/text + trStatus")
poll_xml = (
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
    '<result code="1301"><msg>ack to dequeue</msg></result>'
    '<msgQ count="3" id="42"><qDate>2026-07-04T00:00:00Z</qDate><msg lang="uk">Домен x.com.ua продовжено</msg></msgQ>'
    '<resData><domain:trnData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">'
    "<domain:name>x.com.ua</domain:name><domain:trStatus>pending</domain:trStatus></domain:trnData></resData>"
    "<trID><svTRID>UA-6</svTRID></trID></response></epp>"
)
rp = Response.from_xml(poll_xml)
check("poll messageId", rp.message_id() == "42")
check("poll messageCount", rp.message_count() == 3)
check("poll result message is the result msg, not the queue msg", rp.message() == "ack to dequeue")
check("transferStatus pending", rp.transfer_status() == "pending")

print("response: errorReasons + code getters")
err_xml = (
    '<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"><response>'
    '<result code="2306"><msg>policy</msg><extValue><value/><reason>bad NS count</reason></extValue></result>'
    "<trID><svTRID>UA-7</svTRID></trID></response></epp>"
)
re7 = Response.from_xml(err_xml)
check("code 2306", re7.code() == 2306)
check("not success", not re7.is_success())
check("errorReasons", re7.error_reasons() == ["bad NS count"])

# --------------------------------------------------------------------------
# Error handling + config guards
# --------------------------------------------------------------------------
print("errors: CommandException raised on >=2000, silenced by throw_on_failure(False)")
client, fake = make_client([GREETING, OK(2302, "exists")])
client.connect()
try:
    client.domain.create("dup.com.ua", years=1, registrant="R", contacts={"admin": "A", "tech": "T"},
                         nameservers=["ns1.x.ua"])
    check("2302 raises", False)
except CommandException as exc:
    check("2302 raises CommandException", exc.epp_code == 2302)

client, fake = make_client([GREETING, OK(2303, "nope")])
client.connect()
client.throw_on_failure(False)
resp = client.domain.info("missing.com.ua")
check("throw_on_failure(False) returns response", resp.code() == 2303)

print("errors: login failure raises AuthenticationException")
client, fake = make_client([GREETING, OK(2200, "bad login")])
client.connect()
try:
    client.login()
    check("login 2200 raises", False)
except AuthenticationException as exc:
    check("login 2200 raises AuthenticationException", exc.epp_code == 2200)

print("config guards: empty host / clID / password fail fast")
try:
    Client(Config(host="", clid="x", password="y")).connect()
    check("empty host raises", False)
except ConfigException:
    check("empty host -> ConfigException", True)

client, fake = make_client([GREETING])
client.connect()
client._config.password = ""
try:
    client.login()
    check("empty password raises", False)
except ConfigException:
    check("empty password -> ConfigException", True)
check("no login frame sent on config failure", fake.written == [])

# --------------------------------------------------------------------------
print()
print("%d passed, %d failed" % (_passed, _failed))
sys.exit(1 if _failed else 0)
