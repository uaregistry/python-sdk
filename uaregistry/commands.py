"""Object command handlers (domain / contact / host / poll). Reached through the Client
resource properties: ``client.domain``, ``client.contact``, ``client.host``, ``client.poll``.

Nested option dicts use snake_case keys, e.g. ``chg={'auth_info': 'pw'}``,
``sec_dns={'ds_data': [{'key_tag': 123, 'alg': 8, 'digest_type': 2, 'digest': '...'}]}``.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from . import namespaces as ns
from .frame import Frame
from .response import Response

if TYPE_CHECKING:  # pragma: no cover
    from .client import Client

_ADMIN = ns.CONTACT
_D = ns.DOMAIN
_H = ns.HOST


def _ip_version(ip: str) -> str:
    try:
        return "v6" if ipaddress.ip_address(ip).version == 6 else "v4"
    except ValueError:
        return "v4"


class Domain:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def check(self, names: List[str]) -> Response:
        frame = self._client.frame()
        check = frame.ns(frame.verb("check"), _D, "domain:check")
        for name in names:
            frame.ns(check, _D, "domain:name", name)
        return self._client.request(frame)

    def info(self, name: str, auth_info: Optional[str] = None, hosts: str = "all") -> Response:
        frame = self._client.frame()
        info = frame.ns(frame.verb("info"), _D, "domain:info")
        frame.ns(info, _D, "domain:name", name, {"hosts": hosts})
        if auth_info is not None:
            ai = frame.ns(info, _D, "domain:authInfo")
            frame.ns(ai, _D, "domain:pw", auth_info)
        return self._client.request(frame)

    def create(self, name: str, *, years: Optional[int] = None, registrant: Optional[str] = None,
               contacts: Optional[Dict[str, str]] = None, nameservers: Optional[List[str]] = None,
               auth_info: Optional[str] = None, license: Optional[str] = None,
               sec_dns: Optional[Dict[str, Any]] = None) -> Response:
        frame = self._client.frame()
        create = frame.ns(frame.verb("create"), _D, "domain:create")
        frame.ns(create, _D, "domain:name", name)
        if years is not None:
            frame.ns(create, _D, "domain:period", str(int(years)), {"unit": "y"})
        if nameservers:
            ns_el = frame.ns(create, _D, "domain:ns")
            for host in nameservers:
                frame.ns(ns_el, _D, "domain:hostObj", host)
        if registrant is not None:
            frame.ns(create, _D, "domain:registrant", registrant)
        for ctype, handle in (contacts or {}).items():
            frame.ns(create, _D, "domain:contact", handle, {"type": ctype})
        # authInfo is MANDATORY on domain:create (RFC 5731). Always emit it — with the caller's
        # transfer secret, or an empty <pw/> (pwType allows minLength 0) so the registry applies
        # its per-zone authInfo policy.
        ai = frame.ns(create, _D, "domain:authInfo")
        frame.ns(ai, _D, "domain:pw", auth_info or "")

        # secDNS:create requires at least one dsData or keyData record (RFC 5910); an empty or
        # keyless mapping must not emit a childless <secDNS:create/>, which is invalid.
        has_secdns = isinstance(sec_dns, dict) and (sec_dns.get("ds_data") or sec_dns.get("key_data"))
        if has_secdns or license is not None:
            ext = frame.extension()
            if has_secdns:
                sec_create = frame.ns(ext, ns.SECDNS, "secDNS:create")
                if sec_dns.get("max_sig_life") is not None:
                    frame.ns(sec_create, ns.SECDNS, "secDNS:maxSigLife", str(int(sec_dns["max_sig_life"])))
                _append_secdns(frame, sec_create, sec_dns)
            if license is not None:
                u = frame.ns(ext, ns.UAREG_EXT, "uareg:create")
                frame.ns(u, ns.UAREG_EXT, "uareg:license", license)
        return self._client.request(frame)

    def update(self, name: str, *, add: Optional[Dict[str, Any]] = None,
               rem: Optional[Dict[str, Any]] = None, chg: Optional[Dict[str, Any]] = None,
               restore: bool = False, license: Optional[str] = None,
               sec_dns: Optional[Dict[str, Any]] = None) -> Response:
        frame = self._client.frame()
        update = frame.ns(frame.verb("update"), _D, "domain:update")
        frame.ns(update, _D, "domain:name", name)

        for op, spec in (("add", add), ("rem", rem)):
            if not spec:
                continue
            block = frame.ns(update, _D, "domain:%s" % op)
            if spec.get("ns"):
                ns_el = frame.ns(block, _D, "domain:ns")
                for host in spec["ns"]:
                    frame.ns(ns_el, _D, "domain:hostObj", host)
            for ctype, handle in (spec.get("contacts") or {}).items():
                frame.ns(block, _D, "domain:contact", handle, {"type": ctype})
            for status in (spec.get("statuses") or []):
                frame.ns(block, _D, "domain:status", None, {"s": status})

        if chg:
            block = frame.ns(update, _D, "domain:chg")
            if "registrant" in chg:
                frame.ns(block, _D, "domain:registrant", chg["registrant"])
            if "auth_info" in chg:
                ai = frame.ns(block, _D, "domain:authInfo")
                frame.ns(ai, _D, "domain:pw", chg["auth_info"])

        if restore:
            rgp = frame.ns(frame.extension(), ns.RGP, "rgp:update")
            frame.ns(rgp, ns.RGP, "rgp:restore", None, {"op": "request"})
        if license is not None:
            u = frame.ns(frame.extension(), ns.UAREG_EXT, "uareg:update")
            frame.ns(u, ns.UAREG_EXT, "uareg:license", license)

        # DNSSEC delta (RFC 5910): rem (specific or all), add, chg maxSigLife.
        if isinstance(sec_dns, dict):
            sec_update = frame.ns(frame.extension(), ns.SECDNS, "secDNS:update")
            if sec_dns.get("rem_all"):
                rem_el = frame.ns(sec_update, ns.SECDNS, "secDNS:rem")
                frame.ns(rem_el, ns.SECDNS, "secDNS:all", "true")
            elif sec_dns.get("rem"):
                rem_el = frame.ns(sec_update, ns.SECDNS, "secDNS:rem")
                _append_secdns(frame, rem_el, sec_dns["rem"])
            if sec_dns.get("add"):
                add_el = frame.ns(sec_update, ns.SECDNS, "secDNS:add")
                _append_secdns(frame, add_el, sec_dns["add"])
            if sec_dns.get("max_sig_life") is not None:
                chg_sec = frame.ns(sec_update, ns.SECDNS, "secDNS:chg")
                frame.ns(chg_sec, ns.SECDNS, "secDNS:maxSigLife", str(int(sec_dns["max_sig_life"])))
        return self._client.request(frame)

    def renew(self, name: str, cur_exp_date: str, years: int = 1) -> Response:
        frame = self._client.frame()
        renew = frame.ns(frame.verb("renew"), _D, "domain:renew")
        frame.ns(renew, _D, "domain:name", name)
        frame.ns(renew, _D, "domain:curExpDate", cur_exp_date)
        frame.ns(renew, _D, "domain:period", str(int(years)), {"unit": "y"})
        return self._client.request(frame)

    def delete(self, name: str) -> Response:
        frame = self._client.frame()
        d = frame.ns(frame.verb("delete"), _D, "domain:delete")
        frame.ns(d, _D, "domain:name", name)
        return self._client.request(frame)

    def restore(self, name: str) -> Response:
        """Restore a redemption-period domain (rgp:restore op="request")."""
        return self.update(name, restore=True)

    def transfer(self, op: str, name: str, auth_info: Optional[str] = None,
                 years: Optional[int] = None) -> Response:
        """op is one of request|approve|reject|cancel|query."""
        frame = self._client.frame()
        transfer = frame.verb("transfer")
        transfer.set("op", op)
        d = frame.ns(transfer, _D, "domain:transfer")
        frame.ns(d, _D, "domain:name", name)
        if years is not None:
            frame.ns(d, _D, "domain:period", str(int(years)), {"unit": "y"})
        if auth_info is not None:
            ai = frame.ns(d, _D, "domain:authInfo")
            frame.ns(ai, _D, "domain:pw", auth_info)
        return self._client.request(frame)


def _append_secdns(frame: Frame, parent: ET.Element, spec: Dict[str, Any]) -> None:
    """Append RFC 5910 dsData / keyData records to a secDNS block (create / add / rem)."""
    for ds in (spec.get("ds_data") or []):
        ds_data = frame.ns(parent, ns.SECDNS, "secDNS:dsData")
        frame.ns(ds_data, ns.SECDNS, "secDNS:keyTag", str(int(ds.get("key_tag", 0))))
        frame.ns(ds_data, ns.SECDNS, "secDNS:alg", str(int(ds.get("alg", 0))))
        frame.ns(ds_data, ns.SECDNS, "secDNS:digestType", str(int(ds.get("digest_type", 0))))
        frame.ns(ds_data, ns.SECDNS, "secDNS:digest", str(ds.get("digest", "")))
    for key in (spec.get("key_data") or []):
        key_data = frame.ns(parent, ns.SECDNS, "secDNS:keyData")
        frame.ns(key_data, ns.SECDNS, "secDNS:flags", str(int(key.get("flags", 257))))
        frame.ns(key_data, ns.SECDNS, "secDNS:protocol", str(int(key.get("protocol", 3))))
        frame.ns(key_data, ns.SECDNS, "secDNS:alg", str(int(key.get("alg", 0))))
        frame.ns(key_data, ns.SECDNS, "secDNS:pubKey", str(key.get("pub_key", "")))


class Contact:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def check(self, ids: List[str]) -> Response:
        frame = self._client.frame()
        check = frame.ns(frame.verb("check"), _ADMIN, "contact:check")
        for cid in ids:
            frame.ns(check, _ADMIN, "contact:id", cid)
        return self._client.request(frame)

    def info(self, contact_id: str, auth_info: Optional[str] = None) -> Response:
        frame = self._client.frame()
        info = frame.ns(frame.verb("info"), _ADMIN, "contact:info")
        frame.ns(info, _ADMIN, "contact:id", contact_id)
        if auth_info is not None:
            ai = frame.ns(info, _ADMIN, "contact:authInfo")
            frame.ns(ai, _ADMIN, "contact:pw", auth_info)
        return self._client.request(frame)

    def create(self, contact_id: str, *, name: Optional[str] = None, org: Optional[str] = None,
               street: Optional[List[str]] = None, city: Optional[str] = None,
               sp: Optional[str] = None, pc: Optional[str] = None, cc: Optional[str] = None,
               type: str = "int", postal_infos: Optional[List[Dict[str, Any]]] = None,
               voice: Optional[str] = None, fax: Optional[str] = None,
               email: Optional[str] = None, auth_info: Optional[str] = None,
               disclose: Optional[Dict[str, Any]] = None) -> Response:
        frame = self._client.frame()
        c = frame.ns(frame.verb("create"), _ADMIN, "contact:create")
        frame.ns(c, _ADMIN, "contact:id", contact_id)

        if postal_infos:
            for pi in postal_infos:
                _append_postal(frame, c, pi)
        else:
            _append_postal(frame, c, {"name": name, "org": org, "street": street, "city": city,
                                      "sp": sp, "pc": pc, "cc": cc, "type": type})
        if voice:
            frame.ns(c, _ADMIN, "contact:voice", voice)
        if fax:
            frame.ns(c, _ADMIN, "contact:fax", fax)
        if not email:
            # RFC 5733 requires a contact email (emailType minLength 1). Fail fast client-side.
            raise ValueError("contact.create() requires a non-empty 'email'")
        frame.ns(c, _ADMIN, "contact:email", email)
        ai = frame.ns(c, _ADMIN, "contact:authInfo")
        frame.ns(ai, _ADMIN, "contact:pw", auth_info or "")
        if disclose:
            _append_disclose(frame, c, disclose)
        return self._client.request(frame)

    def update(self, contact_id: str, *, add_statuses: Optional[List[str]] = None,
               rem_statuses: Optional[List[str]] = None,
               chg: Optional[Dict[str, Any]] = None) -> Response:
        frame = self._client.frame()
        update = frame.ns(frame.verb("update"), _ADMIN, "contact:update")
        frame.ns(update, _ADMIN, "contact:id", contact_id)
        # contact:updateType allows a SINGLE add/rem block (each holding up to 7 statuses); emit
        # the wrapper once and append every status into it.
        if add_statuses:
            add = frame.ns(update, _ADMIN, "contact:add")
            for status in add_statuses:
                frame.ns(add, _ADMIN, "contact:status", None, {"s": status})
        if rem_statuses:
            rem = frame.ns(update, _ADMIN, "contact:rem")
            for status in rem_statuses:
                frame.ns(rem, _ADMIN, "contact:status", None, {"s": status})
        if chg:
            block = frame.ns(update, _ADMIN, "contact:chg")
            # RFC 5733 chg order: postalInfo*, voice?, fax?, email?, authInfo?, disclose?
            pis = chg.get("postal_infos")
            if pis is None and chg.get("postal_info") is not None:
                pis = [chg["postal_info"]]
            for pi in (pis or []):
                _append_postal(frame, block, pi)
            if "voice" in chg:
                frame.ns(block, _ADMIN, "contact:voice", chg["voice"])
            if "fax" in chg:
                frame.ns(block, _ADMIN, "contact:fax", chg["fax"])
            if "email" in chg:
                frame.ns(block, _ADMIN, "contact:email", chg["email"])
            if "auth_info" in chg:
                ai = frame.ns(block, _ADMIN, "contact:authInfo")
                frame.ns(ai, _ADMIN, "contact:pw", chg["auth_info"])
            if chg.get("disclose"):
                _append_disclose(frame, block, chg["disclose"])
        return self._client.request(frame)

    def delete(self, contact_id: str) -> Response:
        frame = self._client.frame()
        d = frame.ns(frame.verb("delete"), _ADMIN, "contact:delete")
        frame.ns(d, _ADMIN, "contact:id", contact_id)
        return self._client.request(frame)

    def transfer(self, op: str, contact_id: str, auth_info: Optional[str] = None) -> Response:
        frame = self._client.frame()
        transfer = frame.verb("transfer")
        transfer.set("op", op)
        c = frame.ns(transfer, _ADMIN, "contact:transfer")
        frame.ns(c, _ADMIN, "contact:id", contact_id)
        if auth_info is not None:
            ai = frame.ns(c, _ADMIN, "contact:authInfo")
            frame.ns(ai, _ADMIN, "contact:pw", auth_info)
        return self._client.request(frame)


def _append_postal(frame: Frame, parent: ET.Element, pi: Dict[str, Any]) -> None:
    """Build one <contact:postalInfo> block from name/org/street/city/sp/pc/cc/type."""
    block = frame.ns(parent, _ADMIN, "contact:postalInfo", None, {"type": pi.get("type") or "int"})
    frame.ns(block, _ADMIN, "contact:name", pi.get("name") or "")
    if pi.get("org"):
        frame.ns(block, _ADMIN, "contact:org", pi["org"])
    addr = frame.ns(block, _ADMIN, "contact:addr")
    for line in (pi.get("street") or []):
        frame.ns(addr, _ADMIN, "contact:street", line)
    frame.ns(addr, _ADMIN, "contact:city", pi.get("city") or "")
    if pi.get("sp"):
        frame.ns(addr, _ADMIN, "contact:sp", pi["sp"])
    if pi.get("pc"):
        frame.ns(addr, _ADMIN, "contact:pc", pi["pc"])
    frame.ns(addr, _ADMIN, "contact:cc", pi.get("cc") or "")


def _append_disclose(frame: Frame, parent: ET.Element, disclose: Dict[str, Any]) -> None:
    """Build a <contact:disclose flag="0|1"> block. name/org/addr take a list of types
    (int|loc); voice/fax/email are bare flags toggled by a truthy value."""
    flag = "1" if disclose.get("flag") else "0"
    disc = frame.ns(parent, _ADMIN, "contact:disclose", None, {"flag": flag})
    for f in ("name", "org", "addr"):
        if f not in disclose:
            continue
        for t in disclose[f]:
            frame.ns(disc, _ADMIN, "contact:%s" % f, None, {"type": t})
    for f in ("voice", "fax", "email"):
        if disclose.get(f):
            frame.ns(disc, _ADMIN, "contact:%s" % f)


class Host:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def check(self, names: List[str]) -> Response:
        frame = self._client.frame()
        check = frame.ns(frame.verb("check"), _H, "host:check")
        for name in names:
            frame.ns(check, _H, "host:name", name)
        return self._client.request(frame)

    def info(self, name: str) -> Response:
        frame = self._client.frame()
        info = frame.ns(frame.verb("info"), _H, "host:info")
        frame.ns(info, _H, "host:name", name)
        return self._client.request(frame)

    def create(self, name: str, addresses: Optional[List[str]] = None) -> Response:
        """addresses: IPv4 or IPv6 literals; the version is auto-detected."""
        frame = self._client.frame()
        create = frame.ns(frame.verb("create"), _H, "host:create")
        frame.ns(create, _H, "host:name", name)
        for ip in (addresses or []):
            frame.ns(create, _H, "host:addr", ip, {"ip": _ip_version(ip)})
        return self._client.request(frame)

    def update(self, name: str, *, add_addresses: Optional[List[str]] = None,
               rem_addresses: Optional[List[str]] = None, add_statuses: Optional[List[str]] = None,
               rem_statuses: Optional[List[str]] = None, new_name: Optional[str] = None) -> Response:
        frame = self._client.frame()
        update = frame.ns(frame.verb("update"), _H, "host:update")
        frame.ns(update, _H, "host:name", name)
        for op, addrs, statuses in (("add", add_addresses, add_statuses),
                                    ("rem", rem_addresses, rem_statuses)):
            addrs = addrs or []
            statuses = statuses or []
            if not addrs and not statuses:
                continue
            block = frame.ns(update, _H, "host:%s" % op)
            for ip in addrs:
                frame.ns(block, _H, "host:addr", ip, {"ip": _ip_version(ip)})
            for status in statuses:
                frame.ns(block, _H, "host:status", None, {"s": status})
        if new_name:
            chg = frame.ns(update, _H, "host:chg")
            frame.ns(chg, _H, "host:name", new_name)
        return self._client.request(frame)

    def delete(self, name: str, force: bool = False) -> Response:
        frame = self._client.frame()
        d = frame.ns(frame.verb("delete"), _H, "host:delete")
        frame.ns(d, _H, "host:name", name)
        if force:
            # UARegistry native: detach the host from every domain before deleting it.
            u = frame.ns(frame.extension(), ns.UAREG_EXT, "uareg:delete")
            frame.ns(u, ns.UAREG_EXT, "uareg:deleteNS", None, {"confirm": "yes"})
        return self._client.request(frame)


class Poll:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def request(self) -> Response:
        """Request the next service message (1301 with a message, 1300 when empty)."""
        frame = self._client.frame()
        frame.verb("poll").set("op", "req")
        return self._client.request(frame)

    def ack(self, message_id: str) -> Response:
        frame = self._client.frame()
        poll = frame.verb("poll")
        poll.set("op", "ack")
        poll.set("msgID", str(message_id))
        return self._client.request(frame)
