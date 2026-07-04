"""A parsed EPP response (or greeting). Wraps the raw XML with convenience accessors: the
result code/message, transaction ids, the availability map for ``*:check``, and generic
value/values getters plus the underlying element tree for anything bespoke.

Element lookups are namespace-agnostic (by local name), so a variation in the response's
namespace prefixes never breaks a getter.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from .exceptions import ConnectionException


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(el: Optional[ET.Element]) -> str:
    return (el.text or "").strip() if el is not None else ""


class Response:
    def __init__(self, raw: str, root: ET.Element) -> None:
        self._raw = raw
        self._root = root

    @classmethod
    def from_xml(cls, xml: str) -> "Response":
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise ConnectionException("Server returned malformed XML: %s" % exc)
        return cls(xml, root)

    # --- generic element search (namespace-agnostic) ---------------------------

    def _all(self, local_name: str) -> List[ET.Element]:
        return [e for e in self._root.iter() if _local(e.tag) == local_name]

    def _first(self, local_name: str) -> Optional[ET.Element]:
        for e in self._root.iter():
            if _local(e.tag) == local_name:
                return e
        return None

    @staticmethod
    def _direct_child(parent: ET.Element, local_name: str) -> Optional[ET.Element]:
        for e in list(parent):
            if _local(e.tag) == local_name:
                return e
        return None

    # --- result / trID ---------------------------------------------------------

    def code(self) -> int:
        """The EPP result code (e.g. 1000, 1001, 2200), or 0 for a greeting/codeless frame."""
        result = self._first("result")
        if result is None:
            return 0
        raw = result.get("code")
        return int(raw) if raw and raw.isdigit() else 0

    def message(self) -> Optional[str]:
        result = self._first("result")
        if result is None:
            return None
        msg = self._direct_child(result, "msg")
        return _text(msg) if msg is not None else None

    def message_lang(self) -> Optional[str]:
        """The language of the result <msg> ("en", "uk", "ua" or "ru"), or None."""
        result = self._first("result")
        if result is None:
            return None
        msg = self._direct_child(result, "msg")
        return msg.get("lang") if msg is not None else None

    def is_success(self) -> bool:
        """A 1xxx code means success (1000 done, 1001 action pending)."""
        return 1000 <= self.code() < 2000

    def is_pending(self) -> bool:
        return self.code() == 1001

    def is_greeting(self) -> bool:
        return self._first("greeting") is not None

    def cl_trid(self) -> Optional[str]:
        trid = self._first("trID")
        if trid is None:
            return None
        node = self._direct_child(trid, "clTRID")
        return _text(node) if node is not None else None

    def sv_trid(self) -> Optional[str]:
        trid = self._first("trID")
        if trid is None:
            return None
        node = self._direct_child(trid, "svTRID")
        return _text(node) if node is not None else None

    # --- check / poll ----------------------------------------------------------

    def availability(self) -> Dict[str, bool]:
        """Availability map for a ``*:check`` response: name/id -> is-available."""
        out: Dict[str, bool] = {}
        for el in self._root.iter():
            if "avail" in el.attrib:
                out[(el.text or "").strip()] = el.get("avail") in ("1", "true")
        return out

    def message_id(self) -> Optional[str]:
        """Poll only: the queued message id to pass to poll().ack(), or None."""
        msgq = self._first("msgQ")
        return msgq.get("id") if msgq is not None else None

    def message_count(self) -> int:
        """Poll only: how many messages remain in the queue."""
        msgq = self._first("msgQ")
        if msgq is None:
            return 0
        raw = msgq.get("count")
        return int(raw) if raw and raw.isdigit() else 0

    def statuses(self) -> List[str]:
        """Object status values from the ``s`` attribute (e.g. ['ok'] or ['clientHold', ...])."""
        return [el.get("s") for el in self._all("status") if el.get("s") is not None]

    # --- balance / prices / licence -------------------------------------------

    def balance(self) -> Optional[Dict[str, str]]:
        """Account figures from a balance:info response (creditLimit / balance /
        availableCredit), or None when this is not a balance response."""
        limit = self.value("creditLimit")
        avail = self.value("availableCredit")
        if limit is None and avail is None:
            return None
        return {
            "creditLimit": limit or "",
            "balance": self.value("balance") or "",
            "availableCredit": avail or "",
        }

    def prices(self) -> Dict[str, Dict[str, str]]:
        """Renewal/restore price hints from a domain:info response (the uaregistry priceData
        extension), keyed by operation."""
        out: Dict[str, Dict[str, str]] = {}
        for node in self._all("price"):
            op = node.get("operation")
            if not op:
                continue
            out[op] = {"value": (node.text or "").strip(), "currency": node.get("currency", "")}
        return out

    def license(self) -> Optional[str]:
        """The .ua trademark/licence number from a domain:info response, or None."""
        return self.value("license")

    def rgp_status(self) -> List[str]:
        """RGP status values from a domain:info response (e.g. ['redemptionPeriod'])."""
        return [el.get("s") for el in self._all("rgpStatus") if el.get("s") is not None]

    def transfer_status(self) -> Optional[str]:
        """The transfer status from a transfer response or poll trnData (e.g. "pending")."""
        return self.value("trStatus")

    # --- DNSSEC ----------------------------------------------------------------

    def ds_records(self) -> List[Dict[str, object]]:
        """DNSSEC DS records from a domain:info response (secDNS:dsData)."""
        out = []
        for ds in self._all("dsData"):
            out.append({
                "keyTag": int(_text(self._direct_child(ds, "keyTag")) or 0),
                "alg": int(_text(self._direct_child(ds, "alg")) or 0),
                "digestType": int(_text(self._direct_child(ds, "digestType")) or 0),
                "digest": _text(self._direct_child(ds, "digest")),
            })
        return out

    def key_records(self) -> List[Dict[str, object]]:
        """DNSSEC key records from a domain:info response (top-level secDNS:keyData)."""
        out = []
        for inf in self._all("infData"):
            for kd in list(inf):
                if _local(kd.tag) != "keyData":
                    continue
                out.append({
                    "flags": int(_text(self._direct_child(kd, "flags")) or 0),
                    "protocol": int(_text(self._direct_child(kd, "protocol")) or 0),
                    "alg": int(_text(self._direct_child(kd, "alg")) or 0),
                    "pubKey": _text(self._direct_child(kd, "pubKey")),
                })
        return out

    def is_signed(self) -> bool:
        """True when a domain:info response carries DNSSEC data (any DS or key records)."""
        return bool(self.ds_records() or self.key_records())

    # --- diagnostics / greeting -----------------------------------------------

    def error_reasons(self) -> List[str]:
        """Extra diagnostic text from a failed command's <extValue><reason> elements."""
        out: List[str] = []
        for ext in self._all("extValue"):
            for reason in ext.iter():
                if _local(reason.tag) == "reason":
                    out.append((reason.text or "").strip())
        return out

    def service_obj_uris(self) -> List[str]:
        """Greeting only: the object services the server advertises."""
        return [(e.text or "").strip() for e in self._all("objURI")]

    def service_ext_uris(self) -> List[str]:
        """Greeting only: the extension services the server advertises."""
        return [(e.text or "").strip() for e in self._all("extURI")]

    # --- generic getters -------------------------------------------------------

    def value(self, local_name: str) -> Optional[str]:
        """First element anywhere with this local name (namespace-agnostic), trimmed."""
        el = self._first(local_name)
        return _text(el) if el is not None else None

    def values(self, local_name: str) -> List[str]:
        """Every element with this local name, trimmed."""
        return [(e.text or "").strip() for e in self._all(local_name)]

    def res_data(self) -> Optional[ET.Element]:
        """The <resData> element of the response, if present (for custom parsing)."""
        return self._first("resData")

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def root(self) -> ET.Element:
        return self._root
