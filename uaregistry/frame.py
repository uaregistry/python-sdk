"""EPP command frame builder.

Guarantees the RFC 5730 child order (command content, then an optional ``<extension>``,
then ``<clTRID>``) and proper XML escaping — text is set on element nodes, never
concatenated. Public so you can assemble bespoke frames for anything the high-level client
does not cover and send them via ``Client.request()``.

The base ``epp-1.0`` namespace is emitted as the default (unprefixed) namespace; the object
and extension namespaces carry the conventional ``domain:`` / ``contact:`` / ``host:`` /
``secDNS:`` prefixes.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

from . import namespaces as ns

_PREFIXES = {
    "": ns.EPP,
    "domain": ns.DOMAIN,
    "contact": ns.CONTACT,
    "host": ns.HOST,
    "secDNS": ns.SECDNS,
    "rgp": ns.RGP,
    "uareg": ns.UAREG_EXT,
    "balance": ns.UAREG_BALANCE,
}
for _prefix, _uri in _PREFIXES.items():
    ET.register_namespace(_prefix, _uri)

_XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>'


def _clark(uri: str, local: str) -> str:
    """ElementTree "Clark notation" tag for a namespaced element."""
    return "{%s}%s" % (uri, local)


class Frame:
    def __init__(self) -> None:
        self._epp = ET.Element(_clark(ns.EPP, "epp"))
        self._command = ET.SubElement(self._epp, _clark(ns.EPP, "command"))
        self._extension: Optional[ET.Element] = None
        self._cltrid = ""

    @classmethod
    def command(cls, cltrid: str) -> "Frame":
        """Start a <command> frame."""
        frame = cls()
        frame._cltrid = cltrid
        return frame

    @property
    def root(self) -> ET.Element:
        return self._epp

    def verb(self, name: str) -> ET.Element:
        """Add the command verb element (<check>, <create>, <login>, <poll>, ...)."""
        return ET.SubElement(self._command, _clark(ns.EPP, name))

    def extension(self) -> ET.Element:
        """Lazily add (once) and return the <extension> element."""
        if self._extension is None:
            self._extension = ET.SubElement(self._command, _clark(ns.EPP, "extension"))
        return self._extension

    def epp(self, parent: ET.Element, name: str, text: Optional[str] = None,
            attrs: Optional[Dict[str, Any]] = None) -> ET.Element:
        """Append an element in the base epp-1.0 namespace (no prefix)."""
        return self._fill(ET.SubElement(parent, _clark(ns.EPP, name)), text, attrs)

    def ns(self, parent: ET.Element, ns_uri: str, qname: str, text: Optional[str] = None,
           attrs: Optional[Dict[str, Any]] = None) -> ET.Element:
        """Append a namespaced element (e.g. ``domain:name``) carrying its xmlns prefix."""
        local = qname.split(":", 1)[-1]
        return self._fill(ET.SubElement(parent, _clark(ns_uri, local)), text, attrs)

    def to_xml(self) -> str:
        # clTRID is always the final child of <command> (RFC 5730 ordering).
        cl = ET.SubElement(self._command, _clark(ns.EPP, "clTRID"))
        cl.text = self._cltrid
        return _XML_DECL + ET.tostring(self._epp, encoding="unicode")

    @staticmethod
    def _fill(el: ET.Element, text: Optional[str], attrs: Optional[Dict[str, Any]]) -> ET.Element:
        if text is not None:
            el.text = text
        if attrs:
            for name, value in attrs.items():
                el.set(name, str(value))
        return el
