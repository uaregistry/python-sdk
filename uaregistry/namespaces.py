"""EPP namespace URIs used by the UARegistry service: RFC 5730-5734 plus the secDNS, RGP
and UARegistry extensions. These are the protocol constants sent on the wire."""

EPP = "urn:ietf:params:xml:ns:epp-1.0"
XSI = "http://www.w3.org/2001/XMLSchema-instance"

# Standard RFC object mappings (RFC 5731/5732/5733).
DOMAIN = "urn:ietf:params:xml:ns:domain-1.0"
CONTACT = "urn:ietf:params:xml:ns:contact-1.0"
HOST = "urn:ietf:params:xml:ns:host-1.0"

# Standard extensions.
SECDNS = "urn:ietf:params:xml:ns:secDNS-1.1"  # RFC 5910
RGP = "urn:ietf:params:xml:ns:rgp-1.0"        # RFC 3915

# UARegistry extensions: the .ua trademark licence (<uareg:license>) and the registrar
# account balance (creditLimit / balance / availableCredit).
UAREG_EXT = "http://uaregistry.com/epp/uaregistry-1.0"
UAREG_BALANCE = "http://uaregistry.com/epp/balance-1.0"

# Object services a client logs in with by default (standard RFC mappings).
DEFAULT_OBJ_URIS = [CONTACT, DOMAIN, HOST]

# Extension services the server advertises by default.
DEFAULT_EXT_URIS = [SECDNS, RGP, UAREG_EXT, UAREG_BALANCE]
