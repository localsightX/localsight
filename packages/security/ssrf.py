"""SSRF / egress guard for operator-supplied destinations (camera/NVR URLs).

Cameras and NVRs are configured by authenticated users, so a malicious or
compromised operator could point the platform at internal services
(127.0.0.1, cloud metadata 169.254.169.254, management endpoints) and use it as
a network proxy. This module rejects such targets *before* any connection is
made. It is the application-layer control; it must be paired with network-level
egress restrictions (see docs/security/network.md).
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse

from packages.security.errors import UnsafeUrlError

# Addresses that must never be reachable through the platform.
_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),   # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # ULA
    ipaddress.ip_network("fe80::/10"),       # link-local
]

_ALLOWED_SCHEMES = {"http", "https", "rtsp", "rtsps"}


def _normalize_ip_literal(host: str) -> str:
    """Normalize exotic IPv4 spellings before resolution/validation.

    getaddrinfo (and ffmpeg/curl) accept decimal (`2130706433` == 127.0.0.1),
    hex (`0x7f.0.0.1`), and octal (`0177.0.0.1`) forms, but naive string or
    ipaddress-only checks see "just a hostname" and let them through to DNS —
    where a wildcard resolver (or attacker-controlled DNS) can map them back
    onto the loopback/private target. Normalize here so the blocklist always
    sees the canonical dotted-quad.
    """
    h = host.strip().rstrip(".")
    if not h or ":" in h:
        return host  # IPv6 / empty: nothing to normalize
    parts = h.split(".")
    nums: list[int] = []
    if len(parts) == 1 and h and all(c in "0123456789xXabcdefABCDEF" for c in h):
        # Single-number form: decimal or 0x-hex 32-bit address.
        try:
            nums = [int(h, 16 if h.lower().startswith("0x") else 10)]
        except ValueError:
            return host
        if not 0 <= nums[0] <= 0xFFFFFFFF:
            return host
        return ".".join(str((nums[0] >> s) & 0xFF) for s in (24, 16, 8, 0))
    if 2 <= len(parts) <= 4:
        try:
            for p in parts:
                p = p.strip()
                if not p:
                    return host
                base = 16 if p.lower().startswith("0x") else (8 if len(p) > 1 and p.startswith("0") and p.isdigit() else 10)
                nums.append(int(p, base))
        except ValueError:
            return host
        # inet_aton semantics: last part absorbs the remaining bytes.
        if any(n < 0 or n > 0xFFFFFFFF for n in nums):
            return host
        if len(parts) == 2:
            a, b = nums
            if not (a <= 0xFF and b <= 0xFFFFFF):
                return host
            n = (a << 24) | b
        elif len(parts) == 3:
            a, b, c = nums
            if not (a <= 0xFF and b <= 0xFF and c <= 0xFFFF):
                return host
            n = (a << 16) | (b << 8) | c
        else:
            if any(n > 0xFF for n in nums):
                return host
            n = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))
    return host


def _canonical(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Unwrap IPv4-mapped IPv6 literals (::ffff:a.b.c.d) into their IPv4 form.

    getaddrinfo happily resolves — and URLs happily carry — mapped literals, but
    an IPv6Address matches none of the IPv4 blocked networks, so without this a
    URL like ``rtsp://[::ffff:10.0.0.5]/`` would bypass the entire private-range
    blocklist while ffmpeg still connects to the private IPv4 target.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(_canonical(ip) in net for net in _BLOCKED_NETS)


def validate_egress_url(
    url: str,
    *,
    allowlist: list[str] | None = None,
    allowed_schemes: set[str] | None = None,
) -> urllib.parse.ParseResult:
    """Validate a user-supplied URL. Returns the parsed result on success.

    Raises UnsafeUrlError if the scheme is invalid, the host cannot be
    resolved, or any resolved address is private/loopback/link-local/metadata
    unless explicitly present in `allowlist` (IP or CIDR).
    """
    allow = [ipaddress.ip_network(c.strip()) for c in (allowlist or []) if c.strip()]
    schemes = allowed_schemes or _ALLOWED_SCHEMES

    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        raise UnsafeUrlError(f"malformed URL: {exc}") from exc

    if parsed.scheme.lower() not in schemes:
        raise UnsafeUrlError(f"scheme {parsed.scheme!r} not permitted")
    if not parsed.hostname:
        raise UnsafeUrlError("missing host")

    # Normalize BEFORE anything else: parsed.hostname already strips userinfo
    # (so `user@evil` can't spoof the host) and lowercases, but exotic IPv4
    # spellings (decimal/hex/octal, inet_aton short forms) must be canonicalized
    # to dotted-quad so the allowlist/blocklist/DNS checks see the real target.
    host = _normalize_ip_literal(parsed.hostname)

    # Allowlist bypass (e.g. the deployed camera VLAN CIDR).
    allowlisted = any(
        _host_in_network(host, net) for net in allow
    )

    # Resolve once; reject on resolution failure (fail closed).
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"cannot resolve host {host!r}: {exc}") from exc

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if allowlisted:
            continue
        if _is_blocked(ip):
            raise UnsafeUrlError(
                f"destination {ip} ({host}) is a private/loopback/"
                f"link-local address and not on the egress allowlist"
            )
    # Literal-IP pre-check: catch exotic spellings (decimal/hex/octal/short
    # inet_aton forms) that normalize to a blocked address even when the local
    # resolver maps them elsewhere (macOS maps 0177.0.0.1 → 177.0.0.1 while
    # Linux glibc maps it → 127.0.0.1). The normalized form is what ffmpeg and
    # other egress clients interpret, so block on it directly. Hostnames that
    # are NOT IP literals resolve via DNS below and are unaffected.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not allowlisted and _is_blocked(_canonical(literal)):
        raise UnsafeUrlError(
            f"destination {literal} ({parsed.hostname}) is a private/loopback/"
            f"link-local address and not on the egress allowlist"
        )
    return parsed


def _host_in_network(host: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        # Same unwrap as the blocklist: an allowlist entry for an IPv4 CIDR must
        # also match the address in its IPv4-mapped IPv6 presentation. Host is
        # pre-normalized by the caller (exotic IPv4 spellings → dotted-quad).
        return _canonical(ipaddress.ip_address(_normalize_ip_literal(host))) in net
    except ValueError:
        return False
