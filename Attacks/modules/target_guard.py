import ipaddress
import socket
from urllib.parse import urlparse

PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class TargetNotPermitted(Exception):
    pass


def _resolve_host(host):
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as ex:
        raise TargetNotPermitted(f"cannot resolve host: {host!r} ({ex})") from ex
    return list({info[4][0] for info in infos})


def _normalize(target_url):
    raw = str(target_url or "").strip()
    if not raw:
        raise TargetNotPermitted("target URL is empty")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if not host:
        raise TargetNotPermitted(f"could not parse host from {target_url!r}")
    return host


def assert_permitted(target_url, target=None):
    """Raise TargetNotPermitted unless the URL resolves to loopback/RFC1918 or
    appears in target.scope.allowed_hosts. Returns the resolved host on success."""
    host = _normalize(target_url)

    target = target or {}
    scope = target.get("scope") or {}
    allowed = {str(h).lower() for h in (scope.get("allowed_hosts") or [])}
    if host in allowed:
        return host

    addresses = _resolve_host(host)
    if not addresses:
        raise TargetNotPermitted(f"host {host!r} did not resolve to any address")

    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as ex:
            raise TargetNotPermitted(f"unparseable address {addr!r}: {ex}") from ex
        if not any(ip in net for net in PRIVATE_NETS):
            raise TargetNotPermitted(
                f"host {host!r} resolves to {addr}, which is not loopback/private. "
                "Add the host to target.scope.allowed_hosts to override."
            )
    return host
