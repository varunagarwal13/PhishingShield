"""URL canonicalization and domain-security helpers."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse, urlunparse

import tldextract

from app.config.constants import DEFAULT_TRUSTED_DOMAINS

extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
HOMOGLYPH_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a",
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0456": "i",
    }
)


class UrlSecurityService:
    """Normalize URLs, guard SSRF targets, and validate trusted domains."""

    def __init__(self, trusted_domains_path: Path | str = "trusted_domains.json") -> None:
        self.trusted_domains_path = Path(trusted_domains_path)
        self._trusted_domains = set(DEFAULT_TRUSTED_DOMAINS)
        self.reload_trusted_domains()

    @property
    def trusted_domains(self) -> set[str]:
        return set(self._trusted_domains)

    def reload_trusted_domains(self) -> set[str]:
        """Reload trusted domains from JSON without restarting the process."""
        if self.trusted_domains_path.exists():
            with self.trusted_domains_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            domains = data.get("domains", data) if isinstance(data, dict) else data
            self._trusted_domains = {str(domain).lower().strip(".") for domain in domains}
        return self.trusted_domains

    def canonicalize(self, url: str) -> str:
        """Canonicalize mixed-encoded and Unicode URLs before detection."""
        value = unicodedata.normalize("NFKC", url.strip())
        for _ in range(2):
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            value = f"https://{value}"
        parsed = urlparse(value)
        hostname = (parsed.hostname or "").strip(".").lower()
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        netloc = hostname
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "", "", parsed.query or "", ""))

    def hostname(self, url: str) -> str:
        return (urlparse(self.canonicalize(url)).hostname or "").strip(".").lower()

    def registered_domain(self, hostname: str) -> str:
        ext = extract_domain(hostname)
        if not ext.domain:
            return hostname.lower().strip(".")
        return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()

    def trust_match(self, hostname: str) -> str | None:
        host = hostname.lower().strip(".")
        for trusted_domain in sorted(self._trusted_domains, key=len, reverse=True):
            if host == trusted_domain or host.endswith(f".{trusted_domain}"):
                return trusted_domain
        return None

    def is_trusted(self, hostname: str) -> bool:
        return self.trust_match(hostname) is not None

    def skeleton(self, hostname: str) -> str:
        normalized = unicodedata.normalize("NFKD", hostname.lower())
        asciiish = "".join(char for char in normalized if not unicodedata.combining(char))
        return asciiish.translate(HOMOGLYPH_MAP)

    def homograph_matches(self, hostname: str) -> list[str]:
        host_skeleton = self.skeleton(hostname)
        return [domain for domain in self._trusted_domains if host_skeleton == self.skeleton(domain) and hostname != domain]

    @staticmethod
    def _is_unsafe_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )

    def is_private_host(self, url: str) -> bool:
        """Return True if the URL's host is (or resolves to) a non-public address.

        Checks both literal IP hosts and DNS names. Every resolved A/AAAA
        record is validated, so a public-looking hostname that has been
        pointed at an internal/loopback address (DNS rebinding) is treated
        as private too.
        """
        host = self.hostname(url)
        if not host:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return self._resolves_to_unsafe_address(host)
        return self._is_unsafe_address(address)

    def _resolves_to_unsafe_address(self, hostname: str) -> bool:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except (socket.gaierror, UnicodeError, socket.timeout):
            # Can't resolve it -> treat as unsafe rather than letting it through.
            return True
        for info in infos:
            raw_ip = info[4][0]
            try:
                address = ipaddress.ip_address(raw_ip.split("%")[0])
            except ValueError:
                return True
            if self._is_unsafe_address(address):
                return True
        return False

    def resolved_ips(self, hostname: str) -> list[str]:
        """Return the resolved IP addresses for a hostname, or [] on failure."""
        try:
            infos = socket.getaddrinfo(hostname, None)
        except (socket.gaierror, UnicodeError, socket.timeout):
            return []
        return sorted({info[4][0] for info in infos})

