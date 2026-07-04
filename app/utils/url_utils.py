"""URL canonicalization and domain-security helpers."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse, urlunparse

import tldextract

from config.constants import DEFAULT_TRUSTED_DOMAINS

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

logger = logging.getLogger("phishing_shield")


class UrlSecurityService:
    """Normalize URLs, guard SSRF targets, and validate trusted domains."""

    def __init__(self, trusted_domains_path: Path | str = "config/trusted_domains.json", alexa_top10k_path: Path | str = "config/allowlist/alexa_top10k.txt") -> None:
        self.trusted_domains_path = Path(trusted_domains_path)
        self.alexa_top10k_path = Path(alexa_top10k_path)
        self._trusted_domains = set(DEFAULT_TRUSTED_DOMAINS)
        self._alexa_domains = set()
        self.reload_trusted_domains()
        self.load_alexa_allowlist()

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

    def load_alexa_allowlist(self) -> None:
        """Load Alexa Top 10K domains if the file exists."""
        if self.alexa_top10k_path.exists():
            try:
                with self.alexa_top10k_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        domain = line.strip().lower()
                        if domain:
                            self._alexa_domains.add(domain)
                logger.info(f"Loaded {len(self._alexa_domains)} domains from Alexa Top 10K allowlist")
            except Exception as e:
                logger.error(f"Failed to load Alexa Top 10K: {e}")

    def is_safe(self, hostname: str) -> bool:
        """Check if hostname is in trusted domains list or matches Alexa Top 10K registrable domain."""
        base_domain = self.registered_domain(hostname)
        return self.is_trusted(hostname) or base_domain in self._alexa_domains

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
        """Return True if the URL's host is (or resolves to) a non-public address."""
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
        except (TimeoutError, socket.gaierror, UnicodeError):
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
        except (TimeoutError, socket.gaierror, UnicodeError):
            return []
        return sorted({info[4][0] for info in infos})


def extract_features(url: str, feature_cols: list) -> dict:
    """Extract standard features required by the RF/XGB models."""
    try:
        parsed = urlparse(url)
        ext = extract_domain(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        path = parsed.path or ""
        params = parsed.query or ""
        path_parts = path.rsplit("/", 1)
        directory = path_parts[0] if len(path_parts) > 1 else ""
        file_part = path_parts[1] if len(path_parts) > 1 else ""

        def char_counts(s, prefix):
            chars = {
                "dot": ".", "hyphen": "-", "underline": "_", "slash": "/",
                "questionmark": "?", "equal": "=", "at": "@", "and": "&",
                "exclamation": "!", "space": " ", "tilde": "~", "comma": ",",
                "plus": "+", "asterisk": "*", "hashtag": "#", "dollar": "$",
                "percent": "%"
            }
            return {f"qty_{name}_{prefix}": s.count(c) for name, c in chars.items()}

        features = {}
        features.update(char_counts(url, "url"))
        features["qty_tld_url"] = url.lower().count(ext.suffix) if ext.suffix else 0
        features["length_url"] = len(url)
        features.update(char_counts(domain, "domain"))
        features["qty_vowels_domain"] = sum(domain.count(v) for v in "aeiou")
        features["domain_length"] = len(domain)
        features["domain_in_ip"] = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", ext.domain))) if ext.domain else 0
        features["server_client_domain"] = int("server" in domain or "client" in domain)
        features.update(char_counts(directory, "directory"))
        features["directory_length"] = len(directory)
        features.update(char_counts(file_part, "file"))
        features["file_length"] = len(file_part)
        features.update(char_counts(params, "params"))
        features["params_length"] = len(params)
        features["tld_present_params"] = int(ext.suffix in params if ext.suffix else False)
        features["qty_params"] = len(params.split("&")) if params else 0
        features["email_in_url"] = int("@" in url and "mailto" in url.lower())
        features["time_response"] = -1
        features["domain_spf"] = -1
        features["asn_ip"] = -1
        features["time_domain_activation"] = -1
        features["time_domain_expiration"] = -1
        features["qty_ip_resolved"] = -1
        features["qty_nameservers"] = -1
        features["qty_mx_servers"] = -1
        features["ttl_hostname"] = -1
        features["tls_ssl_certificate"] = int(url.startswith("https"))
        features["qty_redirects"] = 0
        features["url_google_index"] = -1
        features["domain_google_index"] = -1
        features["url_shortened"] = int(ext.domain in [
            "bit", "tinyurl", "goo", "ow", "t", "is", "cli", "yfrog", "migre",
            "ff", "url4", "twit", "su", "snipurl", "short", "ping", "post"
        ]) if ext.domain else 0
        return features
    except Exception as e:
        logger.error(f"Feature extraction error for url={url!r}: {e}")
        return {col: -1 for col in feature_cols}
