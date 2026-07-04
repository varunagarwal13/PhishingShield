# PhishingShield Independent Audit: Security Audit

This report details the audit of the PhishingShield URL security module, SSRF protections, loopback detection, IP checks, input validation, and redirect protections.

---

## 1. SSRF & Private IP Protection

The `UrlSecurityService` (`app/utils/url_utils.py`) enforces strict validation against local infrastructure accesses:
* **Literal Private IP Blocking**: Direct checks classify private ranges (e.g. `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) as unsafe.
* **DNS Resolution Audit**: If a hostname is supplied, `socket.getaddrinfo` is invoked to resolve all mapped IPs. If any returned IP resolves to a private, loopback (`localhost`), link-local, multicast, or unspecified range, the host is flagged as unsafe immediately.
* **Impact**: Completely mitigates Server-Side Request Forgery (SSRF) attempts designed to access local backend endpoints or services.

---

## 2. Homoglyph & Unicode Spoofing Protection

* **Normalization**: The pipeline performs double-percent URL decoding and NFKC Unicode normalization to clean obfuscated inputs.
* **Skeleton Homograph Detection**: Hostnames are converted to unified QWERTY skeletons. The skeleton check flags Cyrillic/Latin confusable homoglyph strings (e.g. substituting `a` with Cyrillic `а` to impersonate popular brands).

---

## 3. Rate Limiting & Input Validation

* **Max Length Enforcement**: The routing logic enforces an absolute threshold of `2048` characters on incoming URLs.
* **Protocol Whitelisting**: Rejects non-web protocols, accepting only `http` and `https`.
* **SQL Injection & XSS Protection**: Database inserts use parameterized SQLAlchemy schemas, preventing raw query injection.
