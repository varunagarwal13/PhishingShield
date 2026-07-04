# PhishingShield Security Architecture

## SSRF / Loopback Protection

The pipeline enforces strict DNS verification. Any URL hostname resolving to private, local loopback, or multicast IP addresses is blocked at pre-check to prevent Server-Side Request Forgery.

## Input Sanitization

Protects against directory path traversal, homoglyph domain attacks, and malformed UTF-8 URL parameters.
