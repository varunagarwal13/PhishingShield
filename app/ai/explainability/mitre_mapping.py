"""MITRE ATT&CK Mapping: Links detector findings to standard cyber-threat techniques."""

from __future__ import annotations


def get_mitre_mapping(evidence_id: str) -> dict[str, str] | None:
    """Return MITRE ATT&CK mapping for a specific evidence identifier."""
    e_id = evidence_id.upper()

    # 1. Obfuscation & Evasion techniques
    if e_id in ("JS-001", "JS-002", "JS-004"):
        return {
            "technique_id": "T1027",
            "name": "Obfuscated Files or Information"
        }
    if e_id == "JS-003":  # Anti-debugging / DevTools blocks
        return {
            "technique_id": "T1622",
            "name": "Debugger Evasion"
        }

    # 2. Phishing delivery techniques
    if e_id.startswith("URL-") or e_id.startswith("TI-") or e_id.startswith("IMG-"):
        return {
            "technique_id": "T1566",
            "name": "Phishing"
        }

    # 3. Telemetry/Information Gathering
    if e_id.startswith("BEH-"):
        return {
            "technique_id": "T1592",
            "name": "Gather Victim Host Information"
        }

    return None
