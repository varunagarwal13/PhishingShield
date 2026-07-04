"""Risk Taxonomy: Maps evidence IDs and findings into high-level phishing categories."""

from __future__ import annotations

from app.ai.explainability.evidence import EvidenceItem


def classify_categories(evidence_items: list[EvidenceItem]) -> list[str]:
    """Map a set of structured evidence items to high-level risk categories."""
    categories = set()

    for item in evidence_items:
        e_id = item.id.upper()
        
        # 1. Brand Impersonation mappings
        if e_id.startswith("VIS-") or "similarity" in item.details or "brand" in item.reason.lower():
            categories.add("Brand Impersonation")

        # 2. Credential Harvesting mappings
        if e_id in ("DOM-001", "OCR-001") or "password" in item.reason.lower() or "login" in item.reason.lower():
            categories.add("Credential Harvesting")

        # 3. Malware Delivery mappings
        if e_id.startswith("TI-") or "malware" in item.reason.lower() or "urlhaus" in item.reason.lower():
            categories.add("Malware Delivery")

        # 4. Financial Fraud mappings
        if "invoice" in item.reason.lower() or "bitcoin" in item.reason.lower() or "payment" in item.reason.lower():
            categories.add("Financial Fraud")

        # 5. QR Phishing mappings
        if e_id.startswith("IMG-") and "qr" in item.reason.lower():
            categories.add("QR Phishing")

        # 6. Browser Exploitation mappings
        if e_id.startswith("JS-") or e_id.startswith("BEH-") or "fingerprint" in item.reason.lower():
            categories.add("Browser Exploitation")

    # Safe fallback if none matched but there is malicious evidence
    if not categories and any(item.severity in ("HIGH", "CRITICAL") for item in evidence_items):
        categories.add("Credential Harvesting")

    return sorted(list(categories))
