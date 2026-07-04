# PhishingShield Independent Audit: Explainability Audit

This report details the audit of the PhishingShield Explainable AI (XAI) subsystem, evidence tracking, MITRE mappings, and remediation advice.

---

## 1. Evidence Compilation & Taxonomy Mappings

The explanation engine (`app/ai/explainability/explanation_engine.py`) maps detector logs to structured evidence entries using unique tracing IDs:
* **Traceable Identifiers**:
  * `URL-001` to `URL-013` (URL structure, redirects, and brand similarities)
  * `TI-001` to `TI-007` (VirusTotal, Google Safe Browsing, OpenPhish feeds)
  * `VIS-001` to `VIS-003` (Visual perceptual matches and password checks)
  * `JS-001` to `JS-005` (Obfuscated JS, script evaluation counts)
* **Confidence Allocation**: Each evidence reason includes a confidence rating matching detector reliability weights (ranging from `0.50` to `1.00`).
* **Source Attribution**: Reasons are attributed to their source detector (e.g. `url_analysis`, `threat_intelligence`).

---

## 2. MITRE ATT&CK Mapping & Recommendations

* **MITRE Mappings**:
  * `T1566` (Phishing) - For malicious URL detections or feed hits.
  * `T1027` (Obfuscated Files or Information) - For obfuscated JavaScript elements.
  * `T1622` (Debugger Evasion) - For anti-debugging techniques in browser scripts.
  * `T1592` (Gather Victim Identity Information) - For credential harvesting forms.
* **Remediation guidance**:
  * **User actions**: "Do not enter credentials", "Do not run script files", "Close browser tab".
  * **Admin recommendations**: "Block IP address on network gateway", "Revoke active session logs".

---

## 3. Formatting & Payloads

* **Markdown Generation**: Formats a clean list ordered from high-priority threats to low-priority alerts.
* **Machine-Readable JSON**: Serializes all properties alongside the human-readable summary, matching the Pydantic schemas.
