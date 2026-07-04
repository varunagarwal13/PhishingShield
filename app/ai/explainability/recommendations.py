"""Recommendations Generator: Produces tailored containment steps based on threat severity."""

from __future__ import annotations

from app.ai.explainability.evidence import RecommendationBlock


def generate_recommendations(highest_severity: str) -> RecommendationBlock:
    """Return tailored remediation guidance based on the highest active threat severity."""
    sev = highest_severity.upper()

    if sev == "CRITICAL":
        return RecommendationBlock(
            user="Do not enter any credentials and close this page immediately.",
            administrator="Block this domain at the firewall/DNS gateway and inspect system traffic logs for related queries."
        )
    elif sev == "HIGH":
        return RecommendationBlock(
            user="Exercise extreme caution. This page resembles a popular brand but is hosted on an unverified domain.",
            administrator="Flag this domain in email gateway filters and audit directory logs for potential credential leakage."
        )
    elif sev == "MEDIUM":
        return RecommendationBlock(
            user="Verify the sender and origin before proceeding. Avoid interacting with authentication inputs.",
            administrator="Add this host to low-reputation monitor lists and analyze downstream client request headers."
        )
    else:
        return RecommendationBlock(
            user="This site appears low risk, but verify the link origin before entering details.",
            administrator="No immediate block actions required. Maintain standard endpoint logging."
        )


