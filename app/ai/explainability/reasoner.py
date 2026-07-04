"""Explainable AI (XAI): Translates URL features to human-readable explanations."""

from __future__ import annotations


def generate_lexical_explanations(features: dict[str, float]) -> list[str]:
    """Inspects extracted URL features and returns descriptive human reasons."""
    reasons = []

    if features.get("has_ip", 0.0) == 1.0:
        reasons.append("URL contains a raw IP address instead of a registered domain name.")

    if features.get("brand_similarity_score", 0.0) >= 0.7:
        score = features["brand_similarity_score"]
        if score == 1.0:
            reasons.append("URL contains an exact match for a popular brand keyword.")
        else:
            reasons.append(f"URL resembles a popular brand name (brand similarity: {score*100:.0f}%).")

    if features.get("entropy", 0.0) > 3.8:
        reasons.append(f"High hostname character entropy ({features['entropy']:.2f}) indicates potential random string generation.")

    if features.get("digit_ratio", 0.0) > 0.12:
        reasons.append(f"High ratio of numbers in URL path/host ({features['digit_ratio']*100:.1f}%).")

    if features.get("special_ratio", 0.0) > 0.15:
        reasons.append(f"High ratio of special characters in URL ({features['special_ratio']*100:.1f}%).")

    if features.get("punycode", 0.0) == 1.0:
        reasons.append("URL hostname uses Punycode (often indicating IDN homoglyph spoof attacks).")

    if features.get("mixed_scripts", 0.0) == 1.0:
        reasons.append("URL hostname contains characters from mixed international scripts (homoglyph indicator).")

    if features.get("non_standard_port", 0.0) == 1.0:
        reasons.append("URL points to a non-standard network port (outside of standard 80/443 web services).")

    if features.get("suspicious_tld", 0.0) == 1.0:
        reasons.append("URL utilizes a top-level domain extension flagged as having a high malicious correlation.")

    return reasons
