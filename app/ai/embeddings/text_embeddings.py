"""Semantic NLP scam classification using SentenceTransformer embeddings."""

from __future__ import annotations

import logging
import numpy as np

from app.ai.loaders.model_loader import ModelLoader

logger = logging.getLogger("nlp_embeddings")

# Reference Phishing Profile Prompts
SCAM_PROFILES = {
    "credential_harvesting": "Sign in to verify your account, enter your username and password to log in",
    "urgency": "Urgent action required: your account will be suspended immediately if you do not act now",
    "payment_scam": "Transfer money to confirm your credit status, payment required to resolve hold on shipping",
    "bank_impersonation": "Secure banking transaction, confirm your OTP and routing number to unlock funds",
    "crypto_scam": "Double your bitcoin, enter your private recovery seed phrase to claim your free reward"
}


def compute_cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    dot = np.dot(a, b)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(dot / (norm_a * norm_b))


def classify_text_semantics(text: str) -> dict[str, float]:
    """Classifies page text against phishing profiles, returning similarity scores."""
    if not text:
        return {k: 0.0 for k in SCAM_PROFILES}

    model = ModelLoader.get_nlp_model()

    # Neural fallback check
    if model is None:
        # Graceful heuristic: Fall back to optimized word-intersection / TF-IDF mockup
        scores = {}
        text_lower = text.lower()
        for key, prompt in SCAM_PROFILES.items():
            words = set(prompt.lower().split())
            matches = sum(1 for w in words if w in text_lower)
            scores[key] = min(matches / len(words) * 1.5, 1.0)
        return scores

    try:
        # Encode target page text
        page_emb = model.encode(text)
        
        scores = {}
        # Compare to pre-compiled profiles
        for key, prompt in SCAM_PROFILES.items():
            prompt_emb = model.encode(prompt)
            scores[key] = compute_cosine_similarity(page_emb, prompt_emb)
        return scores
    except Exception as e:
        logger.error(f"Semantic encoding failed: {e}")
        return {k: 0.0 for k in SCAM_PROFILES}
