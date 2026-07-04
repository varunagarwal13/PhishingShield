"""Lazy loader for structured ML and deep learning models (NLP, OCR)."""

from __future__ import annotations

import logging
from pathlib import Path
import joblib

logger = logging.getLogger("model_loader")

STRUCTURED_MODEL_PATH = Path("training/export/structured_model.pkl")


class ModelLoader:
    """Handles lazy loading of models to optimize startup latency and memory footprint."""

    _structured_model = None
    _sentence_transformer = None
    _easyocr_reader = None

    @classmethod
    def get_structured_model(cls):
        """Lazy load structured LightGBM classifier."""
        if cls._structured_model is None:
            if STRUCTURED_MODEL_PATH.exists():
                try:
                    cls._structured_model = joblib.load(STRUCTURED_MODEL_PATH)
                    logger.info("✓ Structured LightGBM classifier loaded successfully")
                except Exception as e:
                    logger.error(f"Failed to load structured model: {e}")
            else:
                logger.warning(
                    f"LightGBM model not found at {STRUCTURED_MODEL_PATH}. "
                    "Structured prediction will run in heuristic/stub fallback mode."
                )
        return cls._structured_model

    @classmethod
    def get_nlp_model(cls):
        """Lazy load Sentence Transformers all-MiniLM-L6-v2 model."""
        if cls._sentence_transformer is None:
            try:
                from sentence_transformers import SentenceTransformer
                # Download/load model from HF cache
                cls._sentence_transformer = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("✓ SentenceTransformer (all-MiniLM-L6-v2) loaded successfully")
            except ImportError:
                logger.warning(
                    "sentence-transformers not installed. "
                    "Semantic NLP will fall back to keyword-based urgency matching. "
                    "Run 'pip install sentence-transformers' to enable neural NLP."
                )
            except Exception as e:
                logger.error(f"Failed to load SentenceTransformer: {e}")
        return cls._sentence_transformer

    @classmethod
    def get_ocr_reader(cls):
        """Lazy load EasyOCR reader."""
        if cls._easyocr_reader is None:
            try:
                import easyocr
                # Initialize CPU-first reader
                cls._easyocr_reader = easyocr.Reader(["en"])
                logger.info("✓ EasyOCR reader initialized successfully")
            except ImportError:
                logger.warning(
                    "easyocr not installed. "
                    "OCR image scanning will fall back to pytesseract parsing. "
                    "Run 'pip install easyocr' to enable EasyOCR."
                )
            except Exception as e:
                logger.error(f"Failed to initialize EasyOCR: {e}")
        return cls._easyocr_reader
