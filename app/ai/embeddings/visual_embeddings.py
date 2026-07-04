"""CLIP image embeddings encoder for visual similarity checks."""

from __future__ import annotations

import logging
from PIL import Image

logger = logging.getLogger("visual_embeddings")


class CLIPVisualEncoder:
    """Lazy loader and encoder for CLIP image embeddings."""

    _model = None
    _processor = None
    _device = None

    @classmethod
    def _initialize(cls) -> bool:
        if cls._model is not None:
            return True
        try:
            import torch
            from transformers import CLIPModel, CLIPProcessor

            cls._device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Initializing CLIP model on device: {cls._device}")

            cls._processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
            cls._model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(cls._device)
            return True
        except ImportError:
            logger.warning(
                "transformers/torch not available for visual similarity encoding. "
                "Falling back to pHash pre-filtering."
            )
            return False
        except Exception as e:
            logger.error(f"Failed to initialize CLIP model: {e}")
            return False

    @classmethod
    def encode_image(cls, image: Image.Image) -> list[float]:
        """Generate CLIP vector embedding for a PIL image."""
        if not cls._initialize():
            return []
        try:
            import torch

            # Process image using CLIP processor
            inputs = cls._processor(images=image, return_tensors="pt").to(cls._device)
            with torch.no_grad():
                image_features = cls._model.get_image_features(**inputs)
                # Normalize features
                image_features = image_features / image_features.norm(p=2, dim=-1, keepdim=True)
                return image_features.cpu().numpy()[0].tolist()
        except Exception as e:
            logger.error(f"CLIP image encoding failed: {e}")
            return []
