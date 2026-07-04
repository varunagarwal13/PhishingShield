"""Image Analysis detector: OCR (EasyOCR/Pytesseract), QR code decode, and steganography analysis."""

from __future__ import annotations

import base64
import io
import logging
import platform
import numpy as np
from PIL import Image

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.models.detection import DetectorResult
from app.ai.loaders import ModelLoader

logger = logging.getLogger("image_analysis")

# Configure pytesseract path for Windows if running locally as a fallback
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
    if platform.system() == "Windows":
        pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
except ImportError:
    PYTESSERACT_AVAILABLE = False

QR_AVAILABLE = False
QR_LIBRARY = None

try:
    import zxingcpp
    QR_AVAILABLE = True
    QR_LIBRARY = "zxing"
except ImportError:
    try:
        from pyzbar.pyzbar import decode as _pyzbar_decode
        QR_AVAILABLE = True
        QR_LIBRARY = "pyzbar"
    except (ImportError, FileNotFoundError, OSError):
        QR_AVAILABLE = False

SUSPICIOUS_WORDS = [
    "verify", "secure", "account", "suspended", "confirm",
    "credential", "login", "password", "urgent", "act now",
    "validate", "unlock"
]


class ImageAnalysisDetector(BaseDetector):
    name = "image_analysis"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        screenshot_b64 = context.shared.get("puppeteer_screenshot")

        if not screenshot_b64:
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=0.5,
                execution_time=0.0,
                evidence=[],
                metadata={"status": "no_screenshot_available"}
            )

        evidence = []
        metadata = {}
        score = 0.0

        try:
            img_bytes = base64.b64decode(screenshot_b64)
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")

            # 1. OCR text extraction
            ocr_text = ""
            ocr_suspicious = False
            
            # Try EasyOCR first via Lazy Loader
            reader = ModelLoader.get_ocr_reader()
            if reader is not None:
                try:
                    # Convert PIL image to numpy array
                    img_np = np.array(img)
                    results = reader.readtext(img_np)
                    ocr_text = " ".join([res[1] for res in results]).strip()
                    logger.info("✓ Extracted page text using EasyOCR reader")
                except Exception as e:
                    logger.warning(f"EasyOCR parsing failed: {e}")

            # Fallback to Pytesseract if EasyOCR failed/not installed
            if not ocr_text and PYTESSERACT_AVAILABLE:
                try:
                    ocr_text = pytesseract.image_to_string(img).strip()
                    logger.info("✓ Extracted page text using Pytesseract fallback")
                except Exception as e:
                    logger.warning(f"Pytesseract fallback failed: {e}")

            # Check extracted text for keywords
            if ocr_text:
                ocr_lower = ocr_text.lower()
                hits = [w for w in SUSPICIOUS_WORDS if w in ocr_lower]
                if hits:
                    ocr_suspicious = True
                    score += 20.0
                    evidence.append(f"OCR: suspicious login/account keywords found in page image ({', '.join(hits[:3])})")

            # 2. QR code detection & hidden URL extraction
            qr_urls = []
            if QR_AVAILABLE:
                try:
                    qr_urls = self._decode_qr_codes(img)
                    if qr_urls:
                        score += 30.0
                        evidence.append(f"QR Code: embedded destination URL detected ({qr_urls[0]})")
                except Exception as e:
                    logger.warning(f"QR decode failed: {e}")

            # 3. Steganography detection (LSB Chi-square analysis)
            stego_detected = self._check_steganography(img)
            if stego_detected:
                score += 20.0
                evidence.append("Steganography: suspected LSB hidden metadata injection pattern")

            metadata.update({
                "ocr_text": ocr_text[:1000],
                "ocr_suspicious": ocr_suspicious,
                "qr_urls": qr_urls,
                "qr_detected": len(qr_urls) > 0,
                "steganography_detected": stego_detected
            })

        except Exception as e:
            logger.error(f"Image Analysis execution failed: {e}")
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=0.5,
                execution_time=0.0,
                evidence=[],
                metadata={"error": str(e)},
                failed=True
            )

        score = min(score, 100.0)

        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.85 if ocr_suspicious else 0.5,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=metadata
        )

    def _decode_qr_codes(self, img: Image.Image) -> list[str]:
        if not QR_AVAILABLE:
            return []
        try:
            if QR_LIBRARY == "zxing":
                img_array = np.array(img)
                results = zxingcpp.read_barcodes(img_array)
                return [r.text for r in results if r.text]
            else:
                codes = _pyzbar_decode(img)
                return [code.data.decode("utf-8") for code in codes]
        except Exception:
            return []

    def _check_steganography(self, img: Image.Image) -> bool:
        try:
            img_array = np.array(img)
            suspicious_channels = 0
            for channel in range(3):
                channel_data = img_array[:, :, channel].flatten()
                lsb = channel_data & 1
                observed_0 = int(np.sum(lsb == 0))
                observed_1 = int(np.sum(lsb == 1))
                total = len(lsb)
                expected = total / 2.0
                if expected == 0:
                    continue
                chi_sq = ((observed_0 - expected) ** 2 / expected +
                          (observed_1 - expected) ** 2 / expected)
                if chi_sq < 0.05:
                    suspicious_channels += 1
            return suspicious_channels >= 2
        except Exception:
            return False
