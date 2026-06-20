import asyncio
import base64
import io
import logging
import numpy as np
import requests
from PIL import Image

log = logging.getLogger("phishing_shield")

import platform
import pytesseract

if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# On Linux (Render/Docker), tesseract is installed via apt-get and is
# already on PATH, so no override is needed

OCR_ENABLED = True

try:
    import zxingcpp
    QR_ENABLED = True
    QR_LIBRARY = "zxing"
except ImportError:
    try:
        from pyzbar.pyzbar import decode as _pyzbar_decode
        QR_ENABLED = True
        QR_LIBRARY = "pyzbar"
    except (ImportError, FileNotFoundError, OSError):
        # pyzbar requires a native libzbar DLL that may be missing its
        # own dependencies on some Windows setups — fail gracefully
        QR_ENABLED = False
        QR_LIBRARY = None
        log.warning("QR code scanning disabled — pyzbar native library unavailable")
SCREENSHOT_SERVICE = "http://127.0.0.1:3000/screenshot"

SUSPICIOUS_WORDS = [
    "verify", "secure", "account", "suspended", "confirm",
    "credential", "login", "password", "urgent", "immediately",
    "click here", "act now", "validate", "unlock"
]


def _decode_qr_codes(img):
    if not QR_ENABLED:
        return []
    try:
        if QR_LIBRARY == "zxing":
            img_array = np.array(img)
            results = zxingcpp.read_barcodes(img_array)
            return [r.text for r in results if r.text]
        else:
            codes = _pyzbar_decode(img)
            return [code.data.decode("utf-8") for code in codes]
    except Exception as e:
        log.warning(f"QR decode error: {e}")
        return []


def _extract_ocr_text(img):
    if not OCR_ENABLED:
        return ""
    try:
        return pytesseract.image_to_string(img).strip()
    except Exception as e:
        log.warning(f"OCR error: {e}")
        return ""


def _check_steganography(img):
    try:
        img_array = np.array(img.convert("RGB"))
        suspicious_channels = 0
        for channel in range(3):
            channel_data = img_array[:, :, channel].flatten()
            lsb = channel_data & 1
            observed_0 = int(np.sum(lsb == 0))
            observed_1 = int(np.sum(lsb == 1))
            total = len(lsb)
            expected = total / 2
            chi_sq = ((observed_0 - expected) ** 2 / expected +
                      (observed_1 - expected) ** 2 / expected)
            if chi_sq < 0.05:
                suspicious_channels += 1
        return suspicious_channels >= 2
    except Exception as e:
        log.warning(f"Steganography check error: {e}")
        return False


async def run_image_scan(url, stop_event):
    if stop_event.is_set():
        return {}

    result = {
        "qr_urls": [],
        "qr_url_flagged": False,
        "ocr_text": "",
        "ocr_suspicious": False,
        "steganography_detected": False
    }

    try:
        resp = requests.post(
            SCREENSHOT_SERVICE,
            json={"url": url},
            timeout=10
        )
        if resp.status_code != 200:
            return result

        screenshot_b64 = resp.json().get("screenshot", "")
        if not screenshot_b64:
            return result

        img_bytes = base64.b64decode(screenshot_b64)
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")

        if stop_event.is_set():
            return result

        qr_urls = _decode_qr_codes(img)
        result["qr_urls"] = qr_urls
        if qr_urls:
            for qr_url in qr_urls:
                if any(w in qr_url.lower() for w in SUSPICIOUS_WORDS):
                    result["qr_url_flagged"] = True
                    break

        if stop_event.is_set():
            return result

        ocr_text = _extract_ocr_text(img)
        result["ocr_text"] = ocr_text[:500]
        if ocr_text:
            hits = sum(1 for w in SUSPICIOUS_WORDS if w in ocr_text.lower())
            result["ocr_suspicious"] = hits >= 3

        result["steganography_detected"] = _check_steganography(img)

    except Exception as e:
        log.error(f"Image scan error: {e}")

    return result