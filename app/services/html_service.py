"""Async HTML fetching and lightweight page analysis."""

from __future__ import annotations

from bs4 import BeautifulSoup

from app.services.url_security import UrlSecurityService


class HtmlService:
    """Fetch and inspect HTML while applying SSRF protections."""

    def __init__(self, url_security: UrlSecurityService, timeout_seconds: float = 5.0, verify_ssl: bool = True) -> None:
        self.url_security = url_security
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl

    async def fetch(self, url: str) -> str:
        if self.url_security.is_private_host(url):
            return ""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    headers={"User-Agent": "Mozilla/5.0 phishing-classifier"},
                    ssl=self.verify_ssl,
                ) as response:
                    return await response.text()
        except Exception:
            return ""

    def analyze_html(self, html: str) -> dict:
        soup = BeautifulSoup(html or "", "html.parser")
        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", {"type": "password"})
        iframes = soup.find_all("iframe")
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        images = soup.find_all("img")
        text = soup.get_text(separator=" ", strip=True)[:3000]
        return {
            "has_login_form": bool(forms and password_inputs),
            "password_inputs": len(password_inputs),
            "forms": len(forms),
            "iframes": len(iframes),
            "hidden_inputs": len(hidden_inputs),
            "images": len(images),
            "text": text,
            "is_image_heavy": len(images) >= 8 and len(text) < 500,
        }

