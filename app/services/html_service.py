"""Async HTML fetching and lightweight page analysis."""

from __future__ import annotations

from bs4 import BeautifulSoup

from app.services.url_security import UrlSecurityService

MAX_REDIRECTS = 5


class HtmlService:
    """Fetch and inspect HTML while applying SSRF protections.

    SSRF defense-in-depth: the target host (and every DNS-resolved address
    behind it) is validated before *each* request. Redirects are followed
    manually (never automatically by aiohttp) so a malicious or DNS-rebinding
    redirect target is re-checked before it is ever connected to, and a
    bounded number of hops prevents redirect loops.
    """

    def __init__(self, url_security: UrlSecurityService, timeout_seconds: float = 5.0, verify_ssl: bool = True) -> None:
        self.url_security = url_security
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl

    async def fetch(self, url: str) -> str:
        try:
            import aiohttp
        except ImportError:
            return ""

        current_url = url
        try:
            async with aiohttp.ClientSession() as session:
                for _ in range(MAX_REDIRECTS + 1):
                    if self.url_security.is_private_host(current_url):
                        return ""
                    async with session.get(
                        current_url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        headers={"User-Agent": "Mozilla/5.0 phishing-classifier"},
                        ssl=self.verify_ssl,
                        allow_redirects=False,
                    ) as response:
                        if response.status in (301, 302, 303, 307, 308):
                            location = response.headers.get("Location")
                            if not location:
                                return ""
                            current_url = str(response.url.join(aiohttp.client.URL(location)))
                            continue
                        return await response.text()
            return ""
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

