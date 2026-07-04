"""Python client service for Node.js Puppeteer screenshot pool."""

from __future__ import annotations

import logging

import aiohttp

logger = logging.getLogger("phishing_shield")


class PuppeteerService:
    """Client wrapper for calling the local Node.js Puppeteer microservice."""

    def __init__(self, service_url: str = "http://localhost:3001/screenshot", timeout_seconds: float = 8.0) -> None:
        self.service_url = service_url
        self.timeout_seconds = timeout_seconds

    async def get_page_data(self, url: str) -> dict:
        """Call Node.js service to fetch screenshot, DOM signals, and page text.

        Returns:
            {
                "screenshot": "base64...",
                "domSignals": {...},
                "pageText": "..."
            }
            or {} on failure.
        """
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self.service_url, json={"url": url}) as resp:
                    if resp.status == 503:
                        logger.warning("Puppeteer pool busy — skipping visual check")
                        return {}
                    if resp.status != 200:
                        logger.warning(f"Puppeteer service returned status {resp.status}")
                        return {}
                    return await resp.json()
        except TimeoutError:
            logger.warning(f"Puppeteer request timed out for: {url[:60]}")
            return {}
        except Exception as e:
            logger.warning(f"Puppeteer call failed: {e}")
            return {}
