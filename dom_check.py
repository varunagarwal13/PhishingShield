import aiohttp
import tldextract
from urllib.parse import urlparse

SCREENSHOT_SERVICE = "http://127.0.0.1:3000/screenshot"
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

def _normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        return f"https://{url}"
    return url

def _hostname(url: str) -> str:
    parsed = urlparse(_normalize_url(url))
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host

def _registrable_domain(hostname: str) -> str:
    ext = TLD_EXTRACTOR(hostname)
    if not ext.suffix:
        return ext.domain.lower()
    return f"{ext.domain}.{ext.suffix}".lower()

def _same_site(page_host: str, action_host: str) -> bool:
    if not page_host or not action_host:
        return False
    return _registrable_domain(page_host) == _registrable_domain(action_host)

async def check_dom_signals(url: str) -> dict:
    """
    Fetches DOM signals from the Puppeteer service and flags phishing
    patterns: password fields whose form submits to a different domain
    than the one displayed, or hidden iframes (often used to load
    malicious content invisibly).
    """
    result = {
        "has_login_form": False,
        "form_action_mismatch": False,
        "form_action_domain": None,
        "hidden_iframe_count": 0,
        "checked": False
    }

    try:
        url = _normalize_url(url)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                SCREENSHOT_SERVICE,
                json={"url": url},
                timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                if resp.status != 200:
                    return result
                data = await resp.json()
                dom = data.get("domSignals", {})
                if not dom:
                    return result

                result["checked"] = True
                result["has_login_form"] = dom.get("hasLoginForm", False)
                result["hidden_iframe_count"] = dom.get("hiddenIframeCount", 0)

                # Check if any form submits to a domain different from
                # the page's own domain — classic credential-harvesting pattern
                page_host = _hostname(url)

                for action in dom.get("formActions", []):
                    if not action.startswith("http"):
                        continue
                    action_host = _hostname(action)
                    action_domain = _registrable_domain(action_host)
                    if action_domain and not _same_site(page_host, action_host):
                        result["form_action_mismatch"] = True
                        result["form_action_domain"] = action_domain
                        break

    except Exception as e:
        import traceback
        print(f"DOM check error for {url}: {type(e).__name__}: {e}")
        traceback.print_exc()

    return result
