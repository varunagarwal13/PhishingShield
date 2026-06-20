import aiohttp
import tldextract
from urllib.parse import urlparse

SCREENSHOT_SERVICE = "http://127.0.0.1:3000/screenshot"

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
                page_domain_ext = tldextract.extract(url)
                page_domain = f"{page_domain_ext.domain}.{page_domain_ext.suffix}"

                for action in dom.get("formActions", []):
                    if not action.startswith("http"):
                        continue
                    action_ext = tldextract.extract(action)
                    action_domain = f"{action_ext.domain}.{action_ext.suffix}"
                    if action_domain and action_domain != page_domain:
                        result["form_action_mismatch"] = True
                        result["form_action_domain"] = action_domain
                        break

    except Exception as e:
        import traceback
        print(f"DOM check error for {url}: {type(e).__name__}: {e}")
        traceback.print_exc()

    return result