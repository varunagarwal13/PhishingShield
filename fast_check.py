import asyncio
import ssl
import socket
from datetime import datetime, timezone

async def fast_definitive_check(url: str) -> dict:
    from urllib.parse import urlparse
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain:
        return {"early_exit": False, "partial_score": 0, "signals": []}

    whois_age, cert_age = await asyncio.gather(
        _get_domain_age_days(domain),
        _get_cert_age_hours(domain),
        return_exceptions=True
    )

    score = 0
    signals = []

    if isinstance(whois_age, int):
        if whois_age <= 3:
            score += 30
            signals.append(f"Domain registered {whois_age} day(s) ago")
        elif whois_age <= 7:
            score += 20
            signals.append(f"Very new domain ({whois_age} days old)")
        elif whois_age <= 30:
            score += 10
            signals.append(f"New domain ({whois_age} days old)")
    elif isinstance(whois_age, Exception):
        score += 15
        signals.append("No WHOIS record found")

    if isinstance(cert_age, int):
        if cert_age <= 24:
            score += 20
            signals.append(f"SSL certificate issued {cert_age}h ago")
        elif cert_age <= 168:
            score += 10
            signals.append("SSL certificate less than 7 days old")

    if score >= 50:
        return {"early_exit": True, "score": min(score, 100), "signals": signals[:3]}

    return {"early_exit": False, "partial_score": score, "signals": signals}


async def _get_domain_age_days(domain: str) -> int:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _whois_lookup, domain), timeout=8.0
        )
    except asyncio.TimeoutError:
        print(f"WHOIS timeout for {domain}")
        raise Exception("WHOIS timeout")
    except Exception as e:
        print(f"WHOIS error for {domain}: {type(e).__name__}: {e}")
        raise


def _whois_lookup(domain: str) -> int:
    import whois
    w = whois.whois(domain)
    created = w.creation_date
    if isinstance(created, list):
        created = created[0]
    if created is None:
        raise Exception("No creation date")
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - created).days)


async def _get_cert_age_hours(domain: str) -> int:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _ssl_cert_age, domain), timeout=8.0
        )
    except asyncio.TimeoutError:
        print(f"SSL timeout for {domain}")
        raise Exception("SSL timeout")
    except Exception as e:
        print(f"SSL error for {domain}: {type(e).__name__}: {e}")
        raise


def _ssl_cert_age(domain: str) -> int:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    not_before = not_before.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - not_before).total_seconds() / 3600))
