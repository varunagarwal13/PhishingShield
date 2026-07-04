"""Threat Intelligence detector: VirusTotal, GSB, PhishTank, OpenPhish, URLHaus, AbuseIPDB, and OTX."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import socket
from urllib.parse import urlparse
import aiohttp

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.models.detection import DetectorResult
from config.settings import get_settings

logger = logging.getLogger("threat_intelligence")


class ThreatIntelligenceDetector(BaseDetector):
    name = "threat_intelligence"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        url = context.canonical_url
        hostname = context.hostname
        settings = get_settings()

        # Load environment API credentials
        vt_key = settings.vt_api_key or os.getenv("VT_API_KEY", "")
        gsb_key = settings.google_safe_browsing_key or os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
        abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        otx_key = os.getenv("ALIENVAULT_OTX_API_KEY", "")

        timeout = aiohttp.ClientTimeout(total=4)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Execute lookup tasks in parallel with connection pooling
            vt_task = self._check_virustotal(url, vt_key, session)
            gsb_task = self._check_gsb(url, gsb_key, session)
            pt_task = self._check_phishtank(url, session)
            openphish_task = self._check_openphish(url, session)
            urlhaus_task = self._check_urlhaus(url, session)
            abuse_task = self._check_abuseipdb(hostname, abuseipdb_key, session)
            otx_task = self._check_otx(hostname, otx_key, session)

            results = await asyncio.gather(
                vt_task, gsb_task, pt_task, openphish_task, urlhaus_task, abuse_task, otx_task,
                return_exceptions=True
            )

        # Unpack results safely
        vt_res = results[0] if not isinstance(results[0], Exception) else {}
        gsb_res = results[1] if not isinstance(results[1], Exception) else {}
        pt_res = results[2] if not isinstance(results[2], Exception) else {}
        openphish_res = results[3] if not isinstance(results[3], Exception) else {}
        urlhaus_res = results[4] if not isinstance(results[4], Exception) else {}
        abuse_res = results[5] if not isinstance(results[5], Exception) else {}
        otx_res = results[6] if not isinstance(results[6], Exception) else {}

        metadata = {}
        evidence = []
        score = 0.0
        definitive = False

        # Evaluate VirusTotal
        vt_flags = vt_res.get("positives", 0) if isinstance(vt_res, dict) else 0
        metadata["virustotal_flags"] = vt_flags
        if vt_flags > 0:
            evidence.append(f"VirusTotal: flagged by {vt_flags} engine(s)")
            score += min(vt_flags * 12.0, 50.0)
            if vt_flags >= 5:
                definitive = True
                score = 95.0
                evidence.append("VirusTotal early exit trigger: 5+ positive engines")
                if "stop_event" in context.shared:
                    context.shared["stop_event"].set()

        # Evaluate Google Safe Browsing
        gsb_match = gsb_res.get("match", False) if isinstance(gsb_res, dict) else False
        metadata["gsb_match"] = gsb_match
        if gsb_match:
            evidence.append(f"Google Safe Browsing: flagged as malicious site ({gsb_res.get('threat_type')})")
            score += 45.0

        # Evaluate PhishTank
        pt_hit = pt_res.get("in_database", False) if isinstance(pt_res, dict) else False
        metadata["phishtank_hit"] = pt_hit
        if pt_hit:
            evidence.append("PhishTank: confirmed phishing URL listing")
            score += 40.0

        # Evaluate OpenPhish
        op_hit = openphish_res.get("match", False) if isinstance(openphish_res, dict) else False
        metadata["openphish_hit"] = op_hit
        if op_hit:
            evidence.append("OpenPhish: URL matches active threat feed list")
            score += 35.0

        # Evaluate URLHaus
        uh_hit = urlhaus_res.get("match", False) if isinstance(urlhaus_res, dict) else False
        metadata["urlhaus_hit"] = uh_hit
        if uh_hit:
            evidence.append("URLHaus: domain flagged in malware distribution database")
            score += 35.0

        # Evaluate AbuseIPDB
        ip_score = abuse_res.get("abuseScore", 0) if isinstance(abuse_res, dict) else 0
        metadata["abuseipdb_score"] = ip_score
        if ip_score >= 50:
            evidence.append(f"AbuseIPDB: IP address has {ip_score}% abuse report confidence")
            score += 20.0

        # Evaluate AlienVault OTX
        otx_count = otx_res.get("malicious_indicators", 0) if isinstance(otx_res, dict) else 0
        metadata["otx_malicious_indicators"] = otx_count
        if otx_count > 0:
            evidence.append(f"AlienVault OTX: {otx_count} threat indicators found for domain")
            score += min(otx_count * 5.0, 20.0)

        score = min(score, 100.0)
        confidence = 0.95 if (vt_flags > 0 or gsb_match or pt_hit or op_hit or uh_hit) else 0.5

        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=confidence,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=metadata
        )

    # ── VirusTotal Client ──
    async def _check_virustotal(self, url: str, api_key: str, session: aiohttp.ClientSession) -> dict:
        if not api_key:
            return {}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        try:
            async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers) as resp:
                if resp.status == 404:
                    return {"positives": 0, "total": 0}
                if resp.status != 200:
                    return {}
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.values()),
                }
        except Exception:
            return {}

    # ── Google Safe Browsing Client ──
    async def _check_gsb(self, url: str, api_key: str, session: aiohttp.ClientSession) -> dict:
        if not api_key:
            return {}
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishing-shield-api", "clientVersion": "2.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            async with session.post(gsb_url, json=payload) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                matches = data.get("matches", [])
                if matches:
                    return {"match": True, "threat_type": matches[0].get("threatType")}
        except Exception:
            pass
        return {}

    # ── PhishTank Client ──
    async def _check_phishtank(self, url: str, session: aiohttp.ClientSession) -> dict:
        try:
            async with session.post("https://checkurl.phishtank.com/checkurl/", data={"url": url, "format": "json"}) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                results = data.get("results", {})
                return {
                    "in_database": results.get("in_database", False),
                    "verified": results.get("verified", False)
                }
        except Exception:
            return {}

    # ── OpenPhish Client ──
    async def _check_openphish(self, url: str, session: aiohttp.ClientSession) -> dict:
        try:
            # Check against local cached openphish feed, or pull recent feed
            async with session.get("https://openphish.com/feed.txt") as resp:
                if resp.status == 200:
                    feed = await resp.text()
                    if url.rstrip("/") in feed:
                        return {"match": True}
        except Exception:
            pass
        return {}

    # ── URLHaus Client ──
    async def _check_urlhaus(self, url: str, session: aiohttp.ClientSession) -> dict:
        try:
            # Query domain list from URLHaus API
            domain = urlparse(url).netloc.lower().removeprefix("www.")
            async with session.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    status = data.get("query_status", "")
                    if status == "ok" and data.get("blacklisted", False):
                        return {"match": True}
        except Exception:
            pass
        return {}

    # ── AbuseIPDB Client ──
    async def _check_abuseipdb(self, hostname: str, api_key: str, session: aiohttp.ClientSession) -> dict:
        if not api_key:
            return {}
        try:
            # Resolve domain to IP first
            ip = socket.gethostbyname(hostname)
            headers = {"Key": api_key, "Accept": "application/json"}
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    score = data.get("data", {}).get("abuseConfidenceScore", 0)
                    return {"abuseScore": score}
        except Exception:
            pass
        return {}

    # ── AlienVault OTX Client ──
    async def _check_otx(self, hostname: str, api_key: str, session: aiohttp.ClientSession) -> dict:
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/general"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulse_info = data.get("general", {}).get("pulse_info", {})
                    pulses = pulse_info.get("pulses", [])
                    return {"malicious_indicators": len(pulses)}
        except Exception:
            pass
        return {}
