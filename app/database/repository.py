"""Repository helpers for detection persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


class ThreatLogRepository:
    """Persist enriched detector output while preserving legacy tables."""

    def __init__(self, session: Any, threat_log_model: Any) -> None:
        self.session = session
        self.threat_log_model = threat_log_model

    def record_detection(
        self,
        url: str,
        score: float,
        verdict: str,
        detector_outputs: list[dict[str, Any]],
        execution_time: float | None = None,
        screenshot_path: str | None = None,
        html_hash: str | None = None,
        certificate_fingerprint: str | None = None,
        threat_intelligence_results: dict[str, Any] | None = None,
    ) -> Any:
        signals = [
            evidence
            for output in detector_outputs
            for evidence in output.get("evidence", [])
        ]
        log = self.threat_log_model(
            url=url[:2048],
            score=score,
            verdict=verdict,
            signals=json.dumps(signals),
            cached=0,
            timestamp=datetime.now(timezone.utc),
        )
        for optional_field, value in {
            "detector_outputs": detector_outputs,
            "execution_time": execution_time,
            "screenshot_path": screenshot_path,
            "html_hash": html_hash,
            "certificate_fingerprint": certificate_fingerprint,
            "threat_intelligence_results": threat_intelligence_results,
        }.items():
            if hasattr(log, optional_field):
                setattr(log, optional_field, json.dumps(value, default=str) if isinstance(value, (dict, list)) else value)
        self.session.add(log)
        self.session.commit()
        return log

