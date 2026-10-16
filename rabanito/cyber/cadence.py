from __future__ import annotations

import json
import time

from ..config import Settings
from .store import SOURCES
from .sync import sync_source


def run_cyber_watch(settings: Settings, *, start: bool = False, cycles: int | None = None,
                    sync=None, sleep=None, emit=None) -> dict:
    """An opt-in foreground loop. No scheduler, hook, service or LLM is installed."""
    cyber = settings.raw.get("cyber", {})
    if not isinstance(cyber, dict):
        raise ValueError("Invalid Cyber configuration")
    config = cyber.get("cadence", {})
    if not isinstance(config, dict) or type(config.get("enabled", False)) is not bool:
        raise ValueError("Invalid Cyber cadence configuration")
    if not config.get("enabled", False) and not start:
        raise ValueError("Cyber cadence is disabled. Use watch --start to run explicitly in foreground.")
    interval = config.get("interval_minutes", 60)
    catchup = config.get("nvd_catchup_windows", 3)
    sources = config.get("sources", ["kev", "nvd", "epss"])
    if type(interval) is not int or not 60 <= interval <= 10080:
        raise ValueError("Cyber cadence interval must be 60 to 10080 minutes")
    if type(catchup) is not int or not 1 <= catchup <= 6:
        raise ValueError("nvd_catchup_windows must be 1 to 6")
    if (not isinstance(sources, list) or not sources or len(sources) > len(SOURCES)
            or any(s not in SOURCES for s in sources) or len(set(sources)) != len(sources)):
        raise ValueError("Cyber cadence sources must be distinct approved provider names")
    if cycles is not None and (type(cycles) is not int or cycles < 1):
        raise ValueError("cycles must be positive")
    operation, pause = sync or sync_source, sleep or time.sleep
    output = emit or (lambda line: print(line, flush=True))
    completed = 0
    failures = 0
    backlog_sources: set[str] = set()
    pending_sources: set[str] = set()
    try:
        while cycles is None or completed < cycles:
            for source in sources:
                for window in range(catchup if source == "nvd" else 1):
                    result = operation(settings, source)
                    resumable = source == "nvd" and result["status"] == "partial" and result.get("scope", {}).get("resumable") is True
                    failures += result["status"] != "ok" and not resumable
                    if resumable: pending_sources.add(source)
                    else: pending_sources.discard(source)
                    backlog = bool(result.get("scope", {}).get("backlog"))
                    if backlog: backlog_sources.add(source)
                    else: backlog_sources.discard(source)
                    output(json.dumps({"event": "cyber_sync", "cycle": completed + 1, "window": window + 1, "source": source,
                                       "status": result["status"], "added": result.get("added", 0),
                                       "modified": result.get("modified", 0), "error_code": result.get("error_code"),
                                       "backlog": backlog, "resumable": resumable,
                                       "next_offset": result.get("scope", {}).get("next_offset"),
                                       "covered_until": result.get("scope", {}).get("end")}, ensure_ascii=False))
                    if (result["status"] != "ok" and not resumable) or not result.get("scope", {}).get("backlog"):
                        break
            completed += 1
            if cycles is not None and completed >= cycles:
                break
            output(json.dumps({"event": "waiting", "interval_minutes": interval}))
            pause(interval * 60)
    except KeyboardInterrupt:
        return {"status": "stopped", "cycles": completed, "failed_updates": failures, "backlog_sources": sorted(backlog_sources)} | ({"pending_sources": sorted(pending_sources)} if pending_sources else {})
    return {"status": "partial" if failures or pending_sources else "complete", "cycles": completed, "failed_updates": failures, "backlog_sources": sorted(backlog_sources)} | ({"pending_sources": sorted(pending_sources)} if pending_sources else {})
