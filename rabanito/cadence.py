from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .config import Settings
from .indexer import index_all


MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 10_080  # one week


def _interval_from_settings(settings: Settings) -> int:
    cadence = settings.raw.get("cadence", {})
    if not isinstance(cadence, dict):
        raise ValueError("La sección 'cadence' de settings.json debe ser un objeto JSON.")
    interval = cadence.get("interval_minutes", 60)
    if isinstance(interval, bool) or not isinstance(interval, int):
        raise ValueError("cadence.interval_minutes debe ser un entero.")
    return interval


def run_index_watch(
    settings: Settings,
    interval_minutes: int | None = None,
    cycles: int | None = None,
    *,
    indexer: Callable[[Settings], dict[str, Any]] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run an explicitly started, foreground-only incremental index loop."""
    interval = _interval_from_settings(settings) if interval_minutes is None else interval_minutes
    if isinstance(interval, bool) or not isinstance(interval, int) or not MIN_INTERVAL_MINUTES <= interval <= MAX_INTERVAL_MINUTES:
        raise ValueError(
            f"El intervalo debe estar entre {MIN_INTERVAL_MINUTES} y {MAX_INTERVAL_MINUTES} minutos."
        )
    if cycles is not None and (isinstance(cycles, bool) or not isinstance(cycles, int) or cycles < 1):
        raise ValueError("--cycles debe ser un entero positivo.")

    run_index = indexer or index_all
    sleep = sleep_fn or time.sleep
    output = emit or (lambda line: print(line, flush=True))
    completed = 0

    while cycles is None or completed < cycles:
        completed += 1
        try:
            result = run_index(settings)
            record = {
                "event": "index_complete",
                "cycle": completed,
                "status": result.get("status", "ok"),
                "finished_at": result.get("finished_at"),
                "files_seen": result.get("files_seen", 0),
                "added": result.get("added", 0),
                "modified": result.get("modified", 0),
                "unchanged": result.get("unchanged", 0),
                "removed": result.get("removed", 0),
                "skipped": result.get("skipped", 0),
                "errors": result.get("errors", 0),
            }
        except KeyboardInterrupt:
            output(json.dumps({"event": "stopped", "completed_cycles": completed - 1}, ensure_ascii=False))
            return {"status": "stopped", "cycles": completed - 1}
        except Exception as exc:
            # Do not print exception text: filesystem or parser errors may contain sensitive paths.
            record = {
                "event": "index_error",
                "cycle": completed,
                "status": "error",
                "error_type": type(exc).__name__,
                "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        output(json.dumps(record, ensure_ascii=False))

        if cycles is not None and completed >= cycles:
            break
        next_run = datetime.now(timezone.utc) + timedelta(minutes=interval)
        output(json.dumps({
            "event": "waiting",
            "interval_minutes": interval,
            "next_run_at": next_run.isoformat(timespec="seconds"),
        }, ensure_ascii=False))
        try:
            sleep(interval * 60)
        except KeyboardInterrupt:
            output(json.dumps({"event": "stopped", "completed_cycles": completed}, ensure_ascii=False))
            return {"status": "stopped", "cycles": completed}

    output(json.dumps({"event": "watch_complete", "completed_cycles": completed}, ensure_ascii=False))
    return {"status": "complete", "cycles": completed}
