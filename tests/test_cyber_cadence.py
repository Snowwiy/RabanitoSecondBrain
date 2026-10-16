from __future__ import annotations

import json
import unittest
from pathlib import Path

from rabanito.config import Settings
from rabanito.cyber.cadence import run_cyber_watch


class CyberCadenceTests(unittest.TestCase):
    def test_bounded_cycle_can_resume_staged_pages_without_counting_progress_as_a_failure(self):
        calls = []
        def sync(settings, source):
            calls.append(source)
            return ({"status": "partial", "scope": {"backlog": True, "resumable": True, "next_offset": 1500}} if len(calls) == 1 else
                    {"status": "ok", "scope": {"backlog": False}})
        result = run_cyber_watch(self.settings({"sources": ["nvd"]}), start=True, cycles=1, sync=sync, emit=lambda _: None)
        self.assertEqual(calls, ["nvd", "nvd"])
        self.assertEqual(result["failed_updates"], 0)
        self.assertEqual(result["status"], "complete")

    def test_cycle_budget_reports_unpublished_pending_work_instead_of_claiming_complete(self):
        result = run_cyber_watch(self.settings({"sources": ["nvd"], "nvd_catchup_windows": 1}), start=True, cycles=1,
                    sync=lambda *args: {"status": "partial", "scope": {"backlog": True, "resumable": True}}, emit=lambda _: None)
        self.assertEqual(result["failed_updates"], 0)
        self.assertEqual(result["pending_sources"], ["nvd"])
        self.assertEqual(result["status"], "partial")

    def settings(self, cadence=None):
        return Settings(Path(__file__).resolve().parent, {"cyber": {"cadence": cadence or {}}})

    def test_cadence_is_disabled_without_explicit_start(self):
        with self.assertRaises(ValueError):
            run_cyber_watch(self.settings(), cycles=1)

    def test_foreground_cycles_respect_interval_and_report_partial_results(self):
        calls, waits, events = [], [], []
        def sync(settings, source):
            calls.append(source)
            return {"status": "partial" if source == "nvd" else "ok", "added": 1}
        result = run_cyber_watch(self.settings({"sources": ["kev", "nvd"], "interval_minutes": 60}),
                    start=True, cycles=2, sync=sync, sleep=waits.append, emit=lambda line: events.append(json.loads(line)))
        self.assertEqual(result, {"status": "partial", "cycles": 2, "failed_updates": 2, "backlog_sources": []})
        self.assertEqual(calls, ["kev", "nvd", "kev", "nvd"])
        self.assertEqual(waits, [3600])
        self.assertEqual(events[1]["status"], "partial")

    def test_invalid_interval_source_and_cycles_fail_before_fetching(self):
        for config in ({"interval_minutes": 1}, {"sources": ["unknown"]}, {"sources": ["kev", "kev"]}, {"enabled": "true"}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                run_cyber_watch(self.settings(config), start=True, cycles=1)

    def test_interrupt_returns_cleanly_without_installing_service(self):
        def stop(*args): raise KeyboardInterrupt
        self.assertEqual(run_cyber_watch(self.settings(), start=True, cycles=1, sync=stop), {"status": "stopped", "cycles": 0, "failed_updates": 0, "backlog_sources": []})
