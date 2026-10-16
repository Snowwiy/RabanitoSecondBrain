from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from rabanito.cadence import run_index_watch


class CadenceTests(unittest.TestCase):
    def test_watch_runs_bounded_cycles_and_sleeps_only_between_scans(self) -> None:
        settings = SimpleNamespace(raw={"cadence": {"interval_minutes": 15}})
        calls: list[object] = []
        sleeps: list[float] = []
        output: list[dict[str, object]] = []

        def indexer(value: object) -> dict[str, object]:
            calls.append(value)
            return {
                "status": "partial" if len(calls) == 1 else "ok",
                "files_seen": 7, "added": 1, "modified": 0,
                "unchanged": 6, "removed": 0, "skipped": 0, "errors": 0,
                "error_message": "do-not-log-private-path",
            }

        result = run_index_watch(
            settings, cycles=2, indexer=indexer,
            sleep_fn=sleeps.append,
            emit=lambda line: output.append(json.loads(line)),
        )

        self.assertEqual(result, {"status": "complete", "cycles": 2})
        self.assertEqual(calls, [settings, settings])
        self.assertEqual(sleeps, [900])
        self.assertEqual([item["event"] for item in output], ["index_complete", "waiting", "index_complete", "watch_complete"])
        self.assertEqual([output[0]["status"], output[2]["status"]], ["partial", "ok"])
        self.assertEqual(output[0]["files_seen"], 7)
        self.assertNotIn("error_message", output[0])
        self.assertNotIn("do-not-log-private-path", json.dumps(output))

    def test_watch_logs_error_type_without_sensitive_exception_text_and_continues(self) -> None:
        settings = SimpleNamespace(raw={})
        calls = 0
        output: list[dict[str, object]] = []

        def indexer(_: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("secret path C:\\private\\token.env")
            return {"status": "ok", "files_seen": 0}

        result = run_index_watch(
            settings, interval_minutes=5, cycles=2, indexer=indexer,
            sleep_fn=lambda _: None,
            emit=lambda line: output.append(json.loads(line)),
        )

        self.assertEqual(result["cycles"], 2)
        self.assertEqual(output[0]["event"], "index_error")
        self.assertEqual(output[0]["error_type"], "OSError")
        self.assertNotIn("private", json.dumps(output))
        self.assertEqual(output[2]["status"], "ok")

    def test_watch_stops_cleanly_on_keyboard_interrupt_during_wait(self) -> None:
        settings = SimpleNamespace(raw={})
        calls = 0
        output: list[dict[str, object]] = []

        def indexer(_: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {"status": "ok", "files_seen": 1}

        def stop(_: float) -> None:
            raise KeyboardInterrupt

        result = run_index_watch(
            settings, interval_minutes=5, indexer=indexer,
            sleep_fn=stop,
            emit=lambda line: output.append(json.loads(line)),
        )

        self.assertEqual(result, {"status": "stopped", "cycles": 1})
        self.assertEqual(calls, 1)
        self.assertEqual(output[-1], {"event": "stopped", "completed_cycles": 1})

    def test_watch_stops_cleanly_if_scan_is_interrupted(self) -> None:
        settings = SimpleNamespace(raw={})
        output: list[dict[str, object]] = []

        def interrupt(_: object) -> dict[str, object]:
            raise KeyboardInterrupt

        result = run_index_watch(
            settings, interval_minutes=5, indexer=interrupt,
            emit=lambda line: output.append(json.loads(line)),
        )

        self.assertEqual(result, {"status": "stopped", "cycles": 0})
        self.assertEqual(output, [{"event": "stopped", "completed_cycles": 0}])

    def test_watch_validates_interval_cycle_count_and_config_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "entre 5 y 10080"):
            run_index_watch(SimpleNamespace(raw={}), interval_minutes=1, cycles=1)
        with self.assertRaisesRegex(ValueError, "entero positivo"):
            run_index_watch(SimpleNamespace(raw={}), interval_minutes=5, cycles=0)
        with self.assertRaisesRegex(ValueError, "objeto JSON"):
            run_index_watch(SimpleNamespace(raw={"cadence": []}))
        with self.assertRaisesRegex(ValueError, "entero"):
            run_index_watch(SimpleNamespace(raw={"cadence": {"interval_minutes": "15"}}))


if __name__ == "__main__":
    unittest.main()
