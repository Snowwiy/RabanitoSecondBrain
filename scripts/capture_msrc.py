"""One public capture, or offline normalization of a previously captured month."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import load_settings
from rabanito.cyber.model import InvalidFeed
from rabanito.cyber.msrc_capture import capture_month, normalize_capture
from rabanito.cyber.transport import FetchError


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("month")
    capture.add_argument("--gzip", action="store_true", help="require gzip with bounded decompression; no identity fallback")
    capture.add_argument("--max-seconds", type=int, default=120, help="explicit transfer budget, up to300; normalization remains capped at120")
    offline = commands.add_parser("normalize")
    offline.add_argument("manifest")
    offline.add_argument("--save-records", action="store_true")
    offline.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    try:
        settings = load_settings()
        if settings.root.resolve() != ROOT:
            raise ValueError("unexpected_capture_project_root")
        result = (capture_month(settings, args.month, compressed=args.gzip, max_seconds=args.max_seconds, progress=lambda item: print(json.dumps(item), flush=True))
                  if args.command == "capture" else normalize_capture(settings, args.manifest, save_records=args.save_records, profile_stats=args.profile))
        print(json.dumps(result, indent=2))
    except (ValueError, OSError, HTTPError, URLError, FetchError) as exc:
        print(json.dumps({"error": exc.code if isinstance(exc, FetchError) else str(exc) if type(exc) in {ValueError, InvalidFeed} else "msrc_capture_io_error",
                          "status": getattr(exc, "status", None), "retry_after": getattr(exc, "retry_after", None), "database_written": False}))
        raise SystemExit(1) from None
