"""Bounded, public-only MSRC contract probe. Does not import vulnerabilities.

One explicit public month, GET-only, no credentials/proxy/redirects or models.
It stores only aggregate schema evidence under ignored data/, not the raw feed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import load_settings
from rabanito.cyber.cvrf_stream import read_cvrf
from rabanito.cyber.model import CVE, InvalidFeed
from rabanito.cyber.msrc import normalize_stream
from rabanito.cyber.transport import NoRedirect
from rabanito.utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic


MONTH = re.compile(r"20\d{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\Z")


def probe(month: str, *, normalize=False) -> dict:
    if not MONTH.fullmatch(month):
        raise ValueError("invalid_public_msrc_month")
    settings = load_settings()
    if settings.root.resolve() != ROOT or safe_relative(settings.data_dir, ROOT) in {None, "", "."} or contains_reparse_component(settings.data_dir):
        raise ValueError("unsafe_contract_report_root")
    url = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + month + "?api-version=2023-11-01"
    keys, status_types, threat_types, remediation_types = Counter(), Counter(), Counter(), Counter()
    non_cve_ids, sample = [], None
    cves = set()
    def observe(item):
        nonlocal sample
        keys.update(item.keys())
        cve = item.get("CVE")
        if isinstance(cve, str) and CVE.fullmatch(cve):
            cves.add(cve)
        else:
            non_cve_ids.append(cve)
        for name, counts in (("ProductStatuses", status_types), ("Threats", threat_types), ("Remediations", remediation_types)):
            for entry in item.get(name, []):
                counts[str(entry.get("Type"))] += 1
        if sample is None:
            sample = {key: item.get(key) for key in ("CVE", "Title", "CWE", "RevisionHistory", "CVSSScoreSets", "Threats")}
            for key in ("RevisionHistory", "CVSSScoreSets", "Threats"):
                sample[key] = (sample[key] or [])[:1]
                for record in sample[key]:
                    if isinstance(record, dict) and isinstance(record.get("ProductID"), list):
                        record["ProductID"] = record["ProductID"][:3]
            sample["ProductStatuses"] = [{"Type": x.get("Type"), "ProductID_count": len(x.get("ProductID", []))} for x in item.get("ProductStatuses", [])]
            sample["Remediations"] = [{k: x.get(k) for k in ("Type", "URL", "FixedBuild", "SubType", "Date")} for x in item.get("Remediations", [])[:2]]
    started = time.monotonic()
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "RabanitoSecondBrain-contract-review"}, method="GET")
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=25) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() not in {"identity", ""}:
            raise InvalidFeed("unsupported_msrc_probe_response")
        write_json_atomic(settings.data_dir / "msrc-probe-transport.json", {
            "at": iso_now(), "month": month, "phase": "headers_received", "status": response.status,
            "content_length": response.headers.get("Content-Length"), "transfer_encoding": response.headers.get("Transfer-Encoding"),
            "content_type": response.headers.get("Content-Type"), "private_data_sent": False})
        decoded = normalize_stream(response, month) if normalize else read_cvrf(response, observe)
        transport = {"status": response.status, "etag": response.headers.get("ETag"), "last_modified": response.headers.get("Last-Modified")}
    if normalize:
        records = decoded["records"]
        cve = next((r for r in records if r["record_kind"] == "vulnerability"), None)
        result = {"at": iso_now(), "source_url": url, "month": month, "requests": 1, "database_written": False,
                  "normalization_completed": True, "seconds": round(time.monotonic()-started, 3), "coverage": decoded["coverage"],
                  "record_count": len(records), "record_kinds": dict(Counter(r["record_kind"] for r in records)),
                  "numeric_metrics": sum(m.get("score") is not None for r in records for m in r["metrics"]),
                  "vendor_fix_records": sum(bool(r["fixes"]) for r in records),
                  "vendor_exploitation_reported": sum(r["exploitation_reported"] for r in records),
                  "sample_cve": {key: cve[key] for key in ("provider_id", "provider_locator", "published", "modified", "cwes", "source_url")} if cve else None,
                  "transport": transport, "note": "Real normalized provider data, not a registered sync connector or installed-state assessment."}
        write_json_atomic(settings.data_dir / ("msrc-normalization-probe-" + month + ".json"), result)
        return result
    headers = decoded["headers"]
    result = {"at": iso_now(), "source_url": url, "month": month, "complete_envelope": True,
              "database_written": False, "requests": 1, "bytes": decoded["bytes_read"], "seconds": round(time.monotonic()-started, 3),
              "vulnerabilities": decoded["vulnerability_count"], "distinct_cves": len(cves), "non_cve_identifiers": non_cve_ids,
              "tracking": headers["DocumentTracking"], "header_keys": sorted(headers),
              "product_tree_keys": sorted(headers["ProductTree"]),
              "full_product_names": len(headers["ProductTree"].get("FullProductName", [])),
              "vulnerability_field_counts": dict(keys), "product_status_types": dict(status_types), "threat_types": dict(threat_types),
              "remediation_types": dict(remediation_types), "sample": sample, "transport": transport,
              "note": "Real provider schema evidence, not an implemented or globally fresh connector; no private data transmitted."}
    write_json_atomic(settings.data_dir / ("msrc-contract-probe-" + month + ".json"), result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("month", help="explicit public CVRF month, e.g. 2026-Oct")
    parser.add_argument("--normalize", action="store_true", help="validate the normalization foundation, without database publication")
    try:
        args = parser.parse_args()
        print(json.dumps(probe(args.month, normalize=args.normalize), ensure_ascii=True, indent=2))
    except (ValueError, OSError, HTTPError, URLError, TypeError, KeyError) as exc:
        print(json.dumps({"error": str(exc) if type(exc) in {ValueError, InvalidFeed} else "msrc_probe_transport_error",
                          "status": getattr(exc, "code", None), "publication_performed": False}))
        raise SystemExit(1) from None
