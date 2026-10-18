"""MSRC CVRF normalization foundation. No network, publication or schema writes.

Records are provisional until the complete JSON envelope and document identity
validate. Publication is owned separately by msrc_sync.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser

from .model import CVE, InvalidFeed, base, date, number, objects, public_url, text
from .cvrf_stream import read_cvrf


ADAPTER_VERSION = 1
MONTH = re.compile(r"20\d{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\Z")
ADVISORY = re.compile(r"ADV\d{6,12}\Z")
BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"


def document_url(month: str) -> str:
    if not isinstance(month, str) or not MONTH.fullmatch(month):
        raise InvalidFeed("invalid_public_msrc_month")
    return BASE_URL + "/cvrf/" + month + "?api-version=2023-11-01"


class _Plain(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.hidden = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        elif tag in {"p", "br", "li", "div"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def plain(value, maximum=20000):
    if isinstance(value, dict):
        value = value.get("Value")
    raw = text(value, maximum)
    parser = _Plain()
    parser.feed(raw); parser.close()
    return " ".join("".join(parser.parts).split())


def _ids(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 25000 or any(not isinstance(x, str) or not x or len(x) > 200 for x in value):
        raise InvalidFeed("invalid_msrc_product_ids")
    return sorted(set(value))


def _date(value):
    if value is None or value == "" or isinstance(value, str) and value.startswith("0001-"):
        return None  # Serializer sentinel, never a publication date.
    return date(value)


def _type(item):
    value = item.get("Type")
    if type(value) is not int or not 0 <= value <= 100:
        raise InvalidFeed("invalid_msrc_type_code")
    return value


def _scoped_unique(entries):
    """Identical vendor statements may repeat once per product; union scopes."""
    grouped = {}
    for entry in entries:
        key = json.dumps({k: v for k, v in entry.items() if k != "product_ids"}, sort_keys=True, allow_nan=False)
        if key not in grouped:
            grouped[key] = {**entry, "product_ids": set()}
        grouped[key]["product_ids"].update(entry.get("product_ids", []))
    return [{**entry, "product_ids": sorted(entry["product_ids"])} for entry in grouped.values()]


def _record(item: dict, month: str, ordinal: int) -> dict:
    native = text(item.get("CVE"), 100)
    if not CVE.fullmatch(native) and not ADVISORY.fullmatch(native):
        raise InvalidFeed("unsupported_msrc_identifier")
    record = base("MSRC-" + month + "-" + native, document_url(month))
    record.update(provider_id=native, provider_document=month, adapter_version=ADAPTER_VERSION,
                  provider_locator="/Vulnerability/" + str(ordinal),
                  record_kind="vulnerability" if CVE.fullmatch(native) else "security_advisory",
                  record_status="published" if CVE.fullmatch(native) else "advisory",
                  aliases=[native] if CVE.fullmatch(native) else [], title=plain(item.get("Title"), 4000))
    if not record["title"]:
        raise InvalidFeed("missing_msrc_title")
    notes = [{"title": plain(n.get("Title"), 1000), "type_code": _type(n), "text": plain(n.get("Value"))}
             for n in objects(item.get("Notes", []), 128)]
    record["notes"] = notes
    record["description"] = " ".join(n["text"] for n in notes if n["title"].casefold() == "description")[:20000]
    if item.get("ReleaseDateSpecified") is True:
        record["published"] = _date(item.get("ReleaseDate"))
    revisions = [_date(r.get("Date")) for r in objects(item.get("RevisionHistory", []), 256)]
    record["modified"] = max((x for x in revisions if x), default=None)
    statuses = [{"type_code": _type(s), "product_ids": _ids(s.get("ProductID"))}
                for s in objects(item.get("ProductStatuses", []), 128)]
    record["vendor_product_statuses"] = statuses
    for pid in sorted({pid for s in statuses if s["type_code"] == 3 for pid in s["product_ids"]}):
        record["affected"].append({"vendor": "Microsoft", "product_id": pid, "product": "", "version_scope": "vendor_label_only"})
    for metric in objects(item.get("CVSSScoreSets", []), 2048):
        vector = text(metric.get("Vector"), 2000)
        version = re.match(r"CVSS:(2\.0|3\.0|3\.1|4\.0)/", vector)
        record["metrics"].append({"version": version[1] if version else "unversioned", "vector": vector,
                                  "score": number(metric.get("BaseScore")), "type": "Vendor", "source": "Microsoft MSRC",
                                  "product_ids": _ids(metric.get("ProductID"))})
    cwe = item.get("CWE")
    if cwe is not None:
        entries = [cwe] if isinstance(cwe, (dict, str)) else cwe
        if not isinstance(entries, list) or len(entries) > 128:
            raise InvalidFeed("invalid_msrc_cwe")
        candidates = []
        for entry in entries:
            if isinstance(entry, dict):
                candidates.extend((entry.get("ID"), entry.get("Value")))
            elif isinstance(entry, str):
                candidates.append(entry)
            else:
                raise InvalidFeed("invalid_msrc_cwe")
        record["cwes"] = sorted({v if v.startswith("CWE-") else "CWE-" + v for v in candidates
                                 if isinstance(v, str) and re.fullmatch(r"(?:CWE-)?\d+", v)})
    remedies = []
    for remedy in objects(item.get("Remediations", []), 2048):
        kind, description, url = _type(remedy), plain(remedy.get("Description")), public_url(remedy.get("URL"))
        detail = {"type_code": kind, "description": description, "url": url,
                  "product_ids": _ids(remedy.get("ProductID")), "fixed_build": text(remedy.get("FixedBuild"), 200),
                  "subtype": text(remedy.get("SubType"), 200)}
        remedies.append(detail)
        if kind in {0, 1} and description:
            record["mitigations"].append(description)
        if kind == 2:
            record["fixes"].append(detail)
        if url:
            record["references"].append({"url": url, "type": "vendor_remediation", "product_ids": detail["product_ids"]})
    record["fixes"] = _scoped_unique(record["fixes"])
    record["vendor_remediations"] = _scoped_unique([r for r in remedies if r["type_code"] != 2])
    # Fixes live once in fixes; unknown codes remain opaque in other remedies.
    record["references"] = [{"url": url, "type": "vendor_remediation"} for url in sorted({r["url"] for r in record["references"]})]
    record["metrics"] = _scoped_unique(record["metrics"])
    threats, exploited = [], False
    for threat in objects(item.get("Threats", []), 4096):
        code, description = _type(threat), plain(threat.get("Description"))
        threats.append({"type_code": code, "description": description, "product_ids": _ids(threat.get("ProductID"))})
        if code == 1:
            values = {piece.partition(":")[2].strip().casefold() for piece in description.split(";")
                      if piece.partition(":")[0].strip().casefold() == "exploited"}
            exploited |= values == {"yes"}
    record["vendor_threats"] = _scoped_unique(threats)
    record["exploitation_reported"] = exploited if record["record_kind"] == "vulnerability" else False
    record["references"].insert(0, {"url": record["source_url"], "type": "vendor_document", "locator": record["provider_locator"]})
    return record


def normalize_stream(stream, month: str) -> dict:
    """Return a bounded provisional normalized month, only after full validation."""
    document_url(month)
    records, seen, count, encoded_bytes = [], {}, 0, 0
    def consume(item):
        nonlocal count, encoded_bytes
        record = _record(item, month, count)
        count += 1
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False)
        size = len(encoded.encode("utf-8"))
        encoded_bytes += size
        if size > 2 * 1024 * 1024 or encoded_bytes > 32 * 1024 * 1024:
            raise InvalidFeed("msrc_normalized_byte_limit")
        identity = record["id"]
        if identity in seen:
            raise InvalidFeed("duplicate_msrc_identifier")
        seen[identity] = True
        records.append(record)
    decoded = read_cvrf(stream, consume)
    headers = decoded["headers"]
    tracking = headers["DocumentTracking"]
    identity = tracking.get("Identification", {})
    if not isinstance(identity, dict) or plain(identity.get("ID"), 100) != month or plain(identity.get("Alias"), 100) not in {"", month}:
        raise InvalidFeed("msrc_document_identity_mismatch")
    products = {}
    for product in objects(headers["ProductTree"].get("FullProductName", []), 25000):
        pid, label = text(product.get("ProductID"), 200), plain(product.get("Value"), 2000)
        if not pid or not label or pid in products and products[pid] != label:
            raise InvalidFeed("invalid_or_conflicting_msrc_product")
        products[pid] = label
    unresolved, final_bytes = set(), 0
    for record in records:
        record["vendor_document_status_code"] = tracking.get("Status")
        for affected in record["affected"]:
            affected["product"] = products.get(affected["product_id"], "")
            if not affected["product"]:
                unresolved.add(affected["product_id"])
        size = len(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8"))
        final_bytes += size
        if size > 2 * 1024 * 1024 or final_bytes > 32 * 1024 * 1024:
            raise InvalidFeed("msrc_resolved_normalized_byte_limit")
    return {"adapter_version": ADAPTER_VERSION, "month": month, "records": records,
            "document_modified": _date(tracking.get("CurrentReleaseDate")),
            "document_initial_release": _date(tracking.get("InitialReleaseDate")),
            "coverage": {"kind": "single_public_cvrf_document", "complete_envelope": True, "input_bytes": decoded["bytes_read"],
                         "normalized_bytes_before_product_labels": encoded_bytes, "products": len(products),
                         "normalized_bytes": final_bytes,
                         "unresolved_product_ids": len(unresolved), "not_installed_state_or_global_coverage": True}}
