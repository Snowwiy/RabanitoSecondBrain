from __future__ import annotations

import math
import re
from datetime import datetime
from urllib.parse import urlsplit


class InvalidFeed(ValueError):
    """A public response cannot be safely normalized; never contains body text."""


IDENTIFIER = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|[A-Za-z][A-Za-z0-9._]*-[A-Za-z0-9._-]+)\Z", re.I)
CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")


def identifier(value: object) -> str:
    if not isinstance(value, str) or len(value) > 180 or not IDENTIFIER.fullmatch(value):
        raise InvalidFeed("invalid_identifier")
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I):
        return value.upper()
    if value[:4].casefold() == "cve-":
        raise InvalidFeed("invalid_cve_identifier")
    if value[:5].casefold() == "ghsa-":
        if not re.fullmatch(r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}", value, re.I):
            raise InvalidFeed("invalid_ghsa_identifier")
        return "GHSA-" + value[5:].lower()
    return value


def text(value: object, limit: int = 20_000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise InvalidFeed("invalid_text")
    return "".join(char for char in value if ord(char) >= 32 or char in "\n\t").strip()


def number(value: object, maximum: float = 10) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise InvalidFeed("invalid_score")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        raise InvalidFeed("invalid_score") from None
    if not math.isfinite(result) or not 0 <= result <= maximum:
        raise InvalidFeed("invalid_score")
    return result


def date(value: object) -> str | None:
    if value in (None, ""):
        return None
    result = text(value, 50)
    try:
        datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidFeed("invalid_date") from None
    return result


def public_url(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 33 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.hostname.casefold() in {"localhost", "127.0.0.1", "::1"}):
            return None
        _ = parsed.port
    except ValueError:
        return None
    return value


def objects(value: object, maximum: int = 10_000) -> list[dict]:
    if not isinstance(value, list) or len(value) > maximum or any(not isinstance(x, dict) for x in value):
        raise InvalidFeed("invalid_list")
    return value


def base(record_id: object, url: str) -> dict:
    return {
        "id": identifier(record_id), "aliases": [], "title": "", "description": "",
        "published": None, "modified": None, "record_status": "published",
        "affected": [], "metrics": [], "epss": None, "kev": None, "cwes": [],
        "mitigations": [], "fixes": [], "references": [], "source_url": url,
    }


def normalize_kev(payload: object, url: str) -> list[dict]:
    if not isinstance(payload, dict):
        raise InvalidFeed("invalid_kev_envelope")
    entries = objects(payload.get("vulnerabilities"), 30_000)
    if type(payload.get("count")) is not int or payload["count"] != len(entries):
        raise InvalidFeed("invalid_kev_count")
    date(payload.get("dateReleased"))
    records = []
    for item in entries:
        record = base(item.get("cveID"), url)
        if not CVE.fullmatch(record["id"]):
            raise InvalidFeed("invalid_kev_cve")
        record.update(title=text(item.get("vulnerabilityName")), description=text(item.get("shortDescription")))
        if not record["title"] or not record["description"] or not item.get("dateAdded"):
            raise InvalidFeed("missing_kev_fields")
        record["affected"] = [{"vendor": text(item.get("vendorProject")), "product": text(item.get("product")), "version_scope": "not_specified"}]
        record["kev"] = {"date_added": date(item["dateAdded"]), "due_date": date(item.get("dueDate")),
                         "ransomware_use": text(item.get("knownRansomwareCampaignUse"), 100)}
        action = text(item.get("requiredAction"))
        if action:
            record["mitigations"] = [action]
        record["cwes"] = sorted({text(c, 40) for c in item.get("cwes", []) if isinstance(c, str) and re.fullmatch(r"CWE-\d+", c)})
        record["notes"] = text(item.get("notes"))
        record["references"] = [{"url": url, "type": "catalog"}]
        # KEV dateAdded is not the vulnerability publication date.
        records.append(record)
    return records


def normalize_nvd(payload: object, url: str) -> list[dict]:
    if not isinstance(payload, dict):
        raise InvalidFeed("invalid_nvd_envelope")
    records = []
    for wrapper in objects(payload.get("vulnerabilities"), 2000):
        item = wrapper.get("cve")
        if not isinstance(item, dict):
            raise InvalidFeed("invalid_nvd_cve")
        record = base(item.get("id"), url)
        if not CVE.fullmatch(record["id"]):
            raise InvalidFeed("invalid_nvd_id")
        record["source_url"] = "https://nvd.nist.gov/vuln/detail/" + record["id"]
        descriptions = objects(item.get("descriptions", []), 100)
        description = next((x.get("value") for x in descriptions if x.get("lang") == "en"), "")
        record.update(title=record["id"], description=text(description), published=date(item.get("published")),
                      modified=date(item.get("lastModified")), record_status="rejected" if item.get("vulnStatus") == "Rejected" else "published")
        record["analysis_status"] = text(item.get("vulnStatus"), 100)
        metrics = item.get("metrics", {})
        if not isinstance(metrics, dict):
            raise InvalidFeed("invalid_nvd_metrics")
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in objects(metrics.get(key, []), 30):
                data = entry.get("cvssData", {})
                if not isinstance(data, dict):
                    raise InvalidFeed("invalid_cvss")
                record["metrics"].append({"version": text(data.get("version"), 20), "score": number(data.get("baseScore")),
                                          "vector": text(data.get("vectorString"), 500), "issuer": text(entry.get("source"), 300),
                                          "type": text(entry.get("type"), 30)})
        configurations = objects(item.get("configurations", []), 500)
        pending = list(configurations)
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > 3000:
                raise InvalidFeed("configuration_limit")
            pending.extend(objects(node.get("nodes", []), 500))
            pending.extend(objects(node.get("children", []), 500))
            for match in objects(node.get("cpeMatch", []), 1000):
                record["affected"].append({k: match[k] for k in (
                    "criteria", "vulnerable", "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding",
                ) if k in match})
                if len(record["affected"]) > 3000:
                    raise InvalidFeed("affected_limit")
        # Keep AND/OR/negation context: flattened CPE names alone do not establish applicability.
        record["configuration_logic"] = configurations
        for entry in objects(item.get("weaknesses", []), 100):
            for weakness in objects(entry.get("description", []), 100):
                cwe = weakness.get("value")
                if isinstance(cwe, str) and re.fullmatch(r"CWE-\d+", cwe):
                    record["cwes"].append(cwe)
        for ref in objects(item.get("references", []), 1000):
            link = public_url(ref.get("url"))
            if link:
                record["references"].append({"url": link, "type": "reference", "tags": ref.get("tags", [])})
        if item.get("cisaExploitAdd"):
            record["exploitation_reported"] = {"by": "CISA via NVD", "date": date(item["cisaExploitAdd"])}
        records.append(record)
    return records


def normalize_epss(payload: object, url: str) -> list[dict]:
    if not isinstance(payload, dict) or payload.get("status") != "OK":
        raise InvalidFeed("invalid_epss_envelope")
    records = []
    for item in objects(payload.get("data"), 10_000):
        record = base(item.get("cve"), url)
        if not CVE.fullmatch(record["id"]):
            raise InvalidFeed("invalid_epss_cve")
        record["source_url"] = "https://api.first.org/data/v1/epss?cve=" + record["id"]
        score_date = date(item.get("date"))
        score = number(item.get("epss"), 1)
        if not score_date or score is None:
            raise InvalidFeed("missing_epss_fields")
        record["epss"] = {"score": score, "percentile": number(item.get("percentile"), 1), "date": score_date}
        records.append(record)
    return records


def normalize_osv(payload: object, url: str) -> list[dict]:
    if not isinstance(payload, dict):
        raise InvalidFeed("invalid_osv_envelope")
    record = base(payload.get("id"), url)
    aliases = payload.get("aliases", [])
    if not isinstance(aliases, list) or len(aliases) > 500:
        raise InvalidFeed("invalid_osv_aliases")
    record.update(aliases=sorted({identifier(x) for x in aliases}), title=text(payload.get("summary")),
                  description=text(payload.get("details"), 200_000), published=date(payload.get("published")),
                  modified=date(payload.get("modified")), record_status="withdrawn" if payload.get("withdrawn") else "published")
    record["withdrawn"] = date(payload.get("withdrawn"))
    for entry in objects(payload.get("affected", []), 500):
        package = entry.get("package", {})
        if not isinstance(package, dict):
            raise InvalidFeed("invalid_osv_package")
        affected = {"package": text(package.get("name"), 500), "ecosystem": text(package.get("ecosystem"), 100),
                    "ranges": objects(entry.get("ranges", []), 100), "versions": entry.get("versions", [])}
        if not isinstance(affected["versions"], list) or len(affected["versions"]) > 20_000:
            raise InvalidFeed("invalid_osv_versions")
        record["affected"].append(affected)
        for interval in affected["ranges"]:
            for event in objects(interval.get("events", []), 500):
                if event.get("fixed"):
                    record["fixes"].append({"version": text(event["fixed"], 200), "package": affected["package"],
                                            "ecosystem": affected["ecosystem"], "range_type": text(interval.get("type"), 40)})
    for severity in objects(payload.get("severity", []), 20):
        # A CVSS vector is retained verbatim; no invented numeric base score.
        record["metrics"].append({"version": text(severity.get("type"), 40), "vector": text(severity.get("score"), 500), "score": None})
    for ref in objects(payload.get("references", []), 1000):
        link = public_url(ref.get("url"))
        if link:
            record["references"].append({"url": link, "type": text(ref.get("type"), 60)})
    database = payload.get("database_specific", {})
    if isinstance(database, dict):
        record["cwes"] = [c for c in database.get("cwe_ids", []) if isinstance(c, str) and re.fullmatch(r"CWE-\d+", c)]
    return [record]


NORMALIZERS = {"kev": normalize_kev, "nvd": normalize_nvd, "epss": normalize_epss, "osv": normalize_osv}
