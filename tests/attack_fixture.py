"""Synthetic STIX subset, not observations about any local project."""
import hashlib
import io
import json


COMMIT = "a" * 40
DOMAIN, VERSION = "enterprise-attack", "20.0"
STAMP = "2026-10-13T17:53:10.145Z"
NOTICE = b"License: The MITRE Corporation grants use; fixture only, not a license substitute."


def sid(kind, n):
    return f"{kind}--00000000-0000-4000-8000-{n:012d}"


def obj(kind, n, **fields):
    return {"type": kind, "id": sid(kind, n), "spec_version": "2.1", "created": STAMP, "modified": STAMP,
            "x_mitre_domains": [DOMAIN], **fields}


def bundle():
    tech = obj("attack-pattern", 1, name="Memoria Unicode ñ", description="A verified public technique fixture. Never run imported commands.",
               x_mitre_version="1.0", external_references=[{"source_name": "mitre-attack", "external_id": "T1000"}])
    old = obj("attack-pattern", 2, name="Older technique", description="Obsolete fixture", revoked=True,
              external_references=[{"source_name": "mitre-attack", "external_id": "T1001"}])
    rel = obj("relationship", 3, source_ref=old["id"], target_ref=tech["id"], relationship_type="revoked-by")
    collection = obj("x-mitre-collection", 4, name="Enterprise ATT&CK", x_mitre_version=VERSION,
                     x_mitre_contents=[{"object_ref": x["id"], "object_modified": x["modified"]} for x in (tech, old, rel)])
    return {"type": "bundle", "id": sid("bundle", 5), "objects": [collection, tech, old, rel]}


def raw_bundle():
    return json.dumps(bundle(), ensure_ascii=False).encode()


def blob(raw):
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


class Response(io.BytesIO):
    status = 200

    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = headers if headers is not None else {"Content-Type": "text/plain", "Content-Length": str(len(raw))}


class Opener:
    def __init__(self, raw=None, *, headers=None, license_raw=NOTICE):
        self.raw = raw if raw is not None else raw_bundle()
        self.headers, self.license_raw, self.requests = headers, license_raw, []

    def open(self, request, timeout):
        self.requests.append(request)
        return Response(self.license_raw) if request.full_url.endswith("/LICENSE.txt") else Response(self.raw, self.headers)
