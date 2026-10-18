from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from rabanito.cyber.model import InvalidFeed
from rabanito.cyber.msrc import document_url, normalize_stream


def cvrf():
    return {"DocumentTracking": {"Identification": {"ID": {"Value": "2026-Oct"}}, "Status": 2,
                                "InitialReleaseDate": "2026-10-13T07:00:00", "CurrentReleaseDate": "2026-10-16T07:00:00"},
            "ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Microsoft Fixture OS 24H2"}]},
            "Vulnerability": [{"CVE": "CVE-2099-10000", "Title": {"Value": "Fixture vulnerability"},
                "Notes": [{"Type": 2, "Title": "Description", "Value": "<p>Fixture &amp; evidence</p><script>bad()</script>"}],
                "ReleaseDate": "0001-01-01T00:00:00", "ReleaseDateSpecified": False,
                "RevisionHistory": [{"Date": "2026-10-15T07:00:00"}],
                "ProductStatuses": [{"Type": 3, "ProductID": ["1"]}, {"Type": 4, "ProductID": ["2"]}],
                "CVSSScoreSets": [{"Vector": "CVSS:3.1/AV:N/AC:L", "BaseScore": 7.5, "ProductID": ["1"]}],
                "CWE": {"ID": "79", "Value": "Cross-site scripting"},
                "Remediations": [{"Type": 2, "Description": {"Value": "KB000000"}, "URL": "https://support.microsoft.com/help/000000", "ProductID": ["1"], "FixedBuild": "1.2.3"}],
                "Threats": [{"Type": 1, "Description": {"Value": "Exploited:No;Latest Software Release:Exploitation More Likely;"}, "ProductID": ["1"]}]}]}


class MsrcNormalizationTests(unittest.TestCase):
    def normalize(self, data=None):
        return normalize_stream(io.BytesIO(json.dumps(data or cvrf()).encode()), "2026-Oct")

    def test_cited_products_metrics_and_fixes_without_inventing_dates_or_versions(self):
        with patch("socket.socket", side_effect=AssertionError("network prohibited")):
            result = self.normalize()
        record = result["records"][0]
        self.assertEqual(record["aliases"], ["CVE-2099-10000"])
        self.assertEqual(record["description"], "Fixture & evidence")
        self.assertIsNone(record["published"])
        self.assertEqual(record["modified"], "2026-10-15T07:00:00")
        self.assertEqual(record["affected"][0]["product"], "Microsoft Fixture OS 24H2")
        self.assertEqual(len(record["affected"]), 1)
        self.assertNotIn("version", record["affected"][0])
        self.assertEqual(record["metrics"][0]["version"], "3.1")
        self.assertEqual(record["fixes"][0]["fixed_build"], "1.2.3")
        self.assertEqual(record["cwes"], ["CWE-79"])
        self.assertFalse(record["exploitation_reported"])
        self.assertIsNone(record["kev"])
        self.assertEqual(record["provider_locator"], "/Vulnerability/0")

    def test_vendor_advisory_is_not_fabricated_as_a_cve_or_published_vulnerability(self):
        data = cvrf(); data["Vulnerability"][0]["CVE"] = "ADV260001"
        record = self.normalize(data)["records"][0]
        self.assertEqual(record["record_kind"], "security_advisory")
        self.assertEqual(record["record_status"], "advisory")
        self.assertEqual(record["aliases"], [])
        self.assertTrue(record["id"].endswith("ADV260001"))

    def test_positive_exploitation_is_explicit_and_prediction_is_not_exploitation(self):
        for description, expected in (("Exploited:Yes;", True), ("Exploited:No;Exploitation More Likely", False),
                                      ("Exploited:Yes;Exploited:No;", False), ("Not Exploited:Yes", False)):
            data = cvrf(); data["Vulnerability"][0]["Threats"][0]["Description"]["Value"] = description
            with self.subTest(description=description):
                self.assertEqual(self.normalize(data)["records"][0]["exploitation_reported"], expected)

    def test_duplicate_identifiers_and_wrong_document_identity_fail(self):
        data = cvrf(); data["Vulnerability"] *= 2
        with self.assertRaisesRegex(InvalidFeed, "duplicate_msrc"):
            self.normalize(data)
        data = cvrf(); data["DocumentTracking"]["Identification"]["ID"]["Value"] = "2026-Sep"
        with self.assertRaisesRegex(InvalidFeed, "identity_mismatch"):
            self.normalize(data)

    def test_unknown_codes_products_and_unversioned_metrics_are_not_guessed(self):
        data = cvrf(); item = data["Vulnerability"][0]
        item["ProductStatuses"][0]["ProductID"] = ["missing"]
        item["Remediations"][0]["Type"] = 88
        item["CVSSScoreSets"][0]["Vector"] = "vendor-specific"
        result = self.normalize(data); record = result["records"][0]
        self.assertEqual(result["coverage"]["unresolved_product_ids"], 1)
        self.assertEqual(record["affected"][0]["product"], "")
        self.assertEqual(record["fixes"], [])
        self.assertEqual(record["vendor_remediations"][0]["type_code"], 88)
        self.assertEqual(record["metrics"][0]["version"], "unversioned")

    def test_unsafe_reference_is_not_returned_or_fetched(self):
        data = cvrf(); data["Vulnerability"][0]["Remediations"][0]["URL"] = "javascript:bad()"
        record = self.normalize(data)["records"][0]
        self.assertIsNone(record["fixes"][0]["url"])
        self.assertEqual(len(record["references"]), 1)

    def test_product_identity_conflicts_and_bad_identifier_fail(self):
        data = cvrf(); data["ProductTree"]["FullProductName"].append({"ProductID": "1", "Value": "Conflicting fixture"})
        with self.assertRaisesRegex(InvalidFeed, "conflicting_msrc_product"):
            self.normalize(data)
        for native in ("made up", "CVE-2099-bad", "ADVinvented"):
            data = cvrf(); data["Vulnerability"][0]["CVE"] = native
            with self.subTest(native=native), self.assertRaises(InvalidFeed):
                self.normalize(data)

    def test_bad_month_and_incomplete_document_never_produce_records(self):
        for month in ("../../private", "2026-Foo", "2026-Oct?secret=x", "2026-Oct/", None):
            with self.subTest(month=month), self.assertRaises(InvalidFeed):
                document_url(month)
        raw = json.dumps(cvrf()).encode()[:-3]
        with self.assertRaises(InvalidFeed):
            normalize_stream(io.BytesIO(raw), "2026-Oct")

    def test_multiple_cwe_shapes_preserve_only_explicit_numeric_identifiers(self):
        data = cvrf()
        data["Vulnerability"][0]["CWE"] = [{"ID": "CWE-79", "Value": "Description"}, {"ID": "89"}, "CWE-22"]
        self.assertEqual(self.normalize(data)["records"][0]["cwes"], ["CWE-22", "CWE-79", "CWE-89"])

    def test_repeated_vendor_statements_union_product_scopes_without_losing_evidence(self):
        data = cvrf(); item = data["Vulnerability"][0]
        item["CVSSScoreSets"].append({**item["CVSSScoreSets"][0], "ProductID": ["2"]})
        item["Remediations"].append({**item["Remediations"][0], "ProductID": ["2"]})
        record = self.normalize(data)["records"][0]
        self.assertEqual(len(record["metrics"]), 1)
        self.assertEqual(record["metrics"][0]["product_ids"], ["1", "2"])
        self.assertEqual(len(record["fixes"]), 1)
        self.assertEqual(record["fixes"][0]["product_ids"], ["1", "2"])
        self.assertEqual(record["vendor_remediations"], [])
