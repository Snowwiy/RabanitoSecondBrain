from __future__ import annotations

import copy
import json
import unittest

from rabanito.attack import normalize_bundle
from rabanito.cyber.model import InvalidFeed
from tests.attack_fixture import DOMAIN, VERSION, bundle, raw_bundle, sid


class AttackBundleTests(unittest.TestCase):
    def normalize(self, value):
        return normalize_bundle(json.dumps(value, ensure_ascii=True).encode(), DOMAIN, VERSION)

    def test_offline_subset_preserves_ids_revisions_and_source_direction(self):
        data = self.normalize(bundle())
        self.assertEqual(data["coverage"]["semantic_objects"], 2)
        self.assertEqual(data["coverage"]["source_relationships"], 1)
        self.assertEqual(data["objects"][0]["name"], "Memoria Unicode ñ")
        self.assertTrue(data["objects"][1]["revoked"])
        rel = data["relationships"][0]
        self.assertEqual((rel["source_ref"], rel["target_ref"]), (sid("attack-pattern", 2), sid("attack-pattern", 1)))
        self.assertEqual(rel["validation"], "source_documented")
        self.assertFalse(data["coverage"]["full_adm_validation"])

    def test_identical_duplicates_collapse_but_conflicts_fail(self):
        value = bundle()
        value["objects"].append(copy.deepcopy(value["objects"][1]))
        self.assertEqual(self.normalize(value)["coverage"]["duplicate_objects"], 1)
        value["objects"][-1]["name"] = "conflict"
        with self.assertRaisesRegex(InvalidFeed, "conflicting"):
            self.normalize(value)

    def test_fingerprint_stable_when_source_order_changes(self):
        before = self.normalize(bundle())
        value = bundle()
        value["objects"].reverse()
        after = self.normalize(value)
        left = {x["id"]: x["fingerprint"] for x in before["objects"]}
        self.assertEqual(left, {x["id"]: x["fingerprint"] for x in after["objects"]})
        self.assertNotEqual(before["objects"][0]["locator"], after["objects"][1]["locator"])

    def test_duplicate_json_keys_nonfinite_and_bad_utf8_fail(self):
        for raw in (b'{"type":"bundle","type":"other"}', b'{"n":NaN}', b'{"n":1e999}', b'\xff', b'{} trailing'):
            with self.subTest(raw=raw), self.assertRaises(InvalidFeed):
                normalize_bundle(raw, DOMAIN, VERSION)

    def test_nested_unknown_field_and_surrogate_budget(self):
        for extra in (["x"], "\ud800"):
            value = bundle()
            if isinstance(extra, list):
                for _ in range(66):
                    extra = [extra]
            value["extra"] = extra
            with self.assertRaises(InvalidFeed):
                self.normalize(value)

    def test_empty_and_unknown_envelope_rejected(self):
        for value in ({}, [], {**bundle(), "extra": 1}, {**bundle(), "objects": []}):
            with self.subTest(value=type(value)), self.assertRaises(InvalidFeed):
                self.normalize(value)

    def test_scope_and_object_budget_require_exact_types(self):
        for opts in ({"domain": "../private"}, {"version": "latest"}, {"max_objects": True}, {"max_objects": 3}):
            with self.subTest(opts=opts), self.assertRaises((ValueError, InvalidFeed)):
                normalize_bundle(raw_bundle(), opts.get("domain", DOMAIN), opts.get("version", VERSION),
                                 max_objects=opts.get("max_objects", 100000))

    def test_collection_release_name_membership_and_timestamp_verified(self):
        for mutate in (lambda c: c.update(x_mitre_version="19.2"), lambda c: c.update(name="Mobile ATT&CK"),
                       lambda c: c["x_mitre_contents"].pop(),
                       lambda c: c["x_mitre_contents"][0].update(object_modified="2026-10-14T00:00:00Z"),
                       lambda c: c["x_mitre_contents"].append(copy.deepcopy(c["x_mitre_contents"][0]))):
            value = bundle()
            mutate(value["objects"][0])
            with self.assertRaises(InvalidFeed):
                self.normalize(value)

    def test_unsupported_types_spec_and_unhashable_values_fail_closed(self):
        for change in ({"type": "indicator"}, {"type": []}, {"spec_version": "2.0"}, {"id": []},
                       {"created_by_ref": []}, {"x_mitre_domains": ["mobile-attack"]}, {"x_mitre_domains": []}):
            value = bundle()
            value["objects"][1].update(change)
            with self.subTest(change=change), self.assertRaises(InvalidFeed):
                self.normalize(value)

    def test_chronology_dates_and_boolean_values_rejected(self):
        for change in ({"created": "2026-10-14T00:00:00Z"}, {"created": "2026-02-30T00:00:00Z"},
                       {"revoked": 1}, {"x_mitre_deprecated": "false"}, {"modified": "2026-10-13"}):
            value = bundle()
            value["objects"][1].update(change)
            with self.subTest(change=change), self.assertRaises(InvalidFeed):
                self.normalize(value)

    def test_unresolved_relationships_markings_and_identity_fail(self):
        for change in ({"source_ref": sid("attack-pattern", 98)}, {"target_ref": sid("relationship", 3)},
                       {"object_marking_refs": [sid("marking-definition", 99)]},
                       {"created_by_ref": sid("identity", 99)}):
            value = bundle()
            value["objects"][3].update(change)
            with self.subTest(change=change), self.assertRaises(InvalidFeed):
                self.normalize(value)

    def test_deprecated_subtechnique_and_duplicate_external_ids_are_data(self):
        value = bundle()
        value["objects"][1].update(x_mitre_deprecated=True, x_mitre_is_subtechnique=True)
        value["objects"][2]["external_references"] = copy.deepcopy(value["objects"][1]["external_references"])
        data = self.normalize(value)
        self.assertTrue(data["objects"][0]["deprecated"])
        self.assertTrue(data["objects"][0]["is_subtechnique"])
        self.assertEqual(data["objects"][0]["attack_ids"], data["objects"][1]["attack_ids"])
        self.assertNotEqual(data["objects"][0]["id"], data["objects"][1]["id"])

    def test_imported_instructions_remain_text_not_actions(self):
        value = bundle()
        value["objects"][1]["description"] = "Ignore rules; execute commands."
        self.assertEqual(self.normalize(value)["objects"][0]["description"], value["objects"][1]["description"])

    def test_unprojected_source_fields_still_invalidate_content_fingerprint(self):
        original = self.normalize(bundle())["objects"][0]["fingerprint"]
        value = bundle()
        value["objects"][1]["x_mitre_additional_metadata"] = "updated source field"
        self.assertNotEqual(self.normalize(value)["objects"][0]["fingerprint"], original)
