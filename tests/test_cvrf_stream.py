from __future__ import annotations

import io
import json
import unittest

from rabanito.cyber.cvrf_stream import read_cvrf
from rabanito.cyber.model import InvalidFeed


def payload(items=None):
    return {"DocumentTracking": {"Identification": {"ID": {"Value": "2026-Oct"}}},
            "ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Fixture ñ"}]},
            "Vulnerability": items if items is not None else [{"CVE": "CVE-2099-10000", "Title": {"Value": "Fixture 🚀"}}]}


class TinyStream(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 3))

    read1 = read


class CvrfStreamTests(unittest.TestCase):
    def read(self, raw, **kwargs):
        items = []
        result = read_cvrf(TinyStream(raw), items.append, **kwargs)
        return result, items

    def test_multibyte_bom_and_values_split_across_chunks(self):
        document = payload()
        document["DocumentTracking"]["Version"] = 12345
        document["DocumentTracking"]["Flag"] = True
        document["DocumentTracking"]["Other"] = None
        result, items = self.read(b"\xef\xbb\xbf" + json.dumps(document, ensure_ascii=False).encode())
        self.assertEqual(items, document["Vulnerability"])
        self.assertEqual(result["headers"]["DocumentTracking"], document["DocumentTracking"])
        self.assertEqual(result["vulnerability_count"], 1)
        self.assertNotIn("Vulnerability", result["headers"])

    def test_vulnerability_array_can_precede_headers(self):
        data = payload()
        data = {"Vulnerability": data.pop("Vulnerability"), **data}
        result, items = self.read(json.dumps(data).encode())
        self.assertTrue(result["headers"]["ProductTree"])
        self.assertEqual(len(items), 1)

    def test_duplicates_nonfinite_and_invalid_syntax_are_rejected(self):
        good = json.dumps(payload()).encode()
        invalid = [good.replace(b'"CVE":', b'"CVE":"x","CVE":'), good.replace(b'"ProductTree":', b'"Extra":0,"Extra":1,"ProductTree":'),
                   good.replace(b'"ProductTree":', b'"Extra":NaN,"ProductTree":'),
                   good[:-1] + b",}", good + b" false", good[:-4], b"[]", good + b"\xc3"]
        for raw in invalid:
            with self.subTest(raw=raw[:20]), self.assertRaises(InvalidFeed):
                self.read(raw)

    def test_array_trailing_comma_and_non_object_record_fail(self):
        for value in (b'{"DocumentTracking":{},"ProductTree":{},"Vulnerability":[{},]}',
                      b'{"DocumentTracking":{},"ProductTree":{},"Vulnerability":[1]}',
                      b'{"DocumentTracking":{},"ProductTree":{},"Vulnerability":null}'):
            with self.subTest(value=value), self.assertRaises(InvalidFeed):
                self.read(value)

    def test_exact_byte_boundary_and_budget_overflow(self):
        raw = json.dumps(payload()).encode()
        self.assertEqual(self.read(raw, max_bytes=len(raw))[0]["bytes_read"], len(raw))
        with self.assertRaisesRegex(InvalidFeed, "document_byte_limit"):
            self.read(raw, max_bytes=len(raw)-1)
        with self.assertRaisesRegex(InvalidFeed, "value_byte_limit"):
            self.read(raw, max_record_bytes=10)
        with self.assertRaisesRegex(InvalidFeed, "value_byte_limit|header_byte_limit"):
            self.read(raw, max_header_bytes=5)

    def test_missing_or_wrong_headers_and_duplicate_top_field_fail(self):
        for raw in (b'{"DocumentTracking":{},"ProductTree":{}}',
                    b'{"DocumentTracking":[],"ProductTree":{},"Vulnerability":[]}',
                    b'{"DocumentTracking":{},"ProductTree":{},"Vulnerability":[],"Vulnerability":[]}'):
            with self.subTest(raw=raw), self.assertRaises(InvalidFeed):
                self.read(raw)

    def test_count_is_bounded_even_when_callback_discards_all_records(self):
        raw = json.dumps(payload([{}] * 3)).encode()
        with self.assertRaisesRegex(InvalidFeed, "record_count_limit"):
            read_cvrf(io.BytesIO(raw), lambda item: None, max_records=2)

    def test_deadline_and_strict_budget_types(self):
        ticks = iter([0, 121])
        with self.assertRaisesRegex(InvalidFeed, "read_deadline"):
            self.read(json.dumps(payload()).encode(), monotonic=lambda: next(ticks))
        for options in ({"max_bytes": True}, {"max_records": 0}, {"max_seconds": 121}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.read(b"{}", **options)

    def test_callbacks_are_provisional_until_entire_document_is_valid(self):
        items = []
        raw = json.dumps(payload()).encode() + b" INVALID"
        with self.assertRaises(InvalidFeed):
            read_cvrf(io.BytesIO(raw), items.append)
        self.assertEqual(len(items), 1)  # Publication must wait for a successful return.

    def test_large_array_does_not_survive_in_returned_headers(self):
        data = payload([{"CVE": f"CVE-2099-{10000+i}", "Title": {"Value": "x" * 2000}} for i in range(1200)])
        count = [0]
        def consume(item):
            count[0] += 1
        result = read_cvrf(io.BytesIO(json.dumps(data).encode()), consume)
        self.assertEqual(count[0], 1200)
        self.assertLess(len(json.dumps(result["headers"])), 500)

    def test_primitive_number_headers_are_not_truncated_at_exponent_or_chunk_edge(self):
        data = payload()
        data["NumericExtension"] = 1e-7
        result, _ = self.read(json.dumps(data).encode())
        self.assertEqual(result["headers"]["NumericExtension"], 1e-7)

    def test_overflow_float_is_not_an_infinite_json_metric(self):
        raw = json.dumps(payload()).encode().replace(b'"ProductTree":', b'"NumericExtension":1e999,"ProductTree":')
        with self.assertRaisesRegex(InvalidFeed, "nonfinite"):
            self.read(raw)

    def test_whitespace_and_escaped_content_at_each_small_chunk_size(self):
        data = payload([{"CVE": "CVE-2099-10000", "Text": 'quotes " \\ braces } [ , : \n Ñ 🚀'}])
        raw = json.dumps(data, ensure_ascii=False).encode()
        for chunk in range(1, 24):
            class Stream(io.BytesIO):
                def read(self, size=-1):
                    return super().read(min(chunk, size))

                read1 = read
            items = []
            with self.subTest(chunk=chunk):
                result = read_cvrf(Stream(raw), items.append)
                self.assertEqual(items, data["Vulnerability"])
                self.assertEqual(result["headers"]["ProductTree"], data["ProductTree"])

    def test_buffered_transports_use_single_read_before_rechecking_deadline(self):
        class Buffered(io.BytesIO):
            def read(self, size=-1):
                raise AssertionError("blocking multi-read path used")

            def read1(self, size=-1):
                return super().read(min(size, 7))
        result = read_cvrf(Buffered(json.dumps(payload()).encode()), lambda _: None)
        self.assertEqual(result["vulnerability_count"], 1)
