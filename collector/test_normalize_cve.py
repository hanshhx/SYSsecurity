"""실제 공개 기록과 잘못된 입력으로 정보 누락·오판·기존 결과 덮어쓰기를 확인함."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from normalize_cve import CollectorError, normalize_collection

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "CVE-2025-55130.json"
SCHEMA = HERE.parent / "schemas" / "cve-5.2.0" / "CVE_Record_Format_bundled.json"
NOTICE = (HERE / "CVE_LICENSE_NOTICE.txt").read_bytes()


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / "collection"
        self.folder.mkdir()
        self.record = json.loads(FIXTURE.read_bytes())
        self.save(self.record)

    def save(self, record):
        raw = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        meta = record["cveMetadata"]
        self.receipt = {
            "collectionStatus": "COLLECTED", "cveId": meta["cveId"],
            "sourceUrl": "https://cveawg.mitre.org/api/cve/" + meta["cveId"],
            "fetchedAt": "2026-09-17T03:08:01.021836+00:00",
            "dataVersion": record["dataVersion"], "recordState": meta["state"],
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "licenseUrl": "https://www.cve.org/legal/termsofuse",
            "noticeFile": "CVE_LICENSE_NOTICE.txt",
            "validationScope": "basic-envelope-only", "readyForMatching": False,
        }
        (self.folder / "original.json").write_bytes(raw)
        (self.folder / "CVE_LICENSE_NOTICE.txt").write_bytes(NOTICE)
        self.save_receipt()

    def save_receipt(self):
        (self.folder / "receipt.json").write_text(json.dumps(self.receipt), encoding="utf-8")

    def run_normalizer(self):
        path = normalize_collection(self.folder, schema_path=SCHEMA)
        return path, json.loads(path.read_bytes())

    def assert_refused(self, code=None):
        with self.assertRaises(CollectorError) as caught:
            self.run_normalizer()
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(list(self.folder.glob("normalized-*/normalized.json")), [])

    def test_actual_record_keeps_each_provider_and_each_score_separate(self):
        _, result = self.run_normalizer()
        self.assertEqual(result["cveId"], "CVE-2025-55130")
        self.assertEqual(len(result["sources"]), 3)
        self.assertEqual(len(result["products"]), 17)
        self.assertEqual(sum(len(p["data"].get("versions", [])) for p in result["products"]), 22)
        self.assertEqual(len(result["metrics"]), 4)
        self.assertEqual([(s["kind"], s["data"]["baseScore"]) for s in result["scores"]],
                         [("cvssV3_0", 7.1), ("cvssV3_1", 7.1)])
        self.assertFalse(result["readyForMatching"])
        self.assertNotIn("decision", result)

    def test_product_bounds_rpm_strings_and_optional_fields_are_not_invented(self):
        _, result = self.run_normalizer()
        node = result["products"][0]
        self.assertEqual(node["data"]["versions"][0], {
            "version": "20.19.6", "lessThanOrEqual": "20.19.6",
            "status": "affected", "versionType": "semver"})
        self.assertIn("packageName", node["missingFields"])
        self.assertNotIn("packageName", node["data"])
        rpm_versions = [v["version"] for p in result["products"] for v in p["data"].get("versions", [])]
        self.assertIn("1:24.13.0-1.el10_1", rpm_versions)

    def test_all_container_information_can_be_reconstructed_without_loss(self):
        _, result = self.run_normalizer()
        original_containers = [self.record["containers"]["cna"], *self.record["containers"]["adp"]]
        for source, original in zip(result["sources"], original_containers):
            restored = copy.deepcopy(source["information"])
            restored["providerMetadata"] = source["provider"]
            for field, group in (("affected", "products"), ("metrics", "metrics")):
                if field not in source["missingFields"]:
                    restored[field] = [item["data"] for item in result[group]
                                       if item["sourcePath"] == source["path"]]
            self.assertEqual(restored, original)

    def test_repeated_provider_id_does_not_overwrite_a_container(self):
        extra = copy.deepcopy(self.record["containers"]["adp"][0])
        extra["title"] = "Second independently supplied assessment"
        self.record["containers"]["adp"].append(extra)
        self.save(self.record)
        _, result = self.run_normalizer()
        self.assertEqual(len(result["sources"]), 4)
        self.assertEqual(result["sources"][3]["path"], "/containers/adp/2")

    def test_missing_scores_do_not_become_zero_or_safe(self):
        self.record["containers"]["cna"].pop("metrics")
        self.record["containers"].pop("adp")
        self.save(self.record)
        _, result = self.run_normalizer()
        self.assertEqual(result["scores"], [])
        self.assertIn("metrics", result["sources"][0]["missingFields"])
        self.assertFalse(result["readyForMatching"])

    def test_rejected_record_keeps_rejection_reason_without_becoming_a_candidate(self):
        self.record["cveMetadata"]["state"] = "REJECTED"
        self.record["containers"] = {"cna": {
            "providerMetadata": self.record["containers"]["cna"]["providerMetadata"],
            "rejectedReasons": [{"lang": "en", "value": "Test record: duplicate entry."}],
        }}
        self.save(self.record)
        _, result = self.run_normalizer()
        self.assertEqual(result["recordState"], "REJECTED")
        self.assertEqual(result["products"], [])
        self.assertIn("rejectedReasons", result["sources"][0]["information"])
        self.assertFalse(result["readyForMatching"])

    def test_basic_envelope_without_required_cna_information_is_rejected(self):
        self.record["containers"] = {"cna": {}}
        self.save(self.record)
        self.assert_refused("SCHEMA_INVALID")

    def test_invalid_score_null_uri_and_timestamp_shape_are_rejected(self):
        for kind in ("score", "null", "uri", "timestamp_shape"):
            with self.subTest(kind=kind):
                record = copy.deepcopy(self.record)
                cna = record["containers"]["cna"]
                if kind == "score":
                    cna["metrics"][0]["cvssV3_0"]["baseScore"] = 11
                elif kind == "null":
                    cna["affected"][0]["versions"] = None
                elif kind == "uri":
                    cna["references"][0]["url"] = "not an absolute URI"
                else:
                    cna["dateAssigned"] = "not-a-timestamp"
                self.save(record)
                self.assert_refused("SCHEMA_INVALID")

    def test_changes_inside_version_range_are_preserved_without_calculation(self):
        version = self.record["containers"]["cna"]["affected"][0]["versions"][0]
        version["version"] = "20.0.0"
        version["changes"] = [{"at": "20.10.0", "status": "unaffected"}]
        self.save(self.record)
        _, result = self.run_normalizer()
        normalized = result["products"][0]["data"]["versions"][0]
        self.assertEqual(normalized["changes"], [{"at": "20.10.0", "status": "unaffected"}])
        self.assertEqual(normalized["lessThanOrEqual"], "20.19.6")
        self.assertNotIn("matched", normalized)

    def test_future_or_not_yet_supported_format_is_not_silently_accepted(self):
        for version in ("5.0", "5.3", "5.2.0"):
            with self.subTest(version=version):
                record = copy.deepcopy(self.record)
                record["dataVersion"] = version
                self.save(record)
                self.assert_refused("UNSUPPORTED_FORMAT")

    def test_changed_original_is_refused_even_if_still_valid_json(self):
        path = self.folder / "original.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.assert_refused("INTEGRITY_MISMATCH")

    def test_invalid_receipt_fields_are_not_trusted(self):
        for field, value in (("collectionStatus", "FAILED"), ("cveId", "CVE-2025-0001"),
                             ("bytes", True), ("sha256", "x" * 64), ("dataVersion", "5.1"),
                             ("recordState", "REJECTED"), ("fetchedAt", "2026-09-17"),
                             ("sourceUrl", "https://other.example/record"),
                             ("noticeFile", "../notice.txt"), ("readyForMatching", True),
                             ("licenseUrl", "https://other.example/license")):
            with self.subTest(field=field):
                self.save(self.record)
                self.receipt[field] = value
                self.save_receipt()
                self.assert_refused()

    def test_duplicate_receipt_key_is_rejected(self):
        path = self.folder / "receipt.json"
        path.write_text('{"cveId":"x",' + path.read_text()[1:], encoding="utf-8")
        self.assert_refused("INVALID_RECEIPT")

    def test_unpaired_unicode_surrogate_is_a_reported_failure_not_a_traceback(self):
        self.record["containers"]["cna"]["descriptions"][0]["value"] = "bad \ud800 text"
        raw = json.dumps(self.record, ensure_ascii=True).encode("ascii")
        (self.folder / "original.json").write_bytes(raw)
        self.receipt["bytes"] = len(raw)
        self.receipt["sha256"] = hashlib.sha256(raw).hexdigest()
        self.save_receipt()
        self.assert_refused("INVALID_UNICODE")

    def test_missing_or_modified_notice_is_not_redistributed(self):
        (self.folder / "CVE_LICENSE_NOTICE.txt").write_bytes(b"changed notice")
        self.assert_refused("NOTICE_MISMATCH")

    def test_missing_original_or_receipt_is_not_a_success(self):
        for name in ("original.json", "receipt.json"):
            with self.subTest(name=name):
                self.save(self.record)
                (self.folder / name).unlink()
                self.assert_refused("STORAGE_ERROR")

    def test_oversized_original_is_refused_before_parsing(self):
        (self.folder / "original.json").write_bytes(b" " * (2 * 1024 * 1024 + 1))
        self.assert_refused("FILE_TOO_LARGE")

    def test_modified_schema_is_refused_and_does_not_trigger_a_network_fetch(self):
        altered = Path(self.temp.name) / "schema.json"
        altered.write_bytes(b'{"$ref":"https://other.example/schema"}')
        with self.assertRaises(CollectorError) as caught:
            normalize_collection(self.folder, schema_path=altered)
        self.assertEqual(caught.exception.code, "SCHEMA_INTEGRITY")

    def test_repeated_runs_preserve_original_receipt_and_previous_result(self):
        raw = (self.folder / "original.json").read_bytes()
        receipt = (self.folder / "receipt.json").read_bytes()
        first, result = self.run_normalizer()
        first_raw = first.read_bytes()
        second, _ = self.run_normalizer()
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), first_raw)
        self.assertEqual((self.folder / "original.json").read_bytes(), raw)
        self.assertEqual((self.folder / "receipt.json").read_bytes(), receipt)
        self.assertEqual((second.parent / "CVE_LICENSE_NOTICE.txt").read_bytes(), NOTICE)
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(raw).hexdigest())

    def test_failed_final_rename_leaves_no_completed_result(self):
        with patch.object(Path, "replace", side_effect=OSError("test disk failure")):
            self.assert_refused("STORAGE_ERROR")

    def test_symlink_original_is_rejected(self):
        original = self.folder / "original.json"
        other = Path(self.temp.name) / "outside.json"
        original.replace(other)
        try:
            original.symlink_to(other)
        except OSError:
            self.skipTest("이 환경에서는 심볼릭 링크를 만들 권한이 없음")
        self.assert_refused("UNSAFE_INPUT_PATH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
