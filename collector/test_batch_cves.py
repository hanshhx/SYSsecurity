"""네트워크 경계만 시험 자료로 바꾸고 실제 자식 프로세스·수집·정리·파일을 확인함."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
try:
    import batch_cves as batch
except ModuleNotFoundError as exc:
    if exc.name != "batch_cves":
        raise
    batch = None


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(batch, "아직 batch_cves.py 구현이 없어 배치 기능을 사용할 수 없음")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.output = self.base / "reports" / "cve-batches"
        self.ids = self.base / "ids.txt"
        self.ids.write_text("CVE-2025-55130\n", encoding="utf-8")
        # 전달 전 소스 폴더와 설치된 collector/ 양쪽에서 같은 시험을 실행함.
        source = HERE if (HERE / "fetch_cve.py").exists() else HERE.parents[2] / "step2" / "payload" / "collector"
        self.stage = self.base / "project"
        shutil.copytree(source, self.stage / "collector", ignore=shutil.ignore_patterns("__pycache__", "test_*.py"))
        shutil.copytree(source.parent / "schemas", self.stage / "schemas")
        shutil.copy2(HERE / "batch_cves.py", self.stage / "collector" / "batch_cves.py")
        self.raw = (source / "fixtures" / "CVE-2025-55130.json").read_bytes()
        self.notice = (source / "CVE_LICENSE_NOTICE.txt").read_bytes()
        self.record = json.loads(self.raw)
        self.responses = self.base / "responses"
        self.responses.mkdir()
        self.request_log = self.base / "requests.txt"
        self.runner = self.base / "fixture_worker.py"
        # 이 도우미는 시험 폴더에만 존재함. 제품에는 시험 서버나 우회 옵션을 넣지 않음.
        script = '''import io, json, sys, time
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch
sys.path.insert(0, STAGE)
import batch_cves
class Response:
    status = 200
    def __init__(self, raw, slow):
        self.raw, self.slow = raw, slow
        self.headers = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, amount):
        if self.slow:
            time.sleep(10)
            Path(MARKER).write_text("should have been killed")
        return self.raw[:amount]
def transport(url):
    cve_id = url.rsplit("/", 1)[-1]
    with Path(LOG).open("a", encoding="utf-8") as stream: stream.write(cve_id + "\\n")
    value = json.loads((Path(RESPONSES) / (cve_id + ".json")).read_text(encoding="utf-8"))
    if value.get("httpError"): raise HTTPError(url, value["httpError"], "fixture", {}, None)
    return Response(value["raw"].encode("utf-8"), value.get("slow", False))
with patch("fetch_cve.open_response", side_effect=transport):
    raise SystemExit(batch_cves.main())
'''
        variables = {"STAGE": str(self.stage / "collector"), "MARKER": str(self.base / "too-late"),
                     "LOG": str(self.request_log), "RESPONSES": str(self.responses)}
        self.runner.write_text("\n".join(f"{key} = {value!r}" for key, value in variables.items()) + "\n" + script,
                               encoding="utf-8")
        self.put("CVE-2025-55130", raw=self.raw)
        self.addCleanup(patch.stopall)
        patch.object(batch, "HERE", self.stage / "collector").start()
        patch.object(batch, "_worker_command", side_effect=self.command).start()

    def put(self, cve_id, *, record=None, raw=None, http_error=None, slow=False):
        if raw is None:
            record = copy.deepcopy(self.record if record is None else record)
            record["cveMetadata"]["cveId"] = cve_id
            raw = json.dumps(record).encode("utf-8")
        value = {"raw": raw.decode("utf-8"), "slow": slow}
        if http_error:
            value["httpError"] = http_error
        (self.responses / (cve_id + ".json")).write_text(json.dumps(value), encoding="utf-8")

    def command(self, cve_id, record_root):
        return [sys.executable, str(self.runner), "--worker", cve_id, "--record-root", str(record_root)]

    def run_batch(self, text=None, **kwargs):
        if text is not None:
            self.ids.write_text(text, encoding="utf-8")
        final = batch.run_batch(self.ids, self.output, pause_seconds=0, **kwargs)
        return final, json.loads(final.read_bytes())

    def assert_no_completed_batch(self):
        self.assertEqual(list(self.output.glob("batch-*/batch.json")), [])

    def test_real_collection_and_normalization_preserve_original_receipt_and_notices(self):
        final, result = self.run_batch()
        self.assertEqual(result["batchStatus"], "COMPLETED")
        self.assertFalse(result["readyForMatching"])
        self.assertEqual(result["counts"], {"NORMALIZED": 1, "REJECTED": 0, "UNSUPPORTED_FORMAT": 0, "FAILED": 0, "TIMEOUT": 0})
        item = result["items"][0]
        original = final.parent / item["collectionPath"] / "original.json"
        normalized = final.parent / item["normalizedPath"]
        receipt = json.loads(original.with_name("receipt.json").read_bytes())
        self.assertEqual(original.read_bytes(), self.raw)
        self.assertEqual(receipt["sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(original.with_name("CVE_LICENSE_NOTICE.txt").read_bytes(), self.notice)
        self.assertEqual(normalized.with_name("CVE_LICENSE_NOTICE.txt").read_bytes(), self.notice)
        value = json.loads(normalized.read_bytes())
        self.assertEqual(len(value["products"]), 17)
        self.assertFalse(value["readyForMatching"])
        self.assertFalse(item["readyForMatching"])

    def test_parent_rejects_original_or_notice_corruption_after_child_completion(self):
        runner = self.runner.read_text(encoding="utf-8")
        for target in ("original", "collection_notice", "normalized_notice"):
            with self.subTest(target=target):
                tamper = '''code = batch_cves.main()
    root = Path(sys.argv[sys.argv.index("--record-root") + 1])
    item = json.loads((root / "worker-result.json").read_bytes())
    original = root / item["collectionPath"] / "original.json"
    targets = {"original": original, "collection_notice": original.with_name("CVE_LICENSE_NOTICE.txt"),
               "normalized_notice": (root / item["normalizedPath"]).with_name("CVE_LICENSE_NOTICE.txt")}
    targets[TARGET].write_bytes(b"altered after collection")
    raise SystemExit(code)'''.replace("TARGET", repr(target))
                self.runner.write_text(runner.replace("raise SystemExit(batch_cves.main())", tamper), encoding="utf-8")
                _, result = self.run_batch()
                self.assertEqual(result["items"][0]["status"], "FAILED")
                self.assertEqual(result["items"][0].get("errorCode"), "INVALID_CHILD_RESULT")

    def test_parent_checks_raw_identity_even_when_modified_hashes_agree(self):
        runner = self.runner.read_text(encoding="utf-8")
        for field in ("cveId", "state", "dataVersion", "source"):
            with self.subTest(field=field):
                tamper = '''code = batch_cves.main()
    import hashlib
    root = Path(sys.argv[sys.argv.index("--record-root") + 1])
    item = json.loads((root / "worker-result.json").read_bytes())
    original_path = root / item["collectionPath"] / "original.json"
    receipt_path = original_path.with_name("receipt.json")
    normalized_path = root / item["normalizedPath"]
    original = json.loads(original_path.read_bytes())
    receipt = json.loads(receipt_path.read_bytes())
    normalized = json.loads(normalized_path.read_bytes())
    if FIELD == "cveId": original["cveMetadata"]["cveId"] = "CVE-2025-99999"
    elif FIELD == "state": original["cveMetadata"]["state"] = "REJECTED"
    elif FIELD == "dataVersion": original["dataVersion"] = "5.1"
    raw = json.dumps(original).encode("utf-8")
    original_path.write_bytes(raw)
    receipt["sha256"] = normalized["source"]["sha256"] = hashlib.sha256(raw).hexdigest()
    receipt["bytes"] = normalized["source"]["bytes"] = len(raw)
    if FIELD == "source": normalized["source"]["sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt))
    normalized_path.write_text(json.dumps(normalized))
    raise SystemExit(code)'''.replace("FIELD", repr(field))
                self.runner.write_text(runner.replace("raise SystemExit(batch_cves.main())", tamper), encoding="utf-8")
                _, result = self.run_batch()
                self.assertEqual(result["items"][0]["status"], "FAILED")
                self.assertEqual(result["items"][0]["errorCode"], "INVALID_CHILD_RESULT")

    def test_duplicate_lines_keep_first_order_and_record_all_duplicates(self):
        self.put("CVE-2025-55131")
        text = "# chosen records\n\nCVE-2025-55130\n CVE-2025-55131 \nCVE-2025-55130\nCVE-2025-55130\n"
        _, result = self.run_batch(text)
        self.assertEqual([item["cveId"] for item in result["items"]], ["CVE-2025-55130", "CVE-2025-55131"])
        self.assertEqual(self.request_log.read_text().splitlines(), ["CVE-2025-55130", "CVE-2025-55131"])
        self.assertEqual(result["input"]["duplicates"], [
            {"cveId": "CVE-2025-55130", "lineNumber": 5, "firstLineNumber": 3},
            {"cveId": "CVE-2025-55130", "lineNumber": 6, "firstLineNumber": 3}])
        self.assertEqual((result["input"]["inputCount"], result["input"]["uniqueCount"]), (4, 2))
        self.assertEqual(result["input"]["sha256"], hashlib.sha256(self.ids.read_bytes()).hexdigest())

    def test_entire_list_is_validated_before_network_or_output(self):
        for invalid in ("CVE-2025-55130\n../escape\n", "CVE-2025-55130\n\x1b[31m\n", "# no IDs\n", "cve-2025-55130\n", "CVE-2025-55130 # inline\n"):
            with self.subTest(invalid=repr(invalid)):
                self.ids.write_text(invalid, encoding="utf-8")
                with self.assertRaises(batch.BatchError):
                    batch.run_batch(self.ids, self.output, pause_seconds=0)
                self.assertFalse(self.output.exists())
                self.assertFalse(self.request_log.exists())

    def test_invalid_utf8_and_oversized_input_are_refused_without_output(self):
        for raw in (b"\xff", b"#" + b"x" * (256 * 1024)):
            with self.subTest(length=len(raw)):
                self.ids.write_bytes(raw)
                with self.assertRaises(batch.BatchError):
                    batch.run_batch(self.ids, self.output, pause_seconds=0)
                self.assertFalse(self.output.exists())

    def test_unique_id_cap_accepts_1000_and_rejects_1001_before_output(self):
        text = "\n".join(f"CVE-2025-{index:04d}" for index in range(1000, 2000))
        self.ids.write_text(text, encoding="utf-8")
        self.assertEqual(batch.read_id_list(self.ids)["uniqueCount"], 1000)
        self.ids.write_text(text + "\nCVE-2025-2000", encoding="utf-8")
        with self.assertRaises(batch.BatchError) as caught:
            batch.run_batch(self.ids, self.output, pause_seconds=0)
        self.assertEqual(caught.exception.code, "TOO_MANY_IDS")
        self.assertFalse(self.output.exists())

    def test_line_cap_bounds_duplicate_and_comment_work(self):
        self.ids.write_text("#\n" * 10000 + "CVE-2025-55130\n", encoding="utf-8")
        with self.assertRaises(batch.BatchError) as caught:
            batch.run_batch(self.ids, self.output, pause_seconds=0)
        self.assertEqual(caught.exception.code, "TOO_MANY_LINES")
        self.assertFalse(self.output.exists())

    def test_nonfinite_negative_and_overlong_timing_are_rejected_before_output(self):
        for timeout, pause in ((0, 0), (-1, 0), (301, 0), (float("nan"), 0), (45, -1), (45, float("inf"))):
            with self.subTest(timeout=timeout, pause=pause):
                with self.assertRaises(batch.BatchError):
                    batch.run_batch(self.ids, self.output, timeout_seconds=timeout, pause_seconds=pause)
                self.assertFalse(self.output.exists())

    def test_unsupported_50_preserves_raw_and_receipt_but_has_no_normalized_result(self):
        self.record["dataVersion"] = "5.0"
        self.put("CVE-2025-55130", record=self.record)
        final, result = self.run_batch()
        item = result["items"][0]
        self.assertEqual(item["status"], "UNSUPPORTED_FORMAT")
        self.assertEqual(result["batchStatus"], "COMPLETED_WITH_ERRORS")
        folder = final.parent / item["collectionPath"]
        self.assertEqual(json.loads((folder / "original.json").read_bytes())["dataVersion"], "5.0")
        self.assertTrue((folder / "receipt.json").is_file())
        self.assertEqual((folder / "CVE_LICENSE_NOTICE.txt").read_bytes(), self.notice)
        self.assertNotIn("normalizedPath", item)

    def test_mixed_51_and_52_records_use_their_own_rules_in_one_batch(self):
        raw51 = (self.stage / "collector" / "fixtures" / "CVE-2021-32803.json").read_bytes()
        self.put("CVE-2021-32803", raw=raw51)
        final, result = self.run_batch("CVE-2021-32803\nCVE-2025-55130\n")
        self.assertEqual(result["batchStatus"], "COMPLETED")
        self.assertEqual(result["counts"]["NORMALIZED"], 2)
        actual = []
        for item in result["items"]:
            value = json.loads((final.parent / item["normalizedPath"]).read_bytes())
            actual.append((value["dataVersion"], value["validation"]["schemaRelease"]))
            self.assertFalse(value["readyForMatching"])
        self.assertEqual(actual, [("5.1", "5.1.1"), ("5.2", "5.2.0")])
        self.assertEqual((final.parent / result["items"][0]["collectionPath"] / "original.json").read_bytes(), raw51)

    def test_parent_refuses_changed_normalized_version_or_schema_provenance(self):
        runner = self.runner.read_text(encoding="utf-8")
        for field in ("dataVersion", "schemaRelease", "schemaSha256", "schemaUrl"):
            with self.subTest(field=field):
                tamper = '''code = batch_cves.main()
    root = Path(sys.argv[sys.argv.index("--record-root") + 1])
    item = json.loads((root / "worker-result.json").read_bytes())
    path = root / item["normalizedPath"]
    value = json.loads(path.read_bytes())
    if FIELD == "dataVersion": value["dataVersion"] = "5.1"
    else: value["validation"][FIELD] = "wrong-schema"
    path.write_text(json.dumps(value))
    raise SystemExit(code)'''.replace("FIELD", repr(field))
                self.runner.write_text(runner.replace("raise SystemExit(batch_cves.main())", tamper), encoding="utf-8")
                _, result = self.run_batch()
                self.assertEqual(result["items"][0]["errorCode"], "INVALID_CHILD_RESULT")

    def test_rejected_52_is_preserved_as_rejected_without_execution_candidate(self):
        self.record["cveMetadata"]["state"] = "REJECTED"
        self.record["containers"] = {"cna": {
            "providerMetadata": self.record["containers"]["cna"]["providerMetadata"],
            "rejectedReasons": [{"lang": "en", "value": "Synthetic test: duplicate."}]}}
        self.put("CVE-2025-55130", record=self.record)
        final, result = self.run_batch()
        item = result["items"][0]
        self.assertEqual(item["status"], "REJECTED")
        self.assertEqual(result["batchStatus"], "COMPLETED")
        normalized = json.loads((final.parent / item["normalizedPath"]).read_bytes())
        self.assertEqual(normalized["products"], [])
        self.assertFalse(item["readyForMatching"])
        self.assertFalse(normalized["readyForMatching"])

    def test_schema_invalid_does_not_become_normalized(self):
        self.record["containers"] = {"cna": {}}
        self.put("CVE-2025-55130", record=self.record)
        final, result = self.run_batch()
        item = result["items"][0]
        self.assertEqual((item["status"], item["errorCode"]), ("FAILED", "SCHEMA_INVALID"))
        self.assertTrue((final.parent / item["collectionPath"] / "original.json").is_file())
        self.assertNotIn("normalizedPath", item)

    def test_network_and_parse_failures_continue_to_later_ids_without_retry(self):
        self.put("CVE-2025-55130", http_error=429)
        self.put("CVE-2025-55131", raw=b"not json")
        self.put("CVE-2025-55132")
        _, result = self.run_batch("CVE-2025-55130\nCVE-2025-55131\nCVE-2025-55132\n")
        self.assertEqual([item["status"] for item in result["items"]], ["FAILED", "FAILED", "NORMALIZED"])
        self.assertEqual([item.get("errorCode") for item in result["items"]], ["HTTP_STATUS", "INVALID_JSON", None])
        self.assertEqual(self.request_log.read_text().splitlines(), ["CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132"])

    def test_hard_timeout_kills_slow_read_and_continues(self):
        self.put("CVE-2025-55130", slow=True)
        self.put("CVE-2025-55131")
        started = time.monotonic()
        _, result = self.run_batch("CVE-2025-55130\nCVE-2025-55131\n", timeout_seconds=2)
        self.assertLess(time.monotonic() - started, 7)
        self.assertEqual([item["status"] for item in result["items"]], ["TIMEOUT", "NORMALIZED"])
        self.assertFalse((self.base / "too-late").exists())
        self.assertEqual(result["counts"]["TIMEOUT"], 1)

    def test_each_rerun_uses_new_folder_and_keeps_previous_result_bytes(self):
        first, _ = self.run_batch()
        old = {path.relative_to(first.parent): path.read_bytes() for path in first.parent.rglob("*") if path.is_file()}
        second, _ = self.run_batch()
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual(old, {path.relative_to(first.parent): path.read_bytes() for path in first.parent.rglob("*") if path.is_file()})

    def test_configured_spacing_delays_the_next_record_after_previous_completion(self):
        self.put("CVE-2025-55131")
        self.ids.write_text("CVE-2025-55130\nCVE-2025-55131\n", encoding="utf-8")
        intervals = []
        real_run_record = batch._run_record
        def observe(*args):
            started = time.monotonic()
            result = real_run_record(*args)
            intervals.append((started, time.monotonic()))
            return result
        with patch.object(batch, "_run_record", side_effect=observe):
            batch.run_batch(self.ids, self.output, pause_seconds=0.15)
        self.assertEqual(len(intervals), 2)
        self.assertGreaterEqual(intervals[1][0] - intervals[0][1], 0.15)
        self.assertEqual(len(self.request_log.read_text().splitlines()), 2)

    def test_interrupt_keeps_atomic_checkpoint_and_never_finalizes(self):
        self.put("CVE-2025-55131")
        self.ids.write_text("CVE-2025-55130\nCVE-2025-55131\n", encoding="utf-8")
        # 공용 time.sleep을 바꾸면 Ubuntu의 subprocess.wait까지 중단됨.
        # 배치가 쓰는 참조만 바꿔 첫 건 완료 후 요청 사이 대기에서 중단함.
        with patch.object(batch, "time", wraps=time) as batch_time:
            batch_time.sleep.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                batch.run_batch(self.ids, self.output, pause_seconds=1)
            batch_time.sleep.assert_called_once_with(1)
        self.assert_no_completed_batch()
        checkpoint = json.loads(next(self.output.glob("batch-*/checkpoint.json")).read_bytes())
        self.assertEqual(checkpoint["batchStatus"], "INTERRUPTED")
        self.assertEqual(len(checkpoint["items"]), 1)
        self.assertEqual(checkpoint["items"][0]["status"], "NORMALIZED")
        self.assertEqual(self.request_log.read_text().splitlines(), ["CVE-2025-55130"])

    def test_final_report_rename_failure_leaves_no_success_marker(self):
        real_replace = Path.replace
        def replace(path, target):
            if Path(target).name == "batch.json":
                raise OSError("fixture rename failure")
            return real_replace(path, target)
        with patch.object(Path, "replace", replace):
            with self.assertRaises(batch.BatchError) as caught:
                self.run_batch()
        self.assertEqual(caught.exception.code, "STORAGE_ERROR")
        self.assert_no_completed_batch()
        checkpoint = json.loads(next(self.output.glob("batch-*/checkpoint.json")).read_bytes())
        self.assertEqual(checkpoint["batchStatus"], "IN_PROGRESS")
        self.assertEqual(len(checkpoint["items"]), 1)

    def test_interrupt_during_child_stops_the_real_process_and_keeps_active_id(self):
        real_popen = subprocess.Popen
        children = []
        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            real_wait = child.wait
            interrupted = False
            def wait(*args, **kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt
                return real_wait(*args, **kwargs)
            child.wait = wait
            return child
        with patch.object(batch.subprocess, "Popen", side_effect=launch):
            with self.assertRaises(KeyboardInterrupt):
                self.run_batch()
        self.assertTrue(children)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assert_no_completed_batch()
        checkpoint = json.loads(next(self.output.glob("batch-*/checkpoint.json")).read_bytes())
        self.assertEqual(checkpoint["batchStatus"], "INTERRUPTED")
        self.assertEqual(checkpoint["activeCveId"], "CVE-2025-55130")
        self.assertEqual(checkpoint["items"], [])

    def test_interrupt_at_final_publish_does_not_leave_conflicting_completion_marker(self):
        real_replace = Path.replace
        def replace(path, target):
            answer = real_replace(path, target)
            if Path(target).name == "batch.json":
                raise KeyboardInterrupt
            return answer
        with patch.object(Path, "replace", replace):
            with self.assertRaises(KeyboardInterrupt):
                self.run_batch()
        self.assert_no_completed_batch()
        checkpoint = json.loads(next(self.output.glob("batch-*/checkpoint.json")).read_bytes())
        self.assertEqual(checkpoint["batchStatus"], "INTERRUPTED")
        self.assertNotIn("completedAt", checkpoint)

    def test_missing_normalizer_dependency_is_failure_without_network_request(self):
        (self.stage / "collector" / "normalize_cve.py").unlink()
        _, result = self.run_batch()
        self.assertEqual(result["items"][0]["status"], "FAILED")
        self.assertEqual(result["items"][0]["errorCode"], "MISSING_DEPENDENCY")
        self.assertFalse(self.request_log.exists())

    def test_report_write_failure_is_not_a_success(self):
        with patch.object(batch.os, "fsync", side_effect=OSError("fixture full disk")):
            with self.assertRaises(batch.BatchError) as caught:
                self.run_batch()
        self.assertEqual(caught.exception.code, "STORAGE_ERROR")
        self.assert_no_completed_batch()
        self.assertFalse(self.request_log.exists())

    def test_checkpoint_replace_failure_preserves_previous_valid_json(self):
        real_replace = Path.replace
        calls = 0
        def replace(path, target):
            nonlocal calls
            if Path(target).name == "checkpoint.json":
                calls += 1
                if calls == 2:
                    raise OSError("fixture checkpoint failure")
            return real_replace(path, target)
        with patch.object(Path, "replace", replace):
            with self.assertRaises(batch.BatchError):
                self.run_batch()
        self.assert_no_completed_batch()
        checkpoint = json.loads(next(self.output.glob("batch-*/checkpoint.json")).read_bytes())
        self.assertEqual(checkpoint["items"], [])

    def test_symlink_input_and_output_are_refused(self):
        linked = self.base / "linked.txt"
        target = self.base / "outside"
        target.mkdir()
        link_root = self.base / "linked-output"
        try:
            linked.symlink_to(self.ids)
            link_root.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("이 환경에서는 심볼릭 링크를 만들 권한이 없음")
        for source, output in ((linked, self.output), (self.ids, link_root)):
            with self.subTest(path=str(output)):
                with self.assertRaises(batch.BatchError):
                    batch.run_batch(source, output, pause_seconds=0)
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse(self.request_log.exists())

    def fake_worker(self, body):
        fake = self.base / "broken_worker.py"
        fake.write_text("import json, sys\nfrom pathlib import Path\nroot = Path(sys.argv[-1])\n" + body, encoding="utf-8")
        return patch.object(batch, "_worker_command", side_effect=lambda cve_id, root: [sys.executable, str(fake), str(root)])

    def test_nonzero_child_exit_is_not_success_even_with_result_file(self):
        body = '(root / "worker-result.json").write_text(json.dumps({"cveId":"CVE-2025-55130","status":"NORMALIZED","readyForMatching":False}))\nraise SystemExit(7)\n'
        with self.fake_worker(body):
            _, result = self.run_batch()
        self.assertEqual(result["items"][0]["status"], "FAILED")
        self.assertEqual(result["items"][0]["errorCode"], "CHILD_PROCESS_ERROR")

    def test_missing_or_invalid_child_result_cannot_become_success(self):
        bodies = ["pass\n", '(root / "worker-result.json").write_text("not JSON")\n',
            '(root / "worker-result.json").write_text(json.dumps({"cveId":"CVE-2025-55130","status":"NORMALIZED","readyForMatching":False,"collectionPath":".","normalizedPath":"missing.json"}))\n',
            '(root / "worker-result.json").write_text(json.dumps({"cveId":"CVE-2025-55130","status":"FAILED","readyForMatching":True,"collectionPath":".","errorCode":"BAD"}))\n',
            '(root / "worker-result.json").write_text(json.dumps({"cveId":"CVE-2025-55130","status":"FAILED","readyForMatching":False,"collectionPath":"../outside","errorCode":"BAD"}))\n']
        for body in bodies:
            with self.subTest(body=body):
                with self.fake_worker(body):
                    _, result = self.run_batch()
                self.assertEqual(result["items"][0]["status"], "FAILED")
                self.assertEqual(result["items"][0]["errorCode"], "INVALID_CHILD_RESULT")

    def test_process_spawn_error_is_a_failed_record(self):
        with patch.object(batch.subprocess, "Popen", side_effect=OSError("cannot start Python")):
            _, result = self.run_batch()
        self.assertEqual(result["items"][0]["status"], "FAILED")
        self.assertEqual(result["items"][0]["errorCode"], "PROCESS_START_ERROR")

    def test_cli_invalid_input_has_nonzero_exit_and_no_output(self):
        self.ids.write_text("CVE-2025-55130\ninvalid\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(self.stage / "collector" / "batch_cves.py"),
            "--list", str(self.ids), "--output-root", str(self.output), "--pause", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertNotIn(b"Traceback", result.stderr)

    def test_cli_exit_status_distinguishes_completed_errors(self):
        self.put("CVE-2025-55130", http_error=404)
        with patch.object(sys, "argv", ["batch_cves.py", "--list", str(self.ids), "--output-root", str(self.output), "--pause", "0"]):
            with patch("builtins.print"):
                self.assertEqual(batch.main(), 1)
        self.put("CVE-2025-55130")
        with patch.object(sys, "argv", ["batch_cves.py", "--list", str(self.ids), "--output-root", str(self.output), "--pause", "0"]):
            with patch("builtins.print"):
                self.assertEqual(batch.main(), 0)

    def test_cli_report_read_failure_returns_nonzero_without_unhandled_exception(self):
        real_open = Path.open
        def open_file(path, *args, **kwargs):
            if path.name == "batch.json":
                raise PermissionError("fixture unreadable report")
            return real_open(path, *args, **kwargs)
        with patch.object(Path, "open", open_file), patch("builtins.print"):
            self.assertEqual(batch.main(["--list", str(self.ids), "--output-root", str(self.output), "--pause", "0"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
