"""첫 수집기의 오류 분기와 저장 결과를 시험함. 인터넷 요청은 테스트 응답으로 대체함."""
import hashlib
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

try:
    import fetch_cve as subject
except ModuleNotFoundError as exc:
    if exc.name != "fetch_cve":
        raise
    subject = None

CVE = "CVE-2025-55130"
URL = "https://cveawg.mitre.org/api/cve/CVE-2025-55130"


def record(**changes):
    # 공식 CVE 기본 구조를 따른 자작 시험 데이터임. 실제 문제 설명·점수를 꾸며 넣지 않음.
    value = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
             "cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
             "containers": {"cna": {}}}
    value.update(changes)
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


class Response(io.BytesIO):
    """외부 HTTP 응답 경계만 대신함. 파싱·검사·파일 저장은 실제 코드로 수행함."""
    def __init__(self, data, status=200, content_type="application/json", length=None):
        super().__init__(data)
        self.status = status
        self.headers = {"Content-Type": content_type,
                        "Content-Length": str(len(data) if length is None else length)}


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(subject, "FETCHER_NOT_IMPLEMENTED: 수집기를 아직 작성하지 않았음")
        self.temp = tempfile.TemporaryDirectory(prefix="syssecurity-fetch-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "results"

    def collect(self, data=None):
        data = record() if data is None else data
        with patch.object(subject, "open_response", return_value=Response(data)):
            return subject.collect(CVE, self.root)

    def assert_error(self, data, code):
        with self.assertRaises(subject.CollectorError) as caught:
            self.collect(data)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])

    def test_original_bytes_and_receipt_are_saved_without_claiming_full_validation(self):
        raw = record()
        folder = self.collect(raw)
        self.assertEqual((folder / "original.json").read_bytes(), raw)
        receipt = json.loads((folder / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["cveId"], CVE)
        self.assertEqual(receipt["sourceUrl"], URL)
        self.assertEqual(receipt["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt["bytes"], len(raw))
        self.assertEqual(receipt["recordState"], "PUBLISHED")
        self.assertEqual(receipt["validationScope"], "basic-envelope-only")
        self.assertFalse(receipt["readyForMatching"])
        self.assertTrue(receipt["fetchedAt"].endswith("+00:00"))
        self.assertIn("MITRE", (folder / "CVE_LICENSE_NOTICE.txt").read_text(encoding="utf-8"))

    def test_rejected_record_is_preserved_but_is_not_active_vulnerability_data(self):
        raw = record(cveMetadata={"cveId": CVE, "state": "REJECTED"})
        folder = self.collect(raw)
        receipt = json.loads((folder / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["recordState"], "REJECTED")
        self.assertFalse(receipt["readyForMatching"])

    def test_invalid_identifier_is_rejected_before_network_or_output(self):
        for bad in [None, 0, [], "../x", "CVE-2025-55130\n", "cve-2025-55130", "CVE-2025-1", "CVE-2025-55130?x=1"]:
            with self.subTest(identifier=bad), patch.object(subject, "open_response") as network:
                with self.assertRaises(subject.CollectorError) as caught:
                    subject.collect(bad, self.root)
                self.assertEqual(caught.exception.code, "INVALID_CVE_ID")
                network.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_different_id_and_unsupported_envelopes_do_not_create_success_receipt(self):
        cases = [
            (record(cveMetadata={"cveId": "CVE-2025-55131", "state": "PUBLISHED"}), "ID_MISMATCH"),
            (record(dataType="OTHER"), "INVALID_ENVELOPE"),
            (record(dataVersion="9.0"), "UNSUPPORTED_FORMAT"),
            (record(dataVersion=["5.2"]), "UNSUPPORTED_FORMAT"),
            (record(cveMetadata=None), "INVALID_ENVELOPE"),
            (record(cveMetadata={"cveId": CVE, "state": "RESERVED"}), "UNSUPPORTED_STATE"),
            (record(containers=[]), "INVALID_ENVELOPE"),
        ]
        for raw, code in cases:
            with self.subTest(code=code, raw=raw):
                self.assert_error(raw, code)

    def test_invalid_json_duplicate_keys_and_non_finite_numbers_are_rejected(self):
        for raw in [b"not-json", b"[]", b"null", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff']:
            with self.subTest(raw=raw):
                self.assert_error(raw, "INVALID_JSON")

    def test_deep_json_is_rejected_without_recursion_crash(self):
        self.assert_error(b"[" * 100 + b"0" + b"]" * 100, "JSON_TOO_DEEP")

    def test_wrong_http_status_content_type_and_truncated_response_are_not_saved(self):
        cases = [(Response(record(), status=204), "HTTP_STATUS"),
                 (Response(record(), content_type="text/html"), "CONTENT_TYPE"),
                 (Response(record(), length=999999), "INCOMPLETE_RESPONSE")]
        for response, code in cases:
            with self.subTest(code=code), patch.object(subject, "open_response", return_value=response):
                with self.assertRaises(subject.CollectorError) as caught:
                    subject.collect(CVE, self.root)
                self.assertEqual(caught.exception.code, code)
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])

    def test_oversize_response_is_not_parsed_or_saved(self):
        with patch.object(subject, "MAX_BYTES", 100):
            self.assert_error(b" " * 101, "RESPONSE_TOO_LARGE")

    def test_network_errors_return_failure_without_success_receipt(self):
        for error in [URLError("offline"), TimeoutError(), HTTPError(URL, 404, "Not found", {}, None)]:
            with self.subTest(error=type(error).__name__), patch.object(subject, "open_response", side_effect=error):
                with self.assertRaises(subject.CollectorError) as caught:
                    subject.collect(CVE, self.root)
                self.assertIn(caught.exception.code, ("NETWORK_ERROR", "HTTP_STATUS"))
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])

    def test_repeated_collection_does_not_overwrite_previous_files(self):
        one = self.collect()
        original = (one / "original.json").read_bytes()
        two = self.collect(record(dataVersion="5.1"))
        self.assertNotEqual(one, two)
        self.assertEqual((one / "original.json").read_bytes(), original)

    def test_connection_breaks_while_reading_are_network_errors(self):
        for error in [ConnectionResetError("reset"), IncompleteRead(b"partial", 40)]:
            response = Response(record())
            with self.subTest(error=type(error).__name__), patch.object(subject, "open_response", return_value=response), patch.object(response, "read", side_effect=error):
                with self.assertRaises(subject.CollectorError) as caught:
                    subject.collect(CVE, self.root)
                self.assertEqual(caught.exception.code, "NETWORK_ERROR")
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])

    def test_unreasonable_content_length_does_not_crash_integer_conversion(self):
        with patch.object(subject, "open_response", return_value=Response(record(), length="9" * 5000)):
            with self.assertRaises(subject.CollectorError) as caught:
                subject.collect(CVE, self.root)
        self.assertEqual(caught.exception.code, "INCOMPLETE_RESPONSE")
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])

    def test_final_receipt_write_or_rename_failure_never_marks_collection_complete(self):
        real_write = subject.Path.write_bytes
        def fail_pending(path, data):
            if path.name == "receipt.pending.json":
                raise OSError("disk full at receipt")
            return real_write(path, data)
        for operation in [patch.object(subject.Path, "write_bytes", new=fail_pending),
                          patch.object(subject.Path, "replace", side_effect=OSError("rename failed"))]:
            with operation:
                with self.assertRaises(subject.CollectorError) as caught:
                    self.collect()
                self.assertEqual(caught.exception.code, "STORAGE_ERROR")
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])
        self.assertEqual(len(list(self.root.glob("*/failure.json"))), 2)

    def test_disk_write_failure_does_not_leave_success_receipt(self):
        with patch.object(subject.Path, "write_bytes", side_effect=OSError("disk full")):
            with self.assertRaises(subject.CollectorError) as caught:
                self.collect()
        self.assertEqual(caught.exception.code, "STORAGE_ERROR")
        self.assertEqual(list(self.root.glob("*/receipt.json")), [])

    def test_output_root_symlink_is_rejected(self):
        real = Path(self.temp.name) / "real"
        real.mkdir()
        try:
            self.root.symlink_to(real, target_is_directory=True)
        except OSError:
            self.skipTest("This host does not grant symlink creation; rerun on Ubuntu")
        with self.assertRaises(subject.CollectorError) as caught:
            self.collect()
        self.assertEqual(caught.exception.code, "UNSAFE_OUTPUT_PATH")
        self.assertEqual(list(real.iterdir()), [])

    def test_redirect_is_refused_instead_of_fetching_another_host(self):
        with self.assertRaises(subject.CollectorError) as caught:
            subject.NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://elsewhere.test/")
        self.assertEqual(caught.exception.code, "REDIRECT_REFUSED")

    def test_real_request_uses_fixed_https_url_and_bounded_socket_timeout(self):
        captured = {}
        class Opener:
            def open(self, request, timeout):
                captured.update(url=request.full_url, timeout=timeout, method=request.get_method())
                return Response(record())
        with patch.object(subject, "build_opener", return_value=Opener()):
            subject.collect(CVE, self.root)
        self.assertEqual(captured["url"], URL)
        self.assertEqual(captured["method"], "GET")
        self.assertGreater(captured["timeout"], 0)
        self.assertLessEqual(captured["timeout"], 15)


if __name__ == "__main__":
    unittest.main()
