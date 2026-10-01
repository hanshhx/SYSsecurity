#!/usr/bin/env python3
"""공식 CVE 한 건을 저장함. 기본 구조만 확인하며 취약 여부·안전 여부를 판정하지 않음."""
import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
import math
from pathlib import Path
import re
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
SOCKET_TIMEOUT = 10
SUPPORTED_FORMATS = {"5.0", "5.1", "5.2"}
API_ROOT = "https://cveawg.mitre.org/api/cve/"


class CollectorError(Exception):
    """일정한 오류 이름과 쉬운 설명으로 실패 이유를 전달함."""
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 공식 주소가 다른 주소로 바뀌면 사람이 확인함. 몰래 다른 서버로 이동하지 않음.
        raise CollectorError("REDIRECT_REFUSED", "공식 API가 다른 주소로 이동을 요청했음")


def open_response(url):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "SYSsecurity-CVE-collector/0.4-dev"})
    # 인증서 검증은 기본값을 유지함. 10초는 소켓 대기 제한이지 전체 작업 시간 보장이 아님.
    return build_opener(NoRedirect()).open(request, timeout=SOCKET_TIMEOUT)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite number")
    return number


def reject_constant(value):
    raise ValueError("non-standard JSON constant")


def read_record(raw, requested_id):
    try:
        text = raw.decode("utf-8")
        # 너무 깊은 자료를 json.loads에 넘기기 전에 제한함. 문자열 안의 괄호는 세지 않음.
        depth, in_string, escaped = 0, False, False
        for char in text:
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise CollectorError("JSON_TOO_DEEP", "JSON의 중첩 깊이 제한을 넘었음")
            elif char in "]}":
                depth -= 1
        record = json.loads(text, object_pairs_hook=unique_object,
                            parse_constant=reject_constant, parse_float=finite_float)
    except (ValueError, RecursionError) as exc:
        raise CollectorError("INVALID_JSON", "정상적인 UTF-8 JSON으로 읽을 수 없음") from exc
    if not isinstance(record, dict):
        raise CollectorError("INVALID_JSON", "CVE 최상위 내용이 객체가 아님")
    meta = record.get("cveMetadata")
    if record.get("dataType") != "CVE_RECORD" or not isinstance(meta, dict) or not isinstance(record.get("containers"), dict):
        raise CollectorError("INVALID_ENVELOPE", "CVE 기본 구조가 없거나 잘못됐음")
    version = record.get("dataVersion")
    if not isinstance(version, str) or version not in SUPPORTED_FORMATS:
        raise CollectorError("UNSUPPORTED_FORMAT", "이 수집기가 지원하는 CVE 형식 버전이 아님")
    if meta.get("cveId") != requested_id:
        raise CollectorError("ID_MISMATCH", "요청한 CVE 번호와 받은 기록의 번호가 다름")
    if meta.get("state") not in ("PUBLISHED", "REJECTED"):
        raise CollectorError("UNSUPPORTED_STATE", "공개 또는 거부 상태의 CVE 기록이 아님")
    return record


def receive(url):
    try:
        with open_response(url) as response:
            if response.status != 200:
                raise CollectorError("HTTP_STATUS", "공식 서버가 성공 응답 200을 반환하지 않았음")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise CollectorError("CONTENT_TYPE", "서버가 JSON 응답으로 표시하지 않았음")
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise CollectorError("RESPONSE_TOO_LARGE", "응답이 2 MiB 크기 제한을 넘었음")
            expected = response.headers.get("Content-Length")
            # 길이 표시 자체도 외부 입력임. 지나치게 긴 숫자는 정수로 바꾸기 전에 거부함.
            if expected is not None and (len(expected) > 10 or not expected.isascii() or not expected.isdecimal() or int(expected) != len(raw)):
                raise CollectorError("INCOMPLETE_RESPONSE", "응답 길이가 서버가 알린 길이와 다름")
            return raw
    except HTTPError as exc:
        raise CollectorError("HTTP_STATUS", "공식 서버 HTTP 오류: " + str(exc.code)) from exc
    except (URLError, HTTPException, OSError) as exc:
        # 통신 중 연결 끊김과 인증서 오류를 디스크 저장 오류와 구분함.
        raise CollectorError("NETWORK_ERROR", "통신 또는 인증서 확인에 실패했음") from exc


def write_json(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8"))


def collect(cve_id, output_root):
    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve_id):
        raise CollectorError("INVALID_CVE_ID", "CVE-연도-번호 형식으로 입력해야 함")
    root = Path(output_root).absolute()
    # 정상 로컬 작업 영역에서 사용함. 이미 있는 링크 경로는 다른 곳에 쓰지 않도록 거부함.
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise CollectorError("UNSAFE_OUTPUT_PATH", "저장 경로에 심볼릭 링크가 포함되어 있음")
    url = API_ROOT + cve_id
    attempt = None
    try:
        notice = Path(__file__).with_name("CVE_LICENSE_NOTICE.txt").read_bytes()
        if not notice.strip():
            raise CollectorError("MISSING_NOTICE", "CVE 저작권·이용 조건 파일이 비어 있음")
        root.mkdir(parents=True, exist_ok=True)
        # 매번 새 폴더를 쓰므로 기존 수집 결과를 덮어쓰지 않음.
        attempt = Path(tempfile.mkdtemp(prefix=cve_id + "-", dir=root))
        raw = receive(url)
        fetched_at = utc_now()
        record = read_record(raw, cve_id)
        (attempt / "original.json").write_bytes(raw)
        (attempt / "CVE_LICENSE_NOTICE.txt").write_bytes(notice)
        receipt = {"collectionStatus": "COLLECTED", "cveId": cve_id,
                   "sourceUrl": url, "fetchedAt": fetched_at,
                   "dataVersion": record["dataVersion"], "recordState": record["cveMetadata"]["state"],
                   "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                   "validationScope": "basic-envelope-only", "readyForMatching": False,
                   "licenseUrl": "https://www.cve.org/legal/termsofuse",
                   "noticeFile": "CVE_LICENSE_NOTICE.txt"}
        # 완성된 영수증을 마지막에 공개함. 중간 오류나 중단을 수집 성공으로 오해하지 않게 함.
        pending = attempt / "receipt.pending.json"
        write_json(pending, receipt)
        pending.replace(attempt / "receipt.json")
        return attempt
    except CollectorError as exc:
        error = exc
    except OSError as exc:
        error = CollectorError("STORAGE_ERROR", "파일 읽기·저장 또는 입출력에 실패했음")
    if attempt is not None:
        try:
            write_json(attempt / "failure.json", {"collectionStatus": "FAILED", "cveId": cve_id,
                       "sourceUrl": url, "failedAt": utc_now(), "errorCode": error.code})
        except OSError:
            error = CollectorError(error.code, str(error) + "; 실패 기록도 저장하지 못했음")
    raise error


def main():
    parser = argparse.ArgumentParser(description="공식 CVE 한 건을 가져옴. 취약·안전 판정 기능은 아님.")
    parser.add_argument("cve_id")
    parser.add_argument("--output-root", type=Path, default=Path(__file__).resolve().parent.parent / "reports" / "cve")
    args = parser.parse_args()
    try:
        folder = collect(args.cve_id, args.output_root)
    except CollectorError as exc:
        print("[수집 실패] " + exc.code + ": " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[수집 중단] 완료 영수증이 없는 폴더는 성공 자료로 사용하지 않음", file=sys.stderr)
        return 130
    print("[수집 완료] " + str(folder))
    print("원본·출처·확인값·이용 고지를 저장했음. 전체 형식 검사와 실행 판정은 아직 아님.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
