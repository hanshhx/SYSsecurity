#!/usr/bin/env python3
"""CVE 목록을 순서대로 수집·정리함. 실행 후보 선정이나 취약·안전 판정은 하지 않음."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

MAX_LIST_BYTES = 256 * 1024
MAX_LIST_LINES = 10000
MAX_UNIQUE_IDS = 1000
STATUSES = ("NORMALIZED", "REJECTED", "UNSUPPORTED_FORMAT", "FAILED", "TIMEOUT")
ERROR_STATUSES = ("UNSUPPORTED_FORMAT", "FAILED", "TIMEOUT")
ID_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
HERE = Path(__file__).absolute().parent


class BatchError(Exception):
    """배치 자체가 시작·저장되지 못한 이유를 건별 수집 실패와 구분함."""
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_path(path, code):
    path = Path(path).absolute()
    # 정상 개인 작업 폴더에서 링크를 거부함. 다른 사용자의 동시 경로 바꾸기까지 막는 격리는 아님.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise BatchError(code, "경로에 심볼릭 링크가 포함되어 있음")
    return path


def read_id_list(list_path):
    path = _safe_path(list_path, "UNSAFE_INPUT_PATH")
    try:
        if not path.is_file():
            raise BatchError("INVALID_LIST_FILE", "CVE 목록은 일반 파일이어야 함")
        with path.open("rb") as stream:
            raw = stream.read(MAX_LIST_BYTES + 1)
    except OSError as exc:
        raise BatchError("STORAGE_ERROR", "CVE 목록 파일을 읽지 못했음") from exc
    if len(raw) > MAX_LIST_BYTES:
        raise BatchError("LIST_TOO_LARGE", "CVE 목록이 256 KiB 제한을 넘었음")
    try:
        # Windows 메모장의 UTF-8 BOM도 허용하지만 확인값은 받은 파일 바이트 그대로 계산함.
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeError as exc:
        raise BatchError("INVALID_LIST_ENCODING", "CVE 목록은 UTF-8 텍스트여야 함") from exc
    if len(lines) > MAX_LIST_LINES:
        raise BatchError("TOO_MANY_LINES", "CVE 목록이 10000줄 제한을 넘었음")
    first_lines, ids, duplicates = {}, [], []
    input_count = 0
    for line_number, line in enumerate(lines, 1):
        cve_id = line.strip()
        if not cve_id or cve_id.startswith("#"):
            continue
        if not ID_PATTERN.fullmatch(cve_id):
            # 잘못된 원문에는 터미널 제어 문자가 있을 수 있어 번호만 안내함.
            raise BatchError("INVALID_CVE_ID", f"목록의 {line_number}번째 줄이 CVE-연도-번호 형식이 아님")
        input_count += 1
        if cve_id in first_lines:
            duplicates.append({"cveId": cve_id, "lineNumber": line_number,
                               "firstLineNumber": first_lines[cve_id]})
            continue
        ids.append(cve_id)
        first_lines[cve_id] = line_number
        if len(ids) > MAX_UNIQUE_IDS:
            raise BatchError("TOO_MANY_IDS", "한 배치는 중복을 뺀 CVE 1000개 이하만 처리함")
    if not ids:
        raise BatchError("EMPTY_LIST", "처리할 CVE 번호가 하나도 없음")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "lineCount": len(lines),
            "inputCount": input_count, "uniqueCount": len(ids), "duplicates": duplicates, "ids": ids}


def _check_timing(timeout_seconds, pause_seconds):
    for value in (timeout_seconds, pause_seconds):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise BatchError("INVALID_TIMING", "시간 설정은 유한한 숫자여야 함")
    if not 0 < timeout_seconds <= 300 or not 0 <= pause_seconds <= 300:
        raise BatchError("INVALID_TIMING", "건별 제한은 0초 초과 300초 이하, 간격은 0~300초여야 함")


def _atomic_json(path, value):
    # 같은 폴더에 다 쓴 파일만 마지막에 바꿈. 쓰다 중단된 JSON을 완료 기록으로 노출하지 않음.
    path = _safe_path(path, "UNSAFE_OUTPUT_PATH")
    pending = None
    try:
        descriptor, name = tempfile.mkstemp(prefix="." + path.name + "-", suffix=".pending", dir=path.parent)
        pending = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(path)
    except OSError as exc:
        raise BatchError("STORAGE_ERROR", "배치 진행·결과 파일을 저장하지 못했음") from exc
    finally:
        if pending is not None and pending.exists():
            try:
                pending.unlink()
            except OSError as exc:
                raise BatchError("STORAGE_ERROR", "배치 임시 파일을 정리하지 못했음") from exc


def _worker_command(cve_id, record_root):
    # 문자열 명령을 셸로 해석하지 않음. 공백·한글이 있는 경로도 각각 하나의 인자로 전달함.
    return [sys.executable, str(HERE / "batch_cves.py"), "--worker", cve_id,
            "--record-root", str(record_root)]


def _failed(cve_id, code, *, status="FAILED"):
    return {"cveId": cve_id, "status": status, "collectionPath": ".",
            "errorCode": code, "readyForMatching": False}


def _reject_constant(value):
    raise ValueError("non-finite JSON constant")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_bytes(path, limit):
    path = _safe_path(path, "UNSAFE_INPUT_PATH")
    if not path.is_file():
        raise ValueError("not a regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("oversized JSON")
    return raw


def _read_json(path, limit):
    raw = _read_bytes(path, limit)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("not an object")
    return value


def _inside_path(record_root, value, *, file=False):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        raise ValueError("invalid result path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("result path escapes record folder")
    path = _safe_path(record_root / relative, "UNSAFE_INPUT_PATH")
    path.relative_to(record_root)
    if not (path.is_file() if file else path.is_dir()):
        raise ValueError("missing result path")
    return path


def _read_worker_result(cve_id, record_root):
    try:
        result = _read_json(record_root / "worker-result.json", 64 * 1024)
        status = result.get("status")
        if result.get("cveId") != cve_id or result.get("readyForMatching") is not False or status not in STATUSES:
            raise ValueError("invalid result identity or status")
        if status == "TIMEOUT":
            raise ValueError("only the parent can establish a hard timeout")
        collection = _inside_path(record_root, result.get("collectionPath"))
        item = {"cveId": cve_id, "status": status, "collectionPath": collection.relative_to(record_root).as_posix(),
                "readyForMatching": False}
        if status in ("NORMALIZED", "REJECTED"):
            normalized = _inside_path(record_root, result.get("normalizedPath"), file=True)
            normalized.relative_to(collection)
            value = _read_json(normalized, 4 * 1024 * 1024)
            expected_state = "REJECTED" if status == "REJECTED" else "PUBLISHED"
            receipt = _read_json(collection / "receipt.json", 64 * 1024)
            if (value.get("formatVersion") != "syssecurity.cve.normalized.v1" or value.get("cveId") != cve_id
                    or value.get("recordState") != expected_state or value.get("readyForMatching") is not False
                    or value.get("validation", {}).get("status") != "VALID"
                    or receipt.get("cveId") != cve_id or receipt.get("collectionStatus") != "COLLECTED"
                    or receipt.get("recordState") != expected_state or receipt.get("readyForMatching") is not False):
                raise ValueError("completed files disagree with worker result")
            # 자식의 성공 문구만 믿지 않고 실제 파일의 확인값·출처·고지를 함께 대조함.
            raw = _read_bytes(collection / "original.json", 2 * 1024 * 1024)
            original = _read_json(collection / "original.json", 2 * 1024 * 1024)
            # 성공 결과를 확인할 때만 불러옴. 정리기 파일이 없으면 자식이 기존 방식대로
            # MISSING_DEPENDENCY를 기록할 수 있어야 하므로 시작 시점에 불러오지 않음.
            if __package__:
                from .normalize_cve import SCHEMAS
            else:
                from normalize_cve import SCHEMAS
            spec = SCHEMAS.get(original.get("dataVersion"))
            if spec is None:
                raise ValueError("unsupported completed record format")
            # 지원 형식을 늘려도 원본·수집 기록·정리 결과가 같은 형식이어야 함.
            # 자식이 사용했다고 기록한 규칙의 출처와 확인값도 그 형식과 맞아야 함.
            if (type(receipt.get("bytes")) is not int or receipt["bytes"] != len(raw)
                    or receipt.get("sha256") != hashlib.sha256(raw).hexdigest()
                    or original.get("cveMetadata", {}).get("cveId") != cve_id
                    or original.get("cveMetadata", {}).get("state") != expected_state
                    or original.get("dataType") != "CVE_RECORD"
                    or receipt.get("dataVersion") != original.get("dataVersion")
                    or value.get("dataVersion") != original.get("dataVersion")
                    or any(value.get("validation", {}).get(key) != spec[key] for key in
                           ("schemaRelease", "schemaSha256", "schemaUrl"))
                    or any(value.get("source", {}).get(key) != receipt.get(key) for key in
                           ("sourceUrl", "fetchedAt", "sha256", "bytes", "licenseUrl"))):
                raise ValueError("original integrity or provenance differs")
            notice = _read_bytes(HERE / "CVE_LICENSE_NOTICE.txt", 64 * 1024)
            if (not notice.strip() or _read_bytes(collection / "CVE_LICENSE_NOTICE.txt", 64 * 1024) != notice
                    or _read_bytes(normalized.parent / "CVE_LICENSE_NOTICE.txt", 64 * 1024) != notice
                    or value["source"].get("noticeSha256") != hashlib.sha256(notice).hexdigest()):
                raise ValueError("license notice differs")
            item["normalizedPath"] = normalized.relative_to(record_root).as_posix()
        else:
            code = result.get("errorCode")
            if not isinstance(code, str) or not CODE_PATTERN.fullmatch(code) or "normalizedPath" in result:
                raise ValueError("invalid failure result")
            if status == "UNSUPPORTED_FORMAT" and code != "UNSUPPORTED_FORMAT":
                raise ValueError("incorrect unsupported format code")
            item["errorCode"] = code
        return item
    except (BatchError, ImportError, OSError, ValueError, TypeError, AttributeError, RecursionError):
        return _failed(cve_id, "INVALID_CHILD_RESULT")


def _run_record(cve_id, record_root, timeout_seconds):
    try:
        process = subprocess.Popen(_worker_command(cve_id, record_root), shell=False,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return _failed(cve_id, "PROCESS_START_ERROR")
    try:
        # 소켓 대기 제한과 달리 이 시간은 수집·정리 전체의 벽시계 제한임.
        # 조금씩 데이터를 계속 보내는 서버도 정해진 시간이 지나면 자식 프로세스를 종료함.
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return _failed(cve_id, "RECORD_TIMEOUT", status="TIMEOUT")
        if return_code != 0:
            return _failed(cve_id, "CHILD_PROCESS_ERROR")
        return _read_worker_result(cve_id, record_root)
    finally:
        # Ctrl+C 때도 자식만 남아서 다운로드를 계속하지 않게 함.
        if process.poll() is None:
            process.kill()
            process.wait()


def _collect_and_normalize(cve_id, record_root):
    result = _failed(cve_id, "INTERNAL_ERROR")
    collection = None
    try:
        if __package__:
            from .fetch_cve import CollectorError, collect
            from .normalize_cve import normalize_collection
        else:
            from fetch_cve import CollectorError, collect
            from normalize_cve import normalize_collection
        try:
            # 기존 모듈의 원본·영수증·고지 저장과 규칙 검사를 그대로 재사용함.
            collection = collect(cve_id, record_root)
            normalized = normalize_collection(collection)
            value = _read_json(normalized, 4 * 1024 * 1024)
            result = {"cveId": cve_id, "status": "REJECTED" if value["recordState"] == "REJECTED" else "NORMALIZED",
                      "collectionPath": collection.relative_to(record_root).as_posix(),
                      "normalizedPath": normalized.relative_to(record_root).as_posix(), "readyForMatching": False}
        except CollectorError as exc:
            status = "UNSUPPORTED_FORMAT" if exc.code == "UNSUPPORTED_FORMAT" else "FAILED"
            result = _failed(cve_id, exc.code, status=status)
            if collection is not None:
                result["collectionPath"] = collection.relative_to(record_root).as_posix()
    except ImportError:
        result = _failed(cve_id, "MISSING_DEPENDENCY")
    except (OSError, ValueError, KeyError, TypeError, BatchError):
        result = _failed(cve_id, "INTERNAL_ERROR")
    _atomic_json(record_root / "worker-result.json", result)


def run_batch(list_path, output_root, timeout_seconds=45, pause_seconds=1):
    _check_timing(timeout_seconds, pause_seconds)
    source = read_id_list(list_path)
    root = _safe_path(output_root, "UNSAFE_OUTPUT_PATH")
    report = None
    run_root = None
    try:
        # 목록 전체를 확인한 뒤에만 출력 폴더를 만듦. 매번 새 폴더여서 이전 자료를 덮어쓰지 않음.
        root.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(prefix="batch-", dir=root))
        (run_root / "records").mkdir()
        report = {"formatVersion": "syssecurity.cve.batch.v1", "batchStatus": "IN_PROGRESS",
                  "readyForMatching": False, "startedAt": _now(), "input": source,
                  "settings": {"timeoutSeconds": timeout_seconds, "pauseSeconds": pause_seconds,
                               "automaticRetries": 0},
                  "counts": {status: 0 for status in STATUSES}, "items": [], "activeCveId": None}
        _atomic_json(run_root / "checkpoint.json", report)
        for index, cve_id in enumerate(source["ids"], 1):
            if index > 1 and pause_seconds:
                time.sleep(pause_seconds)
            report["activeCveId"] = cve_id
            _atomic_json(run_root / "checkpoint.json", report)
            record_root = run_root / "records" / f"{index:04d}-{cve_id}"
            record_root.mkdir()
            item = _run_record(cve_id, record_root, timeout_seconds)
            for key in ("collectionPath", "normalizedPath"):
                if key in item:
                    item[key] = (record_root / item[key]).relative_to(run_root).as_posix()
            report["items"].append(item)
            report["counts"][item["status"]] += 1
            report["activeCveId"] = None
            _atomic_json(run_root / "checkpoint.json", report)
        report["batchStatus"] = "COMPLETED_WITH_ERRORS" if any(report["counts"][s] for s in ERROR_STATUSES) else "COMPLETED"
        report["completedAt"] = _now()
        final = run_root / "batch.json"
        # 이 이름은 모든 고유 ID를 순회한 뒤 저장까지 성공한 경우에만 생김.
        _atomic_json(final, report)
        return final
    except KeyboardInterrupt:
        if report is not None and run_root is not None:
            # 마지막 이름 변경 직후 Ctrl+C가 들어와도 중단 기록과 완료 표시가 함께 남지 않게 함.
            try:
                _safe_path(run_root / "batch.json", "UNSAFE_OUTPUT_PATH").unlink(missing_ok=True)
            except OSError as exc:
                raise BatchError("STORAGE_ERROR", "중단된 배치의 완료 표시를 회수하지 못했음") from exc
            report["batchStatus"] = "INTERRUPTED"
            report.pop("completedAt", None)
            report["interruptedAt"] = _now()
            _atomic_json(run_root / "checkpoint.json", report)
        raise
    except OSError as exc:
        raise BatchError("STORAGE_ERROR", "배치 폴더·파일을 만들거나 저장하지 못했음") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description="CVE 목록을 순서대로 수집·정리함. 실행 허용·차단 기능은 아님.")
    parser.add_argument("--list", type=Path, dest="list_path")
    parser.add_argument("--output-root", type=Path, default=HERE.parent / "reports" / "cve-batches")
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--pause", type=float, default=1)
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    parser.add_argument("--record-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.worker is not None:
            if not ID_PATTERN.fullmatch(args.worker) or args.record_root is None:
                raise BatchError("INVALID_WORKER_ARGUMENTS", "건별 처리 인자가 잘못됐음")
            record_root = _safe_path(args.record_root, "UNSAFE_OUTPUT_PATH")
            if not record_root.is_dir():
                raise BatchError("INVALID_WORKER_ARGUMENTS", "건별 처리 폴더가 없음")
            _collect_and_normalize(args.worker, record_root)
            return 0
        if args.list_path is None:
            parser.error("--list 인자가 필요함")
        final = run_batch(args.list_path, args.output_root, args.timeout, args.pause)
        result = _read_json(final, 4 * 1024 * 1024)
        print("[배치 순회 완료] " + json.dumps(str(final), ensure_ascii=True))
        print(json.dumps(result["counts"], ensure_ascii=True))
        return 1 if result["batchStatus"] == "COMPLETED_WITH_ERRORS" else 0
    except BatchError as exc:
        print("[배치 실패] " + exc.code + ": " + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RecursionError):
        print("[배치 실패] STORAGE_ERROR: 저장한 배치 결과를 확인하지 못했음", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[배치 중단] checkpoint.json을 확인함. batch.json이 없으면 완료된 배치가 아님", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
