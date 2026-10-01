#!/usr/bin/env python3
"""저장한 CVE를 공식 규칙으로 확인하고 출처별로 정리함. 실행 허용·차단은 하지 않음."""
import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

if __package__:
    from .fetch_cve import (API_ROOT, MAX_BYTES, CollectorError, finite_float,
                            read_record, reject_constant, unique_object, utc_now, write_json)
else:
    from fetch_cve import (API_ROOT, MAX_BYTES, CollectorError, finite_float,
                           read_record, reject_constant, unique_object, utc_now, write_json)

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE.parent / "schemas" / "cve-5.2.0" / "CVE_Record_Format_bundled.json"
SCHEMA_SHA256 = "44c703322b1fcc532bc1c93f3993a0ba042c1a2831aae8cf39c4fbb707d03c8f"
SCHEMA_URL = "https://raw.githubusercontent.com/CVEProject/cve-schema/v5.2.0/schema/docs/CVE_Record_Format_bundled.json"
# 자료의 dataVersion과 검사에 쓰는 공식 규칙의 배포 번호는 다를 수 있음.
# 5.1 자료에는 보완판 5.1.1, 기존 5.2 자료에는 기존 5.2.0 규칙을 사용함.
# 원본의 버전 표시를 바꾸거나 모르는 버전을 가장 가까운 버전으로 추측하지 않음.
SCHEMAS = {
    "5.1": {
        "path": HERE.parent / "schemas" / "cve-5.1.1" / "CVE_Record_Format_bundled.json",
        "schemaRelease": "5.1.1",
        "schemaSha256": "c5f31c951a2934858e0925d40eec81006c9daad554cad133e00bc181ca578c74",
        "schemaUrl": "https://raw.githubusercontent.com/CVEProject/cve-schema/v5.1.1/schema/docs/CVE_Record_Format_bundled.json",
    },
    "5.2": {"path": SCHEMA_PATH, "schemaRelease": "5.2.0",
            "schemaSha256": SCHEMA_SHA256, "schemaUrl": SCHEMA_URL},
}
NOTICE_NAME = "CVE_LICENSE_NOTICE.txt"
LICENSE_URL = "https://www.cve.org/legal/termsofuse"
SCORE_KINDS = ("cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0")


def read_local(path, limit=MAX_BYTES):
    # 다른 곳을 가리키는 링크를 따라 읽거나 쓰지 않음. 본인 작업 폴더에서 사용함.
    # 다른 사용자가 동시에 경로를 바꾸는 공격까지 막는 OS 격리 기능은 아님.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise CollectorError("UNSAFE_INPUT_PATH", "입력 경로에 심볼릭 링크가 있음")
    if not path.is_file():
        raise CollectorError("STORAGE_ERROR", "필요한 일반 파일을 찾지 못했음: " + path.name)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise CollectorError("FILE_TOO_LARGE", "입력 파일의 크기 제한을 넘었음: " + path.name)
    return raw


def parse_receipt(raw):
    try:
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                             parse_constant=reject_constant, parse_float=finite_float)
        if not isinstance(receipt, dict):
            raise ValueError("not an object")
        cve_id = receipt.get("cveId")
        if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve_id):
            raise ValueError("invalid id")
        digest = receipt.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid hash")
        if type(receipt.get("bytes")) is not int or not 0 < receipt["bytes"] <= MAX_BYTES:
            raise ValueError("invalid size")
        # 조회 시각에는 시간대가 있어야 서로 다른 컴퓨터에서도 같은 시점을 뜻함.
        stamp = receipt.get("fetchedAt")
        if not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() is None:
            raise ValueError("invalid timestamp")
        expected = {"collectionStatus": "COLLECTED", "sourceUrl": API_ROOT + cve_id,
                    "licenseUrl": LICENSE_URL, "noticeFile": NOTICE_NAME,
                    "validationScope": "basic-envelope-only"}
        if any(receipt.get(key) != value for key, value in expected.items()) or receipt.get("readyForMatching") is not False:
            raise ValueError("unexpected receipt fields")
        return receipt
    except (ValueError, TypeError, RecursionError) as exc:
        raise CollectorError("INVALID_RECEIPT", "첫 수집 단계의 완료 기록이 없거나 내용이 잘못됐음") from exc


def schema_spec(data_version):
    # 정리기와 배치 결과 확인이 같은 지원 범위·규칙 정보를 사용하도록 한곳에서 정함.
    if not isinstance(data_version, str) or data_version not in SCHEMAS:
        raise CollectorError("UNSUPPORTED_FORMAT", "현재 정리는 dataVersion 5.1과 5.2만 지원함")
    return SCHEMAS[data_version]


def validate_official(record, schema_path=None):
    spec = schema_spec(record.get("dataVersion"))
    path = spec["path"] if schema_path is None else Path(schema_path).absolute()
    raw = read_local(path)
    # 다른 파일을 지정하더라도 해당 버전의 공식 원문 확인값과 일치해야 함.
    if hashlib.sha256(raw).hexdigest() != spec["schemaSha256"]:
        raise CollectorError("SCHEMA_INTEGRITY", "선택한 공식 규칙 파일의 확인값이 다름")
    try:
        from importlib.metadata import version
        from jsonschema import Draft7Validator, FormatChecker
        from referencing import Registry
    except ImportError as exc:
        raise CollectorError("MISSING_DEPENDENCY", ".venv에서 requirements-step2.txt의 패키지를 설치해야 함") from exc
    # uri 검사 의존성이 없으면 jsonschema가 이 검사를 생략할 수 있으므로 먼저 확인함.
    if not {"date", "uri"}.issubset(FormatChecker.checkers):
        raise CollectorError("MISSING_FORMAT_CHECKER", "날짜·주소 검사에 필요한 패키지가 없음")
    schema = json.loads(raw)
    Draft7Validator.check_schema(schema)
    # 고정된 bundled 파일의 참조는 모두 내부 참조임. Registry에는 외부 다운로드 기능을 넣지 않음.
    validator = Draft7Validator(schema, format_checker=FormatChecker(formats=["date", "uri"]),
                                registry=Registry())
    error = next(validator.iter_errors(record), None)
    if error is not None:
        # 원문 전체나 제어 문자를 터미널에 출력하지 않고 실패 위치만 표시함.
        path = json.dumps(list(error.absolute_path), ensure_ascii=True)
        raise CollectorError("SCHEMA_INVALID", "공식 CVE " + spec["schemaRelease"] + " 규칙에 맞지 않음. 위치: " + path)
    return {"status": "VALID", "schemaRelease": spec["schemaRelease"], "schemaUrl": spec["schemaUrl"],
            "schemaSha256": spec["schemaSha256"], "validator": "jsonschema",
            "validatorVersion": version("jsonschema"), "scope": "structure-and-format-only"}


def arrange(record, receipt, validation):
    result = {"formatVersion": "syssecurity.cve.normalized.v1", "normalizerVersion": "0.4-step4",
              "cveId": record["cveMetadata"]["cveId"], "recordState": record["cveMetadata"]["state"],
              "recordMetadata": deepcopy(record["cveMetadata"]), "dataVersion": record["dataVersion"],
              "normalizedAt": utc_now(), "validation": validation,
              "source": {key: receipt[key] for key in ("sourceUrl", "fetchedAt", "sha256", "bytes", "licenseUrl")},
              "noticeFile": NOTICE_NAME, "readyForMatching": False,
              "sources": [], "products": [], "metrics": [], "scores": []}
    entries = [("/containers/cna", "cna", record["containers"]["cna"])]
    entries += [(f"/containers/adp/{index}", "adp", value)
                for index, value in enumerate(record["containers"].get("adp", []))]
    for path, kind, container in entries:
        source = {"path": path, "kind": kind, "provider": deepcopy(container["providerMetadata"]),
                  "information": {key: deepcopy(value) for key, value in container.items()
                                  if key not in ("providerMetadata", "affected", "metrics")},
                  "missingFields": [key for key in ("affected", "metrics", "descriptions", "references")
                                    if key not in container]}
        result["sources"].append(source)
        for index, product in enumerate(container.get("affected", [])):
            # RPM 문자열·범위 끝 포함 여부·중간 상태 변경을 그대로 보존함. 이름만 보고 npm으로 정하지 않음.
            result["products"].append({"path": f"{path}/affected/{index}", "sourcePath": path,
                "data": deepcopy(product), "missingFields": [key for key in
                ("vendor", "product", "packageName", "collectionURL", "versions", "defaultStatus") if key not in product]})
        for index, metric in enumerate(container.get("metrics", [])):
            metric_path = f"{path}/metrics/{index}"
            result["metrics"].append({"path": metric_path, "sourcePath": path, "data": deepcopy(metric)})
            # 기관·점수 규격이 다르면 별도 평가임. 가장 큰 숫자 하나로 합치지 않음.
            for score_kind in SCORE_KINDS:
                if score_kind in metric:
                    result["scores"].append({"path": metric_path + "/" + score_kind,
                        "sourcePath": path, "kind": score_kind, "data": deepcopy(metric[score_kind])})
    return result


def normalize_collection(folder, *, schema_path=None):
    folder = Path(folder).absolute()
    attempt = None
    try:
        receipt = parse_receipt(read_local(folder / "receipt.json", 64 * 1024))
        raw = read_local(folder / "original.json")
        if len(raw) != receipt["bytes"] or hashlib.sha256(raw).hexdigest() != receipt["sha256"]:
            raise CollectorError("INTEGRITY_MISMATCH", "원본이 수집 당시 크기·SHA-256과 다름")
        record = read_record(raw, receipt["cveId"])
        # JSON의 문자 이스케이프를 풀었을 때 단독 surrogate가 남으면 UTF-8로 다시 저장할 수 없음.
        # 결과 폴더를 만들기 전에 검사해 불완전한 자료를 정리 성공으로 남기지 않음.
        json.dumps(record, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if record["dataVersion"] != receipt.get("dataVersion") or record["cveMetadata"]["state"] != receipt.get("recordState"):
            raise CollectorError("RECEIPT_MISMATCH", "원본과 수집 기록의 형식 버전·상태가 다름")
        notice = read_local(folder / NOTICE_NAME, 64 * 1024)
        if notice != read_local(HERE / NOTICE_NAME, 64 * 1024):
            raise CollectorError("NOTICE_MISMATCH", "수집한 이용 고지가 설치된 원문과 다름")
        validation = validate_official(record, schema_path)
        result = arrange(record, receipt, validation)
        result["source"]["noticeSha256"] = hashlib.sha256(notice).hexdigest()
        # 원본과 예전 정리 결과를 유지함. 새 결과의 완성 표시는 마지막 파일 이름 변경으로 남김.
        attempt = Path(tempfile.mkdtemp(prefix="normalized-v1-", dir=folder))
        (attempt / NOTICE_NAME).write_bytes(notice)
        pending = attempt / "normalized.pending.json"
        write_json(pending, result)
        final = attempt / "normalized.json"
        pending.replace(final)
        return final
    except UnicodeError as exc:
        raise CollectorError("INVALID_UNICODE", "CVE 내용에 UTF-8로 저장할 수 없는 문자 값이 있음") from exc
    except OSError as exc:
        suffix = " 중간 폴더가 남았더라도 normalized.json이 없으면 완료가 아님." if attempt else ""
        raise CollectorError("STORAGE_ERROR", "정리 파일 읽기·저장에 실패했음." + suffix) from exc


def main():
    parser = argparse.ArgumentParser(description="기존 CVE 수집 폴더를 확인하고 프로그램·버전·점수를 출처별로 정리함.")
    parser.add_argument("collection_folder", type=Path)
    args = parser.parse_args()
    try:
        final = normalize_collection(args.collection_folder)
        print("[정리 완료] " + str(final))
        print("공식 형식 검사를 통과했음. 정보의 사실 여부·실행 허용·차단 판정은 아님.")
    except CollectorError as exc:
        print("[정리 실패] " + exc.code + ": " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[중단] normalized.json이 없는 폴더는 완료 자료로 사용하지 않음", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
