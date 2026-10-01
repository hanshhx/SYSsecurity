"""OSV 기록을 공식 구조로 확인하고 원문과 출처를 함께 정리함."""
from copy import deepcopy
from datetime import datetime
from pathlib import Path
import re

import osv_io

SCHEMA_PATH = Path(__file__).resolve().parent.parent / 'schemas/osv-1.9/schema.json'
SCHEMA_SHA256 = '15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653'
CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}')
GHSA_ID = re.compile(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}')


def load_validator():
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry
        raw = osv_io.read_bytes(SCHEMA_PATH, 256 * 1024)
        if osv_io.sha256(raw) != SCHEMA_SHA256:
            raise osv_io.OsvError('SCHEMA_CHANGED', '고정한 공식 OSV 규칙과 파일이 다름')
        schema = osv_io.parse_json(raw)
        Draft202012Validator.check_schema(schema)
        # 외부 규칙을 자동으로 받지 않음. 고정 파일의 내부 참조만 사용함.
        return Draft202012Validator(schema, registry=Registry())
    except ImportError as exc:
        raise osv_io.OsvError('DEPENDENCY_MISSING', '프로젝트 Python 환경의 jsonschema가 필요함') from exc
    except OSError as exc:
        raise osv_io.OsvError('SCHEMA_UNAVAILABLE', '공식 OSV 규칙 파일을 읽지 못함') from exc


def _timestamp(value):
    # OSV는 소수점 9자리도 사용함. 검증용으로만 줄이고 저장 원문은 보존함.
    checked = re.sub(r'\.(\d{6})\d+', r'.\1', value)
    try:
        datetime.fromisoformat(checked.replace('Z', '+00:00'))
    except ValueError as exc:
        raise osv_io.OsvError('INVALID_RECORD', '실제로 존재하지 않는 날짜임') from exc


def normalize(record, query, validator):
    if not isinstance(record, dict):
        raise osv_io.OsvError('INVALID_RECORD', 'OSV 기록은 항목 이름과 값의 묶음이어야 함')
    version = record.get('schema_version', '1.0.0')
    if not isinstance(version, str) or not re.fullmatch(r'1\.[0-9]\.(0|[1-9][0-9]*)', version):
        raise osv_io.OsvError('UNSUPPORTED_OSV_FORMAT', '지원하지 않는 OSV 파일 형식임')
    error = next(validator.iter_errors(record), None)
    if error is not None:
        raise osv_io.OsvError('INVALID_RECORD', '공식 OSV 항목 구조와 맞지 않음: ' + str(list(error.path)))
    for key in ('modified', 'published', 'withdrawn'):
        if key in record:
            _timestamp(record[key])
    affected = record.get('affected') or []
    matches = [index for index, item in enumerate(affected)
               if item.get('package', {}).get('name') == query['package']['name']
               and item.get('package', {}).get('ecosystem') == query['package']['ecosystem']]
    state = 'WITHDRAWN' if 'withdrawn' in record else 'ACTIVE'
    missing = [key for key in ('aliases', 'summary', 'details', 'affected', 'references') if not record.get(key)]
    if not record.get('severity') and not any(item.get('severity') for item in affected):
        missing.append('severity')
    issues = []
    if not affected and state == 'ACTIVE':
        issues.append('TARGET_INFORMATION_MISSING')
    elif affected and not matches:
        issues.append('TARGET_NOT_IN_RECORD')
    identifier = record['id']
    # 이번 출처 지원 범위는 GHSA임. 다른 출처에 같은 허락을 추정하지 않음.
    ghsa = GHSA_ID.fullmatch(identifier) is not None
    source = {'recordUrl': 'https://osv.dev/vulnerability/' + identifier,
              'provider': 'GitHub Advisory Database and contributors' if ghsa else None,
              'upstreamUrl': 'https://github.com/advisories/' + identifier if ghsa else None,
              'license': 'CC-BY-4.0' if ghsa else None,
              'licenseUrl': 'https://creativecommons.org/licenses/by/4.0/' if ghsa else None,
              'licenseFile': 'GHSA_CC_BY_4_0.txt' if ghsa else None,
              'noticeFile': 'OSV_DATA_NOTICE.txt',
              'changes': 'Original fields preserved under data; query context and review information added.'}
    if not ghsa:
        issues.append('LICENSE_REVIEW_REQUIRED')
    return {'id': identifier, 'schemaVersion': version, 'state': state,
            'cveIds': sorted({v for v in (record.get('aliases') or []) if CVE_ID.fullmatch(v)}),
            'matchingPackageIndexes': matches, 'missingFields': missing, 'issues': issues,
            'source': source, 'data': deepcopy(record)}
