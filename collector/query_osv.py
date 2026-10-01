"""패키지·버전으로 OSV를 끝까지 조회함. 설치 프로그램 탐지나 실행 차단은 하지 않음."""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

import osv_io
import osv_records

HERE = Path(__file__).resolve().parent
MAX_PAGES = 100
MAX_RECORDS = 10_000
MAX_QUERY_BYTES = 20 * 1024 * 1024
MAX_RESULT_BYTES = 100 * 1024 * 1024
NOTICE_FILES = {
    'GHSA_CC_BY_4_0.txt': (HERE / 'GHSA_CC_BY_4_0.txt', '9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94'),
    'OSV_DATA_NOTICE.txt': (HERE / 'OSV_DATA_NOTICE.txt', '4795d1c1090fddafe79081484a8490e326065d99e1d1253ab8cc5eb4c48edc50'),
}
PACKAGE = re.compile(r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*')
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?')


def make_query(package, version):
    match = SEMVER.fullmatch(version) if isinstance(version, str) and len(version) <= 256 else None
    if not isinstance(package, str) or len(package) > 214 or PACKAGE.fullmatch(package) is None or match is None:
        raise osv_io.OsvError('INVALID_TARGET', 'npm 패키지 이름과 정확한 버전(예: tar, 6.1.0)을 입력해야 함')
    if match.group(4) and any(v.isdigit() and len(v) > 1 and v.startswith('0') for v in match.group(4).split('.')):
        raise osv_io.OsvError('INVALID_TARGET', '시험판 버전 숫자는 앞에 불필요한 0을 붙이지 않음')
    return {'package': {'name': package, 'ecosystem': 'npm'}, 'version': version}


def _check_query(query):
    try:
        expected = make_query(query['package']['name'], query['version'])
        if query != expected:
            raise ValueError('query differs')
    except (KeyError, TypeError, ValueError) as exc:
        raise osv_io.OsvError('INVALID_TARGET', '지원하는 npm 조회 형식과 다름') from exc


def page_contents(value):
    if not isinstance(value, dict):
        raise osv_io.OsvError('INVALID_PAGE', 'OSV 응답은 항목 이름과 값의 묶음이어야 함')
    # {}는 공식 빈 응답임. 오류나 모르는 페이지 표시를 빈 성공으로 바꾸지 않음.
    if set(value) - {'vulns', 'next_page_token'}:
        raise osv_io.OsvError('INVALID_PAGE', '지원하지 않는 OSV 응답 항목이 있음')
    records = value.get('vulns', [])
    token = value.get('next_page_token', '')
    if not isinstance(records, list) or not isinstance(token, str) or len(token) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in token):
        raise osv_io.OsvError('INVALID_PAGE', '조회 목록 또는 다음 페이지 표시가 잘못됨')
    return records, token


def _notices(directory=None):
    values = {}
    for name, (source, expected) in NOTICE_FILES.items():
        raw = osv_io.read_bytes(directory / name if directory else source, 128 * 1024)
        if osv_io.sha256(raw) != expected:
            raise osv_io.OsvError('NOTICE_CHANGED', '이용 조건 또는 출처 고지가 원본과 다름: ' + name)
        values[name] = raw
    return values


class PageSet:
    """수집할 때와 저장 결과를 다시 확인할 때 같은 제한을 적용함."""
    def __init__(self, query, validator):
        self.query, self.validator = query, validator
        self.total = self.duplicates = 0
        self.records, self.tokens = {}, set()
        self.next_token = ''

    def accept(self, raw, page_number):
        if page_number > MAX_PAGES:
            raise osv_io.OsvError('PAGE_LIMIT', '페이지 제한에 도달해 조회를 완료하지 못함')
        self.total += len(raw)
        if self.total > MAX_QUERY_BYTES:
            raise osv_io.OsvError('QUERY_TOO_LARGE', '전체 응답 크기 제한에 도달함')
        records, token = page_contents(osv_io.parse_json(raw))
        for record in records:
            value = osv_records.normalize(record, self.query, self.validator)
            identifier = value['id']
            if identifier in self.records:
                if self.records[identifier]['data'] != value['data']:
                    raise osv_io.OsvError('CONFLICTING_RECORD', '같은 OSV 번호의 내용이 조회 도중 달라짐')
                self.duplicates += 1
            else:
                if len(self.records) >= MAX_RECORDS:
                    raise osv_io.OsvError('RECORD_LIMIT', '기록 수 제한에 도달함')
                self.records[identifier] = value
        if token and token in self.tokens:
            raise osv_io.OsvError('PAGINATION_LOOP', '같은 다음 페이지 표시가 반복됨')
        if token:
            self.tokens.add(token)
        self.next_token = token

    def result(self, pages, started, completed):
        values = list(self.records.values())
        return {'format': 'syssecurity-osv-query-1', 'status': 'COMPLETE',
                'queryOutcome': 'RECORDS_RETURNED' if values else 'NO_RECORDS_RETURNED',
                'query': self.query, 'apiUrl': osv_io.API_URL,
                'startedAt': started, 'completedAt': completed,
                'schema': {'ruleVersion': '1.9.0', 'sha256': osv_records.SCHEMA_SHA256},
                'readyForMatching': False,
                'limitations': ['OSV query uses upstream version matching; local inventory and version matching are not implemented.',
                                'No records returned does not establish safety.',
                                'Source license review may be required before redistribution.'],
                'counts': {'pages': len(pages), 'rawBytes': self.total, 'uniqueRecords': len(values),
                           'duplicateRecords': self.duplicates,
                           'withdrawn': sum(v['state'] == 'WITHDRAWN' for v in values)},
                'cveIds': sorted({cve for v in values for cve in v['cveIds']}),
                'notices': [{'file': name, 'sha256': digest} for name, (_, digest) in NOTICE_FILES.items()],
                'pages': pages, 'records': values}


def collect_pages(query, attempt, pause_seconds=1):
    _check_query(query)
    attempt = osv_io.no_links(attempt)
    try:
        validator = osv_records.load_validator()
        notices = _notices()
        started = osv_io.utc_now()
        osv_io.write_bytes(attempt / 'request.json', osv_io.json_bytes(query))
        for name, raw in notices.items():
            osv_io.write_bytes(attempt / name, raw)
        state, pages = PageSet(query, validator), []
        for number in range(1, MAX_PAGES + 1):
            payload = dict(query)
            if state.next_token:
                payload['page_token'] = state.next_token
            raw = osv_io.receive_page(payload)
            filename = f'page-{number:04d}.json'
            osv_io.write_bytes(attempt / filename, raw)
            pages.append({'file': filename, 'sha256': osv_io.sha256(raw), 'bytes': len(raw),
                          'retrievedAt': osv_io.utc_now(), 'request': payload})
            state.accept(raw, number)
            if not state.next_token:
                result = state.result(pages, started, osv_io.utc_now())
                output = osv_io.json_bytes(result)
                if len(output) > MAX_RESULT_BYTES:
                    raise osv_io.OsvError('QUERY_TOO_LARGE', '정리 결과 크기 제한에 도달함')
                osv_io.write_bytes(attempt / 'draft-result.json', output)
                return
            if number < MAX_PAGES:
                time.sleep(pause_seconds)
        raise osv_io.OsvError('PAGE_LIMIT', '다음 페이지가 남아 있어 완료 처리할 수 없음')
    except OSError as exc:
        raise osv_io.OsvError('STORAGE_ERROR', '수집 자료를 저장하지 못함') from exc


def _time(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise osv_io.OsvError('INVALID_ARTIFACT', '조회 시각이 잘못됨')
    return datetime.fromisoformat(value[:-1] + '+00:00')


def verify_result(query, attempt):
    """종료 코드 대신 실제 원본을 다시 읽어 최종 공개할 내용을 확인함."""
    try:
        _check_query(query)
        attempt = osv_io.no_links(attempt)
        validator = osv_records.load_validator()
        _notices(attempt)
        request = osv_io.parse_json(osv_io.read_bytes(attempt / 'request.json', 8192))
        if request != query:
            raise osv_io.OsvError('INVALID_ARTIFACT', '저장한 조회 대상이 요청과 다름')
        draft = osv_io.parse_json(osv_io.read_bytes(attempt / 'draft-result.json', MAX_RESULT_BYTES))
        if not isinstance(draft, dict) or not isinstance(draft.get('pages'), list) or not 1 <= len(draft['pages']) <= MAX_PAGES:
            raise osv_io.OsvError('INVALID_ARTIFACT', '완료된 페이지 목록이 없음')
        state = PageSet(query, validator)
        started, completed = _time(draft['startedAt']), _time(draft['completedAt'])
        previous = started
        for number, page in enumerate(draft['pages'], 1):
            filename = f'page-{number:04d}.json'
            payload = dict(query)
            if state.next_token:
                payload['page_token'] = state.next_token
            elif number > 1:
                raise osv_io.OsvError('INVALID_ARTIFACT', '끝난 조회 뒤에 페이지가 더 있음')
            if page['file'] != filename or page['request'] != payload:
                raise osv_io.OsvError('INVALID_ARTIFACT', '페이지 이름 또는 요청 연결이 다름')
            raw = osv_io.read_bytes(attempt / filename, osv_io.MAX_PAGE_BYTES)
            if len(raw) != page['bytes'] or osv_io.sha256(raw) != page['sha256']:
                raise osv_io.OsvError('INVALID_ARTIFACT', '수집 원본 크기 또는 확인값이 다름')
            current = _time(page['retrievedAt'])
            if not previous <= current <= completed:
                raise osv_io.OsvError('INVALID_ARTIFACT', '조회 시각 순서가 잘못됨')
            previous = current
            state.accept(raw, number)
        if state.next_token:
            raise osv_io.OsvError('INVALID_ARTIFACT', '아직 받지 않은 다음 페이지가 있음')
        rebuilt = state.result(draft['pages'], draft['startedAt'], draft['completedAt'])
        if draft != rebuilt:
            raise osv_io.OsvError('INVALID_ARTIFACT', '원본에서 다시 읽은 내용과 정리 결과가 다름')
        return rebuilt
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise osv_io.OsvError('INVALID_ARTIFACT', '수집 결과 파일을 확인하지 못함') from exc


def _worker_command(query, attempt):
    return [sys.executable, str(HERE / 'query_osv.py'), '--package', query['package']['name'],
            '--version', query['version'], '--worker-dir', str(attempt)]


def _failure(attempt, error):
    osv_io.write_bytes(attempt / 'failure.json', osv_io.json_bytes({
        'status': 'FAILED', 'code': error.code, 'message': str(error),
        'failedAt': osv_io.utc_now(), 'readyForMatching': False}))


def run_query(package, version, output_root, timeout_seconds=180):
    query = make_query(package, version)
    root = osv_io.no_links(output_root)
    attempt = None
    try:
        root.mkdir(parents=True, exist_ok=True)
        attempt = Path(tempfile.mkdtemp(prefix='query-', dir=root))
        # 전체 시간을 부모가 제한함. 느린 응답이 계속 이어져도 무한히 기다리지 않음.
        with (attempt / 'worker.log').open('xb') as log:
            try:
                run = subprocess.run(_worker_command(query, attempt), stdout=log, stderr=log,
                                     timeout=timeout_seconds, check=False, shell=False)
            except subprocess.TimeoutExpired as exc:
                raise osv_io.OsvError('TIMEOUT', '전체 조회 시간 제한을 넘어 수집을 중단함') from exc
        if run.returncode != 0:
            error_file = attempt / 'worker-error.json'
            if error_file.is_file():
                error = osv_io.parse_json(osv_io.read_bytes(error_file, 8192))
                if isinstance(error, dict) and isinstance(error.get('code'), str) and isinstance(error.get('message'), str):
                    raise osv_io.OsvError(error['code'], error['message'])
            raise osv_io.OsvError('WORKER_FAILED', '수집 프로세스가 실패함. worker.log 확인 필요')
        result = verify_result(query, attempt)
        final = attempt / 'result.json'
        # 마지막 파일은 다 쓴 뒤 이름을 바꿈. 불완전한 파일을 완료 파일로 노출하지 않음.
        pending = attempt / 'result.pending'
        osv_io.write_bytes(pending, osv_io.json_bytes(result))
        if final.exists():
            raise osv_io.OsvError('INVALID_ARTIFACT', '예상하지 않은 완료 파일이 이미 있음')
        pending.rename(final)
        return final
    except (osv_io.OsvError, OSError, KeyboardInterrupt) as exc:
        error = exc if isinstance(exc, osv_io.OsvError) else osv_io.OsvError(
            'INTERRUPTED' if isinstance(exc, KeyboardInterrupt) else 'STORAGE_ERROR',
            '사용자가 수집을 중단함' if isinstance(exc, KeyboardInterrupt) else '수집 파일 또는 작업 프로세스를 준비하지 못함')
        if attempt:
            try:
                _failure(attempt, error)
            except (OSError, osv_io.OsvError):
                print('실패 기록도 저장하지 못함: ' + str(attempt), file=sys.stderr)
        raise error from exc


def main():
    parser = argparse.ArgumentParser(description='npm 패키지 이름·정확한 버전으로 공식 OSV 자료를 수집함')
    parser.add_argument('--package', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output-root', type=Path, default=HERE.parent / 'reports/osv')
    parser.add_argument('--worker-dir', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker_dir:
            collect_pages(make_query(args.package, args.version), args.worker_dir)
        else:
            path = run_query(args.package, args.version, args.output_root)
            print('OSV_QUERY_COMPLETE: ' + str(path))
            print('자료 조회 완료. 설치된 프로그램의 안전 판정은 아직 수행하지 않았음.')
        return 0
    except (osv_io.OsvError, OSError) as exc:
        error = exc if isinstance(exc, osv_io.OsvError) else osv_io.OsvError('STORAGE_ERROR', '파일 저장 실패')
        if args.worker_dir:
            try:
                osv_io.write_bytes(args.worker_dir / 'worker-error.json', osv_io.json_bytes({'code': error.code, 'message': str(error)}))
            except (OSError, osv_io.OsvError):
                pass  # 원래 오류를 지우지 않고 아래 stderr·실패 종료 코드로 알림.
        print(error.code + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
