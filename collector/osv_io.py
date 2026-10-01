"""OSV 자료만 읽고 저장함. 받은 설명·링크·코드를 실행하지 않음."""
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
import math
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, build_opener

API_URL = 'https://api.osv.dev/v1/query'
MAX_PAGE_BYTES = 2 * 1024 * 1024


class OsvError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise OsvError('INVALID_JSON', '같은 항목 이름이 두 번 들어 있음')
        value[key] = item
    return value


def _number(value):
    number = float(value)
    if not math.isfinite(number):
        raise OsvError('INVALID_JSON', '유한하지 않은 숫자임')
    return number


def _constant(value):
    raise OsvError('INVALID_JSON', 'JSON에 허용되지 않는 값임')


def parse_json(raw):
    try:
        text = raw.decode('utf-8')
        # 파서에 넘기기 전 중첩을 제한함. 문자열 속 괄호는 세지 않음.
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '[{':
                depth += 1
                if depth > 64:
                    raise OsvError('INVALID_JSON', 'JSON 중첩이 64단계를 넘음')
            elif char in ']}':
                depth -= 1
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=_number, parse_constant=_constant)
        # 잘못된 유니코드가 저장 단계에서 뒤늦게 오류를 일으키지 않게 함.
        json.dumps(value, ensure_ascii=False).encode('utf-8')
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OsvError('INVALID_JSON', '올바른 UTF-8 JSON이 아님') from exc


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OsvError('REDIRECT_REFUSED', '공식 조회 주소에서 다른 주소로 이동하지 않음')


def open_response(payload):
    request = Request(API_URL, data=json_bytes(payload), method='POST', headers={
        'Content-Type': 'application/json', 'Accept': 'application/json',
        'User-Agent': 'SYSsecurity-v0.4-collector', 'Accept-Encoding': 'identity'})
    return build_opener(NoRedirect()).open(request, timeout=30)


def receive_page(payload):
    try:
        with open_response(payload) as response:
            if response.status != 200:
                raise OsvError('HTTP_STATUS', '서버가 정상 응답 200을 반환하지 않음')
            kind = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
            if kind != 'application/json':
                raise OsvError('CONTENT_TYPE', 'JSON 응답이 아님')
            if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                raise OsvError('CONTENT_TYPE', '압축 응답은 이번 수집에서 지원하지 않음')
            length = response.headers.get('Content-Length')
            if length is not None:
                if not length.isascii() or not length.isdigit():
                    raise OsvError('INCOMPLETE_RESPONSE', '응답 크기 표시가 잘못됨')
                length = int(length)
                if length > MAX_PAGE_BYTES:
                    raise OsvError('RESPONSE_TOO_LARGE', '한 페이지가 2 MiB 제한을 넘음')
            raw = response.read(MAX_PAGE_BYTES + 1)
            if len(raw) > MAX_PAGE_BYTES:
                raise OsvError('RESPONSE_TOO_LARGE', '한 페이지가 2 MiB 제한을 넘음')
            if length is not None and length != len(raw):
                raise OsvError('INCOMPLETE_RESPONSE', '표시한 크기만큼 응답을 받지 못함')
            return raw
    except HTTPError as exc:
        raise OsvError('HTTP_STATUS', '공식 서버 HTTP 오류: ' + str(exc.code)) from exc
    except (URLError, HTTPException, TimeoutError, OSError) as exc:
        raise OsvError('NETWORK_ERROR', '공식 서버와 통신하거나 응답을 읽지 못함') from exc


def no_links(path):
    path = Path(path).absolute()
    if any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()) for p in (path, *path.parents)):
        raise OsvError('UNSAFE_PATH', '링크를 거치는 저장 경로는 사용하지 않음')
    return path


def write_bytes(path, raw):
    path = no_links(path)
    # 매번 새 폴더에 쓰므로 이전 결과가 있으면 덮어쓰지 않고 멈춤.
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()


def read_bytes(path, limit):
    path = no_links(path)
    if not path.is_file():
        raise OsvError('INVALID_ARTIFACT', '필요한 일반 파일이 없음: ' + path.name)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise OsvError('INVALID_ARTIFACT', '저장 파일 크기 제한 초과: ' + path.name)
    return raw
