# SYSsecurity

알려진 취약점 정보를 이용해 프로그램 실행 전에 경고하거나 시작을 막는 보호 소프트웨어를 개발하는 프로젝트임.

**v0.4.0에서 제공하는 것은 공식 CVE·OSV 자료 수집과 정리임.** 설치된 프로그램을 자동 조사하거나 실행을 차단하는 기능은 후속 단계임. 기존 v0.3의 RELAPSE 예제 검사도 함께 제공함.

## 지금 할 수 있는 일

- CVE 번호 한 건 또는 목록으로 공식 기록을 가져옴.
- CVE 5.1·5.2 형식을 공식 규칙과 대조하고 프로그램·버전·평가 정보를 출처별로 정리함.
- npm 패키지 이름과 정확한 버전으로 OSV에서 관련 기록을 조회함. 다음 페이지까지 처리함.
- 원본·조회 시각·출처·파일 확인값·이용 조건을 보존함. 철회·누락·실패를 구분함.
- 기존 자작 예제에서 정상 파일 처리와 경로 탈출 차단 여부를 시험함.

## 설치와 실행

확인한 실행 환경은 본인 Ubuntu 22.04 VM, Node.js 20.20.2, Python 3.10.12임. 아래는 개발용 설치 방법이며 Debian·다른 Linux 전체에 대한 호환성 보장은 아직 하지 않음. Node.js·npm·Python 3·git과 Python 가상 환경 구성 요소가 필요함.

```bash
git clone https://github.com/hanshhx/SYSsecurity.git
cd SYSsecurity
git switch --detach v0.4.0

npm ci
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r collector/requirements-step2.txt

npm run build
```

`.venv`는 이 프로젝트의 Python 패키지를 다른 작업과 분리하는 폴더임. Ubuntu에서 생성이 안 되면 `python3-venv` 구성 요소의 설치 여부를 확인함.

**npm 패키지로 조회**

```bash
.venv/bin/python collector/query_osv.py --package tar --version 6.1.0
```

**CVE 번호 목록으로 수집·정리**

```bash
.venv/bin/python collector/batch_cves.py --list collector/examples/cve-step3-small.txt
```

이 명령들은 취약점 정보를 조회함. 조회 대상 프로그램이나 취약점 설명 안의 코드를 설치·실행하지 않음. 자세한 단건 수집·정리 방법과 출력 설명은 [수집기 안내](collector/README.md)에 있음.

**기존 예제 검사** — 본인 Linux VM에서 실행함.

```bash
npm start -- list
npm start -- check testbed-extractor vuln
npm start -- check testbed-extractor fixed
```

## 결과를 읽는 방법

| 결과 | 의미 |
|---|---|
| `reports/cve/` | CVE 원본과 출처 기록 |
| `reports/cve-batches/` | CVE 목록 처리 결과와 건별 상태 |
| `reports/osv/` | OSV 원본 페이지와 최종 조회 결과 |
| `readyForMatching=false` | 실제 설치 목록·자체 버전 비교와 아직 연결하지 않았음 |
| 조회 기록 0건 | 해당 조회에서 자료를 받지 못했다는 뜻이며 안전하다는 보장은 아님 |

수집 결과는 매번 새 폴더에 저장함. 중간 파일이나 폴더가 있다는 사실만으로 성공을 판단하지 않음. 오류·누락을 위험 점수 0점이나 안전 판정으로 바꾸지 않음.

기존 예제의 `ENFORCED`는 시험한 입력에 대한 차단 결과임. 모든 공격에 안전하다는 뜻이 아님. 실행 실패·증거 부족은 `UNKNOWN`으로 남김.

## 시험과 확인 범위

```bash
.venv/bin/python -m unittest discover -s collector -p 'test_*.py' -v
npm run test:relapse
npm run build
```

Ubuntu에서 수집 시험 110개·기존 예제 시험 5개와 빌드가 통과했음. 공식 OSV의 `tar@6.1.0` 조회에서는 기록 18건을 받아 원본과 저장 내용을 대조했음. 기록 개수는 조회 시점에 따라 달라질 수 있으며 설치된 프로그램 개수나 공격 성공 횟수가 아님.

## 코드 구조

| 위치 | 역할 |
|---|---|
| `collector/` | Python으로 자료를 가져오고 구조·출처·정리 결과를 확인함 |
| `schemas/` | 고정한 공식 파일 규칙과 출처·이용 조건 |
| `src/cli.ts` | 기존 검사 명령의 입구와 현재 버전 안내 |
| `src/core/` | 기존 검사기의 공통 규격과 등록소 |
| `src/plugins/` | RELAPSE와 예시 검사기 |
| `testbeds/`, `tests/` | 자작 검사 대상과 기존 기능 시험 |

다음 단계는 설치된 부품을 알아내고 수집 자료와 비교하는 기능임. 경고·차단은 그 결과에 적용할 정책과 함께 개발함.

## 출처와 이용 조건

프로젝트 자체 코드는 [MIT](LICENSE) 조건으로 제공함. 외부 자료·규칙·의존성의 조건은 별도이며 이 라이선스로 바뀌지 않음.

- CVE 기록: `collector/CVE_LICENSE_NOTICE.txt`에 보존한 저작권·이용 고지 적용.
- OSV 제공 자료: 원출처별 조건 확인. GitHub Advisory Database 기록은 `collector/GHSA_CC_BY_4_0.txt` 및 `collector/OSV_DATA_NOTICE.txt` 참고.
- 공식 규칙: 각 `schemas/` 하위 폴더의 LICENSE·SOURCE·고지 파일 참고.
- Python 의존성: `collector/DEPENDENCY_LICENSES.txt` 참고.
- CVE에 연결된 다른 사람의 프로그램·재현 코드에는 해당 코드의 조건이 별도로 적용됨.

세부 변경은 [CHANGELOG](CHANGELOG.md), v0.4 개발 중 기록은 [개발 이력](docs/history/v0.4-development.md)에 있음.
