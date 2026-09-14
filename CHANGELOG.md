# 릴리즈 노트 (CHANGELOG)

버전별 변경 사항을 쉽게 정리한 기록임.

## v0.2 (2026-09-14)
### 한 일
- 공통 엔진의 뼈대를 만듦.
  - 검사 모듈(플러그인) 규격 정의 — 모든 검사기가 "대상+버전 받기 → 검사 → 결과(ENFORCED/NOT_ENFORCED/UNKNOWN) 반환" 형태를 지키도록.
  - 검사기 등록소(registry) — 가진 검사기를 한 곳에 모아 CLI가 불러 쓰게.
  - 예시 검사기(템플릿) — "선언된 수정 버전 vs 실제 버전" 비교를 보여주는 가장 단순한 검사기.
  - 명령줄 도구(CLI) — list(목록), check <이름> <버전>(검사), 결과를 reports/ 에 JSON 저장.
- TypeScript 개발 환경 설정(typescript, tsx, @types/node, tsconfig.json).

### 겪은 문제와 해결
- 문제: GitHub 업로드(push) 때 토큰 인증이 막힘(Password authentication is not supported).
  - 원인: 넣은 값이 유효한 토큰이 아니었음(이전 토큰 분실/만료 추정).
  - 해결: SSH 키를 만들어 GitHub에 등록하고 원격 주소를 SSH로 바꿈. 이후 push 때 인증을 안 물어봄.

## v0.1 (2026-09-14)
### 한 일
- GitHub 저장소에 프로젝트 기본 틀을 올림.
  - 폴더 구조(src/core, src/plugins, testbeds, reports, reference-fix).
  - README, package.json, .gitignore, CHANGELOG 추가.

### 겪은 문제와 해결
- 문제: git push(업로드) 때 비밀번호가 안 먹힘.
  - 원인: GitHub은 2021년부터 일반 비밀번호를 안 받고 "토큰"을 요구함.
  - 해결: GitHub에서 Personal Access Token(repo 권한)을 만들어 비밀번호 자리에 넣으니 성공함.
