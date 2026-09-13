# SYSsecurity

공개 소프트웨어 부품(런타임·라이브러리)이 "막았다·안전하다"고 선언한 방어가
실제로는 우회되는 지점을 자동으로 검증하는 플랫폼.

## 구조
- `src/core/` : 공통 엔진 (수집·시험입력생성·판정)
- `src/plugins/` : 검사기 5개 (RELAPSE, SLOWLANE, SANDLEAK, PROTOREVIVE, SANDCASTLE)
- `testbeds/` : 자작 취약 예제 (도구 정확도 검증용)
- `reports/` : 검사 결과·비교표
- `reference-fix/` : 안전한 참조 수정 (Before→After)

## 데이터 출처
취약점 데이터: OSV (osv.dev), GitHub Advisory Database (CC-BY 4.0)
