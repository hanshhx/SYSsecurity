// ============================================================
// src/core/types.ts
// "검사 모듈(플러그인)"이 지켜야 할 공통 규격을 정의한다.
// USB처럼: 어떤 검사기든 이 규격만 지키면 코어 엔진에 그냥 꽂힌다.
// 코어는 검사기 내부가 뭘 하는지 몰라도, 이 약속(interface)만 믿고 부른다.
// ============================================================

// 검사 대상 = "무엇의 몇 번 버전을 볼 것인가"
export interface CheckTarget {
  name: string;    // 대상 이름. 예) "node", "demo-lib"
  version: string; // 버전 문자열. 예) "20.20.2"
}

// 판정 결과의 3가지 상태.
// 우리 연구의 핵심 질문: "선언된 방어가 실제로 집행되는가?"
export type Verdict =
  | "ENFORCED"      // 선언대로 방어가 실제 지켜짐 (= 안전)
  | "NOT_ENFORCED"  // 선언과 달리 지켜지지 않음 (= 우리가 찾는 지점)
  | "UNKNOWN";      // 판단 불가 (설치 실패, 환경 없음 등)

// 한 번 검사한 결과를 담는 상자.
// 나중에 JSON으로 저장해서 "부품 × 버전 × 검사기" 표를 만든다.
export interface CheckResult {
  checkerId: string;   // 어떤 검사기가 낸 결과인지
  target: CheckTarget; // 무엇을 검사했는지
  verdict: Verdict;    // 판정
  evidence: string;    // 왜 그렇게 판정했는지 (사람이 읽는 근거)
  detail?: Record<string, unknown>; // 재현/디버깅용 추가 데이터 (선택)
  ranAt: string;       // 검사 시각 (ISO 문자열)
}

// 모든 검사기가 구현해야 하는 규격.
// "대상+버전 받기 → 검사 → 결과 반환" 이 셋이 핵심.
export interface Checker {
  id: string;          // 고유 식별자. 예) "version-gate-demo"
  title: string;       // 사람이 읽는 이름
  description: string; // 한 줄 설명: 무엇을 검사하는가

  // 이 검사기가 주어진 대상을 다룰 수 있는가?
  // 예) node 전용 검사기는 name === "node" 일 때만 true.
  supports(target: CheckTarget): boolean;

  // 실제 검사. async 인 이유: 나중에 파일 실행/네트워크 조회 등
  // 시간이 걸리는 작업을 할 수 있어서.
  run(target: CheckTarget): Promise<CheckResult>;
}
