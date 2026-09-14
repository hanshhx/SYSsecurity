// ============================================================
// src/plugins/template-checker.ts
// 검사기 "예시(템플릿)". 진짜 5개 검사기(RELAPSE 등)를 만들 때
// 이 파일을 복사해서 안을 채우면 된다.
//
// 이 예시가 하는 일(아주 단순):
//   "이 부품은 X 버전에서 고쳤다고 발표됐다."
//   준 버전이 그 이상 → ENFORCED (고친 버전 = 안전)
//   미만            → NOT_ENFORCED (아직 안 고친 버전 = 취약)
// 즉 "선언된 수정 버전" vs "실제 버전" 비교라는
// 이 프로젝트의 가장 기본 뼈대를 그대로 보여준다.
// ============================================================

import { Checker, CheckTarget, CheckResult } from "../core/types";

const ID = "version-gate-demo";
const DEMO_TARGET_NAME = "demo-lib";
const FIXED_IN = "1.2.0"; // 이 버전부터 패치됨(이라고 가정)

// 아주 단순한 버전 비교기: "1.2.0" 같은 숫자.숫자.숫자 만 가정.
// 반환: a<b → -1,  a===b → 0,  a>b → 1
// ⚠️ 한계: "1.2.0-rc1"(프리릴리즈), 자리수 다름 등은 아직 미처리.
//    → 나중에 네가 직접 튼튼하게 고쳐볼 부분(TODO).
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export const templateChecker: Checker = {
  id: ID,
  title: "버전 게이트 데모",
  description: "선언된 수정 버전과 실제 버전을 비교하는 예시 검사기",

  supports(target: CheckTarget): boolean {
    // 이 데모는 이름이 "demo-lib" 인 대상만 다룬다.
    return target.name === DEMO_TARGET_NAME;
  },

  async run(target: CheckTarget): Promise<CheckResult> {
    const cmp = compareVersions(target.version, FIXED_IN);
    const patched = cmp >= 0; // 고친 버전 이상인가?

    return {
      checkerId: ID,
      target,
      verdict: patched ? "ENFORCED" : "NOT_ENFORCED",
      evidence: patched
        ? `버전 ${target.version} 은 수정 버전 ${FIXED_IN} 이상 → 방어 적용됨.`
        : `버전 ${target.version} 은 수정 버전 ${FIXED_IN} 미만 → 방어 없음.`,
      detail: { fixedIn: FIXED_IN, compared: cmp },
      ranAt: new Date().toISOString(),
    };
  },
};
