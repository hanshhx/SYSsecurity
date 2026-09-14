// ============================================================
// src/core/registry.ts
// "등록소": 우리가 가진 검사기들을 한 곳에 모아둔다.
// 코어(CLI)는 여기서 목록을 받아 실행한다.
//
// v0.2에서는 손으로 직접 import 해서 배열에 넣는다(가장 단순).
// 나중(v0.3+)에는 plugins 폴더를 자동으로 훑어 불러오게 바꿀 수 있다.
// ============================================================

import { Checker, CheckTarget } from "./types";
import { templateChecker } from "../plugins/template-checker";

// 사용 가능한 모든 검사기.
// 진짜 검사기(relapse 등)를 만들면 여기 배열에 추가하면 된다.
const ALL_CHECKERS: Checker[] = [
  templateChecker,
];

export function getAllCheckers(): Checker[] {
  return ALL_CHECKERS;
}

export function getCheckerById(id: string): Checker | undefined {
  return ALL_CHECKERS.find((c) => c.id === id);
}

// 이 대상을 검사할 수 있는 검사기만 골라준다.
export function findSupportingCheckers(target: CheckTarget): Checker[] {
  return ALL_CHECKERS.filter((c) => c.supports(target));
}
