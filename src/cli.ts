// ============================================================
// src/cli.ts
// 명령줄 입구(CLI). 웹으로 치면 "프론트엔드 버튼" 역할.
//
// 사용법:
//   npm run dev -- list
//   npm run dev -- check demo-lib 1.1.0
//   npm run dev -- check demo-lib 1.3.0 --checker version-gate-demo
// ("npm run dev" 뒤의 "--" 는 그 뒤 인자를 우리 프로그램에 넘기라는 뜻)
// ============================================================

import { promises as fs } from "fs";
import * as path from "path";
import {
  getAllCheckers,
  getCheckerById,
  findSupportingCheckers,
} from "./core/registry";
import { CheckResult, CheckTarget, Checker } from "./core/types";

const args = process.argv.slice(2); // 진짜 우리 인자만
const command = args[0];

async function main() {
  if (command === "list") return cmdList();
  if (command === "check") return cmdCheck(args.slice(1));
  printUsage();
}

function cmdList() {
  console.log("사용 가능한 검사기:");
  for (const c of getAllCheckers()) {
    console.log(`  - ${c.id}  (${c.title}) : ${c.description}`);
  }
}

async function cmdCheck(rest: string[]) {
  const name = rest[0];
  const version = rest[1];
  if (!name || !version) {
    console.error("사용법: check <이름> <버전> [--checker <검사기id>]");
    process.exitCode = 1;
    return;
  }
  const target: CheckTarget = { name, version };

  // --checker 옵션이 있으면 그 검사기만, 없으면 대상 지원하는 것 전부
  const pickIndex = rest.indexOf("--checker");
  const picked = pickIndex >= 0 ? rest[pickIndex + 1] : undefined;

  let checkers: Checker[];
  if (picked) {
    const one = getCheckerById(picked);
    checkers = one ? [one] : [];
  } else {
    checkers = findSupportingCheckers(target);
  }

  if (checkers.length === 0) {
    console.log(`'${name}' 을(를) 검사할 수 있는 검사기가 없습니다.`);
    return;
  }

  const results: CheckResult[] = [];
  for (const c of checkers) {
    const r = await c.run(target);
    results.push(r);
    console.log("");
    console.log(`[${r.checkerId}] ${r.target.name}@${r.target.version}`);
    console.log(`  판정: ${r.verdict}`);
    console.log(`  근거: ${r.evidence}`);
  }

  await saveReport(results);
}

// 결과를 reports/ 에 JSON으로 저장 (재현·표 만들기용)
async function saveReport(results: CheckResult[]) {
  const dir = path.join(process.cwd(), "reports");
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, `report-${Date.now()}.json`);
  await fs.writeFile(file, JSON.stringify(results, null, 2), "utf-8");
  console.log("");
  console.log(`결과 저장: ${path.relative(process.cwd(), file)}`);
}

function printUsage() {
  console.log("SYSsecurity — 부품 보안 검증 도구 (v0.2)");
  console.log("");
  console.log("명령:");
  console.log("  list                    검사기 목록 보기");
  console.log("  check <이름> <버전>     대상 검사 실행");
  console.log("      옵션: --checker <검사기id>");
  console.log("");
  console.log("예시:");
  console.log("  npm run dev -- list");
  console.log("  npm run dev -- check demo-lib 1.1.0");
}

main().catch((err) => {
  console.error("오류:", err);
  process.exitCode = 1;
});
