import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { randomUUID } from "node:crypto";
import { Checker, CheckResult, CheckTarget } from "../core/types";
import { extract, Mode } from "../../testbeds/pathtrav/extractors";

async function readIfPresent(file: string): Promise<string | null> {
  try { return await fs.readFile(file, "utf8"); }
  catch (error) {
    // 권한 오류 등을 '파일 없음 = 차단 성공'으로 오해하지 않음.
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export const relapseChecker: Checker = {
  id: "relapse",
  title: "RELAPSE",
  description: "자작 추출기의 경로 탈출을 실제 파일 증거로 검사함",
  supports: target => target.name === "testbed-extractor",

  async run(target: CheckTarget): Promise<CheckResult> {
    const result: CheckResult = {
      checkerId: "relapse", target, verdict: "UNKNOWN",
      evidence: "검사를 완료하지 못함.", ranAt: new Date().toISOString(),
    };
    if (target.name !== "testbed-extractor" || !["vuln", "fixed"].includes(target.version)) {
      result.evidence = "지원 대상: testbed-extractor, 버전: vuln 또는 fixed임.";
      return result;
    }
    if (process.platform !== "linux") {
      result.evidence = "본인 Linux VM에서 실행해야 함.";
      return result;
    }

    let workspace: string | undefined;
    try {
      // ../escaped.txt도 이 임시 실험 폴더 안에만 생김.
      // 매 실행마다 다른 폴더를 만들어 과거 결과의 영향을 없앰.
      workspace = await fs.mkdtemp(path.join(os.tmpdir(), "syssecurity-relapse-"));
      const outputDir = path.join(workspace, "output");
      const escapedPath = path.join(workspace, "escaped.txt");
      const marker = `SYSsecurity-${randomUUID()}`;
      const mode = target.version as Mode;
      result.detail = {
        workspace, outputDir, escapedPath, marker, baselinePassed: false,
        scope: "fresh-directory, regular-file, parent-traversal testbed only",
        node: process.version, platform: process.platform, arch: process.arch,
      };

      // 정상 기능이 고장 난 추출기를 '안전'하다고 판정하지 않도록 먼저 확인함.
      await extract([{ name: "nested/normal.txt", content: "normal-file-ok" }], outputDir, mode);
      const normal = await readIfPresent(path.join(outputDir, "nested/normal.txt"));
      if (normal !== "normal-file-ok") {
        result.evidence = "정상 파일 처리를 확인하지 못해 UNKNOWN으로 판정함.";
        return result;
      }
      result.detail.baselinePassed = true;

      const attempt = await extract([{ name: "../escaped.txt", content: marker }], outputDir, mode);
      const outsideContent = await readIfPresent(escapedPath);
      const rejected = attempt.rejected.includes("../escaped.txt");
      Object.assign(result.detail, { outsideContent, rejected });

      if (outsideContent === marker) {
        result.verdict = "NOT_ENFORCED";
        result.evidence = "정상 추출 확인 후, 지정 추출 폴더 밖에서 동일 표식 파일을 읽었음.";
      } else if (outsideContent === null && rejected) {
        result.verdict = "ENFORCED";
        result.evidence = "정상 추출이 동작하며 시험한 ../ 경로 입력을 거부했고 외부 파일이 없었음. 이 시험 범위의 판정임.";
      } else {
        result.evidence = "탈출 성공이나 명시적 차단을 입증하지 못해 UNKNOWN으로 판정함.";
      }
    } catch (error) {
      result.verdict = "UNKNOWN";
      result.evidence = `준비·실행·관측 오류로 UNKNOWN 판정함: ${error instanceof Error ? error.message : String(error)}`;
    } finally {
      if (workspace) {
        try {
          // 이 실행이 mkdtemp로 만든 디렉터리만 정리함. 관측값은 JSON에 남음.
          await fs.rm(workspace, { recursive: true, force: true });
          if (result.detail) result.detail.workspaceRemoved = true;
        } catch (error) {
          if (result.detail) result.detail.cleanupError = String(error);
          result.evidence += " 임시 폴더 정리에 실패해 detail 확인이 필요함.";
        }
      }
    }
    return result;
  },
};
