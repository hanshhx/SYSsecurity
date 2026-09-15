import { promises as fs } from "node:fs";
import * as path from "node:path";

export interface Entry { name: string; content: string }
export type Mode = "vuln" | "fixed";

// 새로 만든 실험 폴더와 고정 입력 전용임. 범용 보안 추출기로 배포하지 않음.
// 기존 심볼릭 링크나 동시 파일 변경까지 막는 구현은 아님.
export async function extract(entries: Entry[], outputDir: string, mode: Mode) {
  const root = path.resolve(outputDir);
  const rejected: string[] = [];
  await fs.mkdir(root, { recursive: true });

  for (const entry of entries) {
    const destination = path.resolve(root, entry.name);
    const relative = path.relative(root, destination);
    // 문자열 접두사만 비교하면 output-other 같은 형제 폴더를 허용할 수 있음.
    // 경로 구성요소 기준으로 상위 폴더 탈출과 절대 경로를 거부함.
    const outside = relative === ".." || relative.startsWith(`..${path.sep}`)
      || path.isAbsolute(relative) || path.isAbsolute(entry.name);
    if (mode === "fixed" && (outside || relative === "")) {
      rejected.push(entry.name);
      continue;
    }
    // vuln은 의도적으로 경로 검증을 생략한 정답지임.
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, entry.content, { encoding: "utf8", flag: "wx" });
  }
  return { rejected };
}
