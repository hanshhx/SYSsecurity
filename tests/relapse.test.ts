import test from "node:test";
import assert from "node:assert/strict";
import { getCheckerById } from "../src/core/registry";

function checker() {
  const found = getCheckerById("relapse");
  assert.ok(found, "RELAPSE_NOT_REGISTERED");
  return found;
}

// 판정 문자열만 확인하지 않고 실제로 읽은 파일 내용도 확인함.
test("취약본은 정상 파일을 처리하고 추출 폴더 밖에 표식 파일을 씀", async () => {
  const r = await checker().run({ name: "testbed-extractor", version: "vuln" });
  assert.equal(r.verdict, "NOT_ENFORCED");
  assert.equal(r.detail?.baselinePassed, true);
  assert.equal(r.detail?.outsideContent, r.detail?.marker);
  assert.equal(typeof r.detail?.marker, "string");
});

test("수정본은 정상 파일을 처리하면서 같은 탈출 입력을 거부함", async () => {
  const r = await checker().run({ name: "testbed-extractor", version: "fixed" });
  assert.equal(r.verdict, "ENFORCED");
  assert.equal(r.detail?.baselinePassed, true);
  assert.equal(r.detail?.outsideContent, null);
  assert.equal(r.detail?.rejected, true);
});

test("알 수 없는 버전을 안전한 것으로 판정하지 않음", async () => {
  const r = await checker().run({ name: "testbed-extractor", version: "typo" });
  assert.equal(r.verdict, "UNKNOWN");
});

test("검사기를 직접 지정해도 지원하지 않는 대상은 UNKNOWN임", async () => {
  const r = await checker().run({ name: "unrelated-package", version: "fixed" });
  assert.equal(r.verdict, "UNKNOWN");
});

test("연속·병렬 검사에서 이전 실험 파일 때문에 결과가 바뀌지 않음", async () => {
  const results = await Promise.all(["vuln", "fixed", "vuln", "fixed"].map(version =>
    checker().run({ name: "testbed-extractor", version })
  ));
  assert.deepEqual(results.map(r => r.verdict), ["NOT_ENFORCED", "ENFORCED", "NOT_ENFORCED", "ENFORCED"]);
  assert.equal(new Set(results.map(r => r.detail?.workspace)).size, 4);
});
