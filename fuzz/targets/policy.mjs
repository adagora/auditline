import { readFileSync } from "node:fs";
import { DIST, fail } from "./common.mjs";

const { compilePolicy, recoverPolicy, evaluatePolicy, PolicyError } = await import(DIST + "policyRuntime.js");

const SAMPLE = JSON.parse(readFileSync(new URL("../../examples/evaluation/machining-policy.json", import.meta.url), "utf8"));
const EVIDENCE = JSON.parse(readFileSync(new URL("../../examples/evidence-policy/policy.json", import.meta.url), "utf8"));
const BASES = [SAMPLE, EVIDENCE];

function safeRun(label, input, fn) {
  try { return fn(); }
  catch (error) {
    if (error instanceof PolicyError) return undefined;
    fail(`${label} threw unexpected ${error}`, { input: String(input).slice(0, 1500) });
  }
}

export function fuzz(data) {
  if (data.length < 2) return;
  const mode = data[0] % 3;
  const text = data.subarray(1).toString("utf8");
  if (mode === 0) {
    let parsed;
    try { parsed = JSON.parse(text); } catch { return; }
    const compiled = safeRun("compilePolicy", text, () => compilePolicy(parsed));
    if (!compiled) return;
    const recovered = recoverPolicy(compiled.source);
    if (recovered.id !== compiled.id || recovered.source !== compiled.source) fail("recoverPolicy mismatch", { id: compiled.id });
    const a = safeRun("evaluatePolicy-a", text, () => evaluatePolicy(compiled.source, {}));
    const b = safeRun("evaluatePolicy-b", text, () => evaluatePolicy(compiled.source, {}));
    if (JSON.stringify(a) !== JSON.stringify(b)) fail("evaluatePolicy non-deterministic", { a, b });
  } else if (mode === 1) {
    const compiled = compilePolicy(BASES[data[1] % BASES.length]);
    let bindings;
    try { bindings = JSON.parse(data.subarray(2).toString("utf8")); } catch { return; }
    const a = safeRun("evaluatePolicy-base-a", text, () => evaluatePolicy(compiled.source, bindings));
    const b = safeRun("evaluatePolicy-base-b", text, () => evaluatePolicy(compiled.source, bindings));
    if (JSON.stringify(a) !== JSON.stringify(b)) fail("evaluatePolicy non-deterministic on bindings", { a, b });
  } else {
    safeRun("recoverPolicy-raw", text, () => recoverPolicy(text));
  }
}
