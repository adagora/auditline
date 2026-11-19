import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DIST, fail } from "./common.mjs";

const { inspectPii, redactPiiLog, PII_TOKEN, piiTokens } = await import(DIST + "pii.js");
const { restorePiiResponse } = await import(DIST + "piiDelivery.js");
const { PiiVault, PiiVaultError } = await import(DIST + "piiVault.js");

const APIS = ["openai-chat", "openai-responses", "anthropic-messages"];
const vault = new PiiVault({ directory: mkdtempSync(join(tmpdir(), "fuzz-pii-vault-")), key: Buffer.alloc(32, 9), ttlSeconds: 3600 });
const SCOPE_A = vault.scope("a".repeat(64), "11111111-1111-4111-8111-111111111111");
const SCOPE_B = vault.scope("b".repeat(64), "22222222-2222-4222-8222-222222222222");

function splitSse(api, fullText, cuts) {
  const chunks = [];
  let pos = 0;
  for (const c of cuts) {
    const next = Math.min(fullText.length, pos + (c % 19) + 1);
    if (next > pos) chunks.push(fullText.slice(pos, next));
    pos = next;
    if (pos >= fullText.length) break;
  }
  if (pos < fullText.length) chunks.push(fullText.slice(pos));
  if (api === "openai-chat") {
    return chunks.map((delta) => `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: delta } }] })}\n\n`).join("") + "data: [DONE]\n\n";
  }
  if (api === "anthropic-messages") {
    return `event: content_block_start\ndata: ${JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })}\n\n`
      + chunks.map((text) => `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text } })}\n\n`).join("")
      + `event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`;
  }
  return chunks.map((delta) => `data: ${JSON.stringify({ type: "response.output_text.delta", output_index: 0, content_index: 0, delta })}\n\n`).join("")
    + `data: ${JSON.stringify({ type: "response.completed", response: { output: [{ type: "message", content: [{ type: "output_text", text: fullText }] }] } })}\n\n`;
}

export function fuzz(data) {
  if (data.length < 4) return;
  const mode = data[0] % 3;
  const api = APIS[data[1] % APIS.length];
  if (mode === 0) {
    const raw = `Customer ada@example.com phone +48 601 234 567 ${data.subarray(2).toString("utf8").slice(0, 500)}`;
    const inspected = inspectPii({ messages: [{ role: "user", content: raw }] });
    if (JSON.stringify(inspected.value).includes("ada@example.com")) fail("raw email survived inspectPii", { raw });
    if (!inspected.pii.length) return;
    vault.put(SCOPE_A, inspected.pii);
    for (const entry of inspected.pii) {
      let leaked = false;
      try { vault.get(SCOPE_B, entry.token); leaked = true; } catch (e) { if (!(e instanceof PiiVaultError)) fail("unexpected vault error", { e: String(e) }); }
      if (leaked) fail("cross-scope PII read succeeded", { token: entry.token });
    }
    const answer = `Reply to ${inspected.pii.map((e) => e.token).join(" and ")}`;
    const sse = splitSse(api, answer, [...data.subarray(2, 14)]);
    const allowed = new Set(piiTokens(answer));
    const restored = restorePiiResponse(api, sse, true, (t) => t.replace(PII_TOKEN, (tok) => allowed.has(tok) ? vault.get(SCOPE_A, tok).value : tok));
    if (!restored.includes("ada@example.com")) fail("split SSE token failed to restore", { api, restored });
    const logged = JSON.stringify(redactPiiLog({ text: answer, token: inspected.pii[0].token }));
    if (PII_TOKEN.test(logged) || logged.includes("ada@example.com")) fail("redactPiiLog leaked token or email", { logged });
  } else if (mode === 1) {
    const raw = data.subarray(2).toString("utf8");
    try { restorePiiResponse(api, raw, data[1] % 2 === 0, (s) => s); }
    catch (error) {
      if (!(error instanceof SyntaxError) && !(error instanceof Error && error.message === "audit_pii_delivery_failed")) {
        fail("unexpected restorePiiResponse error", { api, error: String(error) });
      }
    }
  } else {
    const token = "[PII:email:" + "a".repeat(48) + "]";
    const body = api === "openai-chat"
      ? JSON.stringify({ choices: [{ message: { content: "ok", tool_calls: [{ function: { name: "send", arguments: JSON.stringify({ to: token }) } }] } }] })
      : api === "anthropic-messages"
        ? JSON.stringify({ content: [{ type: "text", text: "ok" }, { type: "tool_use", name: "send", input: { to: token } }] })
        : JSON.stringify({ output: [{ type: "message", content: [{ type: "output_text", text: "ok" }] }, { type: "function_call", name: "send", arguments: JSON.stringify({ to: token }) }] });
    const out = restorePiiResponse(api, body, false, (s) => s.replace(PII_TOKEN, "SECRET@EXAMPLE.COM"));
    if (out.includes("SECRET@EXAMPLE.COM")) fail("tool argument token was restored", { api, out });
  }
}
