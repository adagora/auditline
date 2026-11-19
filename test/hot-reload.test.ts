import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { AuditLog, sha256 } from "../src/audit.js";
import type { ReloadableConfig } from "../src/proxy.js";
import { mockUpstream, startProxy } from "./helpers.js";

const cli = fileURLToPath(new URL("../../dist/src/cli.js", import.meta.url));
const chat = (key: string, body: object, extra: Record<string, string> = {}) => ({
  method: "POST",
  headers: { authorization: `Bearer ${key}`, "content-type": "application/json", ...extra },
  body: JSON.stringify(body),
});

test("POST /audit/reload atomically swaps useCases, keys and actionGate, logs config-reload, and rolls back on invalid config", async () => {
  const up = await mockUpstream();
  const adminKey = "admin-reload-secret-1";
  let liveConfig: ReloadableConfig = {
    keys: [{ name: "agent-a", sha256: sha256("vk-a"), useCases: ["assist"] }],
    useCases: { assist: { tier: "assist" } },
    adminKeySha256: sha256(adminKey),
  };
  const px = await startProxy(up.url, "redact", {
    keys: liveConfig.keys,
    useCases: liveConfig.useCases,
    adminKeySha256: sha256(adminKey),
    reloadConfig: () => liveConfig,
  });
  try {
    const req = () => fetch(px.url + "/v1/chat/completions", chat("vk-a", { model: "m", messages: [{ role: "user", content: "hi" }] }, { "x-audit-use-case": "assist" }));
    assert.equal((await req()).status, 200);
    assert.equal((await fetch(px.url + "/audit/reload", { method: "POST" })).status, 401);

    liveConfig = {
      keys: [{ name: "agent-a", sha256: sha256("vk-a"), useCases: ["assist"] }],
      useCases: { assist: { tier: "off" } },
      adminKeySha256: sha256(adminKey),
    };
    const reloaded = await fetch(px.url + "/audit/reload", { method: "POST", headers: { "x-admin-key": adminKey } });
    assert.equal(reloaded.status, 200);
    const body = await reloaded.json() as { generation: number; useCases: string[]; virtualKeys: number; digest: string };
    assert.equal(body.generation, 2);
    assert.deepEqual(body.useCases, ["assist"]);
    assert.equal(body.virtualKeys, 1);
    assert.match(body.digest, /^[a-f0-9]{64}$/);

    const stopped = await req();
    assert.equal(stopped.status, 403);
    assert.equal((await stopped.json() as { error: { code: string } }).error.code, "audit_use_case_off");

    liveConfig = {
      keys: [{ name: "agent-a", sha256: sha256("vk-a"), useCases: ["assist"] }],
      useCases: { assist: { tier: "not-a-real-tier" } },
      adminKeySha256: sha256(adminKey),
    };
    const bad = await fetch(px.url + "/audit/reload", { method: "POST", headers: { "x-admin-key": adminKey } });
    assert.equal(bad.status, 400);
    assert.equal((await req()).status, 403);

    const metricsText = await (await fetch(px.url + "/metrics")).text();
    assert.match(metricsText, /ai_audit_config_reloads_total\{result="ok",trigger="admin"\} [1-9]/);
    assert.match(metricsText, /ai_audit_config_reloads_total\{result="failed",trigger="admin"\} [1-9]/);
    assert.match(metricsText, /ai_audit_config_generation 2/);

    const records = px.log.read();
    assert.ok(records.some((r) => r.kind === "config-reload"));
    assert.deepEqual(px.log.verifyChain(), { ok: true });
  } finally {
    px.close();
    up.close();
  }
});

test("PII vault rejections and delivery failures increment ai_audit_pii_vault_errors_total by reason", async () => {
  const up = await mockUpstream();
  const vaultDir = mkdtempSync(join(tmpdir(), "pii-metrics-vault-"));
  const px = await startProxy(up.url, "redact", {
    keys: [{ name: "customer", sha256: sha256("vk-pii"), piiRestore: true }],
    piiVault: { directory: vaultDir, key: Buffer.alloc(32, 3), ttlSeconds: 3600 },
  });
  try {
    const missingScope = await fetch(px.url + "/v1/chat/completions", chat("vk-pii", { model: "m", messages: [{ role: "user", content: "hi" }] }));
    assert.equal(missingScope.status, 400);

    const unknownToken = await fetch(px.url + "/v1/chat/completions", chat("vk-pii", {
      model: "m",
      messages: [{ role: "user", content: "use [PII:email:" + "a".repeat(48) + "]" }],
    }, { "x-audit-pii-scope": "11111111-1111-4111-8111-111111111111" }));
    assert.equal(unknownToken.status, 422);

    const unsupported = await fetch(px.url + "/v1/chat/completions", chat("vk-pii", {
      model: "m",
      messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "https://example.com/a.png" } }] }],
    }, { "x-audit-pii-scope": "11111111-1111-4111-8111-111111111111" }));
    assert.equal(unsupported.status, 422);

    const text = await (await fetch(px.url + "/metrics")).text();
    assert.match(text, /ai_audit_pii_vault_errors_total\{reason="scope"\} [1-9]/);
    assert.match(text, /ai_audit_pii_vault_errors_total\{reason="token_invalid"\} [1-9]/);
    assert.match(text, /ai_audit_pii_vault_errors_total\{reason="unsupported_content"\} [1-9]/);
  } finally {
    px.close();
    up.close();
  }
});

test("auditline serve reloads gateway.json on SIGHUP and refuses piiVault toggle without restart", { timeout: 15_000 }, async () => {
  const up = await mockUpstream();
  const dir = mkdtempSync(join(tmpdir(), "serve-sighup-"));
  const cfgPath = join(dir, "gateway.json");
  const logPath = join(dir, "audit.jsonl");
  const adminKey = "admin-sighup-secret";
  writeFileSync(cfgPath, JSON.stringify({
    keys: [{ name: "client", sha256: sha256("vk-hup"), useCases: ["chat"] }],
    useCases: { chat: { tier: "assist" } },
  }));
  const child = spawn(process.execPath, [cli, "serve", "--mode", "redact", "--log", logPath, "--port", "0", "--config", cfgPath, "--upstream-openai", up.url], {
    env: { ...process.env, AUDITLINE_ADMIN_KEY: adminKey, AUDITLINE_UPSTREAM_OPENAI_KEY: "sk-fake" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  const waitFor = (pattern: RegExp) => new Promise<string>((resolve, reject) => {
    const onExit = (code: number | null) => reject(new Error(`child exited ${code}; stderr=${stderr}`));
    const onData = (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      if (pattern.test(stderr)) { child.stderr.off("data", onData); child.off("exit", onExit); resolve(stderr); }
    };
    if (pattern.test(stderr)) return resolve(stderr);
    child.stderr.on("data", onData);
    child.once("exit", onExit);
  });
  try {
    await waitFor(/"event":"listening"/);
    const listening = JSON.parse(stderr.trim().split("\n").find((l) => l.includes('"event":"listening"'))!);
    const url = listening.url as string;
    const call = () => fetch(url + "/v1/chat/completions", chat("vk-hup", { model: "m", messages: [{ role: "user", content: "hi" }] }, { "x-audit-use-case": "chat" }));
    assert.equal((await call()).status, 200);

    writeFileSync(cfgPath, JSON.stringify({
      keys: [{ name: "client", sha256: sha256("vk-hup"), useCases: ["chat"] }],
      useCases: { chat: { tier: "off" } },
    }));
    child.kill("SIGHUP");
    await waitFor(/"event":"config_reloaded"/);
    assert.equal((await call()).status, 403);

    writeFileSync(cfgPath, JSON.stringify({
      piiVault: { directory: join(dir, "vault"), ttlSeconds: 3600 },
      keys: [{ name: "client", sha256: sha256("vk-hup"), useCases: ["chat"] }],
      useCases: { chat: { tier: "assist" } },
    }));
    const badReload = await fetch(url + "/audit/reload", { method: "POST", headers: { "x-admin-key": adminKey } });
    assert.equal(badReload.status, 400);
    assert.equal((await badReload.json() as { error: { code: string } }).error.code, "audit_reload_requires_restart");
    assert.equal((await call()).status, 403);
    assert.deepEqual(new AuditLog(logPath).verifyChain(), { ok: true });
  } finally {
    child.kill("SIGTERM");
    up.close();
  }
});
