import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { caseworkFixture } from "./caseworkFixture.js";

test("auditline qualify and authority CLI commands capture packages and enforce bounded grants end to end", () => {
  const f = caseworkFixture();
  const cli = fileURLToPath(new URL("../../dist/src/cli.js", import.meta.url));
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  const p = f.qualifications.load(f.request.packageDigest);
  const { digest, format, version, createdAt, components, suite, report, calibration, ...metadata } = p;
  writeFileSync(join(f.root, "component.json"), "synthetic-component");
  writeFileSync(join(f.root, "suite.json"), f.qualifications.read(suite));
  writeFileSync(join(f.root, "report.json"), f.qualifications.read(report));
  writeFileSync(join(f.root, "current.json"), JSON.stringify(f.current));
  writeFileSync(join(f.root, "principal.json"), JSON.stringify(f.actor));
  const selections = Object.fromEntries(Object.keys(components).map((name) => [name, { root: ".", files: ["component.json"] }]));
  const spec = join(f.root, "spec.json"), qStore = join(f.root, "q-store"), aStore = join(f.root, "a-store");
  writeFileSync(spec, JSON.stringify({ ...metadata, components: selections, suiteFile: "suite.json", reportFile: "report.json" }));

  const captured = run("qualify", "capture", "--store", qStore, "--spec", spec);
  assert.equal(captured.status, 0, captured.stderr);
  const pkg = JSON.parse(captured.stdout);
  assert.equal(pkg.assessment.integrity, true);

  const listed = run("qualify", "list", "--store", qStore);
  assert.equal(listed.status, 0, listed.stderr);
  assert.equal(JSON.parse(listed.stdout).length, 1);

  const inspected = run("qualify", "inspect", "--store", qStore, "--digest", pkg.package.digest, "--current", join(f.root, "current.json"));
  assert.equal(inspected.status, 0, inspected.stderr);
  assert.equal(JSON.parse(inspected.stdout).assessment.applicable, true);

  const expiresAt = new Date(Date.now() + 3600_000).toISOString();
  const grantReq = join(f.root, "grant.json");
  writeFileSync(grantReq, JSON.stringify({ ...f.request, packageDigest: pkg.package.digest, expiresAt }));
  const opReq = join(f.root, "operation.json");
  writeFileSync(opReq, JSON.stringify(f.operation));

  const deniedBefore = run("authority", "authorize", "--store", aStore, "--qualifications", qStore, "--request", opReq, "--current", join(f.root, "current.json"));
  assert.equal(deniedBefore.status, 1);
  assert.match(deniedBefore.stderr, /audit_authority_not_active/);

  const approved = run("authority", "approve", "--store", aStore, "--qualifications", qStore, "--principal", join(f.root, "principal.json"), "--request", grantReq, "--current", join(f.root, "current.json"));
  assert.equal(approved.status, 0, approved.stderr);
  const grant = JSON.parse(approved.stdout);

  const activated = run("authority", "activate", "--store", aStore, "--qualifications", qStore, "--principal", join(f.root, "principal.json"), "--grant", grant.id, "--current", join(f.root, "current.json"));
  assert.equal(activated.status, 0, activated.stderr);

  const authorized = run("authority", "authorize", "--store", aStore, "--qualifications", qStore, "--request", opReq, "--current", join(f.root, "current.json"));
  assert.equal(authorized.status, 0, authorized.stderr);
  assert.equal(JSON.parse(authorized.stdout).grant.id, grant.id);

  const viewed = run("authority", "view", "--store", aStore, "--qualifications", qStore, "--principal", join(f.root, "principal.json"));
  assert.equal(viewed.status, 0, viewed.stderr);
  assert.equal(JSON.parse(viewed.stdout).grants.length, 1);

  const revoked = run("authority", "revoke", "--store", aStore, "--qualifications", qStore, "--principal", join(f.root, "principal.json"), "--grant", grant.id, "--reason", "regression");
  assert.equal(revoked.status, 0, revoked.stderr);

  const deniedAfter = run("authority", "authorize", "--store", aStore, "--qualifications", qStore, "--request", opReq, "--current", join(f.root, "current.json"));
  assert.equal(deniedAfter.status, 1);
  assert.match(deniedAfter.stderr, /audit_authority_revoked/);
});
