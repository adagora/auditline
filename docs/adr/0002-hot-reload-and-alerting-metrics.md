# 0002: Atomic fail-safe gateway hot-reload and PII/reload alerting metrics

## Status
Accepted

## Context
During a security incident (e.g., compromised virtual key, runaway use case, or untrusted tool-call exfiltration), restarting the proxy drops active SSE streams and adds deployment friction. Operators need sub-second policy updates (flipping a use case to `tier: "off"`, tightening `actionGate` from `observe` to `enforce`, revoking or rotating virtual keys, updating aliases) without restarting the process, plus Prometheus/Grafana alerts covering PII vault failures and rejected reloads.

## Decision
1. Encapsulate reloadable gateway policy (`keys`, `useCases`, `actionGate`, `aliases`, `pageRedaction`, `adminKeySha256`) in an immutable per-generation snapshot inside `createProxy()`. Every HTTP request pins `const snap = current` on arrival so in-flight streams finish consistently while new requests see the swapped snapshot immediately.
2. Expose hot-reload via three surfaces: programmatic `server.reload(next?, trigger?)`, authenticated `POST /audit/reload` (`x-admin-key`), and `SIGHUP` in `auditline serve --config gateway.json`.
3. Validate the entire candidate snapshot before swapping. Invalid JSON, schema errors, or attempts to toggle process-level invariants (`piiVault` or `budgetDirectory`) fail closed with `audit_reload_*`, leave the active snapshot untouched, and increment `ai_audit_config_reloads_total{trigger,result="failed"}`. Successful reloads increment `ai_audit_config_generation`, emit a content-free stderr event, and append a hash-chained `config-reload` record to the audit log.
4. Add bounded-label OpenMetrics counters `ai_audit_pii_vault_errors_total{reason}`, `ai_audit_config_reloads_total{trigger,result}`, and gauge `ai_audit_config_generation`, paired with Grafana alert rules (`ai-audit-pii-vault-errors`, `ai-audit-config-reload-failed`) and dashboard panels.

## Consequences
- Operators can kill-switch a use case or switch `actionGate` to `enforce` in milliseconds with zero dropped streams and full hash-chained auditability.
- Process-level invariants (`mode`, `piiVault` on/off, `budgetDirectory`, `--log`) still require a restart by design so security boundaries cannot be silently downgraded.
- Monitoring stacks immediately page on PII vault failures (`502`/`422`/`503`) and rejected hot-reloads.
