# 0001: Expose qualification and authority CLI commands and case-correlated console views

## Status
Accepted

## Context
Auditline recorded optional `correlation` IDs on proxied `llm-call` and `decision` records and `pii` vault delivery metadata (`tokenized` vs `customer`), yet neither the operator console nor the workbench surfaced cases grouped by correlation or PII vault delivery mode. Meanwhile, `QualificationStore` and `AuthorityStore` existed as tested internal modules without CLI entry points, forcing connected applications (Deskhand, IntentGauge) to maintain parallel local scripts or ad-hoc grant books.

## Decision
1. Add first-class `auditline qualify` (`list`, `inspect`, `capture`) and `auditline authority` (`approve`, `activate`, `revoke`, `authorize`, `view`) commands to `src/cli.ts`, reusing `QualificationStore` and `AuthorityStore` directly with zero runtime dependencies.
2. Add `caseViews()` in `src/consoleModel.ts` and `GET /api/cases` / `GET /api/cases/:correlation` in `src/console.ts`, exposing `#/cases` and `#/cases/:correlation` in the operator console along with PII vault delivery telemetry across Console and Workbench.
3. Unify `auditline report` output to English to match all other Auditline surfaces.

## Consequences
- External applications and evaluators (Deskhand, IntentGauge) can deep-link directly to `/#/cases/<correlation>` and drive qualification/authority workflows through the single `auditline` binary.
- All records remain content-free; no raw PII or prompt text is exposed in Console or Workbench views.
- Existing `scripts/qualification.mjs` remains compatible while `auditline qualify` becomes the canonical interface.
