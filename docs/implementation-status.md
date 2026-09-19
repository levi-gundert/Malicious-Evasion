# Implementation status — September 19, 2026

The engineering work from the project review is implemented. This is a development release with candidate decoys, not a validated malware-prevention product. Existing local edits and unrelated diagnostic scripts were preserved and excluded from publication.

## Implemented

- Shared placement backend with immutable plans, exact-match and OS gates, exclusive creation, durable ownership journal, idempotent placement, startup reconciliation, and conservative rollback. Existing objects, modified decoys, hard-linked files, and nonempty directories are preserved. Parent creation is explicit. Unknown legacy placements cannot be deleted automatically.
- Windows parent-directory handle guards and file deletion through the same verified handle, reducing path-replacement races. Relative, wildcard, network/device, unresolved-variable, and symlink/reparse targets are rejected.
- Narrow elevated helper with structured input, no report-derived executable commands, Windows process completion/exit-code checks, explicit cancellation, post-placement verification, and matching removal operations. Linux/macOS elevation launch paths exist but need native testing; Android elevation is disabled.
- File/directory existence recipes and explicit Windows registry key/typed-value recipes in restricted decoy namespaces, including registry view. Unsupported process, WMI, package, property, and mutex placement fails explicitly.
- GUI per-artifact previews, background operations, real dashboard removal, capability labels, and separation of placement verification from untested efficacy. CLI plan/apply/remove/status commands use the same backend and journal.
- Unified JSON/YAML serialization, repaired statistics and output paths, OS detection fixes, preserved recipe data, canonical artifact IDs, legacy ID/reference migration with archived original rows, per-sample/report/task observations, unique sample counts, actual observation dates, and versioned processed-sample tracking.
- OS credential-store integration, memory-only fallback, and plaintext settings migration. Ordinary settings writes reject API keys. Migration is tested on synthetic data; the user's live database and credentials were not accessed for validation.
- Isolated download workers enforce total deadlines across downloads and retries, stream size limits, reject redirects, and terminate on timeout. Rate-limit waiting is included in the request budget.
- Authored offline Windows candidate catalog, expiry/retest gates, detached Ed25519 verification for external catalogs, explicit minimum accepted catalog version, benign probes, and paired-result summarization.
- Windows/Linux/macOS core CI matrix, Windows GUI smoke configuration, compatibility pin for the existing KivyMD API, corrected README, MIT license matching the previously declared license, contribution guidance, and a validation protocol.

## Validation performed

- Fresh `.venv` installation of core and GUI requirements; `pip check` reports no broken requirements.
- Full regression suite: **224 passed, 1 skipped** on Windows / Python 3.12.10. The skipped symlink test requires Windows symlink creation permission; the cross-platform CI matrix includes it where supported.
- Synthetic Windows HKCU registry creation/value verification/removal; existing-key preservation. No live VM vendor keys were modified.
- Local HTTP server tests for normal responses, slow streaming, retry deadlines, response-size limits, and rejected redirects. No live Triage request or credential was used.
- Benign file/directory before/during/after probes in temporary paths; all checks passed. Report: `output/benign-probes.json`.
- Hidden GUI smoke: four screens, candidate browsing, settings, and full placement preview against temporary state. No GUI placement executed. Log: `output/gui-smoke.log`.
- Fixture CLI extraction produced nine structured Windows artifacts, two JSON files, and one YAML file under `output/review-fixtures/`.
- Compile checks, formatting of new/replaced modules, and `git diff --check` passed.

## Remaining release gates

1. **Malware efficacy:** an isolated lab and an approved sample set are needed for repeated paired runs, held-out evaluation, and review of benign interference. The user was asked which lab is available. No fabricated efficacy results, protection percentages, or validated-catalog claims were added.
2. **Native platform validation:** see [GitHub Actions](https://github.com/levi-gundert/Malicious-Evasion/actions) for current cross-platform CI results. Actual UAC prompts and elevated writes have not been exercised on the developer machine; completion/cancellation are tested with mocked Windows APIs and the helper is tested without elevation. Linux/macOS elevation, POSIX adversarial rename races, and Android packaging need dedicated platform testing before broader release.
3. **Catalog publication:** the bundled entries remain candidates. External verification is implemented, but a maintainer-controlled signing key, distribution channel, and independently communicated public key are needed for production catalog publication. The tool does not auto-trust a key distributed with a catalog. There is no unattended network catalog updater.
4. **Legacy recovery:** pre-journal placements have no ownership proof. They remain a manual review task; guessing which pre-existing files or keys may be deleted would defeat the new safeguards.

The implementation intentionally favors preserving uncertain objects over claiming successful cleanup. It requires existing parent directories/keys and declines unsupported check semantics rather than substituting a different path or ineffective marker.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/smoke_gui.py
.\.venv\Scripts\python.exe -m extractor.cli placement probe --output output/benign-probes.json
.\.venv\Scripts\python.exe -m extractor.cli --config tests/fixtures/config_minimal.yaml extract --os windows --output output/review-fixtures
```

See `docs/validation-protocol.md` for the lab experiment and signed-catalog formats.
