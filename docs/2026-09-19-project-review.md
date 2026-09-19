# MEAP project review — September 19, 2026

MEAP has a useful research premise: reuse malware's environment checks as defensive decoys. The next release should prioritize safe placement and measured effectiveness. An observed anti-analysis check is a candidate for deception; it is not evidence that placing that artifact stops infection.

## Scope and verification

- Read [Start Digging Decoys](https://intelligence2risk.substack.com/p/were-all-counter-intel-experts-now) and inspected the referenced [repository](https://github.com/levi-gundert/Malicious-Evasion).
- GitHub HEAD and local HEAD both resolve to `a4da0e43b8103e0ae4411b9cdc9098ff91515434` (February 9, 2026).
- The working tree has pre-existing edits and untracked diagnostic scripts. They were preserved. The placement, elevation, aggregation, API client, output, pipeline, database, updater, and relevant test files discussed below match HEAD. Tests ran against the working tree, including its existing extractor edits.
- No live malware was executed, no Triage credentials were inspected or used, and no privileged placement was attempted. Reproductions used temporary files, synthetic objects, and a mocked network operation.
- This is a focused code and test review, not an effectiveness benchmark or a complete security audit. No application code was changed.

## Priority 1: Make placement non-destructive and reversible

**Confirmed data-loss defect.** `gui/services/placement_engine.py:150` opens a destination with mode `w`, replacing existing content. Removal at line 208 deletes whatever occupies that path without verifying ownership. A temporary-file reproduction confirmed that placement overwrote original content and removal then deleted the original file. Both operations reported success.

Registry placement similarly opens or creates keys without recording whether they existed; removal attempts to delete the key. The placement table (`gui/services/database.py:98`) records a path and status, but no original state, ownership, or content fingerprint. Logging happens after the modification, leaving a recovery gap if the application stops between those steps. Elevated artifacts are removed through ordinary unelevated calls.

**Recommended change:** introduce a structured placement plan and durable operation journal. Default to refusing existing objects; use exclusive creation, reject symlinks/reparse-point traversal and unsupported target forms, and record the actual resolved destination plus exactly which objects MEAP created. On undo, verify ownership and unchanged content before removal. Record intent before mutation and reconcile interrupted operations at startup. Apply matching elevation rules to rollback.

**Acceptance:** existing files and registry objects remain unchanged; repeated placement is idempotent; externally modified decoys are preserved; interrupted placement can be reconciled; uninstall removes only unchanged objects owned by MEAP.

## Priority 1: Keep report-derived values out of executable commands

**Code-confirmed injection risk.** Artifact paths are inserted directly into PowerShell and shell scripts (`gui/services/placement_engine.py:178`, `:190`). Registry paths are inserted into `reg add` command text; Android property names are interpolated into `setprop` commands. Report-derived strings are untrusted, and shell quoting around a string does not universally prevent interpolation or command substitution. This is a dangerous boundary when elevation is requested. No exploit was executed during this review.

**Recommended change:** use a narrowly scoped privileged helper that accepts a validated data structure and performs filesystem/registry operations through APIs. Validate target OS, artifact type, exact-match semantics, canonical target, registry hive/view, and allowed operation. Reject wildcards, unresolved variables, relative or device paths, and unsupported operations. Avoid arbitrary command execution in the helper.

**Acceptance:** crafted paths and property names are rejected or handled literally in mocked tests; they cannot become commands. A dry run exposes the complete resolved operation before placement.

## Priority 1: Report actual completion of elevated operations

`gui/services/privilege_manager.py:143` treats a successful `ShellExecuteW` launch as successful completion, then immediately deletes the temporary PowerShell script at line 154. The child may not have read that script yet, and its exit status is never checked. The GUI subsequently records a successful placement.

Microsoft documents the return value as launch success, not the invoked command's final result: [ShellExecuteW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew).

**Recommended change:** obtain a child process handle, wait outside the UI thread, collect its exit status, verify the resulting object, and remove the temporary script only after completion. Distinguish pending, cancelled, failed, and verified placements.

**Acceptance:** denial, command failure, and partial creation cannot appear as successful placement; the UI remains responsive.

## Priority 1: Restore the test and export baseline

The normal command `python -m pytest -q -p no:cacheprovider` stops during collection because `tests/unit/test_output.py:30` imports a missing `artifact_to_dict` function.

Excluding that module for diagnosis produced **158 passed, 4 failed**:

- Two failures concern Android/Windows platform-based OS inference.
- Two failures concern output creation, including a full fixture pipeline run.

The output issue is a real caller/writer mismatch: `extractor/pipeline.py:248` produces a list, while `extractor/output/json_writer.py:11` expects an OS-keyed dictionary and calls `.values()`. The writer also returns `None`, while callers expect output paths. Using `default=str` can stringify model objects rather than preserve a useful artifact schema.

**Recommended change:** establish one serialization contract across CLI, GUI, JSON, and YAML; reconcile output tests with the intended public interface; add CI on supported desktop platforms. Include meaningful tests for placement conflicts, rollback ownership, injection rejection, elevation failures, and interrupted operations. No GitHub Actions workflow or placement/elevation-specific test module was found in the tracked tree.

**Acceptance:** the unmodified full test command passes; fixture extraction produces parseable structured records and valid returned paths. A documented installation and CLI smoke test runs in a clean environment.

## Priority 2: Separate observed evidence from demonstrated efficacy

`extractor/aggregation/scorer.py` derives confidence from sample counts, family diversity, and recency. That score does not measure whether malware terminates, delays execution, or continues with harmful behavior after seeing a decoy.

There are additional evidence-quality defects:

- `extractor/aggregation/deduplicator.py:64` sums sample counts even when both records contain the same hash. A synthetic reproduction merged one sample with itself and reported two samples. It also does not union all provenance identifier fields.
- Extractor factories assign extraction time to first/last seen. Reprocessing an old report can make it appear recent.
- `gui/services/updater.py:530` independently generates IDs with hyphen-separated input, while `extractor/models/id.py` uses pipe separators. The same artifact can have different identities across subsystems.
- The GUI database stores one source sample per artifact, which limits visibility into supporting observations.

**Recommended change:** store separate sample/artifact observations, deduplicate by sample hash, retain report/task/event evidence and actual observation time, and use one canonical ID function with a migration for existing references. Separate observation strength, placement feasibility, and experimentally measured efficacy.

For validation, compare identical isolated environments with and without a decoy. Begin with benign probes to check that each intended existence/value test is satisfied. Controlled malware evaluation should then distinguish termination from delay or unrelated failure, with repeated trials and a held-out sample set. Track family/sample coverage and benign application interference. Keep untested records explicitly labeled as candidates.

## Priority 2: Preserve the semantics of the original check

The model includes `recommended_value` and `plant_as`, but the GUI conversion in `gui/services/updater.py:535` drops that guidance. Placement is primarily driven by artifact type and a string value.

Examples of gaps:

- Registry placement creates a key; it does not implement a typed registry value comparison.
- Android property placement always sets `1`, disregarding the recommended value.
- An Android marker file is not evidence that a package-manager query will find an installed package.
- Mutex placement returns success before the worker confirms creation, lasts at most one hour, and has no removal route.
- Process, WMI, service, and other extracted types are unsupported by the placement dispatcher.
- A user-space substitute path does not satisfy a check for a specific system path.

**Recommended change:** introduce explicit recipes for existence, directory existence, typed registry values, and other supported semantics. Display extracted, placeable, placed, and verified states separately. Gate unsupported combinations and foreign-OS artifacts in the backend as well as the UI. Expand capabilities only when their behavior and rollback have tests.

## Priority 2: Enforce real network deadlines

`extractor/triage/client.py:749`, `:808`, and `:905` use `ThreadPoolExecutor` context managers around timed waits. Cancelling a running future does not terminate it; leaving the context waits for the worker. Python documents this behavior in [concurrent.futures](https://docs.python.org/3/library/concurrent.futures.html).

A mocked overview fetch with a 30 ms configured deadline and a 250 ms worker took **253 ms** to return. The existing mechanism therefore does not enforce its advertised total deadline.

**Recommended change:** implement bounded network reads, retry budgets, and a total request deadline with a cancellation strategy that actually closes or isolates the work. Merely switching to `shutdown(wait=False)` does not terminate the worker. Add size limits while streaming reports and test slow/chunked responses. Version processed-sample records by extractor version so improved rules can reprocess cached reports deliberately.

## Priority 2: Store the API key securely

The settings screen persists the API key through the ordinary SQLite settings table (`gui/screens/settings.py`, `gui/services/database.py:624`). `keyring` is listed as a dependency but no GUI usage was found. The README's environment-only secret-storage claim does not match this route.

**Recommended change:** use the OS credential store on supported desktops, retain environment-variable support, and migrate existing stored keys without logging them. Offer session-only storage if a secure backend is unavailable.

## Suggested release sequence

1. **Safety and reliability release:** protect existing objects, replace interpolated elevated commands, implement verified completion and rollback, restore exports and the full test suite, and add CI.
2. **Evidence release:** unify IDs and schemas, preserve exact check semantics, deduplicate observations, and expose provenance and validation status.
3. **Validated Windows catalog:** publish a small reviewed set of recipes with measured results, compatibility notes, expiry/retest dates, and authenticated catalog updates. An offline catalog could let ordinary users try validated decoys without needing a personal Triage API key, subject to source-data redistribution permissions.
4. **Broaden platform support:** extend the same placement, verification, and rollback requirements to macOS, Linux, and Android. A portable GUI alone does not establish equivalent defensive behavior across operating systems.

Also fix the placeholder clone URL, clarify extraction versus placement support in the README, and add the missing tracked license/contribution files referenced there.

The strongest next milestone is a small, safe, measurable Windows release whose interface can explain which check each decoy satisfies, what evidence supports it, and how it can be completely removed.
