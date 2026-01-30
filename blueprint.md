## Blueprint

### 0) Non-negotiables (project guardrails)

* **TDD always**: write/extend tests first, then implement.
* **Real data in tests**: tests must run against **real Triage JSON responses** saved as fixtures (captured from the API), not hand-crafted “toy” JSON.
* **Small steps, always integrated**: every step produces working code that’s reachable from the CLI or from an integration test—no orphan modules.
* **Deterministic runs**: integration tests must not depend on live Triage; they must use captured fixtures + a local fixture server.
* **Traceability**: every extracted artifact must include provenance (sample hash(es), families if present, timestamps).
* **Safety**: strict validation (Pydantic), defensive parsing, clear error reporting, and rate limiting in the real client.

---

## 1) Detailed step-by-step plan (end-to-end)

### Phase A — Repository foundation (fast feedback loop)

1. Create repo skeleton exactly as in the spec (`extractor/`, `tests/`, `output/`, `cache/`, `logs/`).
2. Add Python tooling:

   * `requirements.txt`
   * `pyproject.toml` for formatting/lint/type-check config (black/isort/mypy)
   * `pytest.ini` with markers and sensible defaults
3. Add baseline CLI entry point (`extractor/cli.py`) with commands stubbed but wired.
4. Add logging setup and a `--debug` flag plumbed through CLI.

**Deliverable:** `pytest` runs, CLI runs (`python -m extractor.cli --help`), even if it does “nothing” yet.

---

### Phase B — Real-data fixtures pipeline (enables all testing)

5. Add `scripts/capture_fixtures.py` that:

   * takes `TRIAGE_API_KEY`
   * takes a list of known sample IDs (or a search query)
   * downloads `/samples/{id}/overview`, `/behavioral1`, `/behavioral2` (if present)
   * saves them into `tests/fixtures/<os>/<sample_id>/...json`
6. Add tests that **fail with an actionable message** if fixtures aren’t present.
7. Add a tiny local “fixture HTTP server” used by tests to simulate Triage endpoints returning the captured JSON.

**Deliverable:** tests can run offline using fixtures, and you have a repeatable way to refresh fixtures.

---

### Phase C — Core data models + validation

8. Implement Pydantic models:

   * `Artifact`
   * `SampleMetadata`
   * `ExtractionResult`
9. Implement artifact ID generation (`art-{os}-{type}-{hash8}`) deterministically.
10. Write validation tests using real fixture-derived values.

**Deliverable:** models enforce schema, and tests prove they accept real Triage-driven content.

---

### Phase D — OS extractors (incremental, one capability at a time)

For each OS extractor:

* implement a minimal extractor that reads a single field and emits artifacts,
* then expand field-by-field.

11. Android:

* filesystem → artifacts
* properties_read → artifacts
* package_queries → artifacts
* network loopback probes → port artifacts

12. Windows:

* filesystem checks
* registry checks
* process enumeration checks
* WMI query checks
* mutex checks

13. Linux:

* filesystem checks
* process checks
* environment variable checks

14. macOS:

* filesystem checks
* command/system_profiler checks

**Deliverable:** per-OS unit tests verify extraction from real fixture reports.

---

### Phase E — Aggregation, scoring, filtering

15. Deduplicate by `(os, artifact_type, match_criteria.value)` and merge provenance.
16. Confidence scoring per spec.
17. Filtering per spec (min sample count + min confidence + exclude patterns).

**Deliverable:** given artifacts from multiple fixture samples, output is stable and correct.

---

### Phase F — Output writers (all wired)

18. JSON writer produces:

* `output/artifacts.json` (full)
* per-OS JSON files (optional)

19. YAML writer produces deception configs per OS.
20. Change reporter compares to previous run and emits `extraction_changes.json`.

**Deliverable:** end-to-end pipeline writes all required artifacts and tests validate on disk.

---

### Phase G — Real Triage API client + caching + rate limiting

21. Implement `TriageClient` with:

* auth header
* token bucket rate limiting
* retry/backoff for 429/5xx/timeouts

22. Implement SQLite cache with TTL rules.
23. Integration test the client against the local fixture server.

**Deliverable:** client is correct offline; can be pointed at real Triage later.

---

### Phase H — Full pipeline + CLI commands

24. Implement `extract`:

* search by OS tag + date + min score
* fetch overview + behavioral reports (using cache)
* run OS extractor
* aggregate + score + filter
* write outputs

25. Implement CLI commands in spec:

* `extract`, `extract-sample`, `stats`, `clear-cache`, `validate-config`, `generate-deception`

26. CLI integration tests via `click.testing.CliRunner`.

**Deliverable:** one command runs the whole system deterministically using fixtures.

---

## 2) Break into “right-sized” iterative chunks (1st pass)

1. **Chunk 1 — Foundation + CLI skeleton**
2. **Chunk 2 — Fixture capture + offline test harness**
3. **Chunk 3 — Models + schema enforcement**
4. **Chunk 4 — Android extractor (complete)**
5. **Chunk 5 — Windows extractor (complete)**
6. **Chunk 6 — Linux + macOS extractors (complete)**
7. **Chunk 7 — Aggregation/scoring/filtering**
8. **Chunk 8 — Output writers + change report**
9. **Chunk 9 — Triage client + caching + rate limiting (tested offline)**
10. **Chunk 10 — Full pipeline wiring + CLI commands**

---

## 3) Break chunks into smaller steps (2nd pass)

### Chunk 1 — Foundation + CLI

* 1.1 Create structure + deps + pytest config
* 1.2 Add CLI group + help text + logging wiring
* 1.3 Add “no-op extract” command returning structured empty result

### Chunk 2 — Fixtures + offline harness

* 2.1 Add fixture folder conventions + conftest loader
* 2.2 Add capture script (real API → fixture files)
* 2.3 Add local fixture server + tests for endpoints

### Chunk 3 — Models

* 3.1 Implement Artifact model + ID generator
* 3.2 Implement SampleMetadata model
* 3.3 Implement ExtractionResult model + serialization helpers

### Chunk 4 — Android extractor

* 4.1 filesystem only
* 4.2 properties_read
* 4.3 package_queries
* 4.4 loopback port probes

### Chunk 5 — Windows extractor

* 5.1 filesystem only
* 5.2 registry
* 5.3 processes
* 5.4 WMI
* 5.5 mutexes

### Chunk 6 — Linux/macOS

* 6.1 Linux filesystem
* 6.2 Linux processes + env vars
* 6.3 macOS filesystem
* 6.4 macOS command parsing

### Chunk 7 — Aggregation/scoring/filtering

* 7.1 deduplicator
* 7.2 scorer
* 7.3 filter

### Chunk 8 — Outputs

* 8.1 JSON writer
* 8.2 per-OS splitting
* 8.3 YAML deception writer
* 8.4 change reporter

### Chunk 9 — Client

* 9.1 thin HTTP client (get)
* 9.2 retries/backoff + rate limiter
* 9.3 cache wrapper
* 9.4 client integration tests vs fixture server

### Chunk 10 — Pipeline + CLI

* 10.1 “extract-sample” pipeline from fixture server
* 10.2 search + poller
* 10.3 full `extract` + outputs
* 10.4 remaining CLI commands

---

## 4) Final micro-steps (3rd pass — the “implementation-safe” granularity)

Below is the final step sizing that’s small enough to implement safely with strong tests, but large enough to move forward. This is what the prompt sequence will implement.

1. Repo scaffold + pytest + minimal CLI wired
2. Logging + config file loader (YAML + env overrides)
3. Fixture conventions + loader utilities + “fixtures missing” test
4. Fixture capture script (real Triage) + documentation
5. Local fixture server for offline HTTP tests
6. Pydantic `Artifact` + ID generator + unit tests
7. Pydantic `SampleMetadata` + `ExtractionResult` + unit tests
8. Android extractor: filesystem extraction (real fixture)
9. Android extractor: properties_read extraction
10. Android extractor: package_queries extraction
11. Android extractor: loopback port probe extraction
12. Windows extractor: filesystem extraction
13. Windows extractor: registry extraction
14. Windows extractor: process extraction
15. Windows extractor: WMI + mutex extraction
16. Linux extractor: filesystem + process + env var extraction
17. macOS extractor: filesystem + command parsing extraction
18. Deduplicator + scorer + filter (tested with multi-sample artifacts)
19. Output writers: JSON + per-OS + YAML deception configs
20. Change reporter
21. Triage client: basic GET + error handling (fixture server)
22. Triage client: rate limiting + retries + caching
23. Pipeline: extract-sample end-to-end (fixture server)
24. Pipeline: search + extract end-to-end (fixture server)
25. CLI: all commands implemented + CLI integration tests

---

# Prompt Pack (for a code-generation LLM)

Each prompt is designed to be run **in order**. Every prompt:

* adds/updates tests first,
* uses **real captured fixture JSON**,
* wires new code into the pipeline (no orphan code),
* ends with `pytest` passing.

> **Important**: Prompts assume Python 3.11+ and `pytest`.

---

## Prompt 01 — Scaffold repo + pytest + minimal CLI

```text
You are implementing the “Triage Evasion Artifact Extractor” as a Python package.

Goal (TDD): Create the initial repo skeleton, dependencies, pytest configuration, and a minimal Click-based CLI that runs.

Requirements:
1) Create the project structure exactly matching the spec (extractor/..., tests/..., scripts/..., output/cache/logs directories).
2) Add requirements.txt with the dependencies listed in the spec.
3) Add pytest.ini and a minimal tests/test_smoke.py that asserts:
   - importing extractor works
   - running CLI help exits 0
4) Add extractor/cli.py with a Click group and a single command `version` that prints “Triage Artifact Extractor v1.0”.
5) Ensure `python -m extractor.cli --help` works.

Do NOT implement extraction logic yet.

Acceptance:
- `pytest -q` passes.
- `python -m extractor.cli version` prints the version string.
```

---

## Prompt 02 — Logging + configuration loader (YAML + env overrides)

```text
Goal (TDD): Implement configuration loading as described in the spec.

Tasks:
1) Add extractor/config.py:
   - Load YAML from path (default ./config.yaml or env EXTRACTOR_CONFIG)
   - Validate with Pydantic (create a Config model that mirrors the schema in spec section 7.1)
   - Allow env overrides: EXTRACTOR_OUTPUT_DIR and EXTRACTOR_LOG_LEVEL
2) Add logging initialization in extractor/logging.py:
   - config-driven log level, optional file logging
   - console logging always
3) Wire CLI to load config at startup and initialize logging.
4) Add tests:
   - config loads from tests/fixtures/config_minimal.yaml (create it)
   - env overrides work
   - invalid config yields a clear exception message

Acceptance:
- `pytest -q` passes.
- CLI help still works even if config file is missing (only commands that need config should require it).
```

---

## Prompt 03 — Fixture conventions + loader utilities + missing-fixtures failure message

```text
Goal (TDD): Establish a “real data” fixture standard and make tests fail loudly/helpfully when fixtures are missing.

Fixture standard:
tests/fixtures/
  <os>/
    <sample_id>/
      overview.json
      behavioral1.json
      behavioral2.json (optional)

Tasks:
1) Add extractor/testing/fixtures.py with helpers:
   - list_fixture_samples(os)
   - load_fixture_json(os, sample_id, name)
2) Add tests that:
   - assert the fixture directory exists
   - if no fixtures exist, skip extraction tests but fail with a single clear message telling how to run scripts/capture_fixtures.py
3) Add a new test marker “requires_fixtures” and configure pytest to show skips clearly.

Acceptance:
- `pytest -q` passes even with no fixtures, but the output tells exactly how to capture them.
- The fixture helpers are imported and unit-tested.
```

---

## Prompt 04 — Fixture capture script (real Triage API → fixtures)

```text
Goal (TDD): Create scripts/capture_fixtures.py that downloads real Triage responses and stores them as fixtures.

Behavior:
- Requires TRIAGE_API_KEY env var
- Accepts args:
  --os android|windows|linux|macos
  --sample-id <id> (repeatable)
  --out tests/fixtures (default)
- For each sample_id:
  GET /samples/{id}/overview
  GET /samples/{id}/behavioral1
  GET /samples/{id}/behavioral2 (if 404, skip)
- Save JSON exactly as returned (no reformat that changes semantics)

Tasks:
1) Implement the script using requests and the base_url from config defaults.
2) Add a unit test that runs the script in “offline mode” by pointing base_url at the local fixture server stub (we’ll implement server next), asserting it writes files.

Acceptance:
- Script has --help.
- Test passes without hitting the internet.
```

---

## Prompt 05 — Local fixture HTTP server for offline HTTP tests

```text
Goal (TDD): Implement a small local HTTP server used by tests to serve captured fixture JSON via Triage-like routes.

Tasks:
1) Add extractor/testing/fixture_server.py:
   - Start/stop server on a random port
   - Routes:
     /api/v0/samples/<id>/overview
     /api/v0/samples/<id>/behavioral1
     /api/v0/samples/<id>/behavioral2
   - It should read from tests/fixtures/<os>/<id>/...json (search all OS folders)
2) Add tests:
   - server returns 200 + correct JSON for an existing fixture
   - server returns 404 for missing fixture

Acceptance:
- `pytest -q` passes.
- This server is used by later client tests.
```

---

## Prompt 06 — Artifact model + deterministic ID generator

```text
Goal (TDD): Implement the Pydantic Artifact model from spec section 2.1, plus deterministic artifact ID generation.

Tasks:
1) Add extractor/models/artifact.py implementing:
   - MatchCriteria model
   - Provenance model
   - Metadata model
   - Deception model
   - Artifact model
2) Add extractor/models/id.py with helper:
   - artifact_id(os, artifact_type, match_value) -> art-{os}-{type}-{hash8}
     (use sha256 of “os|type|match_value”, first 8 hex)
3) Add unit tests:
   - ID is stable and matches expected
   - Artifact validates required fields
   - case_sensitive defaults as specified (Linux/Android true, Windows false)

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 07 — SampleMetadata + ExtractionResult models

```text
Goal (TDD): Add remaining Pydantic models and serialization helpers.

Tasks:
1) Add extractor/models/sample.py for SampleMetadata (spec 2.3)
2) Add extractor/models/extraction.py for ExtractionResult (spec 2.4)
3) Add tests:
   - Construct SampleMetadata from a real overview.json fixture and validate fields
   - Construct ExtractionResult containing at least one Artifact and serialize to JSON

Acceptance:
- `pytest -q` passes.
- Models tolerate missing optional fields gracefully.
```

---

## Prompt 08 — Android extractor: filesystem only (real fixture)

```text
Goal (TDD): Implement Android filesystem artifact extraction based on spec 4.1.1.

Tasks:
1) Add extractor/extractors/base.py:
   - BaseExtractor interface: extract(sample_metadata, behavioral_report) -> list[Artifact]
2) Add extractor/extractors/android.py implementing:
   - Parse behavioral.filesystem array
   - For each operation in [stat, access, open, exists], extract path checks
   - Categorize using the evasion_path_patterns in the spec (emulator/sandbox/hooking/root)
   - Emit Artifact objects with:
     os=android, artifact_type=file, category=<android category>, match_criteria.value=<path>
     provenance.sample_hashes includes the sha256 from SampleMetadata
3) Add tests using one real Android behavioral fixture:
   - It must assert at least 3 known paths are extracted and categorized correctly
   - If the fixture doesn’t contain those, the test should instead assert on whatever real paths exist in that fixture (derive expected values from the fixture file contents, not hard-coded guesses)

Acceptance:
- `pytest -q` passes.
- Android extractor is importable and used by its unit tests.
```

---

## Prompt 09 — Android extractor: properties_read

```text
Goal (TDD): Extend Android extractor to emit property artifacts from behavioral.properties_read.

Tasks:
1) In extractor/extractors/android.py, parse behavioral.properties_read array.
2) Emit Artifact with artifact_type=property and match_criteria.value=property name.
3) If value is present in the report, store it in metadata.description or provenance notes (choose a consistent place).
4) Add tests:
   - From the same real fixture, assert at least 1 property is extracted.
   - Derive expected property names from the fixture content (read the JSON in test).

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 10 — Android extractor: package_queries

```text
Goal (TDD): Extend Android extractor to emit package artifacts from behavioral.package_queries.

Tasks:
1) Parse behavioral.package_queries array.
2) Emit Artifact with artifact_type=package and match_criteria.value=package name.
3) Categorize into sandbox_packages / hooking_frameworks / root_indicators based on package name lists in the spec.
4) Add tests derived from fixture content.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 11 — Android extractor: loopback port probes

```text
Goal (TDD): Extend Android extractor to emit port artifacts from behavioral.network.

Rules:
- Only include loopback (127.0.0.1 or localhost)
- Only include results that indicate probing (refused/timeout)

Tasks:
1) Parse behavioral.network array.
2) Emit Artifact with artifact_type=port and match_criteria.value=str(port).
3) Categorize into network_probes.
4) Add tests derived from fixture content.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 12 — Windows extractor: filesystem

```text
Goal (TDD): Implement Windows filesystem extraction based on spec 4.2.1.

Tasks:
1) Add extractor/extractors/windows.py
2) Parse behavioral.filesystem array and extract paths, with case_sensitive=false.
3) Categorize into vm_files / sandbox_files / analysis_tools based on patterns in the spec.
4) Add tests derived from a real Windows fixture behavioral JSON.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 13 — Windows extractor: registry

```text
Goal (TDD): Extend Windows extractor to parse behavioral.registry and emit registry artifacts.

Tasks:
1) Parse registry operations and create Artifact objects with artifact_type=registry.
2) match_criteria.value should be a stable string representation:
   - “<key>” if only key is checked
   - “<key>\\<value_name>” if a value is queried
3) Add tests derived from fixture content.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 14 — Windows extractor: processes

```text
Goal (TDD): Extend Windows extractor to parse behavioral.processes and emit process artifacts.

Tasks:
1) Emit Artifact objects with artifact_type=process and match_criteria.value=process name.
2) Categorize into vm_processes / sandbox_processes / analysis_tools / debugger_indicators where possible.
3) Add tests derived from fixture content.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 15 — Windows extractor: WMI + mutexes

```text
Goal (TDD): Extend Windows extractor for WMI and mutex checks.

Tasks:
1) Parse behavioral.wmi:
   - Extract class/property when possible from query strings, but be defensive.
   - Store original query in metadata.description.
   - Emit artifact_type=wmi with match_criteria.value="<class>.<property>" or fallback to the query string.
2) Parse behavioral.mutexes (or behavioral.sync_objects if used in your real fixture):
   - Emit artifact_type=mutex with match_criteria.value=mutex name.
3) Add tests derived from fixture content.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 16 — Linux extractor: filesystem + process + env vars

```text
Goal (TDD): Implement Linux extraction (spec 4.3).

Tasks:
1) Add extractor/extractors/linux.py
2) filesystem -> file artifacts
3) processes -> process artifacts
4) environment -> environment_vars artifacts
5) Add tests derived from real Linux fixtures (if none exist, tests should skip with a clear message and still pass overall).

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 17 — macOS extractor: filesystem + commands

```text
Goal (TDD): Implement macOS extraction (spec 4.4).

Tasks:
1) Add extractor/extractors/macos.py
2) filesystem -> file artifacts
3) commands -> artifact_type=property or artifact_type=file? (choose a consistent representation; recommended: artifact_type=property with match_criteria.value="command:<command>")
4) Add tests derived from real macOS fixtures (skip if none exist).

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 18 — Aggregation: dedup + scoring + filtering

```text
Goal (TDD): Implement aggregation pipeline components.

Tasks:
1) Add extractor/aggregation/deduplicator.py:
   - Dedup key: (os, artifact_type, match_criteria.value)
   - Merge provenance.sample_count, sample_hashes (max 100), families union
   - Update metadata.last_seen to latest
2) Add extractor/aggregation/scorer.py:
   - Implement confidence formula from spec 5.2
3) Add extractor/aggregation/filter.py:
   - Apply min_sample_count and min_confidence
   - Apply exclude patterns from config
4) Add tests:
   - Use artifacts produced from 2+ fixture samples (same OS) and verify dedup merges properly and confidence increases.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 19 — Output writers: JSON + per-OS + YAML deception configs

```text
Goal (TDD): Implement output generation.

Tasks:
1) Add extractor/output/json_writer.py:
   - Write artifacts.json (schema per spec 6.1)
   - Optionally write per-OS JSON files when split_by_os=true
2) Add extractor/output/yaml_writer.py for deception configs:
   - Use artifacts to generate android/windows/linux deception YAML per spec 6.3
3) Add tests:
   - Run writer to a temp directory and validate files exist and contain expected keys and counts.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 20 — Change reporter

```text
Goal (TDD): Implement extraction_changes.json generation.

Tasks:
1) Add extractor/output/change_reporter.py:
   - Compare current artifacts to previous artifacts.json (by artifact.id)
   - new/updated/removed lists per spec 6.4
2) Add tests:
   - Create two small ExtractionResult objects using artifacts from fixtures and verify diff output.

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 21 — Triage client: basic GET + offline tests

```text
Goal (TDD): Implement the Triage API client (basic) and test it against the local fixture server (no real network).

Tasks:
1) Add extractor/triage/client.py:
   - requests.Session
   - base_url default https://tria.ge/api/v0
   - auth header “Authorization: Bearer <api_key>”
   - methods:
     get_sample_overview(sample_id)
     get_behavioral(sample_id, which=1|2)
2) Add tests:
   - Start fixture server
   - Point client base_url to server
   - Assert returned JSON matches fixture JSON exactly

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 22 — Client: rate limiting + retries + SQLite cache

```text
Goal (TDD): Add rate limiting, retry/backoff, and caching per spec.

Tasks:
1) Add extractor/triage/cache.py:
   - SQLite cache with TTL rules for overview (7d) and behavioral (30d)
2) Add extractor/triage/rate_limit.py:
   - token bucket
3) Enhance client:
   - If cached, return cached
   - On 429, exponential backoff up to max_retries
4) Add tests against fixture server:
   - Cache hit avoids a second HTTP call (instrument server request counter)
   - Simulate 429 then 200 (add a special server mode in tests) and confirm retries happen

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 23 — Pipeline: extract-sample end-to-end

```text
Goal (TDD): Implement a pipeline function that extracts artifacts for a single sample id end-to-end.

Tasks:
1) Add extractor/pipeline.py with function extract_sample(sample_id, config, triage_client) -> ExtractionResult
   - Fetch overview + behavioral1 (+ behavioral2 if available)
   - Determine OS from overview classification.tags or triage tags
   - Select correct extractor (android/windows/linux/macos)
   - Aggregate (dedup/score/filter) within that sample (still useful for normalization)
2) Add CLI command: `extract-sample <sample_id>`
   - Writes outputs to config output directory
3) Add integration test:
   - Use fixture server and a known fixture sample_id
   - Run CLI via CliRunner
   - Assert output files exist and contain artifacts > 0

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 24 — Pipeline: search + full extract (multi-OS)

```text
Goal (TDD): Implement full extraction: search -> process many samples -> write outputs.

Tasks:
1) Implement client.search(query) for /search endpoint.
2) Add extractor/poller.py:
   - build search queries per OS using lookback_days and min_score
   - limit max_samples_per_os
3) Implement pipeline extract(config) -> ExtractionResult:
   - for each OS, search, iterate samples, extract_sample, combine artifacts
   - aggregate across all samples
4) Add integration tests:
   - Extend fixture server to support /search returning fixture sample ids
   - Run CLI `extract --os android --days 7` against fixture server base_url override
   - Assert statistics and outputs match expectations

Acceptance:
- `pytest -q` passes.
```

---

## Prompt 25 — Finish CLI commands + stats/clear-cache/validate-config/generate-deception

```text
Goal (TDD): Implement remaining CLI commands from the spec, fully wired.

Tasks:
1) validate-config: loads config and validates; exits 0 on success.
2) stats: prints cache stats (count entries, size).
3) clear-cache: deletes cache db safely.
4) generate-deception --input artifacts.json: reads JSON and writes deception YAML.
5) Add CLI integration tests for each command using temporary directories.

Acceptance:
- `pytest -q` passes.
- All commands listed in spec section 8.1 exist and work.
```

---

If you want, I can also add a **“fixture acquisition checklist”** (which OSes + how many samples per OS) to ensure the first captured fixtures contain all the fields you need (filesystem, registry, wmi, etc.), so you don’t get blocked mid-implementation.

