# Triage Evasion Artifact Extractor — TODO Checklist (v1.0)

> Use this as a step-by-step checklist. Each item should end in a green test run (`pytest -q`) unless explicitly marked "manual".

---

## API Documentation (Reference)

- [x] Created `docs/triage_api_reference.md` - Complete API reference with endpoints, authentication, rate limits
- [x] Created `docs/behavioral_data_mapping.md` - Maps Triage data structures to extraction requirements
- [x] Updated `spec.md` Section 3 - Corrected API endpoints and search query syntax
- [x] Updated `spec.md` Section 14 - Added kernel log structures (onemon.json, bigmac.json, stahp.json)

**Key API Notes:**
- Base URL: `https://api.tria.ge` (Python client default)
- Auth: `Authorization: Bearer <api_key>`
- Behavioral data comes from: `report_triage.json` AND platform kernel logs
- Search uses `from:` for dates (not `submitted:`)

---

## 0) Prep and guardrails

- [x] Decide Python version (recommended: 3.11+)
- [x] Decide package manager (pip + venv is fine; uv/poetry ok too)
- [x] Confirm **TDD rule**: tests first, then code
- [x] Confirm **real-data rule**: tests must use **captured Triage JSON fixtures**, not toy mocks
- [x] Add `.gitignore` for:
  - [x] `output/`
  - [x] `cache/`
  - [x] `logs/`
  - [x] `.venv/`
  - [x] `__pycache__/`

---

## 1) Repo scaffold and tooling

### 1.1 Project structure (match spec)
- [x] Create directories:
  - [x] `extractor/`
  - [x] `extractor/triage/`
  - [x] `extractor/extractors/`
  - [x] `extractor/aggregation/`
  - [x] `extractor/output/`
  - [x] `extractor/models/`
  - [x] `extractor/testing/`
  - [x] `tests/`
  - [x] `tests/unit/`
  - [x] `tests/integration/`
  - [x] `tests/fixtures/`
  - [x] `scripts/`
  - [x] `output/` (gitignored)
  - [x] `cache/` (gitignored)
  - [x] `logs/` (gitignored)

### 1.2 Dependencies and configs
- [x] Add `requirements.txt` (per spec)
- [x] Add `pyproject.toml` (black/isort/mypy config)
- [x] Add `pytest.ini`:
  - [x] define markers: `requires_fixtures`, `integration`
  - [x] default options: quiet-ish output but readable skips
- [x] Add minimal `README.md`:
  - [x] how to install
  - [x] how to run tests
  - [x] how to capture fixtures
- [x] Add `config.yaml.example` from spec

### 1.3 Minimal CLI smoke
- [x] Implement `extractor/cli.py` with Click:
  - [x] `--help` works
  - [x] `version` command prints `Triage Artifact Extractor v1.0`
- [x] Add `tests/test_smoke.py`:
  - [x] imports `extractor`
  - [x] runs `python -m extractor.cli --help` exit code 0
  - [x] runs `python -m extractor.cli version` prints expected

---

## 2) Configuration and logging

### 2.1 Config loader
- [x] Implement `extractor/config.py`:
  - [x] loads YAML from `./config.yaml` by default
  - [x] supports env var `EXTRACTOR_CONFIG` path override
  - [x] supports env overrides:
    - [x] `EXTRACTOR_OUTPUT_DIR`
    - [x] `EXTRACTOR_LOG_LEVEL`
  - [x] validates with Pydantic Config model (mirror spec 7.1)
- [x] Add fixture config file: `tests/fixtures/config_minimal.yaml`

### 2.2 Logging
- [x] Implement `extractor/logging.py`:
  - [x] console logger always on
  - [x] file logger if configured
  - [x] respects log level from config/env
- [x] Wire CLI to init logging (only for commands that need it)

### 2.3 Tests
- [x] Unit tests:
  - [x] config loads minimal yaml
  - [x] env overrides apply
  - [x] invalid config raises clear error

---

## 3) Real-data fixtures (critical path)

> **Goal:** tests never hit live Triage; they use saved JSON.

### 3.1 Fixture conventions
- [x] Document fixture layout:
  - [ ] `tests/fixtures/<os>/<sample_id>/overview.json`
  - [ ] `tests/fixtures/<os>/<sample_id>/behavioral1/report_triage.json`
  - [ ] `tests/fixtures/<os>/<sample_id>/behavioral1/logs/stahp.json` (Android/Linux)
  - [ ] `tests/fixtures/<os>/<sample_id>/behavioral1/logs/onemon.json` (Windows)
  - [ ] `tests/fixtures/<os>/<sample_id>/behavioral1/logs/bigmac.json` (macOS)
  - [ ] `tests/fixtures/<os>/<sample_id>/behavioral2/...` (optional)

### 3.2 Fixture loader utilities
- [ ] Implement `extractor/testing/fixtures.py`:
  - [ ] `list_fixture_samples(os)`
  - [ ] `load_fixture_json(os, sample_id, name)`
  - [ ] helper to discover `sample_id` across OS folders

### 3.3 “Fixtures missing” behavior
- [ ] Add tests that:
  - [ ] if no fixtures exist → skip `requires_fixtures` tests
  - [ ] BUT produce one clear message: how to run capture script to populate fixtures

### 3.4 Fixture capture script (manual + testable)
- [ ] Implement `scripts/capture_fixtures.py` (**manual**):
  - [ ] requires `TRIAGE_API_KEY`
  - [ ] args: `--os`, `--sample-id` repeatable, `--out`
  - [ ] downloads:
    - [ ] `/samples/{id}/overview.json`
    - [ ] `/samples/{id}/behavioral1/report_triage.json`
    - [ ] `/samples/{id}/behavioral2/report_triage.json` (404 ok)
    - [ ] `/samples/{id}/behavioral1/logs/{platform}.json` (kernel logs - 404 ok)
  - [ ] saves JSON as-is (no semantic changes)
  - [ ] platform kernel log files:
    - [ ] Windows: `onemon.json`
    - [ ] macOS: `bigmac.json`
    - [ ] Linux/Android: `stahp.json`
- [ ] Add automated test that runs capture script against fixture server (offline)

### 3.5 Local fixture HTTP server
- [ ] Implement `extractor/testing/fixture_server.py`:
  - [ ] serves Triage-like routes:
    - [ ] `/samples/<id>` - sample metadata
    - [ ] `/samples/<id>/overview.json` - overview report
    - [ ] `/samples/<id>/<task>/report_triage.json` - behavioral report
    - [ ] `/samples/<id>/<task>/logs/<platform>.json` - kernel logs
    - [ ] `/search` - return fixture sample IDs
  - [ ] returns 404 for missing JSON
- [ ] Tests:
  - [ ] existing fixture returns 200 + correct JSON
  - [ ] missing fixture returns 404

---

## 4) Core Pydantic models

### 4.1 Artifact + ID generator
- [x] Implement `extractor/models/id.py`:
  - [x] deterministic `artifact_id(os, artifact_type, match_value)` → `art-{os}-{type}-{hash8}`
- [x] Implement `extractor/models/artifact.py`:
  - [x] `MatchCriteria`
  - [x] `Metadata`
  - [x] `Provenance`
  - [x] `Deception`
  - [x] `Artifact`
- [x] Defaults:
  - [x] `case_sensitive`: true for android/linux, false for windows (macos choose true)
- [x] Tests:
  - [x] ID stability
  - [x] model validation and defaults

### 4.2 SampleMetadata
- [x] Implement `extractor/models/sample.py`
- [x] Tests:
  - [x] load from a real `overview.json` fixture
  - [x] tolerate missing optional fields

### 4.3 ExtractionResult
- [x] Implement `extractor/models/extraction.py`
- [x] Tests:
  - [x] build minimal ExtractionResult
  - [x] serialize to JSON
  - [x] validate statistics fields

---

## 5) Extractors (OS-specific) — implement incrementally

> Each extractor should:
> - accept (SampleMetadata, behavioral_report_json)
> - return list[Artifact]
> - be defensive about missing fields / structure drift

### 5.1 Base extractor interface
- [x] Implement `extractor/extractors/base.py`:
  - [x] Base class/interface
  - [x] shared helpers for:
    - [x] artifact creation
    - [x] category assignment
    - [x] timestamp mapping (first_seen/last_seen)

---

## 6) Android extractor

### 6.1 Filesystem checks
- [x] Implement `extractor/extractors/android.py`:
  - [x] parse `behavioral.filesystem` (via kernel logs when available)
  - [x] parse signatures IOCs as fallback
  - [x] include operations: stat/access/open/exists
  - [x] extract path checks and categorize:
    - [x] emulator_files
    - [x] sandbox_files
    - [x] hooking_frameworks (file-based)
    - [x] root_indicators (file-based)
- [x] Tests (real fixture-derived expectations):
  - [x] assert >0 artifacts
  - [x] assert categories are valid enums
  - [x] expected values derived from fixture contents (not guesses)

### 6.2 System properties
- [x] Parse `behavioral.properties_read` (via kernel logs when available)
- [x] Emit `artifact_type=property`
- [x] Tests derived from fixture

### 6.3 Package queries
- [x] Parse `behavioral.package_queries` (via kernel logs when available)
- [x] Emit `artifact_type=package`
- [x] Categorize:
  - [x] sandbox_packages
  - [x] hooking_frameworks
  - [x] root_indicators
- [x] Tests derived from fixture

### 6.4 Port probes (loopback)
- [x] Parse `behavioral.network`
- [x] Include only `127.0.0.1` or `localhost`
- [x] Emit `artifact_type=port`, category `network_probes`
- [x] Tests derived from fixture

---

## 7) Windows extractor

### 7.1 Filesystem checks
- [x] Implement `extractor/extractors/windows.py` filesystem parsing
- [x] case_sensitive=false
- [x] Categorize:
  - [x] vm_files
  - [x] sandbox_files
  - [x] analysis_tools
- [x] Tests derived from Windows fixture (mock data)

### 7.2 Registry checks
- [x] Parse `behavioral.registry` (via kernel logs when available)
- [x] Emit `artifact_type=registry`
- [x] Stable match string:
  - [x] `<key>` or `<key>\<value_name>`
- [x] Tests derived from fixture

### 7.3 Process enumeration
- [x] Parse `behavioral.processes`
- [x] Emit `artifact_type=process`
- [x] Categorize:
  - [x] vm_processes
  - [x] sandbox_processes
  - [x] analysis_tools
  - [x] debugger_indicators (when relevant)
- [x] Tests derived from fixture

### 7.4 WMI queries
- [ ] Parse `behavioral.wmi`
- [ ] Emit `artifact_type=wmi`
- [ ] match string:
  - [ ] `Win32_ComputerSystem.Model` when parseable
  - [ ] else fallback to raw query string
- [ ] Store raw query in metadata.description
- [ ] Tests derived from fixture

### 7.5 Mutex checks
- [x] Parse `behavioral.mutexes` or `behavioral.sync_objects`
- [x] Emit `artifact_type=mutex`
- [x] Tests derived from fixture

---

## 8) Linux extractor

### 8.1 Filesystem checks
- [ ] Implement `extractor/extractors/linux.py` filesystem parsing
- [ ] Categorize:
  - [ ] vm_files
  - [ ] container_indicators
  - [ ] sandbox_files
  - [ ] debugger_indicators
  - [ ] analysis_tools
- [ ] Tests derived from Linux fixtures (skip if none)

### 8.2 Process checks
- [ ] Parse `behavioral.processes`
- [ ] Emit `artifact_type=process`
- [ ] Tests derived from fixtures

### 8.3 Environment variable checks
- [ ] Parse `behavioral.environment`
- [ ] Emit `artifact_type=environment_var`
- [ ] Tests derived from fixtures

---

## 9) macOS extractor

### 9.1 Filesystem checks
- [ ] Implement `extractor/extractors/macos.py` filesystem parsing
- [ ] Categorize:
  - [ ] vm_files
  - [ ] sandbox_files
- [ ] Tests derived from macOS fixtures (skip if none)

### 9.2 Command/system profiler checks
- [ ] Parse `behavioral.commands`
- [ ] Detect:
  - [ ] `system_profiler ...`
  - [ ] `sysctl hw.*`
  - [ ] `ioreg -l`
- [ ] Emit stable artifacts:
  - [ ] recommended: `artifact_type=property`, match `command:<cmd>`
- [ ] Tests derived from fixtures

---

## 10) Aggregation and scoring

### 10.1 Deduplication
- [x] Implement `extractor/aggregation/deduplicator.py`:
  - [x] key = (os, artifact_type, match_criteria.value) via artifact ID
  - [x] merge:
    - [x] sample_count sum
    - [x] sample_hashes union (max 100)
    - [x] families union
  - [x] update metadata.last_seen to latest
- [x] Tests:
  - [x] two artifacts merge correctly
  - [x] hashes capped at 100

### 10.2 Confidence scoring
- [x] Implement `extractor/aggregation/scorer.py` per formula:
  - [x] base_score: min(sample_count/10, 0.5)
  - [x] family_bonus: min(unique_families/5, 0.3)
  - [x] recency_bonus: 0.2 if last_seen within 30 days else 0.1
  - [x] cap at 1.0
- [x] Tests:
  - [x] confidence increases with sample_count
  - [x] confidence increases with families
  - [x] confidence bounded [0,1]

### 10.3 Filtering
- [x] Implement `extractor/aggregation/filter.py`:
  - [x] include_if sample_count >= config.filtering.min_sample_count
  - [x] include_if confidence >= config.filtering.min_confidence
  - [x] exclude patterns from config (regex/contains)
  - [x] exclude user-specific patterns (Windows user dirs etc.)
- [x] Tests:
  - [x] excludes user-specific paths
  - [x] respects thresholds

---

## 11) Output generation

### 11.1 JSON writer
- [x] Implement `extractor/output/json_writer.py`:
  - [x] write `artifacts.json` with:
    - [x] version
    - [x] generated_at
    - [x] statistics
    - [x] artifacts grouped by OS
- [x] Tests:
  - [x] file created
  - [x] schema keys present
  - [x] counts match input

### 11.2 Per-OS JSON split
- [x] If `split_by_os=true`, write:
  - [x] `artifacts_android.json`
  - [x] `artifacts_windows.json`
  - [x] `artifacts_linux.json`
  - [x] `artifacts_macos.json`
- [x] Tests:
  - [x] only enabled when configured

### 11.3 YAML deception configs
- [x] Implement `extractor/output/yaml_writer.py`:
  - [x] `android_deception_config.yaml`
    - [x] files_to_create
    - [x] properties_to_set
    - [x] packages_to_fake
    - [x] ports_to_bind
  - [x] `windows_deception_config.yaml`
    - [x] files_to_create
    - [x] registry_to_create
    - [x] processes_to_run
    - [x] mutexes_to_create
  - [x] `linux_deception_config.yaml`
    - [x] files_to_create
    - [x] processes_to_fake
- [x] Tests:
  - [x] YAML created
  - [x] keys present
  - [x] values derived from artifacts

### 11.4 Change report
- [ ] Implement `extractor/output/change_reporter.py`:
  - [ ] compare to previous `artifacts.json`
  - [ ] output `extraction_changes.json`
  - [ ] new/updated/removed
- [ ] Tests:
  - [ ] diff correctness on small synthetic set (built from real artifact objects)

---

## 12) Triage API integration (offline-tested)

> Live API calls are allowed only for `scripts/capture_fixtures.py` (manual). All tests run against fixture server.
> **Reference**: See `docs/triage_api_reference.md` and `docs/behavioral_data_mapping.md` for API details.

### 12.1 Basic client
- [ ] Implement `extractor/triage/client.py`:
  - [ ] session + auth header (`Authorization: Bearer <api_key>`)
  - [ ] base_url: `https://api.tria.ge` (official client default)
  - [ ] methods:
    - [ ] `search(query)` → `/search?query={query}`
    - [ ] `get_sample(sample_id)` → `/samples/{id}`
    - [ ] `get_sample_overview(sample_id)` → `/samples/{id}/overview.json`
    - [ ] `get_behavioral(sample_id, task_id)` → `/samples/{id}/{task_id}/report_triage.json`
    - [ ] `get_kernel_logs(sample_id, task_id)` → `/samples/{id}/{task_id}/logs/{platform}.json`
- [ ] Tests:
  - [ ] client works vs fixture server
  - [ ] returns JSON exactly matching fixture

### 12.2 Rate limiting and retries
- [ ] Implement `extractor/triage/rate_limit.py` (token bucket)
- [ ] Implement retry/backoff policy for:
  - [ ] 429 exponential backoff up to max_retries
  - [ ] 5xx linear backoff
  - [ ] timeouts retry
- [ ] Tests:
  - [ ] simulated 429 then 200 succeeds
  - [ ] retries capped

### 12.3 Caching (SQLite)
- [ ] Implement `extractor/triage/cache.py`:
  - [ ] cache db at `./cache/triage_cache.db` by default
  - [ ] TTL:
    - [ ] overview: 7 days
    - [ ] behavioral: 30 days
- [ ] Tests:
  - [ ] cache hit avoids HTTP request (fixture server request counter)
  - [ ] expired entry refetches

---

## 13) Pipeline (end-to-end)

### 13.1 Extract single sample
- [ ] Implement `extractor/pipeline.py`:
  - [ ] `extract_sample(sample_id, config, client) -> ExtractionResult`
  - [ ] OS detection based on overview tags/classification
  - [ ] run correct extractor
  - [ ] aggregate/score/filter
  - [ ] write outputs to output dir
- [ ] CLI command:
  - [ ] `extract-sample <sample_id>`
- [ ] Integration test (fixture server):
  - [ ] run CLI
  - [ ] assert output files exist and artifacts > 0

### 13.2 Full extraction (search + multi-sample)
- [ ] Implement poller/search query builder per spec:
  - [ ] per OS:
    - [ ] `tag:<os> AND score:>=<min_score> AND submitted:>=<lookback_date>`
- [ ] Implement `extract` pipeline:
  - [ ] for each OS in config.os_targets
  - [ ] search -> iterate sample ids (cap max_samples_per_os)
  - [ ] extract each sample -> accumulate artifacts
  - [ ] aggregate across all samples
  - [ ] write outputs + change report
- [ ] Integration test (fixture server):
  - [ ] fixture server supports `/search` returning fixture sample IDs
  - [ ] run `extract --os android --days 7`
  - [ ] assert outputs + statistics

---

## 14) CLI completion (per spec)

- [ ] `extract`
  - [ ] `--os` comma-separated
  - [ ] `--days`
- [ ] `extract-sample <sample_id>`
- [ ] `stats` (cache stats)
- [ ] `clear-cache`
- [ ] `validate-config`
- [ ] `generate-deception --input artifacts.json`
- [ ] CLI tests for each command with temp dirs

---

## 15) Quality, safety, and polish

### 15.1 Error handling + reporting
- [ ] Central error types:
  - [ ] api_errors (401/429/5xx/timeout)
  - [ ] parsing_errors (missing reports, malformed JSON, unexpected structure)
  - [ ] validation_errors (invalid artifact)
- [ ] Ensure ExtractionResult.errors is populated correctly
- [ ] Tests:
  - [ ] missing behavioral2 handled gracefully
  - [ ] malformed JSON fixture triggers skip_sample with error entry

### 15.2 Defensive parsing
- [ ] Each extractor must:
  - [ ] handle missing fields
  - [ ] handle field type drift (dict vs list)
  - [ ] never crash the whole run for one sample

### 15.3 Determinism
- [ ] Sort artifacts in outputs consistently (by os/category/type/value)
- [ ] Stable extraction_id generation (timestamp + random suffix or UUID, but captured in output)
- [ ] Tests:
  - [ ] repeated run on same fixtures produces same artifact list ordering

### 15.4 Performance & limits
- [ ] Enforce max_samples_per_os
- [ ] Enforce sample_hashes cap 100
- [ ] Streaming / incremental writes not required for v1, but avoid huge memory spikes where reasonable

### 15.5 Docs
- [ ] README includes:
  - [ ] configuration guide
  - [ ] fixture capture instructions
  - [ ] example commands
  - [ ] outputs overview (what files, where)

---

## 16) Fixture acquisition checklist (do this early)

> Capture fixtures **before** heavy implementation so tests have coverage.

- [ ] Android fixtures:
  - [ ] at least 2 samples
  - [ ] includes filesystem checks
  - [ ] includes properties_read
  - [ ] includes package_queries
  - [ ] includes loopback network probes (if possible)
- [ ] Windows fixtures:
  - [ ] at least 2 samples
  - [ ] includes filesystem checks
  - [ ] includes registry checks
  - [ ] includes process enumeration
  - [ ] includes WMI queries (if possible)
  - [ ] includes mutex checks (if possible)
- [ ] Linux fixtures:
  - [ ] at least 1 sample (filesystem + processes + env)
- [ ] macOS fixtures:
  - [ ] at least 1 sample (filesystem + commands)

---

## 17) Release readiness

- [ ] `python -m extractor.cli extract ...` works end-to-end
- [ ] All tests green (`pytest -q`)
- [ ] Run formatter (`black .`, `isort .`)
- [ ] Optional: mypy pass (or clearly documented exclusions)
- [ ] Tag v1.0 output schema version string in artifacts.json

---
