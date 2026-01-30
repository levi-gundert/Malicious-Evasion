# Triage Evasion Artifact Extractor

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run tests

```bash
pytest -q
```

## Capture fixtures (required for extraction tests)

The test suite uses **real Triage JSON fixtures** captured from the API. Use the capture script (added in later steps) to download fixtures into `tests/fixtures/`.

```bash
python scripts/capture_fixtures.py --os android --sample-id <sample_id> --out tests/fixtures
```

Set `TRIAGE_API_KEY` in your environment before running the capture script.
