# Contributing

Use Python 3.10 or newer and install `requirements.txt`. GUI development also requires `gui/requirements.txt`. Run `python -m pytest -q` and the benign probe command documented in the README before submitting a change.

Add synthetic or sanitized report fixtures; never commit credentials, raw malware, private reports, or data without redistribution permission. External catalogs require a detached Ed25519 signature from an independently trusted key. Keep signing keys outside this repository.

Changes to placement must test existing-object preservation, failed and interrupted operations, ownership verification, and rollback. A placement recipe must specify the exact check it satisfies and its compatibility limitations. Unsupported operations must fail explicitly. Never report a launched helper as a completed placement.

Efficacy claims require paired controlled experiments, repeated trials, a held-out corpus, and review of adverse effects. Passing a benign file or registry probe does not establish that malware stops. Use the protocol in `docs/validation-protocol.md`.

Submit a focused pull request describing behavior, validation, and any remaining platform limitations. Do not run malware on developer workstations or in ordinary CI.
