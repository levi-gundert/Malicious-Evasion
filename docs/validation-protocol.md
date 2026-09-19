# Validation protocol

## Distinct evidence levels

1. **Candidate:** an observed or curated check with an explicit recipe. Efficacy is unknown.
2. **Primitive probe:** benign code confirms an existence or value check and complete rollback in a disposable location. This does not validate an original malware target path.
3. **Exact-target verification:** the intended OS build, architecture, registry view, path, and values are checked in an isolated test image. Compatibility tests cover installed VM tools and representative benign software.
4. **Controlled malware observation:** paired runs demonstrate a repeatable behavioral difference. This is evidence for the tested sample/configuration, not a universal prevention claim.

The bundled Windows catalog remains at level 1. The temporary-path CLI probes cover level 2 for files/directories. The Windows-only regression test covers a synthetic HKCU typed-value recipe. No malware-efficacy results ship with this release.

## Experimental design

Use disposable isolated lab images, fixed OS/application versions, controlled network simulation, snapshot restoration, and equal observation windows. Do not use a normal workstation, production endpoint, or ordinary GitHub runner for live samples. Establish that the baseline sample actually exhibits harmful behavior. Randomize run order and repeat both conditions. Keep environment characteristics identical except for the tested recipe; avoid attributing existing sandbox evasion to MEAP.

Record SHA256, family label/source, recipe version, image digest, architecture, registry view, run order, repeat, observation duration, telemetry/report references, and confidence in interpreting termination. Reserve a sample set and preferably families for held-out evaluation. Classify baseline/decoy outcomes as `harmful`, `terminated`, `delayed`, `no_activity`, or `failed`. A silent run or timeout alone is not termination. Record benign application interference and rollback findings separately, including data loss, failed installations, startup issues, and EDR alerts.

## Result format

`python -m extractor.cli placement summarize-trials results.json` accepts a JSON array:

```json
[
  {
    "sample_sha256": "<64-character SHA256>",
    "family": "<label and source>",
    "recipe": "<catalog version / recipe name>",
    "repeat": 1,
    "baseline_environment": "<image digest and configuration identifier>",
    "decoy_environment": "<same identifier, excluding the declared recipe>",
    "baseline_seconds": 300,
    "decoy_seconds": 300,
    "baseline_outcome": "harmful",
    "decoy_outcome": "terminated"
  }
]
```

The summarizer rejects duplicate pairs, unequal observation windows, and mismatched environments. It separates observed termination from delay/no activity and inconclusive baselines. It does not validate the truth of supplied telemetry or automatically promote recipes. Preserve raw evidence, review interpretation independently, and publish denominators and adverse effects with any measured result.

## Catalog releases

Catalog entries contain recipe semantics, source evidence where redistributable, compatibility notes, and a retest date. Increment catalog version on each release and set an expiry. Sign the exact JSON bytes using Ed25519; store the detached signature and raw 32-byte public key as base64 text. The signer private key stays in the release system or maintainer's secure storage, never the repository.

External catalog verification requires a public key obtained through an independent trusted channel and `--minimum-version` set to the highest previously accepted version. Never accept a key merely because it arrived beside an untrusted catalog. There is no automatic remote catalog updater or embedded production signing identity in this development release. Verification never places artifacts.
