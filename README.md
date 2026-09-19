# Malicious Evasion Artifact Placer (MEAP)

A research tool for extracting anti-analysis checks from malware reports and placing reversible decoy candidates. An observed check does not establish that a decoy prevents infection; efficacy requires controlled validation.

![Dashboard](docs/screenshots/dashboard.png)

## Screenshots

| Browse Artifacts | Place Artifact |
|:---:|:---:|
| ![Browse](docs/screenshots/browse_artifacts.png) | ![Place](docs/screenshots/place_artifact.png) |

### Extraction Patterns by OS

![Extractor Patterns](docs/screenshots/extractors_patterns.png)

## Disclaimer

> **WARNING: USE AT YOUR OWN RISK**
>
> This software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
>
> **EXERCISE EXTREME CAUTION** before placing any artifact on your machine, phone, or any other device. The artifacts extracted by this tool are derived from real malware samples and may:
> - Trigger security software alerts or quarantine actions
> - Modify system files, registry entries, or configurations
> - Require administrator/root privileges to place or remove
> - Potentially cause system instability if placed incorrectly
>
> **This tool is intended for security research, testing, and educational purposes only.** Users are solely responsible for understanding the implications of placing artifacts on their systems and for any consequences that may result.
>
> Always test in isolated environments (VMs, sandboxes) before deploying on production systems.

## Overview

The Malicious Evasion Artifact Placer extracts evasion techniques from [Hatching Triage](https://tria.ge) malware analysis reports. These artifacts represent indicators that malware uses to detect analysis environments, including:

- **File paths** checked for sandbox/VM presence (e.g., VirtualBox Guest Additions, VMware Tools)
- **Registry keys** queried to detect virtual environments
- **Process names** enumerated to identify security tools
- **WMI queries** used to fingerprint hardware
- **Network indicators** for environment detection

## Features

- **Multi-OS Support**: Extract artifacts for Windows, Android, Linux, and macOS
- **GUI Application**: User-friendly interface for browsing and placing artifacts
- **CLI Tool**: Command-line interface for automation and scripting
- **API Integration**: Connects to Hatching Triage API to fetch latest evasion samples
- **Intelligent OS Detection**: Automatically infers target OS from sample metadata
- **Caching**: Local SQLite cache to minimize API calls
- **Rate Limiting**: Built-in rate limiting to respect API quotas

## Installation

### Requirements

- Python 3.10+
- Hatching Triage API key (obtain from [tria.ge](https://tria.ge))

### Setup

```bash
# Clone the repository
git clone https://github.com/levi-gundert/Malicious-Evasion.git
cd malicious-evasion

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# For GUI, also install GUI requirements
pip install -r gui/requirements.txt
```

### Configuration

Set your Triage API key as an environment variable:

```bash
# On Windows (PowerShell):
$env:TRIAGE_API_KEY = "your-api-key-here"

# On Linux/macOS:
export TRIAGE_API_KEY="your-api-key-here"
```

Or configure in the GUI via Settings.

## Usage

### GUI Application

Launch the graphical interface:

```bash
python -m gui.main
```

**Dashboard Features:**
- View total artifacts, placed count, and privilege requirements
- Select OS sources (Windows, Android, Linux, macOS)
- Check for updates from Triage API
- Browse and manage artifacts
- Place/remove artifacts with one click

### CLI Tool

Extract artifacts from local fixtures:

```bash
python -m extractor.cli extract --os windows
```

Extract from Triage API:

```bash
python -m extractor.cli live --os windows --limit 50
```

Test API connectivity:

```bash
python -m extractor.cli test-api
```

### Capture Test Fixtures

Download sample data for offline testing:

```bash
python scripts/capture_fixtures.py --os android --sample-id <sample_id> --out tests/fixtures
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=extractor

# Run specific test file
pytest tests/unit/test_os_inference.py -v
```

## Project Structure

```
Malicious Evasion/
├── extractor/           # Core extraction library
│   ├── extractors/      # OS-specific extractors
│   ├── models/          # Data models (Artifact, Sample, etc.)
│   ├── triage/          # Triage API client
│   └── pipeline.py      # Main extraction pipeline
├── gui/                 # Kivy/KivyMD GUI application
│   ├── screens/         # UI screens
│   ├── services/        # Background services
│   └── main.py          # Application entry point
├── tests/               # Test suite
│   ├── fixtures/        # Sample JSON fixtures
│   └── unit/            # Unit tests
├── scripts/             # Utility scripts
└── docs/                # Documentation
```

## Security Considerations

This tool is designed for security professionals to test detection capabilities. Before making this project public or using in any environment:

1. **No Hardcoded Secrets**: Desktop GUI keys use the OS credential store, with a session-only fallback; CLI keys can use environment variables
2. **Isolated Testing**: Always test in VMs or sandboxed environments first
3. **Privilege Awareness**: The tool clearly indicates which artifacts require admin privileges
4. **Reversibility**: New journaled placements can be removed when ownership and unchanged content are verified; legacy placements require manual review

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any enhancements.

## Acknowledgments

- [Hatching Triage](https://tria.ge) for malware analysis API
- [KivyMD](https://kivymd.readthedocs.io/) for Material Design components


## Safe placement and evidence workflow

The current backend supports exact file and directory existence recipes on desktop platforms and explicit new-key/typed-value Windows registry recipes in reviewed namespaces. The registry backend supports both 32-bit and 64-bit views. Existing objects are never adopted or overwritten. Parent directories/registry keys must exist; prerequisites are explicit recipes. Relative paths, unresolved variables, wildcards, network/device paths, symlinks/reparse points, and unsupported operations are rejected.

| Capability | Windows | Linux / macOS | Android |
| --- | --- | --- | --- |
| Extract report candidates | Yes | Yes | Yes |
| File/directory existence placement | Implemented; locally tested | Implemented; CI configured | Experimental app-writable files only |
| New registry key / typed value | Implemented; synthetic HKCU test | Not applicable | Not applicable |
| Privileged helper | UAC with completion check | PolicyKit/sudo or admin prompt; native validation pending | Disabled |
| Processes, WMI, packages, properties, mutexes | Extracted only where applicable | Extracted only where applicable | Extracted only |
| Demonstrated malware efficacy | Untested | Untested | Untested |

An ownership journal lives at `~/.evasion_artifact_placer/placement-journal.db`. Do not delete it while decoys remain placed. Missing, externally changed, replaced, or legacy objects are preserved for review. Directory removal preserves other contents. The GUI previews each plan and performs operations off its UI thread. `Placeable` means a supported recipe, not an efficacy claim. Evidence scores describe observation strength, not protection probability.

No API key is needed for the bundled candidate catalog, placement commands, or benign probes:

```powershell
python -m extractor.cli placement catalog
python -m extractor.cli placement catalog --recipe vmware-software-key > recipe.json
python -m extractor.cli placement plan recipe.json
# Explicit mutation: review the plan and compatibility notes first.
python -m extractor.cli placement apply recipe.json --elevate
python -m extractor.cli placement status
python -m extractor.cli placement remove <operation-id> --elevate
python -m extractor.cli placement probe --output output/benign-probes.json
```

Recipe input accepts JSON in UTF-8, UTF-16, or UTF-32, including Windows PowerShell redirection. The CLI accepts a complete Artifact JSON model or a flattened GUI record. A user-space alternative to a system path is not substituted, because that would change the check's meaning.

To inspect an external catalog, provide its detached signature and an independently trusted public key:

```text
python -m extractor.cli placement catalog --path catalog.json --signature catalog.sig --trusted-key maintainer.pub --minimum-version 2
```

The bundled catalog contains authored Windows candidates with expiry/retest dates and no redistributed private reports. It has **no measured malware efficacy**. External signature verification requires the `cryptography` dependency. See [validation protocol](docs/validation-protocol.md) for experimental design, result formats, signing, and release requirements.

Database migrations preserve legacy rows, migrate canonical artifact IDs and placement references, and version processed samples so new extractors can revisit reports. New observations are keyed by sample/report/task and sample counts are deduplicated. Unknown observation times remain unknown. GUI credentials migrate out of the ordinary settings table; without a supported credential-store backend they are available for the current session only. Existing backups may still contain old settings and must be managed separately.

Network downloads run in isolated workers with a total deadline, bounded response sizes and retries, and no credential-forwarding redirects. Workers are terminated on deadline. This desktop transport is not validated for Android packaging.

Run `python -m pytest -q` for regression tests. CI covers the core on Windows, Linux and macOS with Python 3.10/3.12; native elevation and malware studies require dedicated environments. Review [contributing guidelines](CONTRIBUTING.md) before adding recipes.
