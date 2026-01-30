# Evasion Artifact Placer GUI

A cross-platform application for browsing and placing evasion artifacts to make
your machine appear as a security researcher environment.

## Features

- **Browse Artifacts**: Filter by OS, category, and privilege level
- **Place Artifacts**: Point-and-click artifact placement with confirmation
- **Privilege Awareness**: Clear indicators for user-space vs admin/root artifacts
- **Auto-Updates**: Daily updates from Triage API for new artifacts
- **Cross-Platform**: Works on Windows, macOS, Linux, and Android

## Requirements

- Python 3.11+
- Kivy 2.2+
- See `requirements.txt` for full dependencies

## Installation

```bash
# Install GUI dependencies
pip install -r gui/requirements.txt

# Or install all project dependencies
pip install -r requirements.txt kivy plyer
```

## Running

```bash
# From project root
python -m gui.main
```

## Building Standalone Executables

### Windows/macOS/Linux (PyInstaller)

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller gui/evasion_placer.spec

# Output will be in dist/EvasionArtifactPlacer
```

### Android (Buildozer)

```bash
# Install Buildozer (Linux only, or use WSL on Windows)
pip install buildozer

# Install Android SDK/NDK dependencies
buildozer android debug

# Output APK will be in bin/
```

## Configuration

On first run, go to **Settings** to:
1. Enter your Triage API key
2. Configure update frequency (Hourly, Daily, Weekly, Manual)
3. Set default OS filter

## Usage

### Dashboard
- View artifact statistics
- See placed artifacts count
- Trigger manual updates
- Remove all placed artifacts

### Browse
- Filter artifacts by:
  - **OS**: Android, Windows, Linux, macOS
  - **Category**: vm_files, root_indicators, etc.
  - **Privilege**: User (no elevation), Admin, Root
- Select artifacts for placement

### Placement
- Review selected artifacts
- See privilege requirements
- Place individual artifacts or all user-space at once
- Admin/root artifacts trigger elevation prompts

### Settings
- Configure Triage API key
- Set update frequency
- Test API connection
- Clear placement log or all data

## Privilege Levels

| Level | Description | Elevation Required |
|-------|-------------|-------------------|
| User | User-accessible locations | No |
| Admin | System files, registry | Yes (UAC/sudo) |
| Root | Android system paths | Yes (rooted device) |

## Data Storage

- **Database**: `~/.evasion_artifact_placer/artifacts.db`
- **Settings**: Stored in SQLite database
- **Placement Log**: Tracked for easy removal

## Troubleshooting

### "No module named 'kivy'"
Install Kivy: `pip install kivy`

### "No module named 'extractor'"
Run from project root: `python -m gui.main`

### Android build fails
Ensure you have Android SDK/NDK installed and configured.
See [Buildozer documentation](https://buildozer.readthedocs.io/).

## Security Notes

1. **No auto-elevation**: Admin/root placements always prompt
2. **Placement log**: All changes are logged for reversal
3. **API key storage**: Stored in local SQLite database
4. **Review carefully**: Some artifacts modify system locations
