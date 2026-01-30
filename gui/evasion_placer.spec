# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Evasion Artifact Placer.

Build with:
    pyinstaller gui/evasion_placer.spec

This creates a standalone executable for Windows, macOS, or Linux.
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(SPECPATH).parent
sys.path.insert(0, str(project_root))

block_cipher = None

# Collect all Python files
python_files = []
for root, dirs, files in os.walk(str(project_root / 'gui')):
    for f in files:
        if f.endswith('.py'):
            python_files.append(os.path.join(root, f))

for root, dirs, files in os.walk(str(project_root / 'extractor')):
    for f in files:
        if f.endswith('.py'):
            python_files.append(os.path.join(root, f))

a = Analysis(
    [str(project_root / 'gui' / 'main.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        # Include Kivy dependencies
        (str(project_root / 'gui' / 'assets'), 'gui/assets'),
    ],
    hiddenimports=[
        'kivy',
        'kivy.core.window',
        'kivy.core.text',
        'kivy.core.image',
        'kivy.graphics',
        'kivy.uix.screenmanager',
        'kivy.uix.boxlayout',
        'kivy.uix.gridlayout',
        'kivy.uix.label',
        'kivy.uix.button',
        'kivy.uix.textinput',
        'kivy.uix.spinner',
        'kivy.uix.scrollview',
        'kivy.uix.popup',
        'kivy.uix.checkbox',
        'kivy.uix.switch',
        'plyer',
        'plyer.platforms',
        'gui',
        'gui.app',
        'gui.screens',
        'gui.screens.dashboard',
        'gui.screens.browse',
        'gui.screens.placement',
        'gui.screens.settings',
        'gui.services',
        'gui.services.database',
        'gui.services.placement_engine',
        'gui.services.privilege_manager',
        'gui.services.updater',
        'extractor',
        'extractor.triage',
        'extractor.triage.client',
        'extractor.pipeline',
        'extractor.models',
        'extractor.extractors',
        'extractor.aggregation',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='EvasionArtifactPlacer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path here if available
)

# For macOS, create an app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='Evasion Artifact Placer.app',
        icon=None,  # Add .icns icon path here
        bundle_identifier='com.evasion.artifactplacer',
        info_plist={
            'NSHighResolutionCapable': 'True',
            'NSRequiresAquaSystemAppearance': 'False',  # Support dark mode
        },
    )
