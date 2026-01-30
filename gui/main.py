#!/usr/bin/env python3
"""
Main entry point for the Evasion Artifact Placement GUI.

Run with: python -m gui.main
"""

import os
import sys

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Set Kivy configuration before importing kivy
os.environ.setdefault("KIVY_LOG_LEVEL", "info")

from gui.app import EvasionArtifactApp


def main():
    """Launch the application."""
    app = EvasionArtifactApp()
    app.run()


if __name__ == "__main__":
    main()
