"""
Tests for OS inference functions in the Triage client.

These functions determine the OS type from:
- File extensions
- Platform strings
- Sample data (combined approach)
"""

import pytest

from extractor.triage.client import (
    infer_os_from_filename,
    infer_os_from_platform,
    infer_os_from_sample,
    FILE_EXTENSION_TO_OS,
    PLATFORM_PATTERNS,
)


# =============================================================================
# File Extension Tests
# =============================================================================

class TestInferOsFromFilename:
    """Tests for OS inference from filename extension."""
    
    def test_android_apk(self):
        """Test .apk files are detected as Android."""
        assert infer_os_from_filename("malware.apk") == "android"
        assert infer_os_from_filename("MALWARE.APK") == "android"  # Case insensitive
        assert infer_os_from_filename("test.sample.apk") == "android"
    
    def test_android_dex(self):
        """Test .dex files are detected as Android."""
        assert infer_os_from_filename("classes.dex") == "android"
    
    def test_android_aab(self):
        """Test .aab (Android App Bundle) files are detected as Android."""
        assert infer_os_from_filename("app-release.aab") == "android"
    
    def test_windows_exe(self):
        """Test .exe files are detected as Windows."""
        assert infer_os_from_filename("trojan.exe") == "windows"
        assert infer_os_from_filename("MALWARE.EXE") == "windows"
    
    def test_windows_dll(self):
        """Test .dll files are detected as Windows."""
        assert infer_os_from_filename("payload.dll") == "windows"
    
    def test_windows_various(self):
        """Test various Windows executable formats."""
        assert infer_os_from_filename("installer.msi") == "windows"
        assert infer_os_from_filename("screensaver.scr") == "windows"
        assert infer_os_from_filename("driver.sys") == "windows"
        assert infer_os_from_filename("script.bat") == "windows"
        assert infer_os_from_filename("script.ps1") == "windows"
    
    def test_macos_dmg(self):
        """Test .dmg files are detected as macOS."""
        assert infer_os_from_filename("installer.dmg") == "macos"
    
    def test_macos_pkg(self):
        """Test .pkg files are detected as macOS."""
        assert infer_os_from_filename("package.pkg") == "macos"
    
    def test_linux_elf(self):
        """Test .elf files are detected as Linux."""
        assert infer_os_from_filename("malware.elf") == "linux"
    
    def test_linux_so(self):
        """Test .so files are detected as Linux."""
        assert infer_os_from_filename("libpayload.so") == "linux"
    
    def test_linux_packages(self):
        """Test Linux package formats."""
        assert infer_os_from_filename("malware.deb") == "linux"
        assert infer_os_from_filename("malware.rpm") == "linux"
    
    def test_empty_filename(self):
        """Test empty filename returns None."""
        assert infer_os_from_filename("") is None
        assert infer_os_from_filename(None) is None
    
    def test_no_extension(self):
        """Test filename without extension returns None."""
        assert infer_os_from_filename("malware") is None
    
    def test_unknown_extension(self):
        """Test unknown extension returns None."""
        assert infer_os_from_filename("document.pdf") is None
        assert infer_os_from_filename("image.png") is None
    
    def test_sha256_with_extension(self):
        """Test SHA256-style filenames with extension."""
        sha256 = "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2"
        assert infer_os_from_filename(f"{sha256}.exe") == "windows"
        assert infer_os_from_filename(f"{sha256}.apk") == "android"


# =============================================================================
# Platform String Tests
# =============================================================================

class TestInferOsFromPlatform:
    """Tests for OS inference from platform strings."""
    
    def test_windows_platforms(self):
        """Test Windows platform strings."""
        assert infer_os_from_platform("windows10_x64") == "windows"
        assert infer_os_from_platform("windows7_x64") == "windows"
        assert infer_os_from_platform("win10v200430") == "windows"
        assert infer_os_from_platform("win7-sp1-x64") == "windows"
    
    def test_android_platforms(self):
        """Test Android platform strings."""
        assert infer_os_from_platform("android-11-x64") == "android"
        assert infer_os_from_platform("android-9-x86") == "android"
        assert infer_os_from_platform("android-x64-arm64-20251027-en") == "android"
    
    def test_linux_platforms(self):
        """Test Linux platform strings."""
        assert infer_os_from_platform("linux-x64") == "linux"
        assert infer_os_from_platform("ubuntu-18.04-amd64") == "linux"
        assert infer_os_from_platform("debian-10") == "linux"
    
    def test_macos_platforms(self):
        """Test macOS platform strings."""
        assert infer_os_from_platform("macos-12-x64") == "macos"
        assert infer_os_from_platform("darwin") == "macos"
        assert infer_os_from_platform("osx-10.15") == "macos"
    
    def test_empty_platform(self):
        """Test empty platform returns None."""
        assert infer_os_from_platform("") is None
        assert infer_os_from_platform(None) is None
    
    def test_unknown_platform(self):
        """Test unknown platform returns None."""
        assert infer_os_from_platform("freebsd-13") is None


# =============================================================================
# Sample Data Tests
# =============================================================================

class TestInferOsFromSample:
    """Tests for OS inference from sample data."""
    
    def test_windows_from_task_os(self):
        """Test OS detection from task.os field."""
        sample = {
            "tasks": {
                "sample-behavioral1": {
                    "os": "windows10_x64",
                    "target": "malware.exe"
                }
            }
        }
        assert infer_os_from_sample(sample) == "windows"
    
    def test_android_from_task_platform(self):
        """Test OS detection from task.platform field."""
        sample = {
            "tasks": {
                "sample-behavioral1": {
                    "platform": "android-11-x64",
                    "target": "app.apk"
                }
            }
        }
        assert infer_os_from_sample(sample) == "android"
    
    def test_os_from_target_filename(self):
        """Test OS detection from target filename."""
        sample = {
            "target": "malware.exe",
            "tasks": {}
        }
        assert infer_os_from_sample(sample) == "windows"
    
    def test_os_from_sample_target(self):
        """Test OS detection from sample.target."""
        sample = {
            "sample": {
                "target": "trojan.apk"
            }
        }
        assert infer_os_from_sample(sample) == "android"
    
    def test_os_from_analysis_tags(self):
        """Test OS detection from analysis.tags."""
        sample = {
            "analysis": {
                "tags": ["windows", "evasion", "ransomware"]
            }
        }
        assert infer_os_from_sample(sample) == "windows"
    
    def test_os_from_sample_tags(self):
        """Test OS detection from sample.tags."""
        sample = {
            "sample": {
                "tags": ["android", "banking"]
            }
        }
        assert infer_os_from_sample(sample) == "android"
    
    def test_os_from_elf_tag(self):
        """Test OS detection from 'elf' tag (Linux indicator)."""
        sample = {
            "sample": {
                "tags": ["elf", "botnet"]
            }
        }
        assert infer_os_from_sample(sample) == "linux"
    
    def test_priority_task_os_over_filename(self):
        """Test that task.os has priority over filename extension."""
        sample = {
            "target": "something.dll",  # Would suggest Windows
            "tasks": {
                "sample-behavioral1": {
                    "os": "android-11-x64"  # Should take priority
                }
            }
        }
        assert infer_os_from_sample(sample) == "android"
    
    def test_empty_sample_returns_none(self):
        """Test empty sample data returns None."""
        assert infer_os_from_sample({}) is None
    
    def test_real_fixture_format(self):
        """Test with real fixture-like data format."""
        sample = {
            "sample": {
                "id": "260128-w68cvaczs2",
                "target": "mparivahan.apk",
                "score": 7
            },
            "analysis": {
                "score": 7,
                "tags": ["android", "evasion", "impact"]
            },
            "tasks": {
                "260128-w68cvaczs2-behavioral1": {
                    "kind": "behavioral",
                    "name": "behavioral1",
                    "os": "android-11-x64",
                    "resource": "android-x64-arm64-20251027-en",
                    "score": 7,
                    "tags": ["evasion", "impact"],
                    "target": "mparivahan.apk"
                }
            }
        }
        assert infer_os_from_sample(sample) == "android"
    
    def test_windows_fixture_format(self):
        """Test with Windows fixture-like data format."""
        sample = {
            "sample": {
                "id": "200606-l5dz9871we",
                "target": "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2.exe",
                "score": 10
            },
            "analysis": {
                "score": 10,
                "tags": ["windows", "evasion", "ransomware"]
            },
            "tasks": {
                "200606-l5dz9871we-behavioral1": {
                    "os": "windows7_x64",
                    "platform": "windows7_x64",
                    "target": "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2.exe",
                    "tags": ["evasion", "ransomware"]
                }
            }
        }
        assert infer_os_from_sample(sample) == "windows"


# =============================================================================
# Constants Tests
# =============================================================================

class TestOsInferenceConstants:
    """Tests for OS inference constant mappings."""
    
    def test_all_android_extensions_mapped(self):
        """Verify Android extensions are mapped correctly."""
        android_exts = [".apk", ".aab", ".dex"]
        for ext in android_exts:
            assert ext in FILE_EXTENSION_TO_OS
            assert FILE_EXTENSION_TO_OS[ext] == "android"
    
    def test_all_windows_extensions_mapped(self):
        """Verify Windows extensions are mapped correctly."""
        windows_exts = [".exe", ".dll", ".msi", ".scr", ".sys", ".bat", ".ps1"]
        for ext in windows_exts:
            assert ext in FILE_EXTENSION_TO_OS
            assert FILE_EXTENSION_TO_OS[ext] == "windows"
    
    def test_all_macos_extensions_mapped(self):
        """Verify macOS extensions are mapped correctly."""
        macos_exts = [".dmg", ".pkg", ".app"]
        for ext in macos_exts:
            assert ext in FILE_EXTENSION_TO_OS
            assert FILE_EXTENSION_TO_OS[ext] == "macos"
    
    def test_all_linux_extensions_mapped(self):
        """Verify Linux extensions are mapped correctly."""
        linux_exts = [".elf", ".so", ".deb", ".rpm"]
        for ext in linux_exts:
            assert ext in FILE_EXTENSION_TO_OS
            assert FILE_EXTENSION_TO_OS[ext] == "linux"
    
    def test_platform_patterns_include_all_os(self):
        """Verify platform patterns cover all OS types."""
        os_types = {"android", "windows", "linux", "macos"}
        mapped_os = set(PLATFORM_PATTERNS.values())
        assert os_types == mapped_os
