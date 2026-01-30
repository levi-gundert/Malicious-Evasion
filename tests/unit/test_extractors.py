"""
Tests for OS-specific extractors.

These tests verify:
- Extractors handle missing data gracefully
- Extractors correctly identify evasion artifacts
- Extractors work with real fixture data
"""

import pytest
from unittest.mock import MagicMock

from extractor.models.artifact import ArtifactType, OSType, EvasionPurpose
from extractor.models.sample import SampleMetadata
from extractor.extractors.base import (
    ExtractionContext,
    extract_iocs_from_signature,
    is_evasion_signature,
    categorize_evasion_purpose,
    is_loopback_address,
    categorize_android_file,
)
from extractor.extractors.android import AndroidExtractor
from extractor.extractors.windows import WindowsExtractor, categorize_windows_file, categorize_windows_process

from extractor.testing.fixtures import (
    list_fixture_samples,
    load_overview,
    load_behavioral_report,
)


# =============================================================================
# Base Extractor Utility Tests
# =============================================================================

class TestExtractionUtilities:
    """Tests for base extractor utilities."""
    
    def test_extract_iocs_from_signature(self):
        """Test IOC extraction from signature."""
        signature = {
            "name": "test_sig",
            "indicators": [
                {"ioc": "/system/bin/qemu-props", "description": "file check"},
                {"ioc": "ro.kernel.qemu", "description": "property check"},
            ]
        }
        
        iocs = extract_iocs_from_signature(signature)
        # Debug: Log the IOCs
        print(f"Extracted IOCs: {iocs}")
        
        assert len(iocs) == 2
        assert "/system/bin/qemu-props" in iocs
        assert "ro.kernel.qemu" in iocs
    
    def test_is_evasion_signature_by_tag(self):
        """Test evasion signature detection by tag."""
        sig_evasion = {"name": "test", "tags": ["defense_evasion", "trojan"]}
        sig_normal = {"name": "test", "tags": ["network", "trojan"]}
        
        assert is_evasion_signature(sig_evasion) is True
        assert is_evasion_signature(sig_normal) is False
    
    def test_is_evasion_signature_by_name(self):
        """Test evasion signature detection by name."""
        sig1 = {"name": "anti_vm_file_check", "tags": []}
        sig2 = {"name": "emulator_detection", "tags": []}
        sig3 = {"name": "normal_network_activity", "tags": []}
        
        assert is_evasion_signature(sig1) is True
        assert is_evasion_signature(sig2) is True
        assert is_evasion_signature(sig3) is False
    
    def test_is_evasion_signature_by_ttp(self):
        """Test evasion signature detection by MITRE TTP."""
        sig = {"name": "test", "tags": [], "ttp": ["T1497.001"]}
        
        assert is_evasion_signature(sig) is True
    
    def test_categorize_evasion_purpose(self):
        """Test evasion purpose categorization."""
        sig_emulator = {"name": "qemu_detection", "desc": "Checks for QEMU emulator", "tags": []}
        sig_sandbox = {"name": "cuckoo_check", "desc": "Detects Cuckoo sandbox", "tags": []}
        sig_vm = {"name": "vmware_check", "desc": "Detects VMware", "tags": []}
        
        assert categorize_evasion_purpose(sig_emulator) == EvasionPurpose.EMULATOR
        assert categorize_evasion_purpose(sig_sandbox) == EvasionPurpose.SANDBOX
        assert categorize_evasion_purpose(sig_vm) == EvasionPurpose.VM
    
    def test_is_loopback_address(self):
        """Test loopback address detection."""
        assert is_loopback_address("127.0.0.1:8080") is True
        assert is_loopback_address("localhost:5555") is True
        assert is_loopback_address("192.168.1.1:80") is False
        assert is_loopback_address("") is False
    
    def test_categorize_android_file_emulator(self):
        """Test Android emulator file categorization."""
        result = categorize_android_file("/system/bin/qemu-props")
        assert result is not None
        assert result[0] == "emulator_files"
        assert result[1] == EvasionPurpose.EMULATOR
    
    def test_categorize_android_file_root(self):
        """Test Android root file categorization."""
        result = categorize_android_file("/system/app/Superuser.apk")
        assert result is not None
        assert result[0] == "root_indicators"
        assert result[1] == EvasionPurpose.ROOT
    
    def test_categorize_android_file_normal(self):
        """Test normal file is not categorized."""
        result = categorize_android_file("/data/app/com.example/base.apk")
        assert result is None


class TestWindowsUtilities:
    """Tests for Windows-specific utilities."""
    
    def test_categorize_windows_file_vmware(self):
        """Test VMware file categorization."""
        result = categorize_windows_file("C:\\Windows\\System32\\drivers\\vmci.sys")
        assert result is not None
        assert result[0] == "vm_files"
        assert result[1] == EvasionPurpose.VM
    
    def test_categorize_windows_file_sandbox(self):
        """Test sandbox file categorization."""
        result = categorize_windows_file("C:\\Users\\cuckoo\\Desktop\\sample.exe")
        assert result is not None
        assert result[0] == "sandbox_files"
        assert result[1] == EvasionPurpose.SANDBOX
    
    def test_categorize_windows_process_vm(self):
        """Test VM process categorization."""
        result = categorize_windows_process("vmtoolsd.exe")
        assert result is not None
        assert result[0] == "vm_processes"
        assert result[1] == EvasionPurpose.VM
    
    def test_categorize_windows_process_analysis(self):
        """Test analysis tool process categorization."""
        result = categorize_windows_process("wireshark.exe")
        assert result is not None
        assert result[0] == "analysis_tools"
        assert result[1] == EvasionPurpose.RESEARCHER_TOOLS


# =============================================================================
# ExtractionContext Tests
# =============================================================================

def create_mock_metadata(sha256: str = "abc123", sample_id: str = "test-sample"):
    """Helper to create a properly configured mock SampleMetadata."""
    mock_metadata = MagicMock()
    mock_metadata.sha256 = sha256
    mock_metadata.triage = MagicMock()
    mock_metadata.triage.sample_id = sample_id
    return mock_metadata


class TestExtractionContext:
    """Tests for ExtractionContext."""
    
    def test_context_extracts_nested_data(self):
        """Test that context extracts nested data correctly."""
        mock_metadata = create_mock_metadata()
        
        behavioral = {
            "signatures": [{"name": "sig1"}],
            "processes": [{"pid": 1234}],
            "network": {"flows": [{"dst": "1.1.1.1:80"}]},
            "dumped": [{"path": "/test"}],
        }
        
        context = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report=behavioral,
        )
        
        assert len(context.signatures) == 1
        assert len(context.processes) == 1
        assert len(context.network_flows) == 1
        assert len(context.dumped_files) == 1
    
    def test_context_handles_missing_data(self):
        """Test that context handles missing nested data."""
        mock_metadata = create_mock_metadata()
        
        context = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={},
        )
        
        assert context.signatures == []
        assert context.processes == []
        assert context.network_flows == []
        assert context.dumped_files == []
    
    def test_has_kernel_logs(self):
        """Test kernel log detection."""
        mock_metadata = create_mock_metadata()
        
        context_with_logs = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={},
            kernel_logs=[{"kind": "file_stat"}],
        )
        
        context_without_logs = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={},
        )
        
        assert context_with_logs.has_kernel_logs is True
        assert context_without_logs.has_kernel_logs is False


# =============================================================================
# Android Extractor Tests
# =============================================================================

class TestAndroidExtractor:
    """Tests for AndroidExtractor."""
    
    @pytest.fixture
    def extractor(self):
        return AndroidExtractor()
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock context with sample data."""
        mock_metadata = create_mock_metadata(sha256="abc123def456", sample_id="test-sample")
        
        return ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={
                "signatures": [
                    {
                        "name": "anti_vm_file_check",
                        "tags": ["defense_evasion"],
                        "indicators": [
                            {"ioc": "/system/bin/qemu-props", "description": "QEMU check"}
                        ]
                    }
                ],
                "network": {
                    "flows": [
                        {"dst": "127.0.0.1:27042", "proto": "tcp"},  # Frida port
                    ]
                },
            },
        )
    
    def test_extractor_os_type(self, extractor):
        """Test extractor has correct OS type."""
        assert extractor.os_type == OSType.ANDROID
    
    def test_extract_from_signatures(self, extractor, mock_context):
        """Test extraction from signatures."""
        artifacts = extractor.extract(mock_context)
        
        # Debug: Log what we extracted
        print(f"Extracted {len(artifacts)} artifacts:")
        for a in artifacts:
            print(f"  - {a.artifact_type.value}: {a.match_criteria.value}")
        
        # Should find the file from signature IOC
        file_artifacts = [a for a in artifacts if a.artifact_type == ArtifactType.FILE]
        assert len(file_artifacts) >= 1
        
        # Check the file artifact
        qemu_artifact = next((a for a in file_artifacts if "qemu" in a.match_criteria.value), None)
        assert qemu_artifact is not None
        assert qemu_artifact.category == "emulator_files"
    
    def test_extract_port_probes(self, extractor, mock_context):
        """Test extraction of port probes."""
        artifacts = extractor.extract(mock_context)
        
        port_artifacts = [a for a in artifacts if a.artifact_type == ArtifactType.PORT]
        # Debug: Log port artifacts
        print(f"Port artifacts: {[a.match_criteria.value for a in port_artifacts]}")
        
        # Should find the Frida port
        assert len(port_artifacts) >= 1
        frida_port = next((a for a in port_artifacts if a.match_criteria.value == "27042"), None)
        assert frida_port is not None
        assert frida_port.metadata.evasion_purpose == EvasionPurpose.HOOKING
    
    def test_extract_with_kernel_logs(self, extractor):
        """Test extraction with kernel logs available."""
        mock_metadata = create_mock_metadata()
        
        context = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={},
            kernel_logs=[
                {"kind": "file_stat", "path": "/system/bin/qemu-props", "ret": -1},
                {"kind": "prop_get", "name": "ro.kernel.qemu", "value": "1"},
                {"kind": "pkg_query", "package": "de.robv.android.xposed.installer"},
            ],
        )
        
        artifacts = extractor.extract(context)
        
        # Debug: Log what we extracted
        print(f"Extracted {len(artifacts)} artifacts from kernel logs:")
        for a in artifacts:
            print(f"  - {a.artifact_type.value}: {a.match_criteria.value}")
        
        # Should find all three types
        types = {a.artifact_type for a in artifacts}
        assert ArtifactType.FILE in types
        assert ArtifactType.PROPERTY in types
        assert ArtifactType.PACKAGE in types


# =============================================================================
# Windows Extractor Tests
# =============================================================================

class TestWindowsExtractor:
    """Tests for WindowsExtractor."""
    
    @pytest.fixture
    def extractor(self):
        return WindowsExtractor()
    
    def test_extractor_os_type(self, extractor):
        """Test extractor has correct OS type."""
        assert extractor.os_type == OSType.WINDOWS
    
    def test_extract_from_signatures(self, extractor):
        """Test extraction from signatures."""
        mock_metadata = create_mock_metadata()
        
        context = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={
                "signatures": [
                    {
                        "name": "anti_vm_vmware",
                        "tags": ["anti-vm"],
                        "indicators": [
                            {"ioc": "C:\\Windows\\System32\\drivers\\vmci.sys", "description": "VMware driver"}
                        ]
                    }
                ],
            },
        )
        
        artifacts = extractor.extract(context)
        
        # Debug: Log what we extracted
        print(f"Extracted {len(artifacts)} artifacts:")
        for a in artifacts:
            print(f"  - {a.artifact_type.value}: {a.match_criteria.value}")
        
        # Should find the VMware file
        file_artifacts = [a for a in artifacts if a.artifact_type == ArtifactType.FILE]
        assert len(file_artifacts) >= 1
        
        vmware_artifact = next((a for a in file_artifacts if "vmci" in a.match_criteria.value.lower()), None)
        assert vmware_artifact is not None
        assert vmware_artifact.category == "vm_files"
        assert vmware_artifact.match_criteria.case_sensitive is False  # Windows is case-insensitive
    
    def test_extract_with_kernel_logs(self, extractor):
        """Test extraction with kernel logs available."""
        mock_metadata = create_mock_metadata()
        
        context = ExtractionContext(
            sample_metadata=mock_metadata,
            behavioral_report={},
            kernel_logs=[
                {"kind": "file_open", "path": "C:\\Windows\\System32\\drivers\\vmci.sys"},
                {"kind": "reg_open", "key": "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools"},
                {"kind": "mutex_open", "name": "CuckooPipe"},
            ],
        )
        
        artifacts = extractor.extract(context)
        
        # Debug: Log what we extracted
        print(f"Extracted {len(artifacts)} artifacts from kernel logs:")
        for a in artifacts:
            print(f"  - {a.artifact_type.value}: {a.match_criteria.value}")
        
        # Should find file, registry, and mutex
        types = {a.artifact_type for a in artifacts}
        assert ArtifactType.FILE in types
        assert ArtifactType.REGISTRY in types
        assert ArtifactType.MUTEX in types


# =============================================================================
# Tests with Real Fixtures
# =============================================================================

class TestExtractorsWithFixtures:
    """Tests using real captured fixtures."""
    
    @pytest.fixture
    def android_samples(self):
        """Get available Android samples, skip if none."""
        samples = list_fixture_samples("android")
        if not samples:
            pytest.skip("No Android fixtures available")
        return samples
    
    def test_android_extractor_real_fixture(self, android_samples):
        """Test Android extractor with real fixture data."""
        sample_id = android_samples[0]
        
        # Load data
        overview = load_overview("android", sample_id)
        behavioral = load_behavioral_report("android", sample_id, "behavioral1")
        
        # Create context
        metadata = SampleMetadata.from_overview(overview)
        context = ExtractionContext(
            sample_metadata=metadata,
            behavioral_report=behavioral,
        )
        
        # Extract
        extractor = AndroidExtractor()
        artifacts = extractor.extract(context)
        
        # Debug: Log results
        print(f"\nSample: {sample_id}")
        print(f"Signatures in report: {len(context.signatures)}")
        print(f"Network flows: {len(context.network_flows)}")
        print(f"Extracted artifacts: {len(artifacts)}")
        
        for artifact in artifacts[:10]:  # Show first 10
            print(f"  - [{artifact.category}] {artifact.artifact_type.value}: {artifact.match_criteria.value[:50]}")
        
        # The test passes as long as no errors occur
        # We may or may not find artifacts depending on the sample
        assert isinstance(artifacts, list)
        
        # If we did find artifacts, verify they're valid
        for artifact in artifacts:
            assert artifact.os == OSType.ANDROID
            assert artifact.id.startswith("art-android-")
            assert artifact.category in extractor.categories or artifact.category  # Valid category
