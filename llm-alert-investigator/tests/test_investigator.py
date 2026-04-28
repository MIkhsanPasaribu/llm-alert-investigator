"""Tests for alert investigator."""

import pytest

from src.investigator import AlertInvestigator


class TestAlertInvestigator:
    """Test suite for AlertInvestigator class."""

    @pytest.fixture
    def investigator(self, tmp_path):
        """Create an investigator instance with temporary KB path."""
        kb_path = str(tmp_path / "mitre_kb")
        return AlertInvestigator(
            model="llama-3.3-70b-versatile",
            temperature=0.0,
            retrieval_k=3,
            mitre_kb_path=kb_path,
        )

    @pytest.fixture
    def sample_alert(self):
        """Create a sample alert for testing."""
        return {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.50",
            "event_type": "network_connection",
            "process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand ...",
            "severity": "high",
        }

    def test_investigator_initialization(self, investigator):
        """Test investigator initialization."""
        assert investigator.model == "llama-3.3-70b-versatile"
        assert investigator.temperature == 0.0
        assert investigator.retrieval_k == 3
        assert investigator.mitre_kb is not None

    def test_format_alert(self, investigator, sample_alert):
        """Test alert formatting."""
        text = investigator._format_alert(sample_alert)

        assert "2024-01-15T10:30:00Z" in text
        assert "192.168.1.100" in text
        assert "10.0.0.50" in text
        assert "powershell.exe" in text

    def test_format_techniques(self, investigator):
        """Test technique formatting."""
        from langchain_core.documents import Document

        techniques = [
            Document(
                page_content="Technique ID: T1059.001 | Technique Name: PowerShell",
                metadata={"technique_id": "T1059.001", "technique_name": "PowerShell", "tactics": "Execution"},
            )
        ]

        formatted = investigator._format_techniques(techniques)

        assert "T1059.001" in formatted
        assert "PowerShell" in formatted
        assert "Execution" in formatted

    def test_investigate_alert_structure(self, investigator, sample_alert):
        """Test that investigation returns correct structure."""
        result = investigator.investigate(sample_alert)

        assert "mitre_mapping" in result
        assert "narrative" in result
        assert "next_steps" in result
        assert "severity" in result
        assert "raw_alert" in result
        assert "normalized_alert" in result
        assert "enriched_alert" in result
        assert "retrieved_techniques" in result

    def test_mitre_mapping_format(self, investigator, sample_alert):
        """Test MITRE mapping format."""
        result = investigator.investigate(sample_alert)
        mitre_mapping = result["mitre_mapping"]

        assert isinstance(mitre_mapping, list)
        if mitre_mapping:
            mapping = mitre_mapping[0]
            assert "tactic" in mapping
            assert "technique_id" in mapping
            assert "technique_name" in mapping
            assert "confidence" in mapping
            assert 0.0 <= mapping["confidence"] <= 1.0

    def test_severity_format(self, investigator, sample_alert):
        """Test severity format."""
        result = investigator.investigate(sample_alert)
        severity = result["severity"]

        assert severity in ["low", "medium", "high", "critical"]

    def test_next_steps_format(self, investigator, sample_alert):
        """Test next steps format."""
        result = investigator.investigate(sample_alert)
        next_steps = result["next_steps"]

        assert isinstance(next_steps, list)
        if next_steps:
            assert all(isinstance(step, str) for step in next_steps)

    def test_batch_processing(self, investigator):
        """Test batch alert processing."""
        alerts = [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "event_type": "network_connection",
                "process": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand ...",
                "severity": "high",
            },
            {
                "timestamp": "2024-01-15T11:00:00Z",
                "src_ip": "192.168.1.105",
                "dst_ip": "192.168.1.200",
                "event_type": "network_connection",
                "process": "mstsc.exe",
                "command_line": "mstsc.exe /v:192.168.1.200",
                "severity": "medium",
            },
        ]

        results = investigator.investigate_batch(alerts)

        assert len(results) == 2
        for result in results:
            assert "mitre_mapping" in result
            assert "narrative" in result
