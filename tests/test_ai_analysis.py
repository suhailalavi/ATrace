import pytest
from unittest.mock import patch, MagicMock
import json
from alavitrace.core.models import Target, Host, Service, ScanResult, Finding, Severity, Confidence
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.ai.gemini import GeminiAIProvider
from alavitrace.ai.analyst import SecurityAnalyst
from alavitrace.cli import run_pipeline

def test_prepare_structured_input_sanitization():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[Service(port=22, protocol="tcp", state="open", name="SSH", product="OpenSSH", version="7.9p1")]
    )
    scan_result = ScanResult(target=target, hosts=[host])

    structured_data = SecurityAnalyst.prepare_structured_input(scan_result, [], [])
    assert structured_data["target"] == "192.168.56.106"
    assert len(structured_data["hosts"]) == 1
    assert structured_data["hosts"][0]["open_ports"][0]["product"] == "OpenSSH"
    assert "password" not in json.dumps(structured_data)

def test_gemini_provider_missing_api_key():
    with patch.dict("os.environ", {}, clear=True):
        provider = GeminiAIProvider()
        result = provider.analyze_security_data({"target": "192.168.56.106"})
        assert result.is_available is False
        assert "GEMINI_API_KEY" in result.error_message

def test_gemini_provider_successful_mock():
    mock_ai_json = {
        "executive_summary": "Two services identified. Manual validation required.",
        "attack_surface_summary": "Exposed SSH and FTP services.",
        "key_observations": ["OpenSSH 7.9p1 detected."],
        "investigation_priorities": ["Verify SSH configuration."],
        "remediation_summary": ["Upgrade OpenSSH."],
        "limitations": ["Reconnaissance only."]
    }

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps(mock_ai_json)
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client), \
         patch.dict("os.environ", {"GEMINI_API_KEY": "test_mock_key"}):
        provider = GeminiAIProvider()
        result = provider.analyze_security_data({"target": "192.168.56.106"})

        assert result.is_available is True
        assert result.executive_summary == "Two services identified. Manual validation required."
        assert "OpenSSH 7.9p1 detected." in result.key_observations

def test_gemini_provider_invalid_json():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "NOT_VALID_JSON"
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client), \
         patch.dict("os.environ", {"GEMINI_API_KEY": "test_mock_key"}):
        provider = GeminiAIProvider()
        result = provider.analyze_security_data({"target": "192.168.56.106"})

        assert result.is_available is False
        assert "Failed to parse structured JSON" in result.error_message
