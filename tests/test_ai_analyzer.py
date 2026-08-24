import unittest
from unittest.mock import patch, MagicMock

from detection.ai_analyzer import (
    analyze_with_ai,
    _build_open_ports_table,
    _build_cve_section,
    _build_mitre_section,
    _build_prompt,
)

class TestAIAnalyzer(unittest.TestCase):

    def setUp(self):
        self.sample_scan_results = {
            "target_ip": "192.168.1.100",
            "scan_time": "2026-08-12 10:00:00",
            "open_ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service_name": "ssh",
                    "service_version": "OpenSSH 8.9p1"
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service_name": "http",
                    "service_version": "Apache httpd 2.4.41"
                }
            ]
        }
        self.sample_cve_results = {
            "ssh 22": [
                {
                    "cve_id": "CVE-2023-1234",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "published_date": "2023-01-15",
                    "description": "Remote code execution vulnerability in SSH."
                }
            ]
        }
        self.sample_mitre_mappings = [
            {
                "port": 22,
                "technique_id": "T1021.004",
                "tactic": "Lateral Movement",
                "technique_name": "SSH"
            }
        ]

    def test_build_open_ports_table(self):
        table = _build_open_ports_table(self.sample_scan_results["open_ports"])
        self.assertIn("22", table)
        self.assertIn("ssh", table)
        self.assertIn("OpenSSH 8.9p1", table)

    def test_build_open_ports_table_empty(self):
        table = _build_open_ports_table([])
        self.assertIn("no open ports detected", table)

    def test_build_cve_section(self):
        cve_sec = _build_cve_section(self.sample_cve_results)
        self.assertIn("CVE-2023-1234", cve_sec)
        self.assertIn("CVSS 7.5", cve_sec)

    def test_build_mitre_section(self):
        mitre_sec = _build_mitre_section(self.sample_mitre_mappings)
        self.assertIn("T1021.004", mitre_sec)
        self.assertIn("Lateral Movement", mitre_sec)

    def test_build_prompt(self):
        prompt = _build_prompt(
            self.sample_scan_results,
            self.sample_cve_results,
            self.sample_mitre_mappings
        )
        self.assertIn("192.168.1.100", prompt)
        self.assertIn("CVE-2023-1234", prompt)
        self.assertIn("T1021.004", prompt)

    @patch("detection.ai_analyzer.Config")
    def test_analyze_with_ai_no_api_key(self, mock_config):
        mock_config.GROQ_API_KEY = ""
        result = analyze_with_ai(
            self.sample_scan_results,
            self.sample_cve_results,
            self.sample_mitre_mappings
        )
        self.assertIn("[AI Analysis Unavailable]", result)
        self.assertIn("GROQ_API_KEY is not set", result)

    @patch("detection.ai_analyzer.Config")
    def test_analyze_with_ai_successful_call(self, mock_config):
        mock_config.GROQ_API_KEY = "gsk_test123"

        mock_choice = MagicMock()
        mock_choice.message.content = "## Risk Overview\nRisk is HIGH."

        mock_completion = MagicMock()
        mock_completion.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_completion

        with patch("groq.Groq", return_value=mock_client):
            result = analyze_with_ai(
                self.sample_scan_results,
                self.sample_cve_results,
                self.sample_mitre_mappings
            )
            self.assertEqual(result, "## Risk Overview\nRisk is HIGH.")
            mock_client.chat.completions.create.assert_called_once()
            call_kwargs = mock_client.chat.completions.create.call_args[1]
            self.assertEqual(call_kwargs["model"], "groq/compound-mini")

    @patch("detection.ai_analyzer.Config")
    def test_analyze_with_ai_api_exception(self, mock_config):
        mock_config.GROQ_API_KEY = "gsk_test123"

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API connection timeout")

        with patch("groq.Groq", return_value=mock_client):
            result = analyze_with_ai(
                self.sample_scan_results,
                self.sample_cve_results,
                self.sample_mitre_mappings
            )
            self.assertIn("[AI Analysis Unavailable]", result)
            self.assertIn("An unexpected error occurred", result)

if __name__ == '__main__':
    unittest.main()
