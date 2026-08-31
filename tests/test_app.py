import unittest
import json
from unittest.mock import patch, MagicMock
from app import app
from database.models import SearchHistory, IPReport, create_tables
from sqlalchemy.orm import sessionmaker

class TestThreatIntelAppRoutes(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.engine = create_tables("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)
        self.client = app.test_client()

    def test_home_route(self):
        """Test GET / returns 302 redirect to /dashboard."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard', response.headers['Location'])

    def test_analyze_post_valid_and_invalid(self):
        """Test POST /analyze format validation."""
        # Valid IP
        res_valid = self.client.post('/analyze', data={'ip': '8.8.8.8'})
        self.assertEqual(res_valid.status_code, 302)
        self.assertIn('/report/8.8.8.8', res_valid.headers['Location'])

        # Invalid IP redirects to home
        res_invalid = self.client.post('/analyze', data={'ip': 'not-an-ip'})
        self.assertEqual(res_invalid.status_code, 302)

    @patch('app.analyze_ip')
    def test_api_analyze_route(self, mock_analyze_ip):
        """Test GET /api/analyze/<ip> calls analyze_ip and returns JSON."""
        mock_analyze_ip.return_value = {
            "ip": "1.1.1.1",
            "abuse_score": 0,
            "total_reports": 0,
            "country": "US",
            "isp": "Cloudflare",
            "open_ports": [53, 80, 443],
            "vulnerabilities": [],
            "risk_level": "LOW",
            "ai_analysis": "AI summary"
        }

        # Valid IP request
        response = self.client.get('/api/analyze/1.1.1.1')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["ip"], "1.1.1.1")
        self.assertEqual(data["data"]["risk_level"], "LOW")
        self.assertEqual(data["ai_analysis"], "AI summary")
        mock_analyze_ip.assert_called_once_with("1.1.1.1")

        # Invalid IP request
        res_invalid = self.client.get('/api/analyze/invalid-ip')
        self.assertEqual(res_invalid.status_code, 400)

    @patch('app.analyze_ip')
    def test_report_route(self, mock_analyze_ip):
        """Test GET /report/<ip> calls analyze_ip and renders report.html."""
        mock_analyze_ip.return_value = {
            "ip": "8.8.8.8",
            "abuse_score": 10,
            "total_reports": 2,
            "country": "US",
            "isp": "Google LLC",
            "open_ports": [53],
            "vulnerabilities": [],
            "risk_level": "LOW",
            "ai_analysis": "Google DNS summary"
        }

        response = self.client.get('/report/8.8.8.8')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'8.8.8.8', response.data)
        self.assertIn(b'TARGET ASSESSMENT REPORT', response.data)
        mock_analyze_ip.assert_called_once_with("8.8.8.8")

    def test_history_route(self):
        """Test GET /history queries SearchHistory from DB and renders history.html."""
        session = self.Session()
        log = SearchHistory(ip_address="9.9.9.9", risk_level="HIGH")
        session.add(log)
        session.commit()
        session.close()

        response = self.client.get('/history')
        self.assertEqual(response.status_code, 200)

    def test_scanner_route(self):
        """Test GET /scanner renders scanner.html."""
        response = self.client.get('/scanner')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'IP Threat Analysis', response.data)

    @patch('app.generate_pdf_report')
    @patch('app.analyze_with_ai')
    @patch('app.map_ports_to_mitre')
    @patch('app.get_cves_for_service')
    @patch('app.scan_target')
    def test_api_scan_route(self, mock_scan, mock_cve, mock_mitre, mock_ai, mock_pdf):
        """Test POST /api/scan runs full scan pipeline and returns JSON."""
        mock_scan.return_value = {
            "target_ip": "127.0.0.1",
            "scan_time": "2026-08-12 10:00:00",
            "open_ports": [
                {"port": 22, "protocol": "tcp", "service_name": "ssh", "service_version": "8.9"}
            ]
        }
        mock_cve.return_value = [{"cve_id": "CVE-2023-1234", "severity": "HIGH"}]
        mock_mitre.return_value = [{"port": 22, "technique_id": "T1021.004"}]
        mock_ai.return_value = "AI Analysis Report"
        mock_pdf.return_value = "screenshots/report_127.0.0.1.pdf"

        # Invalid IP request
        res_invalid = self.client.post('/api/scan', json={"target_ip": "bad-ip"})
        self.assertEqual(res_invalid.status_code, 400)

        # Valid IP request
        res_valid = self.client.post('/api/scan', json={"target_ip": "127.0.0.1"})
        self.assertEqual(res_valid.status_code, 200)
        data = json.loads(res_valid.data)
        self.assertEqual(data["ai_analysis"], "AI Analysis Report")
        mock_scan.assert_called_once_with("127.0.0.1")
        mock_cve.assert_called_once_with("ssh", "8.9")
        mock_mitre.assert_called_once()
        mock_ai.assert_called_once()
        mock_pdf.assert_called_once()

    def test_download_report_invalid_or_missing(self):
        """Test GET /download/report/<ip> handling."""
        # Invalid IP
        res_invalid = self.client.get('/download/report/invalid-ip', follow_redirects=True)
        self.assertEqual(res_invalid.status_code, 200)

        # Non-existent report PDF
        res_missing = self.client.get('/download/report/192.168.1.250', follow_redirects=True)
        self.assertEqual(res_missing.status_code, 200)

if __name__ == '__main__':
    unittest.main()

