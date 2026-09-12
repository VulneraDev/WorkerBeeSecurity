import unittest
from pathlib import Path

from workerbee_security.analysis import analyze
from workerbee_security.parser import parse_file

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie.sample.json"


class AnalysisTests(unittest.TestCase):
    def test_reconstructs_session_and_extracts_indicators(self) -> None:
        report = analyze(parse_file(str(FIXTURE)))

        self.assertEqual(report["summary"]["events"], 6)
        self.assertEqual(report["summary"]["sessions"], 1)
        self.assertEqual(report["summary"]["commands"], 1)
        self.assertEqual(report["summary"]["downloads"], 1)

        session = report["sessions"][0]
        self.assertEqual(session["severity"], "high")
        self.assertEqual(session["duration_seconds"], 10.0)
        self.assertEqual(session["credentials"][0]["password"], "toor")

        indicators = {(item["type"], item["value"]) for item in report["indicators"]}
        self.assertIn(("ip", "203.0.113.42"), indicators)
        self.assertIn(("domain", "payload.example"), indicators)
        self.assertIn(("url", "http://payload.example/dropper"), indicators)
        self.assertIn(("sha256", "a" * 64), indicators)
        self.assertNotIn(("ip", "192.0.2.10"), indicators)

    def test_credentials_can_be_redacted(self) -> None:
        report = analyze(parse_file(str(FIXTURE)), show_credentials=False)
        passwords = [item["password"] for item in report["sessions"][0]["credentials"]]
        self.assertEqual(passwords, ["<redacted>", "<redacted>"])


if __name__ == "__main__":
    unittest.main()
