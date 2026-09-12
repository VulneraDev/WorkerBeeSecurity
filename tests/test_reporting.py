import csv
import json
import tempfile
import unittest
from pathlib import Path

from workerbee_security.analysis import analyze
from workerbee_security.dashboard import dashboard
from workerbee_security.models import ParseResult
from workerbee_security.parser import parse_file
from workerbee_security.reporting import markdown, write_reports

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie.sample.json"


class ReportingTests(unittest.TestCase):
    def test_writes_all_formats(self) -> None:
        report = analyze(parse_file(str(FIXTURE)))

        with tempfile.TemporaryDirectory() as directory:
            paths = write_reports(report, directory, ("html", "markdown", "json", "csv"))
            self.assertEqual(len(paths), 6)
            self.assertTrue(all(path.is_file() for path in paths))

            loaded = json.loads((Path(directory) / "workerbee-report.json").read_text())
            self.assertEqual(loaded["summary"]["events"], 6)

            with (Path(directory) / "workerbee-indicators.csv").open() as handle:
                rows = list(csv.DictReader(handle))
            self.assertGreaterEqual(len(rows), 4)

            with (Path(directory) / "workerbee-credentials.csv").open() as handle:
                credential_rows = list(csv.DictReader(handle))
            self.assertEqual(
                {row["kind"] for row in credential_rows}, {"username", "password", "pair"}
            )

            html_report = (Path(directory) / "workerbee-report.html").read_text()
            self.assertIn("Attack intelligence report", html_report)
            self.assertIn("admin123", html_report)

    def test_dashboard_escapes_attacker_content(self) -> None:
        report = analyze(parse_file(str(FIXTURE)))
        report["sessions"][0]["commands"][0]["command"] = "<script>alert(1)</script>"

        rendered = dashboard(report)

        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertIn("Content-Security-Policy", rendered)

    def test_dashboard_respects_password_redaction(self) -> None:
        rendered = dashboard(analyze(parse_file(str(FIXTURE)), show_credentials=False))

        self.assertNotIn("admin123", rendered)
        self.assertIn("Password and credential-pair rankings were redacted", rendered)

    def test_dashboard_handles_an_empty_log(self) -> None:
        report = analyze(ParseResult(source="empty.json", events=[], warnings=[], lines_read=0))

        rendered = dashboard(report)

        self.assertIn("No sessions", rendered)
        self.assertIn("No authentication attempts", rendered)
        self.assertIn("No indicators", rendered)

    def test_markdown_neutralizes_html(self) -> None:
        report = analyze(parse_file(str(FIXTURE)))
        report["sessions"][0]["commands"][0]["command"] = "echo <script>alert(1)</script>"
        rendered = markdown(report)
        self.assertNotIn("<script>", rendered)

    def test_markdown_includes_credential_intelligence(self) -> None:
        rendered = markdown(analyze(parse_file(str(FIXTURE))))

        self.assertIn("## Credential intelligence", rendered)
        self.assertIn("### Top passwords", rendered)
        self.assertIn("`admin123`", rendered)

    def test_markdown_omits_password_rankings_when_redacted(self) -> None:
        rendered = markdown(analyze(parse_file(str(FIXTURE)), show_credentials=False))

        self.assertIn("Password and credential-pair rankings were redacted.", rendered)
        self.assertNotIn("### Top passwords", rendered)

    def test_csv_neutralizes_formulas(self) -> None:
        report = analyze(parse_file(str(FIXTURE)))
        report["sessions"][0]["usernames"] = ['=HYPERLINK("https://example.com")']
        with tempfile.TemporaryDirectory() as directory:
            write_reports(report, directory, ("csv",))
            with (Path(directory) / "workerbee-sessions.csv").open() as handle:
                row = next(csv.DictReader(handle))
        self.assertTrue(row["usernames"].startswith("'="))


if __name__ == "__main__":
    unittest.main()
