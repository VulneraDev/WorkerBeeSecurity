import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from workerbee_security.cli import run

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie.sample.json"


class CliTests(unittest.TestCase):
    def test_analyze_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()):
                code = run(["analyze", str(FIXTURE), "--output", directory])
            self.assertEqual(code, 0)
            self.assertTrue((Path(directory) / "workerbee-report.md").is_file())
            self.assertTrue((Path(directory) / "workerbee-report.json").is_file())

    def test_missing_file(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run(["analyze", "missing.json"]), 2)


if __name__ == "__main__":
    unittest.main()
