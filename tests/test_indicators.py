import unittest

from workerbee_security.indicators import indicators_in_text


class IndicatorTests(unittest.TestCase):
    def test_extracts_and_normalizes_observables(self) -> None:
        found = indicators_in_text(
            "curl HTTPS://Example.COM:443/a?q=1, then connect 8.8.8.8; " + "b" * 32
        )

        self.assertIn(("url", "https://example.com:443/a?q=1"), found)
        self.assertIn(("domain", "example.com"), found)
        self.assertIn(("ip", "8.8.8.8"), found)
        self.assertIn(("md5", "b" * 32), found)

    def test_ignores_file_extensions_and_invalid_ips(self) -> None:
        found = indicators_in_text("python payload.py; cat notes.txt; ping 999.1.2.3")
        self.assertNotIn(("domain", "payload.py"), found)
        self.assertNotIn(("domain", "notes.txt"), found)
        self.assertNotIn(("ip", "999.1.2.3"), found)

    def test_extracts_compressed_ipv6(self) -> None:
        found = indicators_in_text("connection from [2001:4860:4860::8888]:443")
        self.assertIn(("ip", "2001:4860:4860::8888"), found)


if __name__ == "__main__":
    unittest.main()
