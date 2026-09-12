import os
import unittest
from unittest.mock import patch

from workerbee_security.enrichment import AbuseIPDB, EnrichmentError, VirusTotal, providers


class EnrichmentTests(unittest.TestCase):
    def test_requires_keys(self) -> None:
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(EnrichmentError):
            providers(["virustotal"], 1.0)

    def test_skips_non_public_ips(self) -> None:
        client = AbuseIPDB("key", 1.0)
        self.assertFalse(client.supports({"type": "ip", "value": "127.0.0.1"}))
        self.assertTrue(client.supports({"type": "ip", "value": "8.8.8.8"}))

    def test_virustotal_paths(self) -> None:
        client = VirusTotal("key", 1.0)
        self.assertEqual(client._path("ip", "8.8.8.8"), "ip_addresses/8.8.8.8")
        self.assertEqual(client._path("domain", "example.com"), "domains/example.com")
        self.assertEqual(client._path("sha256", "a" * 64), "files/" + "a" * 64)
        self.assertTrue(client._path("url", "https://example.com").startswith("urls/"))


if __name__ == "__main__":
    unittest.main()
