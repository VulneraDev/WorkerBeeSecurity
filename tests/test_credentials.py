import unittest
from pathlib import Path

from workerbee_security.credentials import summarize_credentials
from workerbee_security.parser import parse_file

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie.credentials.json"


class CredentialTests(unittest.TestCase):
    def test_ranks_credentials_and_classifies_sources(self) -> None:
        result = summarize_credentials(parse_file(str(FIXTURE)).events)

        self.assertEqual(result["attempts"], 6)
        self.assertEqual(result["successes"], 1)
        self.assertEqual(result["unique_usernames"], 4)
        self.assertEqual(result["unique_passwords"], 4)
        self.assertEqual(result["top_usernames"][0]["username"], "root")
        self.assertEqual(result["top_usernames"][0]["attempts"], 3)
        self.assertEqual(result["top_passwords"][0]["password"], "welcome")
        self.assertEqual(result["top_passwords"][0]["source_count"], 1)

        patterns = {item["source_ip"]: item for item in result["source_patterns"]}
        self.assertEqual(patterns["203.0.113.10"]["classification"], "brute_force")
        self.assertEqual(patterns["198.51.100.20"]["classification"], "password_spray")

    def test_omits_password_rankings_when_redacted(self) -> None:
        result = summarize_credentials(parse_file(str(FIXTURE)).events, show_passwords=False)

        self.assertTrue(result["passwords_redacted"])
        self.assertEqual(result["top_passwords"], [])
        self.assertEqual(result["top_pairs"], [])
        self.assertEqual(result["unique_passwords"], 4)


if __name__ == "__main__":
    unittest.main()
