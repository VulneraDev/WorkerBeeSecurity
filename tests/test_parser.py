import io
import unittest

from workerbee_security.parser import CowrieParseError, parse_lines


class ParserTests(unittest.TestCase):
    def test_skips_bad_lines_and_records_warning(self) -> None:
        result = parse_lines(
            [
                '{"eventid":"cowrie.session.connect","session":"abc"}\n',
                "not json\n",
                "[]\n",
            ],
            "test.json",
        )

        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.warnings), 2)
        self.assertEqual(result.lines_read, 3)

    def test_strict_mode_stops_on_bad_json(self) -> None:
        with self.assertRaises(CowrieParseError):
            parse_lines(["nope\n"], "test.json", strict=True)

    def test_limit_counts_valid_events(self) -> None:
        line = '{"eventid":"cowrie.session.connect"}\n'
        result = parse_lines(io.StringIO(line * 5), "test.json", limit=2)
        self.assertEqual(len(result.events), 2)


if __name__ == "__main__":
    unittest.main()
