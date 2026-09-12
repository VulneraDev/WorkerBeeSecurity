# Changelog

## 0.2.0 - 2026-09-12

- Rank usernames, passwords, and credential pairs.
- Calculate credential success rates, source counts, and observation windows.
- Classify source behavior as brute force, password spray, mixed, repeated, or low volume.
- Export credential intelligence to Markdown, JSON, and CSV.

## 0.1.1 - 2026-09-12

- Include attempted passwords in reports by default.
- Add `--redact-credentials` for shareable reports.

## 0.1.0 - 2026-09-12

- Parse newline-delimited Cowrie JSON logs.
- Reconstruct sessions, authentication attempts, commands, and downloads.
- Extract IP addresses, domains, URLs, and common file hashes.
- Export Markdown, JSON, and CSV reports.
- Add opt-in AbuseIPDB and VirusTotal enrichment.
- Redact captured passwords by default.
