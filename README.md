# WorkerBee Security

Security telemetry in. Analyst-ready intelligence out. 🐝

WorkerBee Security is a defensive, offline-first CLI for reconstructing sessions,
extracting indicators of compromise, and exporting structured findings from
Cowrie JSON logs.

## Project status

Early development. The first release will focus on:

- parsing newline-delimited `cowrie.json` events;
- grouping activity into attacker sessions;
- extracting IP addresses, URLs, domains, and file hashes;
- producing Markdown, JSON, and CSV reports;
- keeping enrichment optional and local processing as the default.

WorkerBee Security does not deploy honeypots, execute captured files, or perform
counterattacks.

## License

Apache License 2.0. See [LICENSE](LICENSE).
