# Contributing

Bug reports, parser fixtures, output improvements, and enrichment adapters are welcome.

1. Fork the repository and create a focused branch.
2. Add or update tests with the change.
3. Run `python -m unittest discover -s tests -v`.
4. Open a pull request describing the Cowrie event types you tested.

Sanitize fixtures before committing them. Replace public IP addresses with documentation
ranges, remove real credentials, and never add captured binaries.
