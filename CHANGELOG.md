# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Add IPv6 specific handling improvements
- Add geolocation visualization
- Add bulk report generation
- Add support for additional WHOIS sources
- Add support for historical WHOIS data

## [0.1.0] - 2025-05-23

### Added
- Initial release of the IP WHOIS Lookup Tool
- Multiple resolver implementations:
  - IPWhois resolver using RDAP
  - Python-WHOIS resolver with domain resolution
  - System WHOIS command integration
- Automatic fallback between resolvers
- Caching system to avoid unnecessary network requests
- Multiple output formats (CSV, JSON, text)
- Command-line interface with:
  - Rich output formatting
  - Progress bars
  - Colored console output
- Rate limiting to avoid WHOIS server restrictions
- Parallel processing for bulk lookups
- Comprehensive error handling and logging
- Documentation and usage examples

### Notes
- This is the initial release with core functionality
- Feedback and bug reports are welcome

