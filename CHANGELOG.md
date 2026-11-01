# Changelog

## 0.4.0 - 2026-11-01

### Added

- Added cve.now as a supplemental advisory source for resolved npm, Go, and PyPI package versions.
- Included cve.now CVSS scores, affected ranges, source references, and exploitation signals such as CISA KEV and EPSS in reports.
- Deduplicated cve.now advisories against OSV findings and surfaced advisory-source errors in report coverage.
- Added a 15-minute local cache for cve.now package-version responses.

### Changed

- Bumped the JSON report schema to `1.2.0` to include source attribution and cve.now metadata.
