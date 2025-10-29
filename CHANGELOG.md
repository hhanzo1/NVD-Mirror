# Changelog

All notable changes to the NVD Mirror project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of NVD Mirror
- Full synchronization of CVE records from NVD API
- Full synchronization of CPE records from NVD API
- Incremental update support based on last modification timestamps
- PostgreSQL database storage with JSONB columns
- Automatic database table creation
- Raw API response archival for audit trails
- Configurable retention period for archived responses
- Comprehensive logging to file and console
- Database inspection utility (`inspect_db.py`)
- Environment-based configuration via .env files
- Retry logic with exponential backoff for API requests
- Rate limiting compliance (6-second delay between requests)
- Upsert operations to handle duplicate records gracefully

### Security
- API key protection via environment variables
- No credentials stored in code

### Documentation
- Comprehensive README with installation and usage instructions
- Detailed explanation of why NVD mirroring is beneficial
- Example SQL queries for common use cases
- Troubleshooting guide
- Contributing guidelines
- MIT License

## [1.0.0] - 2025-10-29

### Initial Release
- Core functionality for mirroring NVD data
- Support for CVE and CPE datasets
- PostgreSQL backend storage
- Full and incremental sync modes

## [1.0.1] - 2025-10-29
- Fixed Out of memory bug