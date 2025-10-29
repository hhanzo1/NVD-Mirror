# NVD Mirror

A robust Python application for mirroring CVE (Common Vulnerabilities and Exposures) and CPE (Common Platform Enumeration) data from the [National Vulnerability Database (NVD) API](https://nvd.nist.gov/developers) into a PostgreSQL database.

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Overview

The NVD Mirror provides an automated solution for maintaining a local copy of vulnerability and platform enumeration data from NIST's National Vulnerability Database. This is essential for:

- **Offline Security Analysis**: Access vulnerability data without internet connectivity
- **Reduced API Load**: Minimize direct calls to NVD's rate-limited API
- **Custom Integration**: Query vulnerability data using SQL for integration with internal tools
- **Historical Tracking**: Maintain historical records of vulnerability disclosures and updates
- **Compliance Requirements**: Meet regulatory requirements for vulnerability management
- **Performance**: Fast local queries instead of remote API calls

---

## Why Use a Local NVD Mirror?

### Rate Limiting
The NVD API has strict rate limits:
- **Without API Key**: 5 requests per 30-second rolling window
- **With API Key**: 50 requests per 30-second rolling window

For organizations scanning large software inventories, these limits can cause significant delays.

### Reliability
- Eliminates dependency on NVD API availability
- Ensures business continuity during API outages
- Provides consistent query performance

### Data Analysis
- Enables complex SQL queries across vulnerability data
- Supports custom reporting and analytics
- Facilitates trend analysis and risk assessment

### Integration Benefits
- Direct database access for SIEM, GRC, and security tools
- Supports batch processing of vulnerability assessments
- Enables automated compliance reporting

---

## Features

- ✅ **Full & Incremental Synchronization**: Initial full dump with automatic incremental updates
- ✅ **Automatic Database Setup**: Creates PostgreSQL database, tables, and user if missing
- ✅ **API Response Archival**: Backs up raw JSON responses for audit trails
- ✅ **Upsert Operations**: Intelligent insert/update to handle data changes
- ✅ **Automatic Cleanup**: Configurable retention period for archived responses
- ✅ **Comprehensive Logging**: File and console logging with detailed operation tracking
- ✅ **Robust Error Handling**: Retries, rate limiting, and graceful failure management
- ✅ **Database Inspection Utility**: Monitor sync status and record counts
- ✅ **Configuration Flexibility**: Environment-based configuration with sensible defaults

---

## Requirements

- **Python**: 3.11 or higher
- **PostgreSQL**: 12 or higher
- **NVD API Key**: [Request one here](https://nvd.nist.gov/developers/request-an-api-key)
- **Disk Space**: ~10-15 GB for full CVE/CPE dataset plus archives
- **Memory**: Minimum 2 GB RAM recommended

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/hhanzo1/nvd-mirror.git
cd nvd-mirror
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Linux/macOS
# or
venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure PostgreSQL

Ensure PostgreSQL is installed and running. The script can automatically create the database and user, or you can set it up manually:

```bash
# Option 1: Let the script auto-create (recommended)
# The script will attempt to create the database if it doesn't exist

# Option 2: Manual setup
sudo -u postgres psql -f init_db.sql
```

### 4. Configure Environment Variables

```bash
# Copy the example configuration
cp config.example.env .env

# Edit .env with your settings
nano .env
```

**Required Configuration** (`.env` file):

```bash
# Your NVD API Key (REQUIRED - get from https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=your-api-key-here

# PostgreSQL Connection (defaults shown)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=nvd_db
DB_USER=nvd_user
DB_PASSWORD=nvdpassword
```

---

## Usage

### Initial Full Synchronization

For the first run, perform a full sync to download all CVE and CPE records:

```bash
# Ensure FORCE_FULL_SYNC=True in nvd_mirror.py (default)
python nvd_mirror.py
```

**Note**: A full sync can take several hours depending on your internet connection and the NVD dataset size (~250,000+ CVEs and ~1,000,000+ CPEs as of 2025).

### Incremental Updates

After the initial sync, set `FORCE_FULL_SYNC=False` in `nvd_mirror.py` and schedule regular runs:

```bash
# Set up a cron job for daily updates
crontab -e

# Add this line for daily sync at 2 AM
0 2 * * * /path/to/venv/bin/python /path/to/nvd-mirror/nvd_mirror.py
```

### Database Inspection

Monitor your mirror status:

```bash
python inspect_db.py
```

**Sample Output**:

```
--- 📊 NVD Database Inspection ---

[ Table: CVE_RECORDS ]
  Total Records: 245,832
  Last Modified: 2025-10-29 14:23:45 UTC

[ Table: CPE_RECORDS ]
  Total Records: 1,042,567
  Last Modified: 2025-10-29 14:18:12 UTC
```

---

## Project Structure

```
nvd-mirror/
├── README.md                   # This file
├── LICENSE                     # MIT License
├── requirements.txt            # Python dependencies
├── .env                        # Environment configuration (not in git)
├── config.example.env          # Example configuration
├── .gitignore                  # Git ignore rules
├── nvd_mirror.py              # Main synchronization script
├── inspect_db.py              # Database inspection utility
├── init_db.sql                # Manual database initialization script
└── data/                       # Created on first run
    ├── nvd_mirror.log         # Application logs
    └── raw_api_responses/     # Archived JSON responses
```

---

## Configuration Options

Edit these variables in `nvd_mirror.py` for advanced configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `FORCE_FULL_SYNC` | `True` | Force complete sync (set to `False` after initial run) |
| `RESULTS_PER_PAGE_CVE` | `2000` | CVE records per API request (max 2000) |
| `RESULTS_PER_PAGE_CPE` | `2000` | CPE records per API request (max 2000) |
| `SLEEP_TIME` | `6` | Seconds between API requests (respect rate limits) |
| `RETENTION_DAYS` | `90` | Days to keep archived API responses |
| `INCREMENTAL_END_DELAY_MINUTES` | `5` | Minutes before current time for incremental sync end |

---

## Database Schema

### CVE Records Table

```sql
CREATE TABLE cve_records (
    cve_id TEXT PRIMARY KEY,           -- e.g., "CVE-2024-1234"
    json_data JSONB,                   -- Full CVE JSON record
    last_modified TIMESTAMP WITH TIME ZONE
);
```

### CPE Records Table

```sql
CREATE TABLE cpe_records (
    cpe_id TEXT PRIMARY KEY,           -- e.g., "cpe:2.3:a:vendor:product:version"
    json_data JSONB,                   -- Full CPE JSON record
    last_modified TIMESTAMP WITH TIME ZONE
);
```

### Example Queries

```sql
-- Find all critical vulnerabilities from 2024
SELECT cve_id, json_data->'metrics' 
FROM cve_records 
WHERE json_data @> '{"published": "2024"}';

-- Search for vulnerabilities affecting specific software
SELECT cve_id, json_data 
FROM cve_records 
WHERE json_data::text ILIKE '%apache%';

-- Count vulnerabilities by year
SELECT 
    EXTRACT(YEAR FROM (json_data->>'published')::timestamp) as year,
    COUNT(*) as vulnerability_count
FROM cve_records 
GROUP BY year 
ORDER BY year DESC;
```

---

## Logging

Logs are written to both console and `nvd_mirror.log`:

```bash
# View recent log entries
tail -f nvd_mirror.log

# Search for errors
grep ERROR nvd_mirror.log
```

---

## Troubleshooting

### API Key Issues

**Error**: `API call failed: 403`

**Solution**: Verify your API key in `.env` is correct and active. Request a new key at https://nvd.nist.gov/developers/request-an-api-key

### Database Connection Errors

**Error**: `Could not connect to database`

**Solution**: 
1. Verify PostgreSQL is running: `sudo systemctl status postgresql`
2. Check credentials in `.env`
3. Ensure PostgreSQL accepts connections from your host

### Rate Limiting

**Error**: `API call failed: 429`

**Solution**: 
1. Increase `SLEEP_TIME` in `nvd_mirror.py`
2. Verify you're using an API key (required for higher rate limits)
3. Consider running during off-peak hours

### Disk Space

**Error**: `No space left on device`

**Solution**:
1. Check available space: `df -h`
2. Reduce `RETENTION_DAYS` to clean up old archives faster
3. Consider archiving data to external storage

---

## Performance Tips

1. **Initial Sync**: Run the first sync during off-peak hours
2. **Network**: Use a stable, high-bandwidth connection
3. **Database**: Consider adding indexes for frequently queried fields:
   ```sql
   CREATE INDEX idx_cve_published ON cve_records ((json_data->>'published'));
   ```
4. **Resources**: Allocate adequate PostgreSQL shared_buffers for better performance

---

## Security Considerations

- **API Key Protection**: Never commit `.env` to version control
- **Database Security**: Use strong passwords and restrict network access
- **Access Control**: Limit database user permissions to only required operations
- **Updates**: Keep PostgreSQL and Python dependencies updated
- **Monitoring**: Regularly review logs for unusual activity

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) - NIST's vulnerability database
- [MITRE Corporation](https://cve.mitre.org/) - CVE program sponsor
- NVD API Documentation: https://nvd.nist.gov/developers

---

## Disclaimer

This tool is provided as-is for vulnerability management and security research purposes. Always verify critical vulnerability information against the official NVD website. The authors are not responsible for any actions taken based on data obtained through this tool.

---

## Support

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/YOUR_USERNAME/nvd-mirror/issues)
- **Documentation**: NVD API docs at https://nvd.nist.gov/developers
- **Contact**: For security concerns, please email [your-email@example.com]

---

**Last Updated**: October 2025
