# Setup Guide

This guide provides detailed instructions for setting up and running NVD Mirror.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Setup](#system-setup)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Running the Script](#running-the-script)
6. [Automation](#automation)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

- **Operating System**: Linux (Ubuntu/Debian/RHEL/CentOS) or macOS
- **Python**: Version 3.11 or higher
- **PostgreSQL**: Version 12 or higher
- **Git**: For cloning the repository

### API Key

Before starting, obtain an NVD API key:

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the request form
3. Check your email for the API key (usually arrives within a few minutes)
4. Save this key securely - you'll need it for configuration

---

## System Setup

### Install PostgreSQL

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**RHEL/CentOS:**
```bash
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**macOS (using Homebrew):**
```bash
brew install postgresql@14
brew services start postgresql@14
```

### Install Python

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip
```

**macOS:**
```bash
brew install python@3.11
```

---

## Installation

### 1. Clone the Repository

```bash
cd /opt  # or your preferred location
git clone https://github.com/hhanzo1/nvd-mirror.git
cd nvd-mirror
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration

### 1. Set Up PostgreSQL Database

**Option A: Automatic (Recommended)**

The script will attempt to create the database automatically. Just ensure PostgreSQL is running.

**Option B: Manual Setup**

```bash
# Create the database and user
sudo -u postgres psql -f init_db.sql

# Or create manually:
sudo -u postgres psql << EOF
CREATE DATABASE nvd_db;
CREATE USER nvd_user WITH PASSWORD 'nvdpassword';
GRANT ALL PRIVILEGES ON DATABASE nvd_db TO nvd_user;
\c nvd_db
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO nvd_user;
EOF
```

### 2. Configure Environment Variables

```bash
# Copy the example configuration
cp config.example.env .env

# Edit the configuration
nano .env
```

**Update these values in `.env`:**

```bash
# REQUIRED: Your NVD API key
NVD_API_KEY=paste-your-actual-api-key-here

# PostgreSQL settings (adjust if needed)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=nvd_db
DB_USER=nvd_user
DB_PASSWORD=your-secure-password-here
```

### 3. Verify Configuration

```bash
# Test database connection
python inspect_db.py
```

If you see the inspection output without errors, your database is configured correctly.

---

## Running the Script

### Initial Full Sync

For the first run, ensure `FORCE_FULL_SYNC=True` in `nvd_mirror.py` (this is the default):

```bash
# Activate virtual environment if not already active
source venv/bin/activate

# Run the sync
python nvd_mirror.py
```

**Expected Duration**: 3-6 hours depending on your connection speed and API rate limits.

**What's Happening**:
- Downloading ~250,000 CVE records
- Downloading ~1,000,000 CPE records
- Archiving raw API responses
- Inserting records into PostgreSQL

### Monitoring Progress

**Terminal Output:**
The script provides real-time progress updates to the console.

**Log File:**
```bash
# In another terminal, watch the log file
tail -f data/nvd_mirror.log
```

### Subsequent Incremental Syncs

After the initial sync, update `nvd_mirror.py`:

```python
# Change this line in nvd_mirror.py
FORCE_FULL_SYNC = False
```

Then run normally:
```bash
python nvd_mirror.py
```

Incremental syncs typically take 5-15 minutes depending on the number of updates since the last run.

---

## Automation

### Using Cron (Linux/macOS)

**Option 1: Daily Sync**

```bash
# Edit crontab
crontab -e

# Add this line (runs daily at 2 AM)
0 2 * * * cd /opt/nvd-mirror && /opt/nvd-mirror/venv/bin/python /opt/nvd-mirror/nvd_mirror.py >> /opt/nvd-mirror/data/cron.log 2>&1
```

**Option 2: Twice Daily Sync**

```bash
# Runs at 2 AM and 2 PM
0 2,14 * * * cd /opt/nvd-mirror && /opt/nvd-mirror/venv/bin/python /opt/nvd-mirror/nvd_mirror.py >> /opt/nvd-mirror/data/cron.log 2>&1
```

### Using Systemd (Linux)

Create a systemd service and timer:

**1. Create service file:**

```bash
sudo nano /etc/systemd/system/nvd-mirror.service
```

**Content:**
```ini
[Unit]
Description=NVD Mirror Sync Service
After=network.target postgresql.service

[Service]
Type=oneshot
User=your-username
WorkingDirectory=/opt/nvd-mirror
Environment="PATH=/opt/nvd-mirror/venv/bin"
ExecStart=/opt/nvd-mirror/venv/bin/python /opt/nvd-mirror/nvd_mirror.py

[Install]
WantedBy=multi-user.target
```

**2. Create timer file:**

```bash
sudo nano /etc/systemd/system/nvd-mirror.timer
```

**Content:**
```ini
[Unit]
Description=NVD Mirror Sync Timer
Requires=nvd-mirror.service

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

**3. Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable nvd-mirror.timer
sudo systemctl start nvd-mirror.timer

# Check status
sudo systemctl status nvd-mirror.timer
```

---

## Verification

### Check Database Contents

```bash
python inspect_db.py
```

Expected output:
```
📊 NVD Database Inspection
============================================================

[ CVE RECORDS ]
------------------------------------------------------------
  Total Records:     245,832
  Last Modified:     2025-10-29 14:23:45 UTC

[ CPE RECORDS ]
------------------------------------------------------------
  Total Records:     1,042,567
  Last Modified:     2025-10-29 14:18:12 UTC
```

### Query the Database

```bash
psql -U nvd_user -d nvd_db -c "SELECT COUNT(*) FROM cve_records;"
psql -U nvd_user -d nvd_db -c "SELECT COUNT(*) FROM cpe_records;"
```

### Check Logs

```bash
# View recent activity
tail -100 data/nvd_mirror.log

# Search for errors
grep ERROR data/nvd_mirror.log
```

---

## Troubleshooting

### Database Connection Issues

**Problem**: `Could not connect to database`

**Solutions**:
```bash
# Verify PostgreSQL is running
sudo systemctl status postgresql

# Test connection manually
psql -U nvd_user -d nvd_db -h localhost

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### API Authentication Failures

**Problem**: `API call failed: 403`

**Solutions**:
1. Verify your API key is correctly set in `.env`
2. Ensure there are no extra spaces or quotes around the key
3. Request a new API key if the old one expired
4. Check NVD API status: https://nvd.nist.gov/general/news

### Rate Limiting

**Problem**: `API call failed: 429`

**Solutions**:
- Increase `SLEEP_TIME` in `nvd_mirror.py` (e.g., from 6 to 10 seconds)
- Verify you're using an API key (50 requests/30s with key vs 5 without)
- Schedule syncs during off-peak hours

### Disk Space Issues

**Problem**: Running out of disk space

**Solutions**:
```bash
# Check available space
df -h

# Reduce retention period in nvd_mirror.py
RETENTION_DAYS = 30  # instead of 90

# Manually clean old archives
rm -rf data/raw_api_responses/*

# Consider compressing old archives
find data/raw_api_responses -name "*.json" -mtime +30 -exec gzip {} \;
```

### Memory Issues

**Problem**: Script crashes with memory errors

**Solutions**:
- Reduce `RESULTS_PER_PAGE_CVE` and `RESULTS_PER_PAGE_CPE` to 1000
- Increase system swap space
- Run during off-peak hours when system has more available memory

---

## Getting Help

If you encounter issues not covered here:

1. Check the [main README](README.md) for additional information
2. Search existing [GitHub Issues](https://github.com/YOUR_USERNAME/nvd-mirror/issues)
3. Create a new issue with:
   - Detailed description of the problem
   - Relevant log excerpts (sanitized)
   - Your environment details (OS, Python version, PostgreSQL version)
   - Steps to reproduce

---

## Next Steps

After successful setup:

1. Monitor the first few automated runs
2. Set up alerting for failed syncs (optional)
3. Create custom SQL queries for your use cases
4. Integrate with your security tools
5. Consider setting up database backups

---

**Need more help?** Open an issue on GitHub or check the documentation at the [NVD Developer Portal](https://nvd.nist.gov/developers).
