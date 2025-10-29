# Quick Start Guide

Get your NVD Mirror up and running in under 10 minutes!

## Prerequisites Checklist

- [ ] Python 3.11+ installed
- [ ] PostgreSQL 12+ installed and running
- [ ] NVD API Key ([get one here](https://nvd.nist.gov/developers/request-an-api-key))

---

## 5-Step Installation

### Step 1: Clone and Setup

```bash
# Clone repository
git clone https://github.com/hhanzo1/nvd-mirror.git
cd nvd-mirror

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Database

```bash
# Option A: Let the script auto-create (easiest)
# Just ensure PostgreSQL is running
sudo systemctl start postgresql

# Option B: Manual setup
sudo -u postgres psql -f init_db.sql
```

### Step 3: Configure API Key

```bash
# Copy example config
cp config.example.env .env

# Edit with your API key
nano .env
# or
vim .env
```

**Add your API key to `.env`:**
```bash
NVD_API_KEY=your-actual-api-key-here
```

### Step 4: Run Initial Sync

```bash
python nvd_mirror.py
```

⏰ **This will take 3-6 hours** - perfect time for lunch, a meeting, or end of day.

### Step 5: Verify

```bash
python inspect_db.py
```

Expected output:
```
📊 NVD Database Inspection
============================================================
[ CVE RECORDS ]
  Total Records:     245,832
  Last Modified:     2025-10-29 14:23:45 UTC

[ CPE RECORDS ]
  Total Records:     1,042,567
  Last Modified:     2025-10-29 14:18:12 UTC
```

---

## Common First Commands

### Query Your Data

```bash
# Connect to database
psql -U nvd_user -d nvd_db

# Count records
SELECT COUNT(*) FROM cve_records;

# Recent CVEs
SELECT cve_id, json_data->>'published' as published
FROM cve_records
ORDER BY published DESC
LIMIT 10;
```

### Schedule Daily Updates

```bash
# Edit crontab
crontab -e

# Add this line (runs at 2 AM daily)
0 2 * * * cd /path/to/nvd-mirror && /path/to/nvd-mirror/venv/bin/python /path/to/nvd-mirror/nvd_mirror.py
```

**Important**: After the initial sync, set `FORCE_FULL_SYNC = False` in `nvd_mirror.py`

---

## Troubleshooting Quick Fixes

### "Could not connect to database"

```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Start it if needed
sudo systemctl start postgresql
```

### "API call failed: 403"

- Double-check your API key in `.env` has no extra spaces
- Ensure you copied the entire key
- Request a new key if needed

### "Rate limit exceeded"

- This is normal during full sync
- The script will automatically retry
- Consider increasing `SLEEP_TIME` in `nvd_mirror.py`

---

## What's Next?

1. ✅ **Read the full [README.md](README.md)** for detailed information
2. ✅ **Check [EXAMPLES.md](EXAMPLES.md)** for SQL query examples
3. ✅ **Review [SETUP.md](SETUP.md)** for automation and advanced configuration
4. ✅ **Set up monitoring** to track sync success/failure
5. ✅ **Integrate with your tools** (SIEM, scanners, GRC platforms)

---

## Need Help?

- 📖 **Full Documentation**: [README.md](README.md)
- 🔧 **Detailed Setup**: [SETUP.md](SETUP.md)
- 💡 **SQL Examples**: [EXAMPLES.md](EXAMPLES.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/nvd-mirror/issues)

---

## Quick Reference

| File | Purpose |
|------|---------|
| `nvd_mirror.py` | Main sync script |
| `inspect_db.py` | Database inspector |
| `init_db.sql` | Manual DB setup |
| `.env` | Your configuration (don't commit!) |
| `data/nvd_mirror.log` | Application logs |
| `data/raw_api_responses/` | Archived API responses |

---