"""
NVD Mirror - Synchronize CVE and CPE data from NVD API to PostgreSQL

This script fetches vulnerability (CVE) and platform (CPE) data from the
National Vulnerability Database API and stores it in a local PostgreSQL database.
Supports both full and incremental synchronization modes.

Author: hhanzo1
License: MIT
"""

import os
import time
import json
import logging
from datetime import datetime, timezone, timedelta
import requests
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# -----------------------
# Configuration
# -----------------------
API_KEY = os.getenv("NVD_API_KEY", "ENTER_YOUR_API_KEY")
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE_CVE = 500 # Max for CVE 2.0
RESULTS_PER_PAGE_CPE = 500 # Max for CPE 2.0
DATA_DIR = "./data"
LOG_FILE = os.path.join(DATA_DIR, "nvd_mirror.log")
SLEEP_TIME = 6 # seconds between API calls (respect rate limits)

# Sync Configuration
FORCE_FULL_SYNC = True  # Set to True for initial full sync, False for incremental updates

# Archival and Retention Settings
RETENTION_DAYS = 90 # Days to keep archived API responses
INCREMENTAL_END_DELAY_MINUTES = 5 # Buffer time for incremental sync
BACKUP_DIR = os.path.join(DATA_DIR, "raw_api_responses")

# PostgreSQL Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "nvd_db")
DB_USER = os.getenv("DB_USER", "nvd_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "nvdpassword")

# -----------------------
# Logging Setup
# -----------------------
os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger()
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console_handler)

# -----------------------
# Checkpointing Functions (NEW)
# -----------------------
def get_checkpoint(prefix):
    """
    Reads the last successful startIndex from the checkpoint file.
    """
    checkpoint_path = os.path.join(DATA_DIR, f".{prefix}_checkpoint")
    if os.path.exists(checkpoint_path):
        try:
            with open(checkpoint_path, 'r') as f:
                index = int(f.read().strip())
                logger.warning(f"Resuming {prefix} full sync from checkpoint: startIndex={index}")
                return index
        except Exception as e:
            logger.error(f"Could not read checkpoint file {checkpoint_path}: {e}. Starting from 0.")
            os.remove(checkpoint_path) # Delete corrupt checkpoint
    return 0

def save_checkpoint(prefix, index):
    """
    Writes the next startIndex to the checkpoint file.
    """
    checkpoint_path = os.path.join(DATA_DIR, f".{prefix}_checkpoint")
    try:
        with open(checkpoint_path, 'w') as f:
            f.write(str(index))
    except Exception as e:
        logger.error(f"Failed to write checkpoint file {checkpoint_path}: {e}")

def clear_checkpoint(prefix):
    """
    Deletes the checkpoint file upon successful completion or when switching sync modes.
    """
    checkpoint_path = os.path.join(DATA_DIR, f".{prefix}_checkpoint")
    if os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)
        logger.info(f"Cleared checkpoint for {prefix}.")

# -----------------------
# Helper Functions
# -----------------------
def save_json(filename, data):
    """
    Saves a JSON file to the main DATA_DIR.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.info(f"Saved JSON to {path}")

def isoformat_z(dt: datetime) -> str:
    """
    Convert datetime to ISO-8601 string in UTC with 'Z' suffix.
    """
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def save_response_page(prefix, start_index, data):
    """
    Archives raw API response for audit and recovery purposes.
    """
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_page_{start_index}_{timestamp}.json"
    path = os.path.join(BACKUP_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.debug(f"Archived raw response for page {start_index} to {path}")

def find_cpe_identifier(data):
    """
    Recursively searches for CPE identifier in nested data structure.
    """
    if isinstance(data, dict):
        if 'cpeName' in data:
            return data['cpeName'], data
        if 'cpe23Uri' in data:
            return data['cpe23Uri'], data
        for key, value in data.items():
            result_id, result_data = find_cpe_identifier(value)
            if result_id:
                return result_id, result_data
    elif isinstance(data, list):
        for item in data:
            result_id, result_data = find_cpe_identifier(item)
            if result_id:
                return result_id, result_data
    return None, None

def fetch_api(url, params, retries=3):
    """
    Fetches data from NVD API with retry logic and error handling.
    """
    if not API_KEY:
        logger.error("NVD_API_KEY is not set. Please configure your API key in .env file.")
        return None
    headers = {"apiKey": API_KEY}
    logger.info(f"Requesting {url} with params: {params}")
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"No data found for {url} with params={params} (404)")
                return {"vulnerabilities": [], "products": [], "totalResults": 0}
            elif response.status_code == 403:
                logger.error(f"API authentication failed (403). Check your API key.")
                return None
            elif response.status_code == 429:
                logger.warning(f"Rate limit exceeded (429). Increase SLEEP_TIME or wait.")
                time.sleep(SLEEP_TIME * 2)
            else:
                logger.error(f"API call failed: {response.status_code} {response.text} (Attempt {attempt}/{retries})")
        except requests.RequestException as e:
            logger.error(f"Request exception: {e} (Attempt {attempt}/{retries})")
        time.sleep(SLEEP_TIME)
    logger.error(f"Failed API call after {retries} attempts: {url}")
    return None

def cleanup_backups(retention_days):
    """
    Removes archived API responses older than the retention period.
    """
    logger.info(f"Starting backup cleanup for files older than {retention_days} days.")
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    deleted_count = 0
    if not os.path.exists(BACKUP_DIR):
        logger.info("Backup directory does not exist. Skipping cleanup.")
        return
    for filename in os.listdir(BACKUP_DIR):
        path = os.path.join(BACKUP_DIR, filename)
        if os.path.isfile(path):
            try:
                file_mod_timestamp = os.path.getmtime(path)
                file_mod_date = datetime.fromtimestamp(file_mod_timestamp)
                if file_mod_date < cutoff_date:
                    os.remove(path)
                    deleted_count += 1
                    logger.debug(f"Deleted old backup file: {filename}")
            except Exception as e:
                logger.error(f"Error cleaning up file {filename}: {e}")
    logger.info(f"Finished backup cleanup. Deleted {deleted_count} files.")

# Database Functions
def connect_db():
    try:
        return psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
    except psycopg2.OperationalError as e:
        logger.error(f"Database connection failed: {e}")
        raise

def init_db():
    logger.info("Initializing database tables...")
    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS cve_records (
                        cve_id TEXT PRIMARY KEY,
                        json_data JSONB,
                        last_modified TIMESTAMP WITH TIME ZONE
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS cpe_records (
                        cpe_id TEXT PRIMARY KEY,
                        json_data JSONB,
                        last_modified TIMESTAMP WITH TIME ZONE
                    );
                """)
            conn.commit()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def get_last_modified_time(table_name):
    if FORCE_FULL_SYNC:
        logger.warning(f"FORCE_FULL_SYNC is TRUE. Bypassing database check for {table_name}.")
        return None
    logger.info(f"Querying max last_modified time from {table_name}...")
    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT MAX(last_modified) FROM {table_name};")
                result = cur.fetchone()[0]
                if result:
                    safe_start_time = result - timedelta(seconds=1)
                    last_modified_str = isoformat_z(safe_start_time)
                    logger.info(f"Starting incremental sync from: {last_modified_str}")
                    return last_modified_str
                else:
                    logger.info("No records found. Performing a full sync.")
                    return None
    except Exception as e:
        logger.error(f"Could not retrieve last modified time from DB: {e}. Falling back to full sync.")
        return None

def upsert_records(table, records, id_field):
    if not records:
        logger.info(f"No records to upsert for table {table}")
        return
    logger.info(f"Upserting {len(records)} records into {table}")
    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                now = datetime.now(timezone.utc)
                values = []
                for record in records:
                    record_id = record.get(id_field)
                    if record_id:
                        values.append((record_id, json.dumps(record), now))
                if values:
                    query = f"""
                        INSERT INTO {table} ({id_field}, json_data, last_modified)
                        VALUES %s
                        ON CONFLICT ({id_field}) DO UPDATE
                        SET json_data = EXCLUDED.json_data,
                            last_modified = EXCLUDED.last_modified
                    """
                    execute_values(cur, query, values)
                    conn.commit()
                    logger.info(f"Successfully upserted {len(values)} records into {table}")
    except Exception as e:
        logger.exception(f"Database error while upserting into {table}: {e}")

# Synchronization Logic
def sync_nvd(url, filename_prefix, table_name, id_field, last_modified_start=None,
             results_per_page=2000, items_key_override=None):
    is_full_sync = last_modified_start is None
    if is_full_sync:
        start_index = get_checkpoint(filename_prefix)
    else:
        start_index = 0
    if is_full_sync:
        logger.info("Performing a FULL synchronization.")
    else:
        logger.info("Performing an INCREMENTAL synchronization.")
    current_utc_time = datetime.now(timezone.utc)
    last_modified_end = current_utc_time - timedelta(minutes=INCREMENTAL_END_DELAY_MINUTES)
    last_modified_end_str = isoformat_z(last_modified_end)
    while True:
        if is_full_sync:
            save_checkpoint(filename_prefix, start_index)
        params = {"startIndex": start_index, "resultsPerPage": results_per_page}
        if not is_full_sync:
            params["lastModStartDate"] = last_modified_start
            params["lastModEndDate"] = last_modified_end_str
        data = fetch_api(url, params)
        if data is None:
            logger.error("API fetch failed, aborting sync.")
            break
        save_response_page(filename_prefix, start_index, data)
        items_key = items_key_override or ("vulnerabilities" if "cves" in url else "products")
        results = data.get(items_key, [])
        logger.info(f"Fetched {len(results)} items from API")
        batch_records = []
        for record in results:
            record_id, record_data = (None, None)
            if id_field == "cve_id":
                record_data = record.get("cve", record)
                record_id = record_data.get("id")
            else:
                record_id, record_data = find_cpe_identifier(record)
            if record_id and record_data:
                record_to_db = {id_field: record_id, **record_data}
                batch_records.append(record_to_db)
            else:
                logger.warning(f"Failed to find valid {id_field} in record (startIndex {start_index}). Skipping.")
        upsert_records(table_name, batch_records, id_field)
        total_results = data.get("totalResults", 0)
        logger.info(f"Progress: startIndex={start_index} / totalResults={total_results}")
        start_index += results_per_page
        if start_index >= total_results:
            logger.info(f"Completed fetching all {total_results} records for {filename_prefix}")
            if is_full_sync:
                clear_checkpoint(filename_prefix)
            break
        time.sleep(SLEEP_TIME)

def main():
    logger.info("=" * 60)
    logger.info("=== Starting NVD Mirror Workflow (Memory-Safe) ===")
    logger.info("=" * 60)
    if not API_KEY:
        logger.error("ERROR: NVD_API_KEY is not configured!")
        logger.error("Please set your API key in the .env file.")
        return
    init_db()
    cleanup_backups(RETENTION_DAYS)
    logger.info("\n" + "=" * 60)
    logger.info("SYNCING CVE RECORDS")
    logger.info("=" * 60)
    last_cve_time = get_last_modified_time("cve_records")
    sync_nvd(CVE_URL, "cve_data", "cve_records", "cve_id", last_cve_time, RESULTS_PER_PAGE_CVE)
    logger.info("\n" + "=" * 60)
    logger.info("SYNCING CPE RECORDS")
    logger.info("=" * 60)
    last_cpe_time = get_last_modified_time("cpe_records")
    sync_nvd(CPE_URL, "cpe_data", "cpe_records", "cpe_id", last_cpe_time, RESULTS_PER_PAGE_CPE)
    logger.info("\n" + "=" * 60)
    logger.info("=== NVD Mirror Workflow Complete ===")
    logger.info("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nSync interrupted by user. Checkpoint saved for resumption.")
    except Exception as e:
        logger.exception(f"Unexpected error in main workflow: {e}")
