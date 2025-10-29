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
API_KEY = os.getenv("NVD_API_KEY", "")
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE_CVE = 2000
RESULTS_PER_PAGE_CPE = 2000
DATA_DIR = "./data"
LOG_FILE = os.path.join(DATA_DIR, "nvd_mirror.log")
SLEEP_TIME = 6  # seconds between API calls (respect rate limits)

# Sync Configuration
# Set to True for initial full sync, False for incremental updates
FORCE_FULL_SYNC = True

# Archival and Retention Settings
RETENTION_DAYS = 90  # Days to keep archived API responses
INCREMENTAL_END_DELAY_MINUTES = 5  # Buffer time for incremental sync
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
# Also log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console_handler)

# -----------------------
# Helper Functions
# -----------------------
def save_json(filename, data):
    """
    Saves a JSON file to the main DATA_DIR.
    
    Args:
        filename: Name of the file to save
        data: Data to serialize as JSON
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.info(f"Saved JSON to {path}")


def isoformat_z(dt: datetime) -> str:
    """
    Convert datetime to ISO-8601 string in UTC with 'Z' suffix.
    
    Args:
        dt: datetime object to convert
        
    Returns:
        ISO-8601 formatted string with 'Z' suffix (e.g., "2025-10-29T12:00:00Z")
    """
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def save_response_page(prefix, start_index, data):
    """
    Archives raw API response for audit and recovery purposes.
    
    Args:
        prefix: Prefix for filename (e.g., "cve_data")
        start_index: Starting index of this batch
        data: Raw API response data
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
    
    The CPE identifier can be in 'cpeName' or 'cpe23Uri' fields depending
    on the API response structure.
    
    Args:
        data: Dictionary or list to search
        
    Returns:
        Tuple of (cpe_identifier, containing_dict) or (None, None) if not found
    """
    if isinstance(data, dict):
        # Priority: Look for 'cpeName' first (current API format)
        if 'cpeName' in data:
            return data['cpeName'], data
        
        # Fallback: Look for standard 'cpe23Uri'
        if 'cpe23Uri' in data:
            return data['cpe23Uri'], data
            
        # Recursively search nested dictionaries
        for key, value in data.items():
            result_id, result_data = find_cpe_identifier(value)
            if result_id:
                return result_id, result_data
                
    elif isinstance(data, list):
        # Recursively search list items
        for item in data:
            result_id, result_data = find_cpe_identifier(item)
            if result_id:
                return result_id, result_data
                
    return None, None


def fetch_api(url, params, retries=3):
    """
    Fetches data from NVD API with retry logic and error handling.
    
    Args:
        url: API endpoint URL
        params: Query parameters dictionary
        retries: Number of retry attempts
        
    Returns:
        JSON response data or None on failure
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
    
    Args:
        retention_days: Number of days to keep archived files
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


# -----------------------
# Database Functions
# -----------------------
def connect_db():
    """
    Establishes connection to PostgreSQL database.
    
    Returns:
        psycopg2 connection object
    """
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
        logger.error("Please verify PostgreSQL is running and credentials are correct.")
        raise


def init_db():
    """
    Initializes database tables if they don't exist.
    Creates cve_records and cpe_records tables with proper schema.
    """
    logger.info("Initializing database tables...")
    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                # Create CVE records table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS cve_records (
                        cve_id TEXT PRIMARY KEY,
                        json_data JSONB,
                        last_modified TIMESTAMP WITH TIME ZONE
                    );
                """)
                
                # Create CPE records table
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
    """
    Retrieves the most recent last_modified timestamp from the database.
    Used to determine the starting point for incremental synchronization.
    
    Args:
        table_name: Name of the table to query
        
    Returns:
        ISO-8601 formatted timestamp string or None for full sync
    """
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
                    # Start slightly before the last record to ensure no gaps
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
    """
    Inserts new records or updates existing ones (upsert operation).
    
    Args:
        table: Target table name
        records: List of record dictionaries to upsert
        id_field: Name of the ID field (cve_id or cpe_id)
    """
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


# -----------------------
# Synchronization Logic
# -----------------------
def sync_nvd(url, filename_prefix, table_name, id_field, last_modified_start=None, 
             results_per_page=2000, items_key_override=None):
    """
    Main synchronization function for CVE or CPE data.
    
    Args:
        url: API endpoint URL
        filename_prefix: Prefix for saved files
        table_name: Database table name
        id_field: ID field name (cve_id or cpe_id)
        last_modified_start: Starting timestamp for incremental sync (None for full)
        results_per_page: Number of records per API request
        items_key_override: Override key for items in API response
    """
    is_full_sync = last_modified_start is None
    start_index = 0
    all_results = []
    
    if is_full_sync:
        logger.info("Performing a FULL synchronization.")
    else:
        logger.info("Performing an INCREMENTAL synchronization.")

    # Set end time for incremental sync (buffer to avoid missing very recent updates)
    current_utc_time = datetime.now(timezone.utc)
    last_modified_end = current_utc_time - timedelta(minutes=INCREMENTAL_END_DELAY_MINUTES)
    last_modified_end_str = isoformat_z(last_modified_end)

    while True:
        # Build API request parameters
        params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }

        # Add date range for incremental sync
        if not is_full_sync:
            params["lastModStartDate"] = last_modified_start
            params["lastModEndDate"] = last_modified_end_str

        # Fetch data from API
        data = fetch_api(url, params)
        if data is None:
            logger.error("API fetch failed, aborting sync.")
            break

        # Archive the raw response
        save_response_page(filename_prefix, start_index, data)
        
        # Extract items from response
        items_key = items_key_override or ("vulnerabilities" if "cves" in url else "products")
        results = data.get(items_key, [])
        logger.info(f"Fetched {len(results)} items from API")
        
        # For full sync, collect all results
        if is_full_sync:
            all_results.extend(results)

        # Process batch and prepare for database insertion
        batch_records = []
        for record in results:
            record_id = None
            record_data = None
            
            if id_field == "cve_id":
                # Extract CVE ID
                record_data = record.get("cve", record)
                record_id = record_data.get("id")
            else:
                # Extract CPE ID (requires recursive search)
                record_id, record_data = find_cpe_identifier(record)

            if record_id and record_data:
                record_to_db = {id_field: record_id, **record_data}
                batch_records.append(record_to_db)
            else:
                logger.warning(f"Failed to find valid {id_field} in record (startIndex {start_index}). Skipping.")

        # Insert/update batch in database
        upsert_records(table_name, batch_records, id_field)

        # Check if we've processed all available records
        total_results = data.get("totalResults", 0)
        logger.info(f"Progress: startIndex={start_index} / totalResults={total_results}")

        start_index += results_per_page
        
        if start_index >= total_results:
            logger.info(f"Completed fetching all {total_results} records for {filename_prefix}")
            break

        # Respect rate limits
        time.sleep(SLEEP_TIME)

    # Save full dump for archival purposes
    if is_full_sync and all_results:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_json(f"{filename_prefix}_FULL_{timestamp}.json", all_results)


# -----------------------
# Main Workflow
# -----------------------
def main():
    """
    Main execution function orchestrating the sync workflow.
    """
    logger.info("=" * 60)
    logger.info("=== Starting NVD Mirror Workflow ===")
    logger.info("=" * 60)
    
    # Validate configuration
    if not API_KEY:
        logger.error("ERROR: NVD_API_KEY is not configured!")
        logger.error("Please set your API key in the .env file.")
        logger.error("Get your API key at: https://nvd.nist.gov/developers/request-an-api-key")
        return
    
    # Initialize database
    init_db()
    
    # Clean up old archived files
    cleanup_backups(RETENTION_DAYS)
    
    # Synchronize CVE records
    logger.info("\n" + "=" * 60)
    logger.info("SYNCING CVE RECORDS")
    logger.info("=" * 60)
    last_cve_time = get_last_modified_time("cve_records")
    sync_nvd(CVE_URL, "cve_data", "cve_records", "cve_id", last_cve_time, RESULTS_PER_PAGE_CVE)

    # Synchronize CPE records
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
        logger.info("\nSync interrupted by user.")
    except Exception as e:
        logger.exception(f"Unexpected error in main workflow: {e}")
