"""
NVD Mirror Database Inspector

Utility script to inspect the NVD mirror database and display statistics
about CVE and CPE records, including counts and last modification times.

Usage:
    python inspect_db.py
"""

import os
import psycopg2
from datetime import datetime
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# -----------------------
# Configuration
# -----------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "nvd_db")
DB_USER = os.getenv("DB_USER", "nvd_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "nvdpassword")

# -----------------------
# Logging Setup
# -----------------------
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger()


def connect_db():
    """
    Establishes a connection to the PostgreSQL database.
    
    Returns:
        psycopg2 connection object
    """
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def inspect_database():
    """
    Queries and displays record counts and last modification times
    for CVE and CPE tables.
    """
    logger.info("\n" + "=" * 60)
    logger.info("📊 NVD Database Inspection")
    logger.info("=" * 60)
    
    tables = ["cve_records", "cpe_records"]
    
    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                for table in tables:
                    logger.info(f"\n[ {table.upper().replace('_', ' ')} ]")
                    logger.info("-" * 60)
                    
                    # Get total record count
                    cur.execute(f"SELECT COUNT(*) FROM {table};")
                    count = cur.fetchone()[0]
                    logger.info(f"  Total Records:     {count:>15,}")

                    # Get last modification timestamp
                    cur.execute(f"SELECT MAX(last_modified) FROM {table};")
                    max_date = cur.fetchone()[0]
                    
                    if max_date:
                        formatted_date = max_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                        logger.info(f"  Last Modified:     {formatted_date:>15}")
                    else:
                        logger.info(f"  Last Modified:     {'(No records)':>15}")
                    
                    # Get earliest record
                    cur.execute(f"SELECT MIN(last_modified) FROM {table};")
                    min_date = cur.fetchone()[0]
                    
                    if min_date:
                        formatted_date = min_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                        logger.info(f"  First Record:      {formatted_date:>15}")
                
                # Display database size
                logger.info(f"\n[ DATABASE SIZE ]")
                logger.info("-" * 60)
                cur.execute("""
                    SELECT pg_size_pretty(pg_database_size(%s)) as size;
                """, (DB_NAME,))
                db_size = cur.fetchone()[0]
                logger.info(f"  Total Size:        {db_size:>15}")
                
        logger.info("\n" + "=" * 60)
        logger.info("✅ Inspection complete")
        logger.info("=" * 60 + "\n")

    except psycopg2.OperationalError as e:
        logger.error("\n" + "=" * 60)
        logger.error("❌ ERROR: Could not connect to database")
        logger.error("=" * 60)
        logger.error("\nPlease verify:")
        logger.error("  1. PostgreSQL is running")
        logger.error("  2. Database credentials in .env are correct")
        logger.error("  3. Database 'nvd_db' exists")
        logger.error(f"\nDetails: {e}\n")
    except Exception as e:
        logger.error(f"\n❌ Unexpected error: {e}\n")


if __name__ == "__main__":
    inspect_database()
