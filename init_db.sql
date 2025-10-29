-- ========================================
-- NVD Mirror Database Initialization
-- ========================================
-- This script creates the database, user, and tables for NVD Mirror
-- Run as PostgreSQL superuser: sudo -u postgres psql -f init_db.sql

-- Create database (if it doesn't exist)
-- Note: This will fail if the database already exists, which is fine
CREATE DATABASE nvd_db;

-- Connect to the new database
\c nvd_db;

-- Create CVE records table
-- Stores Common Vulnerabilities and Exposures data
CREATE TABLE IF NOT EXISTS cve_records (
    cve_id TEXT PRIMARY KEY,                     -- e.g., CVE-2024-1234
    json_data JSONB,                             -- Full CVE record in JSON format
    last_modified TIMESTAMP WITH TIME ZONE       -- Last modification timestamp from NVD
);

-- Create CPE records table
-- Stores Common Platform Enumeration data
CREATE TABLE IF NOT EXISTS cpe_records (
    cpe_id TEXT PRIMARY KEY,                     -- e.g., cpe:2.3:a:vendor:product:version:...
    json_data JSONB,                             -- Full CPE record in JSON format
    last_modified TIMESTAMP WITH TIME ZONE       -- Last modification timestamp from NVD
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_cve_last_modified ON cve_records(last_modified);
CREATE INDEX IF NOT EXISTS idx_cpe_last_modified ON cpe_records(last_modified);

-- Create GIN indexes for JSONB columns to enable fast JSON queries
CREATE INDEX IF NOT EXISTS idx_cve_json_data ON cve_records USING GIN (json_data);
CREATE INDEX IF NOT EXISTS idx_cpe_json_data ON cpe_records USING GIN (json_data);

-- Grant permissions to nvd_user
-- Note: You may need to create the user first if it doesn't exist:
-- CREATE USER nvd_user WITH PASSWORD 'nvdpassword';

GRANT CONNECT ON DATABASE nvd_db TO nvd_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_records TO nvd_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON cpe_records TO nvd_user;

-- Display table information
\dt

-- Show success message
\echo 'Database initialization complete!'
\echo 'Tables created: cve_records, cpe_records'
\echo 'Indexes created for performance optimization'
