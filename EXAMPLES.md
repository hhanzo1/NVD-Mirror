# Example SQL Queries

This document provides example SQL queries for common vulnerability analysis tasks using your local NVD mirror.

## Table of Contents

- [Basic Queries](#basic-queries)
- [CVE Analysis](#cve-analysis)
- [CPE Analysis](#cpe-analysis)
- [Severity Analysis](#severity-analysis)
- [Temporal Analysis](#temporal-analysis)
- [Vendor Analysis](#vendor-analysis)
- [Integration Examples](#integration-examples)

---

## Basic Queries

### Count Total Records

```sql
-- Count CVE records
SELECT COUNT(*) as total_cves FROM cve_records;

-- Count CPE records
SELECT COUNT(*) as total_cpes FROM cpe_records;

-- Both counts in one query
SELECT 
    (SELECT COUNT(*) FROM cve_records) as total_cves,
    (SELECT COUNT(*) FROM cpe_records) as total_cpes;
```

### Recent Updates

```sql
-- CVEs updated in the last 24 hours
SELECT cve_id, last_modified
FROM cve_records
WHERE last_modified > NOW() - INTERVAL '24 hours'
ORDER BY last_modified DESC;

-- CVEs updated in the last week
SELECT cve_id, last_modified
FROM cve_records
WHERE last_modified > NOW() - INTERVAL '7 days'
ORDER BY last_modified DESC
LIMIT 100;
```

### Search by Keyword

```sql
-- Find CVEs mentioning a specific product (e.g., Apache)
SELECT cve_id, json_data->>'published' as published_date
FROM cve_records
WHERE json_data::text ILIKE '%apache%'
ORDER BY published_date DESC
LIMIT 50;

-- Find CVEs mentioning multiple keywords
SELECT cve_id, json_data->'descriptions' as description
FROM cve_records
WHERE json_data::text ILIKE '%apache%'
  AND json_data::text ILIKE '%remote code execution%';
```

---

## CVE Analysis

### CVEs by Publication Year

```sql
SELECT 
    EXTRACT(YEAR FROM (json_data->>'published')::timestamp) as year,
    COUNT(*) as cve_count
FROM cve_records
WHERE json_data->>'published' IS NOT NULL
GROUP BY year
ORDER BY year DESC;
```

### Recent Critical CVEs

```sql
-- CVEs published in 2024 and 2025
SELECT 
    cve_id,
    json_data->>'published' as published,
    json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore' as cvss_score
FROM cve_records
WHERE json_data->>'published' LIKE '2024%'
   OR json_data->>'published' LIKE '2025%'
ORDER BY published DESC
LIMIT 100;
```

### CVEs with Exploits

```sql
-- Find CVEs with known exploits or references
SELECT 
    cve_id,
    json_data->>'published' as published,
    json_data->'references' as references
FROM cve_records
WHERE json_data->'references' IS NOT NULL
  AND json_data::text ILIKE '%exploit%'
ORDER BY published DESC;
```

### CVEs Affecting Specific Vendor

```sql
-- Example: Microsoft products
SELECT 
    cve_id,
    json_data->>'published' as published,
    json_data->'configurations' as affected_products
FROM cve_records
WHERE json_data::text ILIKE '%microsoft%'
  AND json_data->>'published' > '2024-01-01'
ORDER BY published DESC;
```

---

## CPE Analysis

### CPEs by Vendor

```sql
-- Count CPEs by vendor (extract from CPE string)
SELECT 
    SPLIT_PART(cpe_id, ':', 4) as vendor,
    COUNT(*) as product_count
FROM cpe_records
WHERE cpe_id LIKE 'cpe:2.3:a:%'
GROUP BY vendor
ORDER BY product_count DESC
LIMIT 50;
```

### Find Specific Product Versions

```sql
-- Find all versions of a specific product (e.g., Apache HTTP Server)
SELECT 
    cpe_id,
    json_data
FROM cpe_records
WHERE cpe_id ILIKE '%apache%httpd%'
ORDER BY cpe_id;
```

### CPE by Type

```sql
-- Count CPEs by type (application, operating system, hardware)
SELECT 
    CASE 
        WHEN cpe_id LIKE 'cpe:2.3:a:%' THEN 'Application'
        WHEN cpe_id LIKE 'cpe:2.3:o:%' THEN 'Operating System'
        WHEN cpe_id LIKE 'cpe:2.3:h:%' THEN 'Hardware'
        ELSE 'Other'
    END as cpe_type,
    COUNT(*) as count
FROM cpe_records
GROUP BY cpe_type
ORDER BY count DESC;
```

---

## Severity Analysis

### CVSS Score Distribution

```sql
-- Distribution of CVSS v3.1 base scores
SELECT 
    CASE 
        WHEN (json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float >= 9.0 THEN 'Critical (9.0-10.0)'
        WHEN (json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float >= 7.0 THEN 'High (7.0-8.9)'
        WHEN (json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float >= 4.0 THEN 'Medium (4.0-6.9)'
        WHEN (json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float > 0 THEN 'Low (0.1-3.9)'
        ELSE 'Not Scored'
    END as severity,
    COUNT(*) as count
FROM cve_records
WHERE json_data->'metrics'->'cvssMetricV31' IS NOT NULL
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'Critical (9.0-10.0)' THEN 1
        WHEN 'High (7.0-8.9)' THEN 2
        WHEN 'Medium (4.0-6.9)' THEN 3
        WHEN 'Low (0.1-3.9)' THEN 4
        ELSE 5
    END;
```

### Top Critical CVEs by CVSS Score

```sql
SELECT 
    cve_id,
    json_data->>'published' as published,
    json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore' as cvss_score,
    json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseSeverity' as severity,
    json_data->'descriptions'->0->>'value' as description
FROM cve_records
WHERE json_data->'metrics'->'cvssMetricV31' IS NOT NULL
  AND (json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float >= 9.0
ORDER BY cvss_score DESC, published DESC
LIMIT 50;
```

---

## Temporal Analysis

### CVEs Published Per Month (Last Year)

```sql
SELECT 
    TO_CHAR((json_data->>'published')::timestamp, 'YYYY-MM') as month,
    COUNT(*) as cve_count
FROM cve_records
WHERE (json_data->>'published')::timestamp > NOW() - INTERVAL '1 year'
GROUP BY month
ORDER BY month DESC;
```

### CVEs Modified Recently

```sql
-- CVEs that were modified (not just published) in the last 30 days
SELECT 
    cve_id,
    json_data->>'published' as published,
    json_data->>'lastModified' as last_modified_nvd,
    last_modified as synced_at
FROM cve_records
WHERE last_modified > NOW() - INTERVAL '30 days'
ORDER BY last_modified DESC
LIMIT 100;
```

### Vulnerability Disclosure Lag

```sql
-- Time between publication and last modification
SELECT 
    cve_id,
    json_data->>'published' as published,
    json_data->>'lastModified' as last_modified,
    (json_data->>'lastModified')::timestamp - (json_data->>'published')::timestamp as modification_lag
FROM cve_records
WHERE json_data->>'published' IS NOT NULL 
  AND json_data->>'lastModified' IS NOT NULL
ORDER BY modification_lag DESC
LIMIT 50;
```

---

## Vendor Analysis

### Most Affected Vendors (Simple Approach)

```sql
-- Count CVEs mentioning major vendors
SELECT 
    vendor,
    COUNT(*) as cve_count
FROM (
    SELECT 
        CASE 
            WHEN json_data::text ILIKE '%microsoft%' THEN 'Microsoft'
            WHEN json_data::text ILIKE '%apple%' THEN 'Apple'
            WHEN json_data::text ILIKE '%google%' THEN 'Google'
            WHEN json_data::text ILIKE '%cisco%' THEN 'Cisco'
            WHEN json_data::text ILIKE '%oracle%' THEN 'Oracle'
            WHEN json_data::text ILIKE '%adobe%' THEN 'Adobe'
            WHEN json_data::text ILIKE '%linux%' THEN 'Linux'
            ELSE 'Other'
        END as vendor
    FROM cve_records
    WHERE json_data->>'published' > '2024-01-01'
) vendor_data
GROUP BY vendor
ORDER BY cve_count DESC;
```

### CVEs by CWE (Weakness Type)

```sql
-- Common Weakness Enumeration analysis
SELECT 
    json_data->'weaknesses'->0->'description'->0->>'value' as cwe,
    COUNT(*) as count
FROM cve_records
WHERE json_data->'weaknesses' IS NOT NULL
GROUP BY cwe
ORDER BY count DESC
LIMIT 20;
```

---

## Integration Examples

### Export CVEs for Scanning Tools

```sql
-- Export CVEs from last 90 days in a scanner-friendly format
COPY (
    SELECT 
        cve_id,
        json_data->>'published' as published,
        json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore' as cvss_score,
        json_data->'descriptions'->0->>'value' as description
    FROM cve_records
    WHERE (json_data->>'published')::timestamp > NOW() - INTERVAL '90 days'
    ORDER BY published DESC
) TO '/tmp/recent_cves.csv' WITH CSV HEADER;
```

### Check if Specific CVEs Exist

```sql
-- Check if your scanner-found CVEs are in the database
SELECT cve_id, json_data->>'published' as published
FROM cve_records
WHERE cve_id IN ('CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9012')
ORDER BY cve_id;
```

### Find CVEs for Your Software Inventory

```sql
-- Example: Check for vulnerabilities in your stack
WITH software_inventory AS (
    SELECT unnest(ARRAY['apache', 'nginx', 'postgresql', 'python', 'nodejs']) as product
)
SELECT 
    si.product,
    cr.cve_id,
    cr.json_data->>'published' as published,
    cr.json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore' as cvss_score
FROM software_inventory si
CROSS JOIN cve_records cr
WHERE cr.json_data::text ILIKE '%' || si.product || '%'
  AND (cr.json_data->>'published')::timestamp > NOW() - INTERVAL '1 year'
ORDER BY si.product, published DESC;
```

### Dashboard Statistics

```sql
-- Summary statistics for security dashboard
SELECT 
    (SELECT COUNT(*) FROM cve_records) as total_cves,
    (SELECT COUNT(*) FROM cve_records 
     WHERE last_modified > NOW() - INTERVAL '24 hours') as cves_updated_today,
    (SELECT COUNT(*) FROM cve_records 
     WHERE (json_data->>'published')::timestamp > NOW() - INTERVAL '30 days') as cves_last_30_days,
    (SELECT COUNT(*) FROM cve_records 
     WHERE json_data->'metrics'->'cvssMetricV31' IS NOT NULL
     AND (json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float >= 9.0) as critical_cves,
    (SELECT MAX(last_modified) FROM cve_records) as last_sync;
```

---

## Performance Tips

### Create Custom Indexes

```sql
-- Index for published date queries
CREATE INDEX idx_cve_published ON cve_records ((json_data->>'published'));

-- Index for CVSS score queries
CREATE INDEX idx_cve_cvss_score ON cve_records (
    ((json_data->'metrics'->'cvssMetricV31'->0->'cvssData'->>'baseScore')::float)
) WHERE json_data->'metrics'->'cvssMetricV31' IS NOT NULL;

-- Full-text search index
CREATE INDEX idx_cve_fulltext ON cve_records USING gin(to_tsvector('english', json_data::text));
```

### Query Optimization

```sql
-- Use EXPLAIN ANALYZE to optimize queries
EXPLAIN ANALYZE
SELECT cve_id FROM cve_records WHERE json_data::text ILIKE '%apache%';

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;
```

---

## Additional Resources

- [PostgreSQL JSON Functions](https://www.postgresql.org/docs/current/functions-json.html)
- [NVD CVE JSON Schema](https://nvd.nist.gov/developers/vulnerabilities)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CWE List](https://cwe.mitre.org/data/index.html)

---

**Note**: These queries assume the standard NVD JSON schema. Adjust JSON paths as needed based on your specific use case and NVD API version.
