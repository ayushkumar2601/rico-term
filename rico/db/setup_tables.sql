-- Snowflake table setup for RICO Security Intelligence Warehouse
-- Database: RICO_INTEL
-- Schema: SECURITY
-- Warehouse: COMPUTE_WH

-- Use the correct database and schema
USE DATABASE RICO_INTEL;
USE SCHEMA SECURITY;
USE WAREHOUSE COMPUTE_WH;

-- ============================================
-- SCANS TABLE
-- Stores high-level scan metadata
-- ============================================
CREATE TABLE IF NOT EXISTS SCANS (
    SCAN_ID VARCHAR(36) PRIMARY KEY,
    API_NAME VARCHAR(255),
    API_BASE_URL VARCHAR(500),
    FRAMEWORK VARCHAR(100),
    TOTAL_ENDPOINTS INTEGER,
    TOTAL_VULNERABILITIES INTEGER,
    RISK_SCORE INTEGER,
    SCAN_DURATION_SECONDS FLOAT,
    SCAN_TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================
-- PAYLOAD_RESULTS TABLE
-- Stores individual payload test results for RAG
-- ============================================
CREATE TABLE IF NOT EXISTS PAYLOAD_RESULTS (
    PAYLOAD_ID VARCHAR(36) PRIMARY KEY,
    SCAN_ID VARCHAR(36),
    VULNERABILITY_TYPE VARCHAR(50),
    PAYLOAD VARCHAR(5000),
    API_FRAMEWORK VARCHAR(100),
    AUTH_TYPE VARCHAR(50),
    ENDPOINT_PATH VARCHAR(500),
    RESPONSE_CODE INTEGER,
    RESPONSE_TIME_MS FLOAT,
    EXPLOIT_SUCCESS BOOLEAN,
    RESULT_TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    FOREIGN KEY (SCAN_ID) REFERENCES SCANS(SCAN_ID)
);

-- ============================================
-- VULNERABILITIES TABLE
-- Stores detected vulnerabilities
-- ============================================
CREATE TABLE IF NOT EXISTS VULNERABILITIES (
    VULN_ID VARCHAR(36) PRIMARY KEY,
    SCAN_ID VARCHAR(36),
    ENDPOINT_PATH VARCHAR(500),
    VULNERABILITY_TYPE VARCHAR(50),
    SEVERITY VARCHAR(20),
    CONFIDENCE INTEGER,
    CVSS_SCORE FLOAT,
    DESCRIPTION TEXT,
    POC_CURL TEXT,
    FIX_SUGGESTION TEXT,
    VULN_TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    FOREIGN KEY (SCAN_ID) REFERENCES SCANS(SCAN_ID)
);

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

-- Index for retrieving successful payloads by type
CREATE INDEX IF NOT EXISTS idx_payload_vuln_type_success 
ON PAYLOAD_RESULTS(VULNERABILITY_TYPE, EXPLOIT_SUCCESS, RESULT_TIMESTAMP);

-- Index for framework-specific queries
CREATE INDEX IF NOT EXISTS idx_payload_framework 
ON PAYLOAD_RESULTS(API_FRAMEWORK, VULNERABILITY_TYPE, EXPLOIT_SUCCESS);

-- Index for scan history queries
CREATE INDEX IF NOT EXISTS idx_scans_url 
ON SCANS(API_BASE_URL, SCAN_TIMESTAMP);

-- Index for vulnerability queries
CREATE INDEX IF NOT EXISTS idx_vuln_type_severity 
ON VULNERABILITIES(VULNERABILITY_TYPE, SEVERITY, CVSS_SCORE);

-- ============================================
-- VIEWS FOR ANALYTICS
-- ============================================

-- View: Payload success rates by vulnerability type
CREATE OR REPLACE VIEW PAYLOAD_SUCCESS_RATES AS
SELECT 
    VULNERABILITY_TYPE,
    API_FRAMEWORK,
    COUNT(*) as TOTAL_ATTEMPTS,
    SUM(CASE WHEN EXPLOIT_SUCCESS = TRUE THEN 1 ELSE 0 END) as SUCCESSFUL_ATTEMPTS,
    ROUND(100.0 * SUM(CASE WHEN EXPLOIT_SUCCESS = TRUE THEN 1 ELSE 0 END) / COUNT(*), 2) as SUCCESS_RATE_PCT,
    AVG(RESPONSE_TIME_MS) as AVG_RESPONSE_TIME_MS
FROM PAYLOAD_RESULTS
GROUP BY VULNERABILITY_TYPE, API_FRAMEWORK
ORDER BY SUCCESS_RATE_PCT DESC;

-- View: Top vulnerable endpoints
CREATE OR REPLACE VIEW TOP_VULNERABLE_ENDPOINTS AS
SELECT 
    v.ENDPOINT_PATH,
    v.VULNERABILITY_TYPE,
    v.SEVERITY,
    v.CVSS_SCORE,
    s.API_BASE_URL,
    s.FRAMEWORK,
    v.VULN_TIMESTAMP
FROM VULNERABILITIES v
JOIN SCANS s ON v.SCAN_ID = s.SCAN_ID
WHERE v.CONFIDENCE >= 70
ORDER BY v.CVSS_SCORE DESC, v.VULN_TIMESTAMP DESC;

-- View: Scan summary statistics
CREATE OR REPLACE VIEW SCAN_SUMMARY AS
SELECT 
    s.SCAN_ID,
    s.API_NAME,
    s.API_BASE_URL,
    s.FRAMEWORK,
    s.TOTAL_ENDPOINTS,
    s.TOTAL_VULNERABILITIES,
    s.RISK_SCORE,
    COUNT(DISTINCT v.VULN_ID) as CONFIRMED_VULNERABILITIES,
    MAX(v.CVSS_SCORE) as MAX_CVSS_SCORE,
    s.SCAN_TIMESTAMP
FROM SCANS s
LEFT JOIN VULNERABILITIES v ON s.SCAN_ID = v.SCAN_ID
GROUP BY s.SCAN_ID, s.API_NAME, s.API_BASE_URL, s.FRAMEWORK, 
         s.TOTAL_ENDPOINTS, s.TOTAL_VULNERABILITIES, s.RISK_SCORE, s.SCAN_TIMESTAMP
ORDER BY s.SCAN_TIMESTAMP DESC;

-- ============================================
-- GRANT PERMISSIONS (adjust as needed)
-- ============================================
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA SECURITY TO ROLE YOUR_ROLE;
-- GRANT SELECT ON ALL VIEWS IN SCHEMA SECURITY TO ROLE YOUR_ROLE;

-- ============================================
-- VERIFICATION QUERIES
-- ============================================

-- Verify tables created
SHOW TABLES IN SCHEMA SECURITY;

-- Verify views created
SHOW VIEWS IN SCHEMA SECURITY;

-- Test data insertion (optional)
-- INSERT INTO SCANS VALUES (
--     'test-scan-001',
--     'Demo API',
--     'http://localhost:8000',
--     'FastAPI',
--     10,
--     2,
--     75,
--     45.5,
--     CURRENT_TIMESTAMP()
-- );

SELECT 'Snowflake tables setup complete!' as status;
