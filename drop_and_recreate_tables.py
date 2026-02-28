"""
Drop and recreate Snowflake tables with correct schema.
This script fixes the column name mismatch issue.
"""
import os
from dotenv import load_dotenv
from rico.db.snowflake_client import get_connection

# Load environment variables
load_dotenv()

def drop_and_recreate_tables():
    """Drop existing tables and recreate them with correct schema."""
    
    print("=" * 60)
    print("RICO Snowflake Table Recreation")
    print("=" * 60)
    print()
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        print("✓ Connected to Snowflake")
        print(f"  Account: {os.getenv('SNOWFLAKE_ACCOUNT')}")
        print(f"  Database: RICO_INTEL")
        print(f"  Schema: SECURITY")
        print()
        
        # Drop existing tables (in reverse order due to foreign keys)
        print("Dropping existing tables...")
        
        try:
            cur.execute("DROP TABLE IF EXISTS VULNERABILITIES")
            print("  ✓ Dropped VULNERABILITIES table")
        except Exception as e:
            print(f"  ⚠ Could not drop VULNERABILITIES: {e}")
        
        try:
            cur.execute("DROP TABLE IF EXISTS PAYLOAD_RESULTS")
            print("  ✓ Dropped PAYLOAD_RESULTS table")
        except Exception as e:
            print(f"  ⚠ Could not drop PAYLOAD_RESULTS: {e}")
        
        try:
            cur.execute("DROP TABLE IF EXISTS SCANS")
            print("  ✓ Dropped SCANS table")
        except Exception as e:
            print(f"  ⚠ Could not drop SCANS: {e}")
        
        print()
        print("Recreating tables with correct schema...")
        
        # Create SCANS table
        print("  Creating SCANS table...")
        cur.execute("""
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
            )
        """)
        print("  ✓ Created SCANS table")
        
        # Create PAYLOAD_RESULTS table
        print("  Creating PAYLOAD_RESULTS table...")
        cur.execute("""
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
            )
        """)
        print("  ✓ Created PAYLOAD_RESULTS table")
        
        # Create VULNERABILITIES table
        print("  Creating VULNERABILITIES table...")
        cur.execute("""
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
            )
        """)
        print("  ✓ Created VULNERABILITIES table")
        
        # Create indexes
        print("  Creating indexes...")
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_payload_vuln_type_success 
            ON PAYLOAD_RESULTS(VULNERABILITY_TYPE, EXPLOIT_SUCCESS, RESULT_TIMESTAMP)
        """)
        print("  ✓ Created idx_payload_vuln_type_success")
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_payload_framework 
            ON PAYLOAD_RESULTS(API_FRAMEWORK, VULNERABILITY_TYPE, EXPLOIT_SUCCESS)
        """)
        print("  ✓ Created idx_payload_framework")
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_url 
            ON SCANS(API_BASE_URL, SCAN_TIMESTAMP)
        """)
        print("  ✓ Created idx_scans_url")
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_type_severity 
            ON VULNERABILITIES(VULNERABILITY_TYPE, SEVERITY, CVSS_SCORE)
        """)
        print("  ✓ Created idx_vuln_type_severity")
        
        conn.commit()
        
        print()
        print("=" * 60)
        print("✓ Tables recreated successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("1. Run a scan: rico report --spec demo-api/openapi.yaml --url http://localhost:8000")
        print("2. Verify data: python verify_snowflake_data.py")
        print()
        
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        return False
    
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass
    
    return True


if __name__ == "__main__":
    success = drop_and_recreate_tables()
    exit(0 if success else 1)
