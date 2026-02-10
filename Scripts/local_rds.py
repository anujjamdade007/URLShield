import psycopg2
import time

import os
from dotenv import load_dotenv

load_dotenv()

# 1. Database Connection Details (Replace with your RDS info)
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT"),
}

CSV_FILE_PATH = "url_dataset.csv" 
TABLE_NAME = "phishing_data"

def setup_and_import():
    try:
        # 2. Connect to RDS
        print(f"Connecting to RDS at {DB_CONFIG['host']}...")
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # 3. Create Table Schema
        # We use TEXT for URLs because they can be longer than 255 chars
        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            url TEXT,
            type VARCHAR(20)
        );
        """
        print("Creating table schema...")
        cur.execute(create_table_query)
        conn.commit()

        # 4. Fast Import using copy_expert
        # This streams the CSV directly without loading it all into memory
        print(f"Starting import of 731k records...")
        start_time = time.time()
        
        with open(CSV_FILE_PATH, 'r', encoding='utf-8') as f:
            # HEADER true tells it to skip the first row (url, type)
            sql = f"COPY {TABLE_NAME} FROM STDIN WITH (FORMAT csv, HEADER true)"
            cur.copy_expert(sql, f)
        
        conn.commit()
        end_time = time.time()
        
        print(f"✅ Success! Data imported in {round(end_time - start_time, 2)} seconds.")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

def verify_data():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Check total count
    cur.execute("SELECT COUNT(*) FROM phishing_data;")
    total = cur.fetchone()[0]
    
    # Check distribution
    cur.execute("SELECT type, COUNT(*) FROM phishing_data GROUP BY type;")
    distribution = cur.fetchall()
    
    print(f"--- URLShield Database Audit ---")
    print(f"Total Records: {total}")
    for row in distribution:
        print(f"Type: {row[0]} | Count: {row[1]}")
    
    cur.close()
    conn.close()

if __name__ == "__main__":\
    # First time while importing data from local to rds
    # setup_and_import() 
    verify_data()