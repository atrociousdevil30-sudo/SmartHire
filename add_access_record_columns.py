#!/usr/bin/env python3
"""
Add missing columns to access_record table
"""
import sqlite3
import os
from datetime import datetime

# Database path
db_path = 'instance/smarthire.db'

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if columns exist
        cursor.execute("PRAGMA table_info(access_record)")
        columns = [row[1] for row in cursor.fetchall()]
        
        # Add missing columns
        if 'resource_name' not in columns:
            cursor.execute("ALTER TABLE access_record ADD COLUMN resource_name VARCHAR(200)")
            print("Added resource_name column")
        
        if 'resource_description' not in columns:
            cursor.execute("ALTER TABLE access_record ADD COLUMN resource_description TEXT")
            print("Added resource_description column")
        
        if 'status' not in columns:
            cursor.execute("ALTER TABLE access_record ADD COLUMN status VARCHAR(20) DEFAULT 'active'")
            print("Added status column")
        
        if 'granted_at' not in columns:
            cursor.execute("ALTER TABLE access_record ADD COLUMN granted_at DATETIME DEFAULT CURRENT_TIMESTAMP")
            print("Added granted_at column")
        
        if 'expires_at' not in columns:
            cursor.execute("ALTER TABLE access_record ADD COLUMN expires_at DATETIME")
            print("Added expires_at column")
        
        if 'granted_by' not in columns:
            cursor.execute("ALTER TABLE access_record ADD COLUMN granted_by INTEGER")
            print("Added granted_by column")
        
        conn.commit()
        print("\nSuccessfully updated access_record table")
        
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
    finally:
        conn.close()
else:
    print(f"Database file {db_path} not found")
