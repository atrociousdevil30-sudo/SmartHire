#!/usr/bin/env python3
"""
Migration script to add reset_token and reset_token_expires columns to User table
"""

import sqlite3
import os
from pathlib import Path

def migrate_database():
    """Add reset token columns to the user table"""
    
    # Get the database path - use absolute path
    db_path = r'c:\Users\atroc\CascadeProjects\Backup\SmartHire\instance\smarthire.db'
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(user)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'reset_token' in columns and 'reset_token_expires' in columns:
            print("Reset token columns already exist in the database")
            return True
        
        # Add reset_token column
        cursor.execute("""
            ALTER TABLE user 
            ADD COLUMN reset_token VARCHAR(255)
        """)
        
        # Add reset_token_expires column
        cursor.execute("""
            ALTER TABLE user 
            ADD COLUMN reset_token_expires DATETIME
        """)
        
        # Commit the changes
        conn.commit()
        print("Successfully added reset token columns to the user table")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Starting database migration...")
    if migrate_database():
        print("Migration completed successfully!")
    else:
        print("Migration failed!")
