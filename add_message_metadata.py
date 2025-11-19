#!/usr/bin/env python3
"""
Migration script to add metadata column to message table
"""
import sqlite3
import os

# Database path
db_path = os.path.join(os.path.dirname(__file__), 'instance', 'smarthire.db')

def add_metadata_column():
    """Add metadata column to message table"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if column already exists
        cursor.execute("PRAGMA table_info(message)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'metadata' not in columns:
            # Add the metadata column
            cursor.execute("""
                ALTER TABLE message 
                ADD COLUMN metadata TEXT
            """)
            print("Added 'metadata' column to message table")
        else:
            print("'metadata' column already exists in message table")
        
        conn.commit()
        print("Migration completed successfully")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    add_metadata_column()
