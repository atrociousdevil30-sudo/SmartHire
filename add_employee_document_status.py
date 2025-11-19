#!/usr/bin/env python3
"""
Migration script to add status column to employee_document table
"""
import sqlite3
import os

# Database path
db_path = os.path.join(os.path.dirname(__file__), 'instance', 'smarthire.db')

def add_status_column():
    """Add status column to employee_document table"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if column already exists
        cursor.execute("PRAGMA table_info(employee_document)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'status' not in columns:
            # Add the status column
            cursor.execute("""
                ALTER TABLE employee_document 
                ADD COLUMN status TEXT DEFAULT 'pending'
            """)
            print("Added 'status' column to employee_document table")
            
            # Update existing records to have 'pending' status
            cursor.execute("""
                UPDATE employee_document 
                SET status = 'pending' 
                WHERE status IS NULL
            """)
            print("Updated existing records with 'pending' status")
        else:
            print("'status' column already exists in employee_document table")
        
        conn.commit()
        print("Migration completed successfully")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    add_status_column()
