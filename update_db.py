#!/usr/bin/env python3
"""
Database schema update script for SmartHire
"""

import sqlite3
import os
from datetime import datetime

def update_database_schema():
    """Update the database schema to add missing columns"""
    
    # Database path
    db_path = 'instance/smarthire.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current columns in interview table
        cursor.execute('PRAGMA table_info(interview)')
        columns = [column[1] for column in cursor.fetchall()]
        
        print('Current columns in interview table:', columns)
        
        # Add user_id column if it doesn't exist
        if 'user_id' not in columns:
            print('Adding user_id column...')
            cursor.execute('ALTER TABLE interview ADD COLUMN user_id INTEGER')
            conn.commit()
            print('user_id column added')
        else:
            print('user_id column already exists')
        
        # Add status column if it doesn't exist
        if 'status' not in columns:
            print('Adding status column...')
            cursor.execute('ALTER TABLE interview ADD COLUMN status VARCHAR(20) DEFAULT "pending"')
            conn.commit()
            print('status column added')
        else:
            print('status column already exists')
        
        # Add updated_at column if it doesn't exist
        if 'updated_at' not in columns:
            print('Adding updated_at column...')
            cursor.execute('ALTER TABLE interview ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP')
            conn.commit()
            print('updated_at column added')
        else:
            print('updated_at column already exists')
        
        # Check if candidate_id has NOT NULL constraint
        cursor.execute('PRAGMA table_info(interview)')
        table_info = cursor.fetchall()
        for col in table_info:
            if col[1] == 'candidate_id':
                if col[3] == 1:  # NOT NULL constraint
                    print('Making candidate_id nullable...')
                    # SQLite doesn't support ALTER COLUMN directly
                    # We need to recreate the table
                    cursor.execute('''
                        CREATE TABLE interview_new (
                            id INTEGER PRIMARY KEY,
                            candidate_id INTEGER,
                            user_id INTEGER,
                            responses TEXT,
                            summary TEXT,
                            status VARCHAR(20) DEFAULT 'pending',
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                    
                    # Copy data from old table
                    cursor.execute('''
                        INSERT INTO interview_new (id, candidate_id, responses, summary, created_at)
                        SELECT id, candidate_id, responses, summary, created_at FROM interview
                    ''')
                    
                    # Drop old table and rename new one
                    cursor.execute('DROP TABLE interview')
                    cursor.execute('ALTER TABLE interview_new RENAME TO interview')
                    
                    conn.commit()
                    print('candidate_id is now nullable')
                break
        
        conn.close()
        print('Database schema updated successfully')
        return True
        
    except Exception as e:
        print(f'Error updating database: {e}')
        return False

if __name__ == '__main__':
    update_database_schema()
