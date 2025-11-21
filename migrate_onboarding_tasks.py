#!/usr/bin/env python3
"""
Migration script to add issue reporting and comment fields to OnboardingTask model
"""

import sqlite3
import sys
from datetime import datetime

def migrate_database():
    """Add new columns to OnboardingTask table"""
    try:
        # Connect to database
        conn = sqlite3.connect('instance/smarthire.db')
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(onboarding_task)")
        columns = [row[1] for row in cursor.fetchall()]
        
        # New columns to add (without DEFAULT constraints for SQLite)
        new_columns = [
            ('due_date', 'DATE'),
            ('has_issue', 'BOOLEAN'),
            ('issue_type', 'VARCHAR(50)'),
            ('issue_description', 'TEXT'),
            ('issue_reported_at', 'DATETIME'),
            ('employee_comment', 'TEXT'),
            ('hr_resolution_note', 'TEXT'),
            ('hr_resolved_at', 'DATETIME'),
            ('hr_resolved_by', 'INTEGER'),
            ('updated_at', 'DATETIME')
        ]
        
        # Add missing columns
        for column_name, column_type in new_columns:
            if column_name not in columns:
                print(f"Adding column: {column_name}")
                cursor.execute(f"ALTER TABLE onboarding_task ADD COLUMN {column_name} {column_type}")
                
                # Set default values for existing records
                if column_name == 'has_issue':
                    cursor.execute("UPDATE onboarding_task SET has_issue = 0 WHERE has_issue IS NULL")
                elif column_name == 'updated_at':
                    cursor.execute("UPDATE onboarding_task SET updated_at = created_at WHERE updated_at IS NULL")
            else:
                print(f"Column {column_name} already exists")
        
        # Commit changes
        conn.commit()
        print("Migration completed successfully!")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Migration error: {e}")
        return False
    finally:
        if conn:
            conn.close()
    
    return True

if __name__ == "__main__":
    print("Starting OnboardingTask migration...")
    if migrate_database():
        print("Migration completed successfully!")
        sys.exit(0)
    else:
        print("Migration failed!")
        sys.exit(1)
