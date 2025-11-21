#!/usr/bin/env python3
"""
Check existing database entries
"""

import sqlite3
import os

def check_database():
    """Check existing database entries"""
    db_path = os.path.join('instance', 'smarthire.db')
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if exit_feedback table exists and count entries
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='exit_feedback'")
        table_exists = cursor.fetchone()
        
        if table_exists:
            cursor.execute('SELECT COUNT(*) FROM exit_feedback')
            count = cursor.fetchone()[0]
            print(f'✅ Exit feedback table exists with {count} existing entries')
            
            if count > 0:
                cursor.execute('SELECT id, name, reason, sentiment, created_at FROM exit_feedback ORDER BY created_at DESC LIMIT 5')
                entries = cursor.fetchall()
                print('\n📋 Recent entries (preserved):')
                for entry in entries:
                    print(f'  ID: {entry[0]}, Name: {entry[1]}, Reason: {entry[2][:30]}..., Sentiment: {entry[3]}, Date: {entry[4]}')
            else:
                print('📝 No existing entries found (table is empty)')
        else:
            print('❌ Exit feedback table not found')
        
        # Check what columns exist now
        cursor.execute("PRAGMA table_info(exit_feedback)")
        columns = cursor.fetchall()
        print('\n📊 Current table columns:')
        for col in columns:
            print(f'  {col[1]} ({col[2]})')
        
        conn.close()
    else:
        print('❌ Database file not found')

if __name__ == "__main__":
    check_database()
