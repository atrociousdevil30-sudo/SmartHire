#!/usr/bin/env python3
"""
Verify all existing data is preserved
"""

import sqlite3
import os

def verify_all_data():
    """Check all tables and data preservation"""
    db_path = os.path.join('instance', 'smarthire.db')
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Checking all database tables and data...\n")
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        total_records = 0
        
        for table in tables:
            cursor.execute(f'SELECT COUNT(*) FROM {table}')
            count = cursor.fetchone()[0]
            total_records += count
            
            if count > 0:
                print(f'✅ {table}: {count} records')
                
                # Show sample data for important tables
                if table in ['user', 'task', 'message', 'exit_feedback', 'candidate', 'interview']:
                    cursor.execute(f'SELECT * FROM {table} LIMIT 3')
                    sample_rows = cursor.fetchall()
                    
                    # Get column names
                    cursor.execute(f'PRAGMA table_info({table})')
                    columns = [col[1] for col in cursor.fetchall()]
                    
                    print(f'   📋 Sample data:')
                    for i, row in enumerate(sample_rows, 1):
                        # Show first few columns for readability
                        display_data = str(row[:3]) if len(row) > 3 else str(row)
                        print(f'      {i}. {display_data}')
            else:
                print(f'📝 {table}: 0 records (empty)')
        
        print(f'\n📊 Total records across all tables: {total_records}')
        
        # Check specifically for saved credentials
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='remembered_credential'")
        if cursor.fetchone():
            cursor.execute('SELECT COUNT(*) FROM remembered_credential')
            cred_count = cursor.fetchone()[0]
            print(f'🔐 Saved credentials: {cred_count} records')
        else:
            print('🔐 Saved credentials table not found')
        
        # Check employees specifically
        cursor.execute("SELECT COUNT(*) FROM user WHERE role IN ('employee', 'hr', 'admin')")
        employee_count = cursor.fetchone()[0]
        print(f'👥 Users (employees, HR, admin): {employee_count} records')
        
        if employee_count > 0:
            cursor.execute('SELECT username, full_name, role, email FROM user WHERE role IN ("employee", "hr", "admin") LIMIT 5')
            users = cursor.fetchall()
            print('   📋 Sample users:')
            for user in users:
                print(f'      - {user[0]} ({user[1]}) - {user[2]} - {user[3]}')
        
        conn.close()
        print('\n✅ Data verification complete!')
        
    else:
        print('❌ Database file not found')

if __name__ == "__main__":
    verify_all_data()
