#!/usr/bin/env python3
"""
Migration script to add AI analysis fields to ExitFeedback table for PostgreSQL
"""

import os
import psycopg2
from psycopg2 import sql
from app import app

def add_ai_fields_to_exit_feedback():
    """Add AI analysis fields to ExitFeedback table in PostgreSQL"""
    
    # Parse database URL
    db_url = app.config['SQLALCHEMY_DATABASE_URI']
    
    # Initialize variables
    host = port = database = user = password = None
    
    # Extract connection details from postgresql://user:password@host:port/database
    if db_url.startswith('postgresql://'):
        db_info = db_url.replace('postgresql://', '')
        user_pass_host_port, database = db_info.split('/')
        user_pass, host_port = user_pass_host_port.split('@')
        user, password = user_pass.split(':')
        
        if ':' in host_port:
            host, port = host_port.split(':')
        else:
            host = host_port
            port = 5432
    
    print(f"Connecting to: {host}:{port}/{database} as {user}")
    
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'exit_feedback'
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        
        # Fields to add
        fields_to_add = [
            ('key_themes', 'TEXT'),
            ('risk_level', 'VARCHAR(20)'),
            ('actionable_insights', 'TEXT'),
            ('emotional_tone', 'VARCHAR(30)'),
            ('retention_probability', 'VARCHAR(20)'),
            ('recommendations', 'TEXT')
        ]
        
        added_fields = []
        
        for field_name, field_type in fields_to_add:
            if field_name not in existing_columns:
                try:
                    alter_query = sql.SQL("ALTER TABLE exit_feedback ADD COLUMN {} {}").format(
                        sql.Identifier(field_name),
                        sql.SQL(field_type)
                    )
                    cursor.execute(alter_query)
                    added_fields.append(field_name)
                    print(f"✅ Added column: {field_name}")
                except psycopg2.Error as e:
                    print(f"❌ Failed to add column {field_name}: {e}")
            else:
                print(f"⚠️ Column {field_name} already exists")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        if added_fields:
            print(f"\n✅ Successfully added {len(added_fields)} AI analysis fields to ExitFeedback table")
            print(f"Added fields: {', '.join(added_fields)}")
        else:
            print("\n✅ All AI analysis fields already exist in ExitFeedback table")
            
        return True
        
    except Exception as e:
        print(f"❌ Error updating database: {e}")
        return False

if __name__ == "__main__":
    print("🔄 Adding AI analysis fields to ExitFeedback table (PostgreSQL)...")
    success = add_ai_fields_to_exit_feedback()
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("🚀 AI-Powered Exit Interviews are now ready!")
    else:
        print("\n❌ Migration failed!")
        print("Please check the error messages above.")
