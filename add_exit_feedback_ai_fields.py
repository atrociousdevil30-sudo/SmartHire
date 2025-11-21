#!/usr/bin/env python3
"""
Migration script to add AI analysis fields to ExitFeedback table
"""

import sqlite3
import os
from app import app, db

def add_ai_fields_to_exit_feedback():
    """Add AI analysis fields to ExitFeedback table"""
    
    # Get database path - check instance folder first
    db_path = os.path.join('instance', 'smarthire.db')
    
    if not os.path.exists(db_path):
        # Try the main directory
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(exit_feedback)")
        columns = [row[1] for row in cursor.fetchall()]
        
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
            if field_name not in columns:
                try:
                    cursor.execute(f"ALTER TABLE exit_feedback ADD COLUMN {field_name} {field_type}")
                    added_fields.append(field_name)
                    print(f"✅ Added column: {field_name}")
                except sqlite3.OperationalError as e:
                    print(f"❌ Failed to add column {field_name}: {e}")
            else:
                print(f"⚠️ Column {field_name} already exists")
        
        conn.commit()
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
    print("🔄 Adding AI analysis fields to ExitFeedback table...")
    success = add_ai_fields_to_exit_feedback()
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("🚀 AI-Powered Exit Interviews are now ready!")
    else:
        print("\n❌ Migration failed!")
        print("Please check the error messages above.")
