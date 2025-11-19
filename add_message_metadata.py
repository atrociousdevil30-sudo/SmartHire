#!/usr/bin/env python3
"""
Migration script to add notification_data column to message table
"""
from app import app, db
from sqlalchemy import text

def add_notification_data_column():
    """Add notification_data column to message table"""
    with app.app_context():
        try:
            # Check if column exists
            result = db.session.execute(text("PRAGMA table_info(message)"))
            columns = [row[1] for row in result]
            
            if 'notification_data' not in columns:
                # Add the column
                db.session.execute(text("""
                    ALTER TABLE message 
                    ADD COLUMN notification_data JSON
                """))
                db.session.commit()
                print("✓ Added notification_data column to message table")
            else:
                print("✓ notification_data column already exists in message table")
                
        except Exception as e:
            print(f"✗ Error adding notification_data column: {e}")
            db.session.rollback()

if __name__ == "__main__":
    add_notification_data_column()
