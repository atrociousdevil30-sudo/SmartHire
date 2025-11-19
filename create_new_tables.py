#!/usr/bin/env python3
"""
Database migration script to create new tables for SmartHire application.
Creates: tasks, access_records, messages tables
"""

import os
import sys
from datetime import datetime

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, Employee, EmployeeDocument, EmployeeFeedback, OnboardingChecklist, OnboardingTask, EmployeeSettings

def create_task_table():
    """Create the tasks table"""
    try:
        # Check if table already exists
        inspector = db.inspect(db.engine)
        if 'task' in inspector.get_table_names():
            print("Tasks table already exists")
            return
        
        # Create table using raw SQL for better control
        sql = """
        CREATE TABLE task (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            assigned_to INTEGER REFERENCES "user"(id),
            assigned_by INTEGER REFERENCES "user"(id),
            task_type VARCHAR(50) DEFAULT 'general',
            priority VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'pending',
            due_date TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            checklist_id INTEGER REFERENCES onboarding_checklist(id),
            FOREIGN KEY (assigned_to) REFERENCES "user"(id),
            FOREIGN KEY (assigned_by) REFERENCES "user"(id),
            FOREIGN KEY (checklist_id) REFERENCES onboarding_checklist(id)
        );
        """
        
        db.session.execute(sql)
        db.session.commit()
        print("Tasks table created successfully")
        
    except Exception as e:
        print(f"Error creating tasks table: {str(e)}")
        db.session.rollback()

def create_access_record_table():
    """Create the access_records table"""
    try:
        # Check if table already exists
        inspector = db.inspect(db.engine)
        if 'access_record' in inspector.get_table_names():
            print("Access records table already exists")
            return
        
        # Create table using raw SQL
        sql = """
        CREATE TABLE access_record (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES "user"(id),
            access_type VARCHAR(50) NOT NULL,
            access_details TEXT,
            ip_address VARCHAR(45),
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'success',
            FOREIGN KEY (user_id) REFERENCES "user"(id)
        );
        """
        
        db.session.execute(sql)
        db.session.commit()
        print("Access records table created successfully")
        
    except Exception as e:
        print(f"Error creating access records table: {str(e)}")
        db.session.rollback()

def create_message_table():
    """Create the messages table"""
    try:
        # Check if table already exists
        inspector = db.inspect(db.engine)
        if 'message' in inspector.get_table_names():
            print("Messages table already exists")
            return
        
        # Create table using raw SQL
        sql = """
        CREATE TABLE message (
            id SERIAL PRIMARY KEY,
            subject VARCHAR(200) NOT NULL,
            content TEXT NOT NULL,
            sender_id INTEGER REFERENCES "user"(id),
            recipient_id INTEGER REFERENCES "user"(id),
            message_type VARCHAR(50) DEFAULT 'notification',
            priority VARCHAR(20) DEFAULT 'normal',
            status VARCHAR(20) DEFAULT 'unread',
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            parent_id INTEGER REFERENCES message(id),
            FOREIGN KEY (sender_id) REFERENCES "user"(id),
            FOREIGN KEY (recipient_id) REFERENCES "user"(id),
            FOREIGN KEY (parent_id) REFERENCES message(id)
        );
        """
        
        db.session.execute(sql)
        db.session.commit()
        print("Messages table created successfully")
        
    except Exception as e:
        print(f"Error creating messages table: {str(e)}")
        db.session.rollback()

def create_indexes():
    """Create indexes for better performance"""
    try:
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_task_assigned_to ON task(assigned_to);",
            "CREATE INDEX IF NOT EXISTS idx_task_status ON task(status);",
            "CREATE INDEX IF NOT EXISTS idx_task_due_date ON task(due_date);",
            "CREATE INDEX IF NOT EXISTS idx_task_checklist_id ON task(checklist_id);",
            "CREATE INDEX IF NOT EXISTS idx_access_record_user_id ON access_record(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_access_record_timestamp ON access_record(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_access_record_type ON access_record(access_type);",
            "CREATE INDEX IF NOT EXISTS idx_message_sender_id ON message(sender_id);",
            "CREATE INDEX IF NOT EXISTS idx_message_recipient_id ON message(recipient_id);",
            "CREATE INDEX IF NOT EXISTS idx_message_status ON message(status);",
            "CREATE INDEX IF NOT EXISTS idx_message_sent_at ON message(sent_at);",
            "CREATE INDEX IF NOT EXISTS idx_message_parent_id ON message(parent_id);"
        ]
        
        for index_sql in indexes:
            db.session.execute(index_sql)
        
        db.session.commit()
        print("Indexes created successfully")
        
    except Exception as e:
        print(f"Error creating indexes: {str(e)}")
        db.session.rollback()

def verify_tables():
    """Verify that all tables were created successfully"""
    try:
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        required_tables = ['task', 'access_record', 'message']
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            print(f"ERROR: Missing tables: {missing_tables}")
            return False
        else:
            print("All required tables created successfully")
            print(f"Total tables in database: {len(tables)}")
            return True
            
    except Exception as e:
        print(f"Error verifying tables: {str(e)}")
        return False

def main():
    """Main migration function"""
    print("Starting database migration for new tables...")
    print("=" * 50)
    
    with app.app_context():
        try:
            # Create tables
            create_task_table()
            create_access_record_table()
            create_message_table()
            
            # Create indexes
            create_indexes()
            
            # Verify tables
            if verify_tables():
                print("\n" + "=" * 50)
                print("Migration completed successfully!")
                print("New tables created: task, access_record, message")
            else:
                print("\n" + "=" * 50)
                print("Migration completed with errors!")
                sys.exit(1)
                
        except Exception as e:
            print(f"\nMigration failed: {str(e)}")
            sys.exit(1)

if __name__ == '__main__':
    main()
