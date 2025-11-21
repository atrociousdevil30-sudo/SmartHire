"""
Add is_priority column to Message table
"""
from app import app, db
from sqlalchemy import text

def add_is_priority_column():
    """Add is_priority column to Message table if it doesn't exist"""
    with app.app_context():
        try:
            # Check if column already exists
            inspector = db.inspect(db.engine)
            columns = inspector.get_columns('message')
            column_names = [col['name'] for col in columns]
            
            if 'is_priority' not in column_names:
                print("Adding is_priority column to Message table...")
                
                # Add the column
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE message ADD COLUMN is_priority BOOLEAN DEFAULT FALSE"))
                    conn.commit()
                
                print("✅ is_priority column added successfully")
            else:
                print("✅ is_priority column already exists")
                
        except Exception as e:
            print(f"❌ Error adding is_priority column: {e}")

if __name__ == '__main__':
    add_is_priority_column()
