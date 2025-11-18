from app import app, db
import os

def reset_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        print("Database has been reset successfully!")

if __name__ == '__main__':
    # Make sure the instance directory exists
    os.makedirs('instance', exist_ok=True)
    
    # Reset the database
    reset_database()
