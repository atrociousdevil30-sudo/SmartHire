import os
from app import app, db
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

# Load environment variables
load_dotenv()

def create_database():
    # Get database URL from environment or use default
    db_url = os.getenv('DATABASE_URL', 'postgresql://postgres:sairam@localhost/smarthire')
    
    # Create database if it doesn't exist
    try:
        # Connect to the default 'postgres' database to create our database
        temp_engine = create_engine('postgresql://postgres:sairam@localhost/postgres')
        conn = temp_engine.connect()
        conn.execution_options(isolation_level="AUTOCOMMIT")
        
        # Create database if it doesn't exist
        conn.execute(text("CREATE DATABASE smarthire"))
        print("Database 'smarthire' created successfully.")
        conn.close()
    except ProgrammingError as e:
        # Database already exists
        if "already exists" in str(e):
            print("Database 'smarthire' already exists.")
        else:
            print(f"Error creating database: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def create_tables():
    try:
        # Create all tables
        with app.app_context():
            db.create_all()
        print("Tables created successfully.")
    except Exception as e:
        print(f"Error creating tables: {e}")

if __name__ == '__main__':
    create_database()
    create_tables()