import os
import sys
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def create_sample_users():
    """Create sample users in the database."""
    print("Creating sample users...")
    
    # Check if users already exist
    if User.query.filter_by(username='hr_manager').first():
        print("Sample users already exist in the database.")
        return
    
    # Create HR Manager
    hr_manager = User(
        username='hr_manager',
        email='hr@example.com',
        full_name='Sarah Johnson',
        phone='+1234567890',
        role='hr',
        is_active=True,
        status='Active',
        position='HR Manager',
        hire_date=datetime.utcnow().date() - timedelta(days=365*2)  # 2 years ago
    )
    hr_manager.set_password('hrpassword123')
    
    # Create Employee
    employee = User(
        username='employee1',
        email='employee1@example.com',
        full_name='John Smith',
        phone='+1987654321',
        role='employee',
        is_active=True,
        status='Active',
        position='Senior Developer',
        department='Engineering',
        hire_date=datetime.utcnow().date() - timedelta(days=180)  # 6 months ago
    )
    employee.set_password('employeepass123')
    
    # Add to database
    db.session.add(hr_manager)
    db.session.add(employee)
    
    try:
        db.session.commit()
        print("Successfully created sample users:")
        print(f"- HR Manager: {hr_manager.username} (password: hrpassword123)")
        print(f"- Employee: {employee.username} (password: employeepass123)")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating sample users: {str(e)}")
        raise

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables if they don't exist
        db.create_all()
        
        # Create sample users
        create_sample_users()
