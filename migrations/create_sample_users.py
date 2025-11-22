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
    
    # Create Department Manager
    dept_manager = User(
        username='dept_manager',
        email='raj.kumar@company.in',
        full_name='Raj Kumar',
        phone='+919876543210',
        role='manager',
        is_active=True,
        status='Active',
        position='Engineering Manager',
        department='Engineering',
        hire_date=datetime.utcnow().date() - timedelta(days=365*3)  # 3 years ago
    )
    dept_manager.set_password('managerpass123')
    
    # Create Employee
    employee = User(
        username='employee1',
        email='priya.sharma@company.in',
        full_name='Priya Sharma',
        phone='+919812345678',
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
    db.session.add(dept_manager)
    db.session.add(employee)
    
    # Flush to get IDs before setting relationships
    db.session.flush()
    
    # Assign manager after getting the manager ID
    employee.manager_id = dept_manager.id
    
    try:
        db.session.commit()
        print("Successfully created sample users:")
        print(f"- HR Manager: {hr_manager.username} (password: hrpassword123)")
        print(f"- Department Manager: {dept_manager.username} (password: managerpass123)")
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
