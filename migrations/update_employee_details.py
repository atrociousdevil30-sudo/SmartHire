import os
import sys
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def update_employee_details():
    """Update existing employee details with Indian information and assign manager."""
    print("Updating employee details...")
    
    with app.app_context():
        try:
            # Find existing employee
            employee = User.query.filter_by(username='employee1').first()
            if not employee:
                print("Employee not found!")
                return
            
            print(f"Found employee: {employee.full_name}")
            
            # Find or create manager
            manager = User.query.filter_by(username='dept_manager').first()
            if not manager:
                print("Creating new manager...")
                manager = User(
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
                manager.set_password('managerpass123')
                db.session.add(manager)
                db.session.flush()  # Get the manager ID
                print(f"Created manager: {manager.full_name}")
            else:
                print(f"Found existing manager: {manager.full_name}")
            
            # Update employee details
            employee.email = 'priya.sharma@company.in'
            employee.full_name = 'Priya Sharma'
            employee.phone = '+919812345678'
            employee.manager_id = manager.id
            
            print(f"Updated employee details:")
            print(f"- Name: {employee.full_name}")
            print(f"- Email: {employee.email}")
            print(f"- Phone: {employee.phone}")
            print(f"- Manager: {manager.full_name}")
            
            # Commit changes
            db.session.commit()
            print("Successfully updated employee details!")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating employee details: {str(e)}")
            raise

if __name__ == '__main__':
    update_employee_details()
