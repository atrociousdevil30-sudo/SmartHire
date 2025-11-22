import os
import sys
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def add_new_employees():
    """Add new employees with proper hire dates."""
    print("Adding new employees...")
    
    with app.app_context():
        try:
            # Check if employees already exist
            manoj = User.query.filter_by(email='reddymanojsk123@gmail.com').first()
            pavan = User.query.filter_by(email='pavanm0325@gmail.com').first()
            
            if manoj and pavan:
                print("Employees already exist. Updating hire dates...")
                
                # Update hire dates
                manoj.hire_date = datetime.utcnow().date() - timedelta(days=90)  # 3 months ago
                pavan.hire_date = datetime.utcnow().date() - timedelta(days=60)  # 2 months ago
                
                db.session.commit()
                print("Updated hire dates for existing employees")
                
            else:
                print("Creating new employees...")
                
                # Find existing manager to assign
                manager = User.query.filter_by(role='manager').first()
                if not manager:
                    print("No manager found. Creating default manager...")
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
                        hire_date=datetime.utcnow().date() - timedelta(days=365*3)
                    )
                    manager.set_password('managerpass123')
                    db.session.add(manager)
                    db.session.flush()
                
                # Create Manoj Reddy
                if not manoj:
                    manoj = User(
                        username='manoj_reddy',
                        email='reddymanojsk123@gmail.com',
                        full_name='Manoj Reddy S K',
                        phone='+919874563210',
                        role='employee',
                        is_active=True,
                        status='Onboarding',
                        position='Marketing Head',
                        department='Marketing',
                        manager_id=manager.id if manager.department == 'Marketing' else None,
                        hire_date=datetime.utcnow().date() - timedelta(days=90)  # 3 months ago
                    )
                    manoj.set_password('employeepass123')
                    db.session.add(manoj)
                
                # Create Pavan Yadav
                if not pavan:
                    pavan = User(
                        username='pavan_yadav',
                        email='pavanm0325@gmail.com',
                        full_name='Pavan Yadav',
                        phone='+919852147896',
                        role='employee',
                        is_active=True,
                        status='Onboarding',
                        position='Web Developer',
                        department='Engineering',
                        manager_id=manager.id if manager.department == 'Engineering' else None,
                        hire_date=datetime.utcnow().date() - timedelta(days=60)  # 2 months ago
                    )
                    pavan.set_password('employeepass123')
                    db.session.add(pavan)
                
                db.session.commit()
                print("Successfully created new employees:")
                print(f"- Manoj Reddy S K (Marketing Head) - Hire date: {manoj.hire_date}")
                print(f"- Pavan Yadav (Web Developer) - Hire date: {pavan.hire_date}")
                
        except Exception as e:
            db.session.rollback()
            print(f"Error adding employees: {str(e)}")
            raise

if __name__ == '__main__':
    add_new_employees()
