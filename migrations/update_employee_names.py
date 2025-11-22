import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def update_employee_names():
    """Update employee names to Indian names."""
    print("Updating employee names to Indian names...")
    
    with app.app_context():
        try:
            # Find Sarah Wilson (now sarah.wilson@company.in)
            sarah = User.query.filter_by(email='sarah.wilson@company.in').first()
            if sarah:
                print(f"Found Sarah Wilson: {sarah.full_name}")
                # Update to Indian name
                sarah.full_name = 'Priya Sharma'
                print(f"Updated name to: {sarah.full_name}")
            else:
                print("Sarah Wilson not found")
            
            # Find Alex Johnson (now alex.johnson@company.in)
            alex = User.query.filter_by(email='alex.johnson@company.in').first()
            if alex:
                print(f"Found Alex Johnson: {alex.full_name}")
                # Update to Indian name
                alex.full_name = 'Rohan Verma'
                print(f"Updated name to: {alex.full_name}")
            else:
                print("Alex Johnson not found")
            
            # Commit changes
            db.session.commit()
            print("Successfully updated employee names!")
            
            print("\nUpdated Employee Details:")
            print("Former Sarah Wilson:")
            print(f"  Name: {sarah.full_name if sarah else 'Not found'}")
            print(f"  Email: {sarah.email if sarah else 'Not found'}")
            print(f"  Username: {sarah.username if sarah else 'Not found'}")
            print("\nFormer Alex Johnson:")
            print(f"  Name: {alex.full_name if alex else 'Not found'}")
            print(f"  Email: {alex.email if alex else 'Not found'}")
            print(f"  Username: {alex.username if alex else 'Not found'}")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating names: {str(e)}")
            raise

if __name__ == '__main__':
    update_employee_names()
