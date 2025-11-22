import os
import sys
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def update_offboarding_employees():
    """Update offboarding employees with Indian details and credentials."""
    print("Updating offboarding employees with Indian details...")
    
    with app.app_context():
        try:
            # Find Sarah Wilson
            sarah = User.query.filter_by(email='sarah.wilson@company.com').first()
            if sarah:
                print(f"Found Sarah Wilson: {sarah.full_name}")
                # Update to Indian details
                sarah.email = 'sarah.wilson@company.in'
                sarah.full_name = 'Sarah Wilson'
                sarah.phone = '+919876543211'
                sarah.username = 'sarah_wilson'
                sarah.set_password('sarahpass123')
                print(f"Updated Sarah Wilson to: {sarah.email}, {sarah.phone}")
            else:
                print("Sarah Wilson not found")
            
            # Find Alex Johnson
            alex = User.query.filter_by(email='alex.johnson@company.com').first()
            if alex:
                print(f"Found Alex Johnson: {alex.full_name}")
                # Update to Indian details
                alex.email = 'alex.johnson@company.in'
                alex.full_name = 'Alex Johnson'
                alex.phone = '+919876543212'
                alex.username = 'alex_johnson'
                alex.set_password('alexpass123')
                print(f"Updated Alex Johnson to: {alex.email}, {alex.phone}")
            else:
                print("Alex Johnson not found")
            
            # Commit changes
            db.session.commit()
            print("Successfully updated offboarding employees!")
            
            print("\nUpdated Login Credentials:")
            print("Sarah Wilson:")
            print("  Username: sarah_wilson")
            print("  Password: sarahpass123")
            print("  Email: sarah.wilson@company.in")
            print("\nAlex Johnson:")
            print("  Username: alex_johnson")
            print("  Password: alexpass123")
            print("  Email: alex.johnson@company.in")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating employees: {str(e)}")
            raise

if __name__ == '__main__':
    update_offboarding_employees()
