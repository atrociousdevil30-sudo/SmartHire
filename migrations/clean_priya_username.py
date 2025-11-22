import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def clean_priya_username():
    """Update Priya Sharma's username to a cleaner version."""
    print("Cleaning Priya Sharma's username...")
    
    with app.app_context():
        try:
            # Find Priya Sharma (the one with priya_sharma_active username)
            priya = User.query.filter_by(username='priya_sharma_active').first()
            if priya and priya.full_name == 'Priya Sharma':
                print(f"Found: {priya.full_name} (current username: {priya.username})")
                # Update username to cleaner version
                priya.username = 'priya_sharma'
                print(f"Updated username to: {priya.username}")
                
                db.session.commit()
                print("Successfully updated Priya Sharma's username!")
                
                print(f"\nPriya Sharma's Final Details:")
                print(f"  Name: {priya.full_name}")
                print(f"  Email: {priya.email}")
                print(f"  Username: {priya.username}")
                print(f"  Password: employeepass123")
                print(f"  Phone: {priya.phone}")
                print(f"  Position: {priya.position}")
                print(f"  Department: {priya.department}")
                print(f"  Status: {priya.status}")
                
            else:
                print("Priya Sharma with username 'priya_sharma_active' not found")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating username: {str(e)}")
            raise

if __name__ == '__main__':
    clean_priya_username()
