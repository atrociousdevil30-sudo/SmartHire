import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def update_usernames():
    """Update usernames to match Indian names."""
    print("Updating usernames to match Indian names...")
    
    with app.app_context():
        try:
            # Find Priya Sharma (formerly Sarah Wilson)
            priya = User.query.filter_by(email='sarah.wilson@company.in').first()
            if priya:
                print(f"Found: {priya.full_name} (current username: {priya.username})")
                # Update username to match Indian name
                priya.username = 'priya_sharma'
                print(f"Updated username to: {priya.username}")
            else:
                print("Priya Sharma not found")
            
            # Find Rohan Verma (formerly Alex Johnson)
            rohan = User.query.filter_by(email='alex.johnson@company.in').first()
            if rohan:
                print(f"Found: {rohan.full_name} (current username: {rohan.username})")
                # Update username to match Indian name
                rohan.username = 'rohan_verma'
                print(f"Updated username to: {rohan.username}")
            else:
                print("Rohan Verma not found")
            
            # Commit changes
            db.session.commit()
            print("Successfully updated usernames!")
            
            print("\nFinal Employee Details:")
            print("Priya Sharma (formerly Sarah Wilson):")
            print(f"  Name: {priya.full_name if priya else 'Not found'}")
            print(f"  Email: {priya.email if priya else 'Not found'}")
            print(f"  Username: {priya.username if priya else 'Not found'}")
            print(f"  Password: sarahpass123")
            print("\nRohan Verma (formerly Alex Johnson):")
            print(f"  Name: {rohan.full_name if rohan else 'Not found'}")
            print(f"  Email: {rohan.email if rohan else 'Not found'}")
            print(f"  Username: {rohan.username if rohan else 'Not found'}")
            print(f"  Password: alexpass123")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating usernames: {str(e)}")
            raise

if __name__ == '__main__':
    update_usernames()
