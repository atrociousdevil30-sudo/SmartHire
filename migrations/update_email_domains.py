import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def update_email_domains():
    """Update emails to use Indian email domains."""
    print("Updating emails to Indian domains...")
    
    with app.app_context():
        try:
            # Find Priya Sharma
            priya = User.query.filter_by(username='priya_sharma').first()
            if priya:
                print(f"Found: {priya.full_name} (current email: {priya.email})")
                # Update to Indian email domain
                priya.email = 'priya.sharma@gmail.co.in'
                print(f"Updated email to: {priya.email}")
            else:
                print("Priya Sharma not found")
            
            # Find Rohan Verma
            rohan = User.query.filter_by(username='rohan_verma').first()
            if rohan:
                print(f"Found: {rohan.full_name} (current email: {rohan.email})")
                # Update to Indian email domain
                rohan.email = 'rohan.verma@yahoo.co.in'
                print(f"Updated email to: {rohan.email}")
            else:
                print("Rohan Verma not found")
            
            # Commit changes
            db.session.commit()
            print("Successfully updated email domains!")
            
            print("\nFinal Employee Details:")
            print("Priya Sharma:")
            print(f"  Name: {priya.full_name if priya else 'Not found'}")
            print(f"  Email: {priya.email if priya else 'Not found'}")
            print(f"  Username: {priya.username if priya else 'Not found'}")
            print(f"  Password: sarahpass123")
            print(f"  Phone: {priya.phone if priya else 'Not found'}")
            print("\nRohan Verma:")
            print(f"  Name: {rohan.full_name if rohan else 'Not found'}")
            print(f"  Email: {rohan.email if rohan else 'Not found'}")
            print(f"  Username: {rohan.username if rohan else 'Not found'}")
            print(f"  Password: alexpass123")
            print(f"  Phone: {rohan.phone if rohan else 'Not found'}")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating email domains: {str(e)}")
            raise

if __name__ == '__main__':
    update_email_domains()
