import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def update_anjali_email():
    """Update Anjali Sharma's email to match her name."""
    print("Updating Anjali Sharma's email...")
    
    with app.app_context():
        try:
            # Find Anjali Sharma
            anjali = User.query.filter_by(username='anjali_sharma').first()
            if anjali:
                print(f"Found: {anjali.full_name} (current email: {anjali.email})")
                # Update email to match her name
                anjali.email = 'anjali.sharma@gmail.co.in'
                print(f"Updated email to: {anjali.email}")
                
                db.session.commit()
                print("Successfully updated Anjali Sharma's email!")
                
                print(f"\nAnjali Sharma's Final Details:")
                print(f"  Name: {anjali.full_name}")
                print(f"  Email: {anjali.email}")
                print(f"  Username: {anjali.username}")
                print(f"  Password: sarahpass123")
                print(f"  Phone: {anjali.phone}")
                print(f"  Position: {anjali.position}")
                print(f"  Department: {anjali.department}")
                print(f"  Status: {anjali.status}")
                
            else:
                print("Anjali Sharma not found")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating email: {str(e)}")
            raise

if __name__ == '__main__':
    update_anjali_email()
