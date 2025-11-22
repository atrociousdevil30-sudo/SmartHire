import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def fix_duplicate_names():
    """Fix duplicate Priya names by changing one to a different Indian name."""
    print("Fixing duplicate Priya names...")
    
    with app.app_context():
        try:
            # Find both Priyas
            priyas = User.query.filter(User.full_name.like('%Priya%')).all()
            
            print(f"Found {len(priyas)} employees with Priya in name:")
            for priya in priyas:
                print(f"  - {priya.full_name} (email: {priya.email}, username: {priya.username})")
            
            # Find the one who was formerly Sarah Wilson (offboarding status)
            offboarding_priya = None
            onboarding_priya = None
            
            for priya in priyas:
                if priya.status == 'Offboarding':
                    offboarding_priya = priya
                    print(f"Found offboarding Priya: {priya.full_name} ({priya.email})")
                elif priya.status == 'Onboarding':
                    onboarding_priya = priya
                    print(f"Found onboarding Priya: {priya.full_name} ({priya.email})")
            
            # Change the offboarding Priya to a different name to avoid confusion
            if offboarding_priya:
                new_name = "Anjali Sharma"
                new_username = "anjali_sharma"
                print(f"Changing offboarding Priya to: {new_name}")
                
                offboarding_priya.full_name = new_name
                offboarding_priya.username = new_username
                
                print(f"Updated: {offboarding_priya.full_name} (username: {offboarding_priya.username})")
            else:
                print("No offboarding Priya found to rename")
            
            # Commit changes
            db.session.commit()
            print("Successfully fixed duplicate names!")
            
            print("\nFinal Employee List:")
            all_employees = User.query.filter(User.role == 'employee').all()
            for emp in all_employees:
                status_icon = "🔄" if emp.status == 'Onboarding' else "🚪" if emp.status == 'Offboarding' else "✅"
                print(f"{status_icon} {emp.full_name} - {emp.email} ({emp.username})")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error fixing names: {str(e)}")
            raise

if __name__ == '__main__':
    fix_duplicate_names()
