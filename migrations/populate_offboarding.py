import os
import sys
from datetime import datetime, timedelta
from random import choice, randint

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models.offboarding import OffboardingCandidate, OffboardingAsset, OffboardingDocument, OffboardingClearance
from app import User  # Import User model from app

def create_sample_offboarding_candidates():
    """Create sample offboarding candidates in the database."""
    print("Creating sample offboarding candidates...")
    
    # Get existing users for employees and managers
    employees = User.query.filter_by(role='employee', is_active=True).all()
    managers = User.query.filter_by(role='hr').all()
    
    if not employees or not managers:
        print("Error: Need at least one employee and one manager in the database.")
        return
    
    # Sample reasons for leaving
    reasons = [
        "Pursuing higher education",
        "Better career opportunity",
        "Relocating to a different city/country",
        "Personal reasons",
        "Career change",
        "Starting own business",
        "Retirement",
        "Health reasons"
    ]
    
    # Sample assets
    asset_types = [
        {"name": "Dell XPS 15", "type": "Laptop"},
        {"name": "MacBook Pro 16\"", "type": "Laptop"},
        {"name": "iPhone 13", "type": "Mobile"},
        {"name": "Samsung Galaxy S21", "type": "Mobile"},
        {"name": "Access Card", "type": "Security"},
        {"name": "Company ID", "type": "Security"},
        {"name": "Docking Station", "type": "Accessory"},
        {"name": "Monitor 24\"", "type": "Accessory"},
        {"name": "Keyboard & Mouse", "type": "Accessory"},
        {"name": "Corporate Credit Card", "type": "Finance"}
    ]
    
    # Sample documents
    document_types = [
        {"name": "Resignation Acceptance Letter", "type": "pdf"},
        {"name": "Exit Interview Form", "type": "doc"},
        {"name": "Experience Letter", "type": "pdf"},
        {"name": "Tax Forms (Form 16)", "type": "pdf"},
        {"name": "NDA Agreement", "type": "pdf"},
        {"name": "Final Settlement Sheet", "type": "xls"},
        {"name": "Benefits Termination Notice", "type": "pdf"},
        {"name": "Equipment Return Form", "type": "doc"}
    ]
    
    # Departments for clearances
    departments = ["IT", "Finance", "HR", "Admin", "Facilities", "Operations", "Legal"]
    
    # Create 5 sample offboarding candidates
    for i in range(min(5, len(employees))):
        employee = employees[i]
        manager = choice(managers)
        
        # Random dates
        hire_date = datetime.utcnow().date() - timedelta(days=randint(365, 365*5))  # 1-5 years ago
        last_working_day = datetime.utcnow().date() + timedelta(days=randint(7, 30))  # 1 week to 1 month from now
        
        # Create offboarding candidate
        candidate = OffboardingCandidate(
            employee_id=employee.id,
            manager_id=manager.id,
            department=employee.department or choice(["Engineering", "Marketing", "Sales", "HR", "Finance"]),
            position=employee.position or f"Senior {choice(['Developer', 'Designer', 'Manager', 'Analyst'])}",
            hire_date=hire_date,
            last_working_day=last_working_day,
            reason_for_leaving=choice(reasons),
            exit_interview_scheduled=choice([True, False]),
            status=choice(['pending', 'in_progress', 'completed'])
        )
        
        if candidate.exit_interview_scheduled:
            candidate.exit_interview_date = last_working_day - timedelta(days=randint(1, 7))
            candidate.exit_interview_notes = f"Exit interview scheduled with {manager.full_name}."
        
        db.session.add(candidate)
        db.session.flush()  # To get the candidate ID for related records
        
        # Add 2-4 assets per candidate
        num_assets = randint(2, 4)
        selected_assets = []
        for _ in range(num_assets):
            # Ensure unique assets per candidate
            asset = None
            while True:
                asset = choice(asset_types)
                if asset not in selected_assets:
                    selected_assets.append(asset)
                    break
            
            status = choice(['pending', 'returned', 'not_returned'])
            asset_due_date = last_working_day - timedelta(days=randint(0, 7))
            
            off_asset = OffboardingAsset(
                offboarding_id=candidate.id,
                name=asset['name'],
                asset_type=asset['type'],
                asset_id=f"{asset['type'][:2].upper()}-{randint(2020, 2023)}-{randint(1000, 9999)}",
                condition=choice(['Good', 'Fair', 'Excellent', 'Needs Repair']),
                due_date=asset_due_date,
                status=status,
                returned_date=asset_due_date - timedelta(days=randint(1, 3)) if status == 'returned' else None,
                notes=f"{asset['name']} in good condition." if status == 'returned' else "Pending return"
            )
            db.session.add(off_asset)
        
        # Add documents
        num_docs = randint(3, 6)
        selected_docs = []
        for _ in range(num_docs):
            doc = None
            while True:
                doc = choice(document_types)
                if doc not in selected_docs:
                    selected_docs.append(doc)
                    break
            
            status = choice(['pending', 'available', 'processing'])
            doc = OffboardingDocument(
                offboarding_id=candidate.id,
                name=doc['name'],
                doc_type=doc['type'],
                status=status,
                notes=f"{doc['name']} - {status.capitalize()}"
            )
            db.session.add(doc)
        
        # Add department clearances
        num_depts = randint(3, len(departments))
        selected_depts = []
        for _ in range(num_depts):
            dept = None
            while True:
                dept = choice(departments)
                if dept not in selected_depts:
                    selected_depts.append(dept)
                    break
            
            status = choice(['pending', 'cleared'])
            clearance = OffboardingClearance(
                offboarding_id=candidate.id,
                department=dept,
                status=status,
                cleared_by=manager.id if status == 'cleared' else None,
                cleared_at=datetime.utcnow() - timedelta(days=randint(1, 3)) if status == 'cleared' else None,
                notes=f"{dept} clearance {'completed' if status == 'cleared' else 'pending'}"
            )
            db.session.add(clearance)
    
    try:
        db.session.commit()
        print("Successfully added sample offboarding candidates to the database.")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding sample offboarding candidates: {str(e)}")
        raise

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables if they don't exist
        db.create_all()
        
        # Clear existing offboarding data to avoid duplicates
        OffboardingClearance.query.delete()
        OffboardingDocument.query.delete()
        OffboardingAsset.query.delete()
        OffboardingCandidate.query.delete()
        db.session.commit()
        
        # Add sample offboarding candidates
        create_sample_offboarding_candidates()
