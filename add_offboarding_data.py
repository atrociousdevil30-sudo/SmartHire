#!/usr/bin/env python3
"""
Script to add sample offboarding candidates and documents to the SmartHire database.
"""

import os
import sys
from datetime import datetime, timedelta

# Add the app directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the app and models
from app import app, db, User, EmployeeDocument

def add_offboarding_data():
    """Add sample offboarding candidates and documents"""
    with app.app_context():
        print("Adding sample offboarding data...")
        
        # Create offboarding employees
        offboarding_employees = [
            {
                'username': 'alex.johnson',
                'email': 'alex.johnson@company.com',
                'full_name': 'Alex Johnson',
                'phone': '+1-555-0123',
                'role': 'employee',
                'department': 'Engineering',
                'position': 'Senior Developer',
                'status': 'Offboarding',
                'exit_date': datetime.now().date() + timedelta(days=7),
                'hire_date': datetime.now().date() - timedelta(days=365)
            },
            {
                'username': 'sarah.wilson',
                'email': 'sarah.wilson@company.com',
                'full_name': 'Sarah Wilson',
                'phone': '+1-555-0124',
                'role': 'employee',
                'department': 'Marketing',
                'position': 'Marketing Manager',
                'status': 'Offboarding',
                'exit_date': datetime.now().date() + timedelta(days=14),
                'hire_date': datetime.now().date() - timedelta(days=730)
            }
        ]
        
        created_users = []
        for emp_data in offboarding_employees:
            # Check if user already exists
            existing_user = User.query.filter_by(email=emp_data['email']).first()
            if existing_user:
                print(f"User {emp_data['email']} already exists, updating...")
                existing_user.status = 'Offboarding'
                existing_user.exit_date = emp_data['exit_date']
                created_users.append(existing_user)
            else:
                user = User(
                    username=emp_data['username'],
                    email=emp_data['email'],
                    full_name=emp_data['full_name'],
                    phone=emp_data['phone'],
                    role=emp_data['role'],
                    department=emp_data['department'],
                    position=emp_data['position'],
                    status=emp_data['status'],
                    exit_date=emp_data['exit_date'],
                    hire_date=emp_data['hire_date'],
                    is_active=True
                )
                user.set_password('password123')
                db.session.add(user)
                created_users.append(user)
                print(f"Created offboarding employee: {emp_data['full_name']}")
        
        db.session.flush()  # Get user IDs
        
        # Create sample documents for offboarding employees
        document_types = [
            {
                'file_name': 'Resignation_Acceptance_Letter.pdf',
                'document_type': 'Resignation Letter',
                'status': 'approved',
                'description': 'Official resignation acceptance letter'
            },
            {
                'file_name': 'Exit_Checklist.docx',
                'document_type': 'Exit Checklist',
                'status': 'approved',
                'description': 'Employee exit checklist document'
            },
            {
                'file_name': 'Experience_Letter.pdf',
                'document_type': 'Experience Letter',
                'status': 'pending',
                'description': 'Experience certificate - pending HR approval'
            },
            {
                'file_name': 'Form_16_Tax_Document.pdf',
                'document_type': 'Tax Forms',
                'status': 'processing',
                'description': 'Form 16 tax document - processing by finance'
            }
        ]
        
        for user in created_users:
            for doc_data in document_types:
                # Check if document already exists
                existing_doc = EmployeeDocument.query.filter_by(
                    user_id=user.id,
                    file_name=doc_data['file_name']
                ).first()
                
                if not existing_doc:
                    document = EmployeeDocument(
                        user_id=user.id,
                        file_name=doc_data['file_name'],
                        file_path=f'/uploads/documents/{user.id}_{doc_data["file_name"]}',
                        document_type=doc_data['document_type'],
                        file_size=1024 * 50,  # 50KB sample size
                        status=doc_data['status'],
                        description=doc_data['description'],
                        is_verified=doc_data['status'] == 'approved'
                    )
                    db.session.add(document)
                    print(f"Created document: {doc_data['file_name']} for {user.full_name}")
        
        db.session.commit()
        print("Sample offboarding data added successfully!")
        
        # Print summary
        offboarding_count = User.query.filter_by(status='Offboarding').count()
        documents_count = EmployeeDocument.query.count()
        print(f"\nSummary:")
        print(f"Offboarding employees: {offboarding_count}")
        print(f"Total documents: {documents_count}")

if __name__ == "__main__":
    add_offboarding_data()