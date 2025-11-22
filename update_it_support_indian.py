from app import app, db, User
from werkzeug.security import generate_password_hash

def update_it_support_to_indian():
    with app.app_context():
        # Indian IT Support Team Members
        indian_it_support = [
            {
                'username': 'it.support.lead',
                'email': 'raj.sharma@company.com',
                'full_name': 'Raj Sharma',
                'role': 'hr',
                'position': 'IT Support Lead',
                'department': 'Information Technology',
                'is_active': True
            },
            {
                'username': 'it.support.tech1',
                'email': 'priya.patel@company.com', 
                'full_name': 'Priya Patel',
                'role': 'hr',
                'position': 'Senior IT Technician',
                'department': 'Information Technology',
                'is_active': True
            },
            {
                'username': 'it.support.tech2',
                'email': 'amit.kumar@company.com',
                'full_name': 'Amit Kumar',
                'role': 'hr', 
                'position': 'IT Support Specialist',
                'department': 'Information Technology',
                'is_active': True
            }
        ]
        
        for member_data in indian_it_support:
            # Find existing user
            existing_user = User.query.filter_by(username=member_data['username']).first()
            
            if existing_user:
                # Update existing user
                existing_user.email = member_data['email']
                existing_user.full_name = member_data['full_name']
                existing_user.position = member_data['position']
                existing_user.department = member_data['department']
                existing_user.is_active = member_data['is_active']
                print(f'Updated IT support user: {member_data["full_name"]}')
            else:
                # Create new user if doesn't exist
                user = User(
                    username=member_data['username'],
                    email=member_data['email'],
                    full_name=member_data['full_name'],
                    role=member_data['role'],
                    position=member_data['position'],
                    department=member_data['department'],
                    is_active=member_data['is_active'],
                    password=generate_password_hash('ITsupport2024!'),
                    phone='555-0123',
                    created_at=db.func.current_timestamp()
                )
                
                db.session.add(user)
                print(f'Created IT support user: {member_data["full_name"]}')
        
        try:
            db.session.commit()
            print('Indian IT support team updated successfully!')
        except Exception as e:
            db.session.rollback()
            print(f'Error: {e}')

if __name__ == '__main__':
    update_it_support_to_indian()
