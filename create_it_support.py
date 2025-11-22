from app import app, db, User
from werkzeug.security import generate_password_hash

def create_it_support_users():
    with app.app_context():
        # IT Support Team Members
        it_support_members = [
            {
                'username': 'it.support.lead',
                'email': 'it.lead@company.com',
                'full_name': 'Alex Johnson',
                'role': 'hr',  # Using 'hr' role for IT support to have necessary permissions
                'position': 'IT Support Lead',
                'department': 'Information Technology',
                'is_active': True
            },
            {
                'username': 'it.support.tech1',
                'email': 'tech1@company.com', 
                'full_name': 'Sarah Chen',
                'role': 'hr',
                'position': 'Senior IT Technician',
                'department': 'Information Technology',
                'is_active': True
            },
            {
                'username': 'it.support.tech2',
                'email': 'tech2@company.com',
                'full_name': 'Mike Rodriguez',
                'role': 'hr', 
                'position': 'IT Support Specialist',
                'department': 'Information Technology',
                'is_active': True
            }
        ]
        
        for member_data in it_support_members:
            # Check if user already exists
            existing_user = User.query.filter_by(username=member_data['username']).first()
            if existing_user:
                print(f'User {member_data["username"]} already exists, skipping...')
                continue
                
            # Create new user
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
            print('IT support team members added successfully!')
        except Exception as e:
            db.session.rollback()
            print(f'Error: {e}')

if __name__ == '__main__':
    create_it_support_users()
