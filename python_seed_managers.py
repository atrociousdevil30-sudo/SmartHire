from app import app, db, User

with app.app_context():
    def create_manager(username, email, full_name, phone, department, password):
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            phone=phone,
            role='manager',
            department=department,
            is_active=True,
        )
        user.set_password(password)
        db.session.add(user)

    create_manager(
        username='manager1',
        email='manager1@company.com',
        full_name='Alice Manager',
        phone='+1-555-0001',
        department='Engineering',
        password='Manager1Pass!'
    )

    create_manager(
        username='manager2',
        email='manager2@company.com',
        full_name='Bob Lead',
        phone='+1-555-0002',
        department='Sales',
        password='Manager2Pass!'
    )

    db.session.commit()