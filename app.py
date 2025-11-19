import os
import json
import logging
import random
import re
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import PyPDF2
import docx
import google.generativeai as genai

# Load environment variables
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=env_path)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Verify environment variables
logger.debug("Environment variables loaded:")
logger.debug(f"GEMINI_API_KEY present: {'Yes' if os.getenv('GEMINI_API_KEY') else 'No'}")
logger.debug(f"DEBUG mode: {os.getenv('DEBUG', 'False')}")

# Initialize Gemini
gemini_api_key = os.getenv('GEMINI_API_KEY')
if not gemini_api_key or gemini_api_key == 'your-gemini-api-key-here':
    logger.error("ERROR: GEMINI_API_KEY is not properly configured in .env file")
else:
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-1.0-pro')

from dashboard import dashboard_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Debug route to check environment variables
@app.route('/debug/env')
def debug_env():
    """Debug endpoint to check environment variables"""
    env_vars = {
        'GEMINI_API_KEY': 'Set' if os.getenv('GEMINI_API_KEY') else 'Not set',
        'DEBUG': os.getenv('DEBUG', 'False'),
        'Current Directory': os.getcwd(),
        'Files in Directory': ', '.join(os.listdir('.'))
    }
    return jsonify(env_vars)

# PostgreSQL configuration
# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:sairam@localhost/smarthire')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,  # Recycle connections after 5 minutes
    'pool_size': 20,
    'max_overflow': 30
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

app.register_blueprint(dashboard_bp, url_prefix='/hr/dashboard')

# Initialize extensions
db = SQLAlchemy()
db.init_app(app)
migrate = Migrate(app, db)

# Create database engine
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], **app.config.get('SQLALCHEMY_ENGINE_OPTIONS', {}))
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

def get_db_session():
    db_session = SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='Active')
    hire_date = db.Column(db.Date, nullable=True)
    position = db.Column(db.String(100), nullable=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationships
    manager = db.relationship('User', remote_side=[id], backref=db.backref('direct_reports', lazy=True))
    onboarding_checklist = db.relationship('OnboardingChecklist', 
                                         foreign_keys='OnboardingChecklist.employee_id',
                                         backref=db.backref('employee_ref', uselist=False), 
                                         uselist=False, 
                                         lazy=True)
    assigned_checklists = db.relationship('OnboardingChecklist', 
                                        foreign_keys='OnboardingChecklist.assigned_hr_id',
                                        backref='hr_personnel',
                                        lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class OnboardingChecklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Pending')
    
    # Onboarding tasks
    paperwork_completed = db.Column(db.Boolean, default=False)
    equipment_assigned = db.Column(db.Boolean, default=False)
    training_completed = db.Column(db.Boolean, default=False)
    hr_orientation = db.Column(db.Boolean, default=False)
    team_introduction = db.Column(db.Boolean, default=False)
    
    # Additional fields for tracking
    notes = db.Column(db.Text, nullable=True)
    assigned_hr_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationships
    employee = db.relationship(
        'User',
        foreign_keys=[employee_id],
        backref=db.backref('checklists', lazy=True)
    )

    assigned_hr = db.relationship(
        'User',
        foreign_keys=[assigned_hr_id],
        backref='hr_assignments'
    )
    
    def get_progress(self):
        """Calculate completion percentage of onboarding tasks"""
        tasks = [
            self.paperwork_completed,
            self.equipment_assigned,
            self.training_completed,
            self.hr_orientation,
            self.team_introduction
        ]
        completed = sum(1 for task in tasks if task)
        return (completed / len(tasks)) * 100 if tasks else 0


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    employee_id = db.Column(db.String(20), nullable=False)
    job_title = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hire_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships with explicit foreign_keys
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('employee', uselist=False, lazy=True))
    manager = db.relationship('User', foreign_keys=[manager_id], remote_side=[User.id], backref=db.backref('managed_employees', lazy=True))


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    job_desc = db.Column(db.Text, nullable=True)
    resume_text = db.Column(db.Text, nullable=True)
    score = db.Column(db.Float, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    interviews = db.relationship('Interview', backref='candidate', lazy=True)

class Interview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    responses = db.Column(db.JSON, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ExitFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    feedback = db.Column(db.Text, nullable=True)
    sentiment = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmployeeFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mood_rating = db.Column(db.Integer, nullable=False)  # 1-5 scale
    confidence_rating = db.Column(db.Integer, nullable=False)  # 1-5 scale
    feedback = db.Column(db.Text, nullable=True)  # Optional anonymous feedback
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('feedbacks', lazy=True))

# Create database tables
with app.app_context():
    db.create_all()

# Routes
# Login required decorator for role-based access
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or 'role' not in session:
                # Redirect to role selection page if not logged in
                return redirect(url_for('index'))
            if role:
                # Handle both single role string and list of roles
                allowed_roles = role if isinstance(role, list) else [role]
                if session.get('role') not in allowed_roles:
                    flash('You do not have permission to access this page.', 'danger')
                    # For candidates, redirect to the login with candidate role
                    if session.get('role') == 'candidate':
                        return redirect(url_for('login', role='candidate'))
                    # For other roles, redirect to their appropriate dashboard
                    return redirect(url_for(session.get('role', 'index') + '_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    if 'user_id' in session:
        # Handle candidate role by redirecting to employee login
        if session.get('role') == 'candidate':
            return redirect(url_for('login', role='employee'))
        # For other roles, redirect to their dashboard
        return redirect(url_for(session['role'] + '_dashboard'))
    return redirect(url_for('select_role'))

@app.route('/select-role')
def select_role():
    # Clear the current session to ensure a clean role switch
    session.clear()
    return render_template('role_selection.html')

@app.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    try:
        # Map role to valid roles to prevent injection
        valid_roles = ['hr', 'employee']
        if role not in valid_roles:
            flash('Invalid role selected', 'danger')
            return redirect(url_for('select_role'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            remember = True if request.form.get('remember') else False
            
            if not username or not password:
                flash('Please enter both username and password', 'danger')
                return redirect(url_for('login', role=role))
            
            try:
                # Find user by username and role (case-insensitive)
                user = User.query.filter(
                    db.func.lower(User.username) == username.lower(),
                    User.role == role,
                    User.is_active == True
                ).first()
                
                # Check if user exists and password is correct
                if not user or not user.check_password(password):
                    app.logger.warning(f'Failed login attempt for username: {username}')
                    flash('Invalid username or password', 'danger')
                    return redirect(url_for('login', role=role))
                
                # Update last login
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                # Set session
                session['user_id'] = user.id
                session['role'] = user.role
                session.permanent = remember  # Session expires when browser closes if not remembered
                
                app.logger.info(f'User {user.username} logged in successfully')
                flash(f'Welcome back, {user.full_name}!', 'success')
                
                # Store display name for welcome bar / navbar
                session['username'] = user.full_name
                
                # Redirect based on role
                if role == 'employee':
                    return redirect(url_for('employee_dashboard'))
                return redirect(url_for('hr_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error during login: {str(e)}')
                flash('An error occurred during login. Please try again.', 'danger')
                return redirect(url_for('login', role=role))
        
        # For GET request, show login form
        return render_template('login.html', role=role.title())
        
    except Exception as e:
        app.logger.error(f'Unexpected error in login route: {str(e)}')
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('select_role'))

@app.route('/register/<role>', methods=['GET', 'POST'])
def register(role):
    try:
        # Map role to valid roles to prevent injection
        valid_roles = ['hr', 'employee']
        if role not in valid_roles:
            flash('Invalid role selected', 'danger')
            return redirect(url_for('select_role'))
        
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            full_name = request.form.get('full_name', '').strip()
            phone = request.form.get('phone', '').strip()
            department = request.form.get('department', '').strip() if role == 'employee' else None
            
            # Basic validation
            if not all([username, email, password, confirm_password, full_name, phone]):
                flash('Please fill in all required fields', 'danger')
                return redirect(url_for('register', role=role))
            
            # Validate email format
            if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
                flash('Please enter a valid email address', 'danger')
                return redirect(url_for('register', role=role))
            
            # Validate password strength
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('register', role=role))
            
            # Validate passwords match
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register', role=role))
            
            try:
                # Check if username or email already exists (case-insensitive)
                if User.query.filter(db.func.lower(User.username) == username.lower()).first():
                    flash('Username already exists', 'danger')
                    return redirect(url_for('register', role=role))
                    
                if User.query.filter(db.func.lower(User.email) == email.lower()).first():
                    flash('Email already registered', 'danger')
                    return redirect(url_for('register', role=role))
                
                # Create new user
                user = User(
                    username=username,
                    email=email,
                    full_name=full_name,
                    phone=phone,
                    role=role,
                    department=department,
                    is_active=True,
                    created_at=datetime.utcnow()
                )
                user.set_password(password)
                
                db.session.add(user)
                db.session.commit()
                
                app.logger.info(f'New user registered: {username} ({role})')
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login', role=role))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Database error during registration: {str(e)}')
                flash('An error occurred during registration. Please try again.', 'danger')
                return redirect(url_for('register', role=role))
        
        # For GET request, show registration form
        return render_template('register.html', role=role.title())
        
    except Exception as e:
        app.logger.error(f'Unexpected error in register route: {str(e)}')
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('select_role'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))  # Redirect to role selection page

@app.route('/analytics/mood', endpoint='mood_analytics')
@login_required()
def mood_analytics():
    """Redirect to index"""
    return redirect(url_for('index'))

# HR Dashboard
@app.route('/hr/employees/add', methods=['GET', 'POST'])
@login_required('hr')
def add_employee():
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            department = request.form.get('department')
            position = request.form.get('position')
            hire_date_str = request.form.get('hire_date')
            manager_id = request.form.get('manager_id')
            
            # Convert hire_date string to date object
            hire_date = datetime.strptime(hire_date_str, '%Y-%m-%d').date() if hire_date_str else datetime.utcnow().date()
            
            # Create new user with 'Onboarding' status
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                phone=phone,
                role='employee',
                department=department,
                position=position,
                hire_date=hire_date,
                manager_id=manager_id if manager_id != 'None' else None,
                status='Onboarding',
                is_active=True
            )
            user.set_password(password)
            
            # Add to database
            db.session.add(user)
            db.session.flush()  # Get the user ID
            
            # Create default onboarding checklist
            checklist = OnboardingChecklist(
                employee_id=user.id,
                assigned_hr_id=session['user_id'],
                status='Pending'
            )
            db.session.add(checklist)
            
            db.session.commit()
            
            flash(f'Employee {full_name} added successfully! Onboarding checklist has been created.', 'success')
            return redirect(url_for('view_employee', employee_id=user.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding employee: {str(e)}')
            flash('An error occurred while adding the employee. Please try again.', 'danger')
    
    # For GET request or if there was an error
    managers = User.query.filter_by(role='manager', is_active=True).all()
    return render_template('hr/add_employee.html', managers=managers)

@app.route('/hr/employees/<int:employee_id>')
@login_required('hr')
def view_employee(employee_id):
    employee = User.query.get_or_404(employee_id)
    return render_template('hr/view_employee.html', employee=employee)

@app.route('/hr/employees')
@login_required('hr')
def list_employees():
    employees = User.query.filter_by(role='employee').order_by(User.created_at.desc()).all()
    return render_template('hr/employees.html', employees=employees)

@app.route('/hr/dashboard')
@login_required('hr')
def hr_dashboard():
    # Get the logged-in user
    user = User.query.get(session['user_id'])
    
    # Get counts for dashboard
    total_employees = User.query.filter_by(role='employee').count()
    onboarding_count = User.query.filter_by(status='Onboarding').count()
    active_count = User.query.filter_by(status='Active').count()
    
    # Get recent onboarding activities
    recent_onboarding = db.session.query(
        User, OnboardingChecklist
    ).join(
        OnboardingChecklist, User.id == OnboardingChecklist.employee_id
    ).filter(
        User.status == 'Onboarding'
    ).order_by(
        User.created_at.desc()
    ).limit(5).all()
    
    # Generate sample data for the dashboard
    resume_scores = [random.randint(60, 100) for _ in range(50)]
    # Generate sentiment data and calculate total
    sentiment_data = {
        'Positive': random.randint(5, 15),
        'Neutral': random.randint(2, 10),
        'Negative': random.randint(1, 5)
    }
    sentiment_total = sum(sentiment_data.values())
    
    # Generate hiring trends data
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=90)
    date_range = [start_date + timedelta(days=x) for x in range(0, 91, 7)]
    trends_data = {
        'date': date_range,
        'applications': [random.randint(10, 50) for _ in date_range],
        'interviews': [random.randint(5, 25) for _ in date_range],
        'hires': [random.randint(1, 10) for _ in date_range]
    }
    
    # Generate top candidates data
    candidates = [
        {'name': 'John Doe', 'score': 92, 'status': 'Interview Scheduled', 'applied': (end_date - timedelta(days=5)).strftime('%Y-%m-%d')},
        {'name': 'Jane Smith', 'score': 88, 'status': 'Offer Sent', 'applied': (end_date - timedelta(days=10)).strftime('%Y-%m-%d')},
        {'name': 'Robert Johnson', 'score': 85, 'status': 'New Application', 'applied': (end_date - timedelta(days=1)).strftime('%Y-%m-%d')},
        {'name': 'Emily Davis', 'score': 82, 'status': 'Interviewed', 'applied': (end_date - timedelta(days=7)).strftime('%Y-%m-%d')},
        {'name': 'Michael Brown', 'score': 79, 'status': 'Screening', 'applied': (end_date - timedelta(days=3)).strftime('%Y-%m-%d')},
    ]
    
    # Create charts using the dashboard blueprint's functions
    from dashboard import create_resume_score_chart, create_sentiment_chart, create_hiring_trends_chart
    
    resume_distribution = create_resume_score_chart(resume_scores)
    sentiment_chart = create_sentiment_chart(sentiment_data)
    hiring_trends = create_hiring_trends_chart(trends_data)
    
    return render_template('dashboard.html',
                         user=user,
                         current_user=user,  # For compatibility with existing templates
                         resume_distribution=resume_distribution,
                         sentiment_chart=sentiment_chart,
                         hiring_trends=hiring_trends,
                         candidates=candidates,
                         sentiment_data=sentiment_data,
                         sentiment_total=sentiment_total,
                         trends_data=trends_data)

# Employee Dashboard
@app.route('/employee/dashboard')
@login_required('employee')
def employee_dashboard():
    # Get the logged-in user
    user = User.query.get(session['user_id'])
    
    # Generate employee data based on the logged-in user
    employee_data = {
        'name': user.full_name,
        'username': user.username,
        'email': user.email,
        'phone': user.phone,
        'department': user.department or 'Not specified',
        'position': 'Employee',  # You might want to add a position field to the User model
        'hire_date': user.created_at.strftime('%Y-%m-%d') if user.created_at else 'N/A',
        'onboarding_progress': random.randint(30, 100),  # Sample progress
        'tasks_completed': random.randint(5, 15),
        'tasks_in_progress': random.randint(1, 5),
        'tasks_upcoming': random.randint(1, 5),
        'tasks_not_started': random.randint(1, 5),
        'upcoming_events': [
            {'title': 'Team Standup', 'time': '10:00 AM', 'type': 'meeting', 'location': 'Zoom'},
            {'title': 'Code Review', 'time': '2:00 PM', 'type': 'review', 'location': 'GitHub'},
            {'title': 'Training Session', 'time': '4:00 PM', 'type': 'training', 'location': 'Conference Room B'}
        ],
        'pending_tasks': [
            {'id': 1, 'title': 'Submit timesheet', 'due': 'Today', 'priority': 'high'},
            {'id': 2, 'title': 'Complete training module', 'due': 'Tomorrow', 'priority': 'medium'},
            {'id': 3, 'title': 'Update project documentation', 'due': 'Next week', 'priority': 'low'}
        ],
        'support_team': [
            {'name': 'HR Department', 'role': 'HR Team', 'email': 'hr@company.com', 'phone': '+1 (555) 123-4567'},
            {'name': 'IT Support', 'role': 'Technical Support', 'email': 'support@company.com', 'phone': '+1 (555) 987-6543'}
        ],
        'resources': [
            {'name': 'Employee Handbook', 'type': 'document', 'format': 'PDF'},
            {'name': 'Benefits Guide', 'type': 'document', 'format': 'PDF'},
            {'name': 'Training Materials', 'type': 'folder', 'format': 'ZIP'},
            {'name': 'Company Policies', 'type': 'document', 'format': 'PDF'},
            {'name': 'IT Helpdesk', 'type': 'link', 'url': '#'}
        ]
    }
    
    return render_template('employee_dashboard.html', 
                         employee=employee_data, 
                         user=user,
                         current_user=user,  # For compatibility with existing templates
                         title=f'{user.full_name}\\s Dashboard')

# Onboarding Tasks
@app.route('/employee/onboarding-tasks')
@login_required('employee')
def onboarding_tasks():
    # Sample onboarding tasks data - in a real app, this would come from the database
    onboarding_data = {
        'tasks': [
            {
                'id': 1,
                'title': 'Upload Aadhaar Card',
                'category': 'Documentation',
                'due_date': (datetime.utcnow() + timedelta(days=3)).strftime('%b %d, %Y'),
                'status': 'completed',
                'completed': True,
                'description': 'Please upload a clear scan of your Aadhaar card for verification.',
                'file_uploaded': 'aadhaar_card.pdf',
                'uploaded_at': (datetime.utcnow() - timedelta(days=1)).strftime('%b %d, %Y')
            },
            {
                'id': 2,
                'title': 'Upload PAN Card',
                'category': 'Documentation',
                'due_date': (datetime.utcnow() + timedelta(days=3)).strftime('%b %d, %Y'),
                'status': 'pending',
                'completed': False,
                'description': 'Please upload a clear scan of your PAN card for tax purposes.'
            },
            {
                'id': 3,
                'title': 'Complete Personal Information Form',
                'category': 'Personal Information',
                'due_date': (datetime.utcnow() + timedelta(days=5)).strftime('%b %d, %Y'),
                'status': 'in_progress',
                'completed': False,
                'description': 'Please complete your personal details in the employee portal.',
                'progress': 40
            },
            {
                'id': 4,
                'title': 'Submit Bank Details',
                'category': 'Documentation',
                'due_date': (datetime.utcnow() + timedelta(days=7)).strftime('%b %d, %Y'),
                'status': 'not_started',
                'completed': False,
                'description': 'Provide your bank account details for salary processing.'
            },
            {
                'id': 5,
                'title': 'Sign Offer Letter',
                'category': 'Documentation',
                'due_date': (datetime.utcnow() - timedelta(days=1)).strftime('%b %d, %Y'),
                'status': 'overdue',
                'completed': False,
                'description': 'Please review and sign your offer letter.'
            },
            {
                'id': 6,
                'title': 'Watch Company Introduction Video',
                'category': 'Orientation',
                'due_date': (datetime.utcnow() + timedelta(days=14)).strftime('%b %d, %Y'),
                'status': 'completed',
                'completed': True,
                'description': 'Watch the company introduction video to learn about our culture and values.',
                'video_url': '#'
            },
            {
                'id': 7,
                'title': 'Acknowledge Company Policies',
                'category': 'Orientation',
                'due_date': (datetime.utcnow() + timedelta(days=10)).strftime('%b %d, %Y'),
                'status': 'pending',
                'completed': False,
                'description': 'Please review and acknowledge the company policies.'
            }
        ],
        'stats': {
            'total_tasks': 7,
            'completed_tasks': 2,
            'in_progress_tasks': 1,
            'pending_tasks': 3,
            'overdue_tasks': 1,
            'completion_percentage': 29  # 2/7 tasks completed
        },
        'comments': [
            {
                'author': 'HR Team',
                'avatar': 'HR',
                'content': 'Please make sure to upload high-quality scans of your documents. Blurry images will not be accepted.',
                'time_ago': '2 hours ago',
                'timestamp': (datetime.utcnow() - timedelta(hours=2)).isoformat()
            }
        ]
    }
    
    return render_template('onboarding_tasks.html', 
                         tasks=onboarding_data['tasks'],
                         stats=onboarding_data['stats'],
                         comments=onboarding_data['comments'],
                         now=datetime.utcnow())

# Offboarding Tasks
@app.route('/employee/offboarding-tasks')
@login_required('employee')
def offboarding_tasks():
    # Sample offboarding data - in a real app, this would come from the database
    offboarding_data = {
        'status': 'in_progress',
        'progress_percentage': 40,
        'assets': [
            {
                'id': 1,
                'name': 'Dell XPS 15',
                'type': 'Laptop',
                'asset_id': 'IT-2022-0456',
                'condition': 'Good',
                'due_date': (datetime.utcnow() + timedelta(days=3)).strftime('%b %d, %Y'),
                'status': 'to_be_returned',
                'returned': False
            },
            {
                'id': 2,
                'name': 'iPhone 13',
                'type': 'Mobile',
                'asset_id': 'MB-2022-0789',
                'condition': 'Good',
                'due_date': (datetime.utcnow() + timedelta(days=3)).strftime('%b %d, %Y'),
                'status': 'returned',
                'returned': True,
                'returned_date': (datetime.utcnow() - timedelta(days=1)).strftime('%b %d, %Y')
            },
            {
                'id': 3,
                'name': 'Access Card',
                'type': 'Security',
                'asset_id': 'AC-2022-1234',
                'condition': 'Good',
                'due_date': (datetime.utcnow() + timedelta(days=3)).strftime('%b %d, %Y'),
                'status': 'to_be_returned',
                'returned': False
            }
        ],
        'exit_interview': {
            'scheduled': True,
            'date': (datetime.utcnow() + timedelta(days=1)).strftime('%b %d, %Y, %I:%M %p'),
            'with': 'Sarah Johnson (HR Manager)',
            'completed': False,
            'form': {
                'reason_for_leaving': '',
                'enjoyed_most': '',
                'could_improve': '',
                'contact_consent': False
            }
        },
        'documents': [
            {
                'id': 1,
                'name': 'Resignation Acceptance Letter',
                'type': 'pdf',
                'status': 'available',
                'download_url': '#'
            },
            {
                'id': 2,
                'name': 'Exit Checklist',
                'type': 'doc',
                'status': 'available',
                'download_url': '#'
            },
            {
                'id': 3,
                'name': 'Experience Letter',
                'type': 'pdf',
                'status': 'pending',
                'message': 'Will be available after clearance'
            },
            {
                'id': 4,
                'name': 'Tax Forms (Form 16)',
                'type': 'pdf',
                'status': 'processing',
                'message': 'Will be available after your last working day'
            }
        ],
        'clearances': [
            {
                'department': 'IT',
                'status': 'cleared',
                'cleared_at': (datetime.utcnow() - timedelta(days=1)).strftime('%b %d, %Y')
            },
            {
                'department': 'Finance',
                'status': 'pending',
                'assigned_to': 'finance@company.com'
            },
            {
                'department': 'HR',
                'status': 'cleared',
                'cleared_at': (datetime.utcnow() - timedelta(hours=2)).strftime('%b %d, %Y')
            },
            {
                'department': 'Admin',
                'status': 'pending',
                'assigned_to': 'admin@company.com'
            },
            {
                'department': 'Facilities',
                'status': 'cleared',
                'cleared_at': (datetime.utcnow() - timedelta(days=1)).strftime('%b %d, %Y')
            }
        ],
        'settlement': {
            'basic_salary': 85000.00,
            'leave_balance': 12,
            'leave_encashment': 39310.34,
            'deductions': 0.00,
            'net_payable': 124310.34,
            'payment_date': (datetime.utcnow() + timedelta(days=7)).strftime('%b %d, %Y'),
            'bank_details': {
                'account_holder': 'Alex Johnson',
                'bank_name': 'HDFC Bank',
                'account_number': 'XXXXXX7890',
                'ifsc_code': 'HDFC0001234'
            }
        }
    }
    
    return render_template('offboarding_tasks.html', 
                         assets=offboarding_data['assets'],
                         exit_interview=offboarding_data['exit_interview'],
                         documents=offboarding_data['documents'],
                         clearances=offboarding_data['clearances'],
                         settlement=offboarding_data['settlement'],
                         now=datetime.utcnow(),
                         timedelta=timedelta)

# Candidate routes have been removed - candidates now use the employee dashboard

# Sample candidate data for demonstration
SAMPLE_CANDIDATES = [
    {
        'name': 'John Smith',
        'job_desc': 'Senior Python Developer',
        'resume_text': """EXPERIENCE:
- Senior Python Developer at TechCorp (2018-Present)
  - Led a team of 5 developers to build a scalable microservices architecture
  - Implemented CI/CD pipelines reducing deployment time by 40%
  - Technologies: Python, Django, Flask, AWS, Docker, Kubernetes

- Software Engineer at WebSolutions (2015-2018)
  - Developed RESTful APIs using Flask and Django
  - Improved application performance by 30% through query optimization

EDUCATION:
- MS in Computer Science, Stanford University (2013-2015)
- BS in Computer Science, University of California (2009-2013)

SKILLS:
- Python, Django, Flask, FastAPI
- PostgreSQL, MongoDB, Redis
- AWS, Docker, Kubernetes
- Machine Learning, Data Analysis"""
    },
    {
        'name': 'Sarah Johnson',
        'job_desc': 'UX/UI Designer',
        'resume_text': """EXPERIENCE:
- Senior UX Designer at DesignHub (2019-Present)
  - Led UX design for enterprise SaaS products
  - Conducted user research and usability testing
  - Created design systems and component libraries

- UI/UX Designer at CreativeMinds (2016-2019)
  - Designed mobile and web applications
  - Created wireframes, prototypes, and user flows

EDUCATION:
- BFA in Graphic Design, Rhode Island School of Design
- UX Design Certification, Nielsen Norman Group

SKILLS:
- Figma, Sketch, Adobe XD
- User Research, Wireframing, Prototyping
- HTML, CSS, JavaScript"""
    },
    {
        'name': 'Michael Chen',
        'job_desc': 'Data Scientist',
        'resume_text': """EXPERIENCE:
- Data Scientist at DataInsights (2019-Present)
  - Built predictive models with 90% accuracy
  - Developed recommendation systems using collaborative filtering
  - Technologies: Python, TensorFlow, PyTorch, Spark

- Data Analyst at AnalyticsPro (2017-2019)
  - Created dashboards and visualizations
  - Performed statistical analysis on large datasets

EDUCATION:
- PhD in Data Science, MIT (2012-2017)
- MS in Statistics, Stanford University (2010-2012)

SKILLS:
- Machine Learning, Deep Learning
- Python, R, SQL
- Data Visualization, Big Data"""
    }
]

@app.route('/pre-onboarding')
@login_required('hr')
def pre_onboarding():
    candidates = Candidate.query.order_by(Candidate.created_at.desc()).all()
    return render_template('pre-onboarding.html', sample_candidates=candidates)

@app.route('/onboarding', methods=['GET', 'POST'])
@login_required('hr')
def onboarding():
    candidates = Candidate.query.order_by(Candidate.created_at.desc()).all()
    selected_candidate = None
    selected_candidate_id = request.args.get('candidate_id')
    
    if selected_candidate_id and selected_candidate_id.isdigit():
        selected_candidate = Candidate.query.get(selected_candidate_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        job_desc = request.form.get('job_desc')
        resume_text = request.form.get('resume_text')
        
        # Mock AI analysis
        score = round(random.uniform(60, 95), 1)
        summary = f"AI analysis shows strong potential candidate with relevant experience in {job_desc.split()[0]}."
        
        candidate = Candidate(
            name=name,
            job_desc=job_desc,
            resume_text=resume_text,
            score=score,
            summary=summary
        )
        db.session.add(candidate)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'candidate': {
                'name': name,
                'score': score,
                'summary': summary
            }
        })
    
    return render_template('onboarding.html', 
                         sample_candidates=candidates,
                         selected_candidate=selected_candidate)

@app.route('/interview', methods=['GET', 'POST'])
def interview():
    if request.method == 'POST':
        data = request.get_json()
        candidate_id = data.get('candidate_id')
        responses = data.get('responses', {})
        
        # Mock interview summary
        summary = "Candidate demonstrated good communication skills and relevant experience."
        
        interview = Interview(
            candidate_id=candidate_id,
            responses=responses,
            summary=summary
        )
        db.session.add(interview)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'summary': summary
        })
    
    return render_template('interview.html')

@app.route('/exit', methods=['GET', 'POST'])
@login_required(['employee', 'hr'])  # Allow both employees and HR to access
def exit_interview():
    # Get the current user's employee data
    employee = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Use the logged-in user's name instead of form data
        name = f"{employee.full_name} ({employee.username})"
        reason = request.form.get('reason')
        feedback = request.form.get('feedback', '')
        
        # Simple sentiment analysis
        positive_words = ['good', 'great', 'excellent', 'happy', 'satisfied']
        negative_words = ['bad', 'poor', 'stress', 'unhappy', 'dissatisfied']
        
        sentiment = 'Neutral'
        feedback_lower = feedback.lower()
        if any(word in feedback_lower for word in positive_words):
            sentiment = 'Positive'
        elif any(word in feedback_lower for word in negative_words):
            sentiment = 'Negative'
        
        try:
            exit_feedback = ExitFeedback(
                name=name,
                reason=reason,
                feedback=feedback,
                sentiment=sentiment,
                user_id=employee.id
            )
            db.session.add(exit_feedback)
            db.session.commit()
            
            app.logger.info(f'Exit feedback submitted by {employee.username}')
            return jsonify({
                'success': True,
                'message': 'Feedback submitted successfully!'
            })
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error submitting exit feedback: {str(e)}')
            return jsonify({
                'success': False,
                'message': 'An error occurred while submitting your feedback. Please try again.'
            }), 500
    
    # For GET request, render the template with employee data
    return render_template('exit.html', employee=employee)

@app.route('/analytics')
def analytics():
    try:
        # Here you would typically fetch real data from your database
        # For now, we'll let the frontend handle mock data
        return render_template('analytics.html')
    except Exception as e:
        app.logger.error(f"Error in analytics route: {str(e)}")
        return render_template('error.html', error="Failed to load analytics"), 500


@app.route('/analytics_data')
def analytics_data():
    # Mock data for analytics
    candidates = Candidate.query.count()
    avg_score = db.session.query(db.func.avg(Candidate.score)).scalar() or 0
    
    feedbacks = ExitFeedback.query.all()
    positive_feedback = sum(1 for f in feedbacks if f.sentiment == 'Positive')
    positive_percentage = (positive_feedback / len(feedbacks)) * 100 if feedbacks else 0
    
    return jsonify({
        'candidates_processed': candidates,
        'avg_resume_score': round(float(avg_score), 1),
        'positive_feedback_percentage': round(positive_percentage, 1),
        'sentiment_distribution': {
            'Positive': positive_feedback,
            'Neutral': sum(1 for f in feedbacks if f.sentiment == 'Neutral'),
            'Negative': sum(1 for f in feedbacks if f.sentiment == 'Negative')
        }
    })

@app.route('/support')
@login_required('employee')
def support():
    """Render the support page for employees."""
    return render_template('support.html', title='Support')

@app.route('/onboarding-assistant')
@login_required('employee')
def onboarding_assistant():
    """Render the onboarding assistant page for employees."""
    from datetime import datetime
    from flask import session
    
    # Get current user from session using SQLAlchemy 2.0 style
    user_id = session.get('user_id')
    user = db.session.get(User, user_id) if user_id else None
    
    # Create employee data to pass to template
    employee_data = {
        'name': user.username if user else 'New Employee',
        'role': 'Employee',
        'start_date': datetime.utcnow().strftime('%B %d, %Y')
    }
    
    return render_template(
        'onboarding_assistant.html',
        title='Onboarding Assistant',
        today=datetime.utcnow(),
        employee=employee_data
    )

def extract_text_from_pdf(file_stream):
    pdf_reader = PyPDF2.PdfReader(file_stream)
    text = ""
    for page in pdf_reader.pages:
        text += page.extract_text() + "\n"
    return text

def extract_text_from_docx(file_stream):
    doc = docx.Document(BytesIO(file_stream.read()))
    return "\n".join([paragraph.text for paragraph in doc.paragraphs])

def extract_skills(text):
    # Common tech skills to look for
    skills = [
        'Python', 'JavaScript', 'Java', 'C++', 'C#', 'Ruby', 'PHP', 'Swift', 'Kotlin', 'Go',
        'React', 'Angular', 'Vue', 'Node.js', 'Django', 'Flask', 'Spring', 'Laravel', 'Ruby on Rails',
        'SQL', 'MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'DynamoDB',
        'AWS', 'Azure', 'Google Cloud', 'Docker', 'Kubernetes', 'Terraform',
        'Git', 'CI/CD', 'Jenkins', 'GitHub Actions',
        'Machine Learning', 'Data Science', 'TensorFlow', 'PyTorch', 'Pandas', 'NumPy',
        'Agile', 'Scrum', 'DevOps', 'TDD', 'REST API', 'GraphQL', 'Microservices'
    ]
    
    found_skills = []
    for skill in skills:
        if re.search(r'\b' + re.escape(skill) + r'\b', text, re.IGNORECASE):
            found_skills.append(skill)
    return found_skills[:15]  # Return max 15 skills to avoid clutter

def extract_experience(text):
    # Look for job experience patterns
    experience = []
    
    # Look for date patterns like 2020 - 2022 or 01/2020 - Present
    date_patterns = [
        r'(\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4})\s*[-–]\s*(\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4}|Present\b)',
        r'(\d{1,2}/\d{4})\s*[-–]\s*(\d{1,2}/\d{4}|Present\b)',
        r'(\d{4})\s*[-–]\s*(\d{4}|Present\b)'
    ]
    
    for pattern in date_patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        for i, match in enumerate(matches):
            if i < 3:  # Limit to first 3 experiences
                start = max(0, match.start() - 150)
                end = min(len(text), match.end() + 150)
                context = text[start:end].strip()
                experience.append(context)
    
    return experience if experience else ["Experience not found in standard format"]

def extract_education(text):
    education = []
    
    # Look for education section
    education_indicators = [
        r'(?i)education\s*',
        r'(?i)academic\s*background',
        r'(?i)qualifications',
        r'(?i)degrees?\s*',
    ]
    
    # Look for degree patterns
    degree_patterns = [
        r'\b(?:B\.?S\.?|Bachelor(?:\'?s)?\s+of\s+Science|B\.?A\.?|Bachelor(?:\'?s)?\s+of\s+Arts|M\.?S\.?|Master(?:\'?s)?\s+of\s+Science|M\.?A\.?|Master(?:\'?s)?\s+of\s+Arts|Ph\.?D\.?|Doctor(?:ate)?(?:\'?s)?\s+of\s+Philosophy)\b',
        r'\b(?:B\.?E\.?|Bachelor(?:\'?s)?\s+of\s+Engineering|B\.?Tech|Bachelor(?:\'?s)?\s+of\s+Technology)\b',
        r'\b(?:M\.?B\.?A\.?|Master(?:\'?s)?\s+of\s+Business\s+Administration)\b',
    ]
    
    # First try to find education section
    for indicator in education_indicators:
        section_match = re.search(indicator + r'[\s\S]*?(?=\n\s*\n|$)', text, re.IGNORECASE)
        if section_match:
            section = section_match.group(0)
            # Extract lines that look like education entries
            lines = [line.strip() for line in section.split('\n') if any(re.search(pattern, line, re.IGNORECASE) for pattern in degree_patterns)]
            if lines:
                return lines[:3]  # Return first 3 education entries
    
    # If no education section found, search the whole text for degree patterns
    for pattern in degree_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for i, match in enumerate(matches):
            if i < 3:  # Limit to 3 entries
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                context = text[start:end].strip()
                education.append(context)
    
    return education if education else ["Education information not found"]

def extract_email(text):
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    return email_match.group(0) if email_match else ''

def extract_name(text):
    # Look for name at the beginning of the document
    first_line = text.split('\n')[0].strip()
    # Simple heuristic: if the first line is likely a name (2-4 words, title case)
    if re.match(r'^[A-Z][a-z]+(?:\s+[A-Z][a-z\.]+){1,3}$', first_line):
        return first_line
    return ''

@app.route('/analyze-resume', methods=['POST'])
def analyze_resume():
    if 'resume' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['resume']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        filename = file.filename.lower()
        file_stream = file.stream
        
        if filename.endswith('.pdf'):
            text = extract_text_from_pdf(file_stream)
        elif filename.endswith(('.doc', '.docx')):
            text = extract_text_from_docx(file_stream)
        else:
            return jsonify({'error': 'Unsupported file format. Please upload a PDF or Word document.'}), 400
        
        # Extract information
        result = {
            'name': extract_name(text),
            'email': extract_email(text),
            'skills': extract_skills(text),
            'experience': extract_experience(text),
            'education': extract_education(text)
        }
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error processing resume: {str(e)}")
        return jsonify({'error': 'Error processing resume. Please try again.'}), 500

def generate_ai_response(messages, max_tokens=500, temperature=0.7):
    """Helper function to generate AI responses using Gemini"""
    try:
        if not gemini_api_key or gemini_api_key == 'your-gemini-api-key-here':
            raise Exception("Gemini API key not configured")
            
        logger.debug("Using Gemini Pro model")
        
        # Convert messages to Gemini format if needed
        if isinstance(messages, list) and len(messages) > 0:
            # If it's a chat completion format, extract the last user message
            last_message = messages[-1]
            if isinstance(last_message, dict) and 'content' in last_message:
                prompt = last_message['content']
            else:
                prompt = str(messages[-1])
        else:
            prompt = str(messages)
            
        # Generate response using Gemini
        response = model.generate_content(
            prompt,
            generation_config={
                'max_output_tokens': max_tokens,
                'temperature': temperature,
            }
        )
        
        return response.text.strip()
    except Exception as e:
        logger.error(f"Error in generate_ai_response: {str(e)}")
        raise Exception(f"Error generating response: {str(e)}")

def generate_onboarding_plan(role, department, start_date):
    """Generate a personalized onboarding plan using Gemini AI"""
    prompt = f"""As an HR specialist, create a comprehensive 30-60-90 day onboarding plan for a new {role} in the {department} department starting on {start_date}.
    
    Include these sections with detailed, actionable items:
    
    # {role} Onboarding Plan - {department} Department
    
    ## First 30 Days: Learning & Orientation
    - Week 1: Company introduction, tools setup, and team integration
    - Week 2-3: Role-specific training and initial tasks
    - Week 4: First month review and goal setting
    
    ## Days 31-60: Skill Development
    - Department-specific training
    - Cross-functional exposure
    - Performance check-ins
    
    ## Days 61-90: Independence & Contribution
    - Independent project work
    - Process improvements
    - 90-day review preparation
    
    ## Key Resources:
    - Department playbook
    - Training materials
    - Important contacts
    
    Format the response in clean markdown with clear sections and bullet points."""
    
    try:
        response = model.generate_content({
            'parts': [prompt],
            'generation_config': {
                'max_output_tokens': 2000,
                'temperature': 0.7,
            }
        })
        return response.text
    except Exception as e:
        app.logger.error(f"Error generating onboarding plan: {str(e)}")
        return "I couldn't generate an onboarding plan at the moment. Please try again later."

def generate_offboarding_checklist(employee_name, last_working_day, role, department):
    """Generate a comprehensive offboarding checklist using Gemini AI"""
    prompt = f"""As an HR professional, create a detailed offboarding checklist for {employee_name} ({role} in {department}) who is leaving on {last_working_day}.
    
    Include these categories with specific, actionable items:
    
    # Offboarding Checklist for {employee_name}
    
    ## Pre-Exit (Before {last_working_day})
    - [ ] Schedule and conduct exit interview
    - [ ] Document knowledge transfer sessions
    - [ ] Collect company assets (laptop, ID, access cards, etc.)
    
    ## IT & Access
    - [ ] Disable email and system access
    - [ ] Transfer or archive files and documents
    - [ ] Update contact lists and distribution groups
    
    ## HR & Admin
    - [ ] Finalize payroll and benefits
    - [ ] Return company property
    - [ ] Update organizational charts and directories
    
    ## Department-Specific Tasks
    - [ ] Handover ongoing projects
    - [ ] Document key processes
    - [ ] Update documentation and manuals
    
    ## Post-Exit
    - [ ] Send farewell/transition email
    - [ ] Update external contacts if needed
    - [ ] Schedule knowledge transfer with replacement if applicable
    
    Format as a clean markdown checklist with checkboxes [ ]."""
    
    try:
        response = model.generate_content({
            'parts': [prompt],
            'generation_config': {
                'max_output_tokens': 2000,
                'temperature': 0.5,
            }
        })
        return response.text
    except Exception as e:
        app.logger.error(f"Error generating offboarding checklist: {str(e)}")
        return "I couldn't generate an offboarding checklist at the moment. Please try again later."


@app.route('/api/generate-welcome-email', methods=['POST'])
def generate_welcome_email():
    try:
        data = request.json
        employee_name = data.get('name', 'New Employee')
        start_date = data.get('start_date', 'their start date')
        
        prompt = f"""Write a warm, professional welcome email for {employee_name} 
        who is joining on {start_date}. Include:
        1. A warm welcome message
        2. First day details (time, location, who to ask for)
        3. What to bring on the first day
        4. A friendly closing"""
        
        email_content = generate_ai_response([
            {"role": "system", "content": "You are an HR professional writing welcome emails."},
            {"role": "user", "content": prompt}
        ], max_tokens=800)
        
        return jsonify({
            'status': 'success',
            'email': email_content
        })
        
    except Exception as e:
        app.logger.error(f"Error generating welcome email: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate welcome email'
        }), 500

@app.route('/api/feedback/submit', methods=['POST'])
@login_required('employee')
def submit_feedback():
    try:
        data = request.json
        mood_rating = data.get('mood_rating')
        confidence_rating = data.get('confidence_rating')
        feedback = data.get('feedback', '')
        
        # Validate ratings (1-5)
        if not (1 <= mood_rating <= 5) or not (1 <= confidence_rating <= 5):
            return jsonify({'status': 'error', 'message': 'Ratings must be between 1 and 5'}), 400
        
        # Create new feedback entry
        new_feedback = EmployeeFeedback(
            user_id=session['user_id'],
            mood_rating=mood_rating,
            confidence_rating=confidence_rating,
            feedback=feedback
        )
        
        db.session.add(new_feedback)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Feedback submitted successfully',
            'data': {
                'id': new_feedback.id,
                'created_at': new_feedback.created_at.isoformat()
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to submit feedback. Please try again.'
        }), 500

@app.route('/api/feedback/summary')
@login_required('hr')
def get_feedback_summary():
    try:
        # Get feedback from the last 7 days
        one_week_ago = datetime.utcnow() - timedelta(days=7)
        recent_feedback = EmployeeFeedback.query.filter(
            EmployeeFeedback.created_at >= one_week_ago
        ).all()
        
        if not recent_feedback:
            return jsonify({
                'status': 'success',
                'data': {
                    'total_submissions': 0,
                    'avg_mood': 0,
                    'avg_confidence': 0,
                    'mood_trend': [],
                    'confidence_trend': [],
                    'alerts': []
                }
            })
        
        # Calculate averages
        total = len(recent_feedback)
        avg_mood = sum(f.mood_rating for f in recent_feedback) / total
        avg_confidence = sum(f.confidence_rating for f in recent_feedback) / total
        
        # Generate daily trends (last 7 days)
        today = datetime.utcnow().date()
        dates = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
        
        mood_trend = []
        confidence_trend = []
        alerts = []
        
        for date in dates:
            daily_feedback = [f for f in recent_feedback if f.created_at.date().isoformat() == date]
            if daily_feedback:
                mood_avg = sum(f.mood_rating for f in daily_feedback) / len(daily_feedback)
                conf_avg = sum(f.confidence_rating for f in daily_feedback) / len(daily_feedback)
                
                # Check for significant drops in confidence
                if len(daily_feedback) >= 3 and conf_avg < 2.5:  # Threshold for low confidence
                    alerts.append({
                        'type': 'low_confidence',
                        'date': date,
                        'value': round(conf_avg, 1)
                    })
            else:
                mood_avg = 0
                conf_avg = 0
                
            mood_trend.append(round(mood_avg, 1))
            confidence_trend.append(round(conf_avg, 1))
        
        # Calculate engagement score (simple average of mood and confidence)
        engagement_score = round((avg_mood + avg_confidence) / 2, 1)
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_submissions': total,
                'avg_mood': round(avg_mood, 1),
                'avg_confidence': round(avg_confidence, 1),
                'engagement_score': engagement_score,
                'mood_trend': mood_trend,
                'confidence_trend': confidence_trend,
                'alerts': alerts,
                'dates': dates
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching feedback summary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch feedback summary.'
        }), 500

if __name__ == '__main__':
    app.run(debug=True)