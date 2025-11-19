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
    employee_id = db.Column(db.String(20), nullable=True)
    exit_date = db.Column(db.Date, nullable=True)
    
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


class OnboardingTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    checklist_id = db.Column(db.Integer, db.ForeignKey('onboarding_checklist.id'), nullable=False)
    task_name = db.Column(db.String(200), nullable=False)
    task_description = db.Column(db.Text, nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OnboardingChecklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Pending')
    
    # Legacy fields for backward compatibility
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
    
    tasks = db.relationship('OnboardingTask', backref='checklist', lazy=True, cascade='all, delete-orphan')
    
    def get_progress(self):
        """Calculate completion percentage of onboarding tasks"""
        if self.tasks:
            completed = sum(1 for task in self.tasks if task.is_completed)
            return (completed / len(self.tasks)) * 100 if self.tasks else 0
        else:
            # Fallback to legacy fields
            legacy_tasks = [
                self.paperwork_completed,
                self.equipment_assigned,
                self.training_completed,
                self.hr_orientation,
                self.team_introduction
            ]
            completed = sum(1 for task in legacy_tasks if task)
            return (completed / len(legacy_tasks)) * 100 if legacy_tasks else 0


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


class EmployeeDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    document_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)  # in bytes
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    user = db.relationship('User',
                           backref=db.backref('documents', lazy=True))


class EmployeeSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False, unique=True)
    email_notifications = db.Column(db.Boolean, default=True)
    sms_notifications = db.Column(db.Boolean, default=False)
    notification_frequency = db.Column(db.String(50),
                                       default='immediately')
    theme = db.Column(db.String(50), default='light')  # light/dark
    language = db.Column(db.String(10), default='en')
    two_factor_enabled = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    user = db.relationship('User',
                           backref=db.backref('settings', uselist=False,
                                              lazy=True))

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
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            department = request.form.get('department')
            position = request.form.get('position')
            manager_id = request.form.get('manager_id')
            password = request.form.get('password')

            # Create new user with 'Onboarding' status
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                phone=phone,
                role='employee',
                department=department,
                position=position,
                manager_id=manager_id if manager_id != 'None' else None,
                status='Onboarding',
                is_active=True
            )
            user.set_password(password)
            
            # Add to database
            db.session.add(user)
            db.session.flush()  # Get the user ID
            
            # Create onboarding checklist
            checklist = OnboardingChecklist(
                employee_id=user.id,
                assigned_hr_id=session['user_id'],
                status='Pending'
            )
            db.session.add(checklist)
            db.session.flush()  # Get the checklist ID
            
            # Get custom tasks from form
            task_names = request.form.getlist('task_name[]')
            task_descriptions = request.form.getlist('task_description[]')
            task_enabled = request.form.getlist('task_enabled[]')
            
            # Create custom onboarding tasks
            for i, task_name in enumerate(task_names):
                if task_name.strip() and str(i+1) in task_enabled:
                    task = OnboardingTask(
                        checklist_id=checklist.id,
                        task_name=task_name.strip(),
                        task_description=task_descriptions[i].strip() if i < len(task_descriptions) else '',
                        order_index=i
                    )
                    db.session.add(task)
            
            db.session.commit()

            flash(f"Employee {full_name} added successfully with custom onboarding checklist!", 'success')
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
    checklist = OnboardingChecklist.query.filter_by(employee_id=employee_id).first()
    return render_template('hr/view_employee.html', employee=employee, checklist=checklist)

@app.route('/hr/employees')
@login_required('hr')
def list_employees():
    # Get filter parameters
    search = request.args.get('search', '')
    department_filter = request.args.get('department', '')
    status_filter = request.args.get('status', '')
    
    # Build query
    query = User.query.filter_by(role='employee')
    
    # Apply filters
    if search:
        query = query.filter(
            db.or_(
                User.full_name.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%')
            )
        )
    
    if department_filter:
        query = query.filter(User.department == department_filter)
    
    if status_filter:
        query = query.filter(User.status == status_filter)
    
    employees = query.order_by(User.created_at.desc()).all()
    
    # Get unique departments for filter dropdown
    departments = db.session.query(User.department).filter(
        User.role == 'employee',
        User.department.isnot(None)
    ).distinct().all()
    departments = [dept[0] for dept in departments if dept[0]]
    
    return render_template('hr/employees.html', 
                         employees=employees,
                         departments=departments,
                         current_search=search,
                         current_department=department_filter,
                         current_status=status_filter)

@app.route('/hr/dashboard')
@login_required('hr')
def hr_dashboard():
    # Get the logged-in user
    user = User.query.get(session['user_id'])
    
    # Get real counts from database
    total_employees = User.query.filter_by(role='employee').count()
    onboarding_count = User.query.filter_by(status='Onboarding').count()
    active_count = User.query.filter_by(status='Active').count()
    
    # Get recent AI interview results from database
    recent_interviews = Interview.query.order_by(Interview.created_at.desc()).limit(10).all()
    interview_results = []
    for interview in recent_interviews:
        candidate = interview.candidate if interview.candidate else None
        interview_results.append({
            'id': interview.id,
            'candidate_name': candidate.name if candidate else 'Unknown Candidate',
            'role': candidate.job_desc[:50] + '...' if candidate and candidate.job_desc else 'N/A',
            'score': round(candidate.score, 1) if candidate and candidate.score else 'N/A',
            'recommendation': 'Proceed to Next Round' if (candidate and candidate.score and candidate.score >= 7.5) else 'Hold for Review' if (candidate and candidate.score and candidate.score >= 6.0) else 'Reject',
            'date': interview.created_at.strftime('%Y-%m-%d'),
            'summary': interview.summary[:100] + '...' if interview.summary else 'No summary available'
        })
    
    # Get exit feedback sentiment analysis from database
    exit_feedbacks = ExitFeedback.query.all()
    sentiment_counts = {'Positive': 0, 'Neutral': 0, 'Negative': 0}
    for feedback in exit_feedbacks:
        if feedback.sentiment:
            sentiment_counts[feedback.sentiment] = sentiment_counts.get(feedback.sentiment, 0) + 1
        else:
            sentiment_counts['Neutral'] += 1
    
    # Calculate employee feedback averages
    employee_feedbacks = EmployeeFeedback.query.filter(
        EmployeeFeedback.created_at >= datetime.utcnow() - timedelta(days=30)
    ).all()
    
    avg_mood = sum(f.mood_rating for f in employee_feedbacks) / len(employee_feedbacks) if employee_feedbacks else 3.5
    avg_confidence = sum(f.confidence_rating for f in employee_feedbacks) / len(employee_feedbacks) if employee_feedbacks else 3.5
    engagement_score = round((avg_mood + avg_confidence) / 2 * 20, 1)  # Convert to percentage
    
    # Get department statistics
    departments = db.session.query(
        User.department, 
        db.func.count(User.id).label('count')
    ).filter(
        User.role == 'employee',
        User.department.isnot(None)
    ).group_by(User.department).all()
    
    # Calculate onboarding progress statistics
    onboarding_checklists = OnboardingChecklist.query.all()
    avg_onboarding_days = 7.2  # Default value
    if onboarding_checklists:
        completed_checklists = [c for c in onboarding_checklists if c.completed_at]
        if completed_checklists:
            total_days = sum((c.completed_at - c.created_at).days for c in completed_checklists)
            avg_onboarding_days = total_days / len(completed_checklists)
    
    return render_template('dashboard.html',
                         user=user,
                         current_user=user,
                         total_employees=total_employees,
                         onboarding_count=onboarding_count,
                         active_count=active_count,
                         interview_results=interview_results,
                         sentiment_data=sentiment_counts,
                         engagement_score=engagement_score,
                         avg_onboarding_days=round(avg_onboarding_days, 1),
                         departments=departments)

# Employee Dashboard
@app.route('/employee/dashboard')
@login_required('employee')
def employee_dashboard():
    # Get the logged-in user
    user = User.query.get(session['user_id'])
    
    # Get HR contact information
    hr_contact = User.query.filter_by(role='hr').first()
    
    # Get onboarding checklist for progress calculation
    onboarding_checklist = OnboardingChecklist.query.filter_by(employee_id=user.id).first()
    onboarding_progress = 20  # Default progress
    if onboarding_checklist:
        onboarding_progress = onboarding_checklist.get_progress()
    
    # Generate employee data based on the logged-in user
    employee_data = {
        'name': user.full_name,
        'username': user.username,
        'email': user.email,
        'phone': user.phone,
        'department': user.department or 'Not specified',
        'position': user.position or 'Employee',
        'hire_date': user.hire_date.strftime('%B %d, %Y') if user.hire_date else 'Not specified',
        'employee_id': user.employee_id or f'EMP-{user.id:04d}',
        'status': user.status or 'Active',
        'manager': 'Sarah Johnson',  # This would come from manager relationship
        'location': 'Main Office',
        'work_schedule': '9:00 AM - 5:00 PM',
        'team_members': [
            {'name': 'John Smith', 'role': 'Senior Developer', 'status': 'online'},
            {'name': 'Emily Chen', 'role': 'Product Designer', 'status': 'busy'},
            {'name': 'Michael Brown', 'role': 'DevOps Engineer', 'status': 'offline'}
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
        ],
        'onboarding_progress': {
            'current_day': 1,
            'total_days': 5,
            'percentage': onboarding_progress,
            'tasks_completed': int(onboarding_progress / 20) if onboarding_progress else 1,
            'total_tasks': 5
        }
    }
    
    # Get employee documents count
    documents_count = EmployeeDocument.query.filter_by(user_id=user.id).count()
    
    return render_template('employee_dashboard.html', 
                         employee=employee_data, 
                         user=user,
                         hr_contact=hr_contact,
                         documents_count=documents_count,
                         onboarding_progress=onboarding_progress,
                         current_user=user,  # For compatibility with existing templates
                         title=f'{user.full_name}\'s Dashboard')

@app.route('/employee/profile', methods=['GET', 'POST'])
@login_required('employee')
def employee_profile():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        try:
            user.phone = request.form.get('phone', user.phone)
            user.department = request.form.get('department', user.department)
            user.position = request.form.get('position', user.position)

            db.session.commit()
            flash('Your profile has been updated successfully.', 'success')
            return redirect(url_for('employee_profile'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error updating employee profile: {str(e)}')
            flash('An error occurred while updating your profile. Please try again.', 'danger')

    return render_template('employee_profile.html', user=user, current_user=user)

# Onboarding Tasks
@app.route('/employee/onboarding-tasks')
@login_required('employee')
def onboarding_tasks():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    checklist = OnboardingChecklist.query.filter_by(employee_id=user.id).first()

    tasks = []
    if checklist:
        tasks = [
            {
                'id': 1,
                'field': 'paperwork_completed',
                'title': 'Complete HR paperwork',
                'category': 'Documentation',
                'due_date': (checklist.created_at + timedelta(days=3)).strftime('%b %d, %Y'),
                'completed': bool(checklist.paperwork_completed),
            },
            {
                'id': 2,
                'field': 'equipment_assigned',
                'title': 'Confirm equipment received',
                'category': 'Documentation',
                'due_date': (checklist.created_at + timedelta(days=5)).strftime('%b %d, %Y'),
                'completed': bool(checklist.equipment_assigned),
            },
            {
                'id': 3,
                'field': 'training_completed',
                'title': 'Complete mandatory training',
                'category': 'Orientation',
                'due_date': (checklist.created_at + timedelta(days=14)).strftime('%b %d, %Y'),
                'completed': bool(checklist.training_completed),
            },
            {
                'id': 4,
                'field': 'hr_orientation',
                'title': 'Attend HR orientation',
                'category': 'Orientation',
                'due_date': (checklist.created_at + timedelta(days=7)).strftime('%b %d, %Y'),
                'completed': bool(checklist.hr_orientation),
            },
            {
                'id': 5,
                'field': 'team_introduction',
                'title': 'Meet your team',
                'category': 'Orientation',
                'due_date': (checklist.created_at + timedelta(days=10)).strftime('%b %d, %Y'),
                'completed': bool(checklist.team_introduction),
            },
        ]

    total_tasks = len(tasks)
    completed_tasks = sum(1 for t in tasks if t['completed'])
    in_progress_tasks = 0
    pending_tasks = total_tasks - completed_tasks
    overdue_tasks = 0

    stats = {
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'in_progress_tasks': in_progress_tasks,
        'pending_tasks': pending_tasks,
        'overdue_tasks': overdue_tasks,
        'completion_percentage': checklist.get_progress() if checklist else 0,
    }

    comments = []

    return render_template(
        'onboarding_tasks.html',
        tasks=tasks,
        stats=stats,
        comments=comments,
        now=datetime.utcnow(),
    )


@app.route('/employee/offboarding-tasks')
@login_required('employee')
def offboarding_tasks():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    status = user.status or 'Active'
    exit_date = user.exit_date

    offboarding = {
        'status': status,
        'exit_date': exit_date,
    }

    return render_template('offboarding_tasks.html', offboarding=offboarding)

@app.route('/pre-onboarding')
@login_required('hr')
def pre_onboarding():
    # Show employees who are currently in the Onboarding stage
    employees = User.query.filter_by(role='employee', status='Onboarding').order_by(User.created_at.desc()).all()
    return render_template('pre-onboarding.html', employees=employees)

@app.route('/hr/start-onboarding', methods=['POST'])
@login_required('hr')
def hr_start_onboarding():
    try:
        employee_id = request.form.get('employee_id')
        hire_date_str = request.form.get('hire_date')

        if not employee_id or not hire_date_str:
            flash('Employee and hire date are required to start onboarding.', 'danger')
            return redirect(url_for('pre_onboarding'))

        employee = User.query.filter_by(id=int(employee_id), role='employee').first_or_404()

        # Parse hire date
        hire_date = datetime.strptime(hire_date_str, '%Y-%m-%d').date()
        employee.hire_date = hire_date

        db.session.commit()

        flash(f'Onboarding started for {employee.full_name} with hire date {hire_date.strftime("%B %d, %Y")}.', 'success')
        # Redirect to onboarding page, passing hire date
        return redirect(url_for('onboarding', employee_id=employee.id, hire_date=hire_date_str))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error starting onboarding: {str(e)}')
        flash('Failed to start onboarding. Please try again.', 'danger')
        return redirect(url_for('pre_onboarding'))

@app.route('/api/candidates', methods=['GET'])
@login_required('hr')
def get_candidates_list():
    """Get list of all candidates for employee selection"""
    try:
        candidates = Candidate.query.order_by(
            Candidate.created_at.desc()).all()

        candidates_list = []
        for candidate in candidates:
            candidates_list.append({
                'id': candidate.id,
                'name': candidate.name,
                'email': candidate.email or 'N/A',
                'job_desc': candidate.job_desc or 'N/A',
                'score': round(float(candidate.score), 1) if (
                    candidate.score) else None,
                'summary': candidate.summary or '',
                'created_at': candidate.created_at.strftime(
                    '%Y-%m-%d')
            })

        return jsonify({
            'status': 'success',
            'data': candidates_list
        })
    except Exception as e:
        app.logger.error(f'Error fetching candidates: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to fetch candidates'}), 500


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
@login_required(['hr', 'employee'])
def interview():
    if request.method == 'POST':
        data = request.get_json()
        
        # Handle training session data
        if data.get('action') == 'save_training':
            training_data = {
                'user_id': session['user_id'],
                'session_type': data.get('type'),
                'difficulty': data.get('difficulty'),
                'responses': data.get('responses', []),
                'score': data.get('score', 0),
                'completed_at': datetime.utcnow()
            }
            
            # In a real app, save to database
            # For now, just return success
            return jsonify({
                'success': True,
                'message': 'Training session saved successfully'
            })
        
        # Handle interview responses (existing functionality)
        candidate_id = data.get('candidate_id')
        responses = data.get('responses', {})
        
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
        
        try:
            # Create new exit feedback entry
            exit_feedback = ExitFeedback(
                name=name,
                reason=reason,
                feedback=feedback
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
    
    # For GET request, get exit feedback data
    if session.get('role') == 'hr':
        # HR can see all exit feedback
        exit_feedbacks = ExitFeedback.query.order_by(ExitFeedback.created_at.desc()).limit(10).all()
    else:
        # Employees can only see their own feedback
        exit_feedbacks = ExitFeedback.query.filter(
            ExitFeedback.name.like(f"%{employee.full_name}%")
        ).order_by(ExitFeedback.created_at.desc()).limit(10).all()
    
    # Get HR contact information
    hr_contact = User.query.filter_by(role='hr').first()
    
    # Render the template with employee data, exit feedbacks, and HR contact
    return render_template('exit.html', employee=employee, exit_feedbacks=exit_feedbacks, hr_contact=hr_contact)

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
    """Render the support page for employees with recent issues from the database."""
    recent_issues = []

    try:
        # Lazily detect a Ticket/Issue-style model if it exists to avoid breaking imports
        TicketModel = None

        for candidate_name in ['Ticket', 'Issue', 'SupportTicket', 'ITIssue']:
            try:
                TicketModel = globals().get(candidate_name)
                if TicketModel is not None:
                    break
            except Exception:
                TicketModel = None

        if TicketModel is not None:
            user_id = session.get('user_id')
            if user_id:
                # Try common field names for user reference and timestamps
                query = TicketModel.query

                if hasattr(TicketModel, 'user_id'):
                    query = query.filter(TicketModel.user_id == user_id)
                elif hasattr(TicketModel, 'employee_id'):
                    query = query.filter(TicketModel.employee_id == user_id)

                # Order by recent update/creation if available
                if hasattr(TicketModel, 'updated_at'):
                    query = query.order_by(TicketModel.updated_at.desc())
                elif hasattr(TicketModel, 'created_at'):
                    query = query.order_by(TicketModel.created_at.desc())

                recent_issues = query.limit(5).all()
    except Exception as e:
        app.logger.error(f"Error loading recent issues for support page: {str(e)}")
        recent_issues = []

    return render_template('support.html', title='Support', recent_issues=recent_issues)

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

def calculate_ats_score(resume_data, job_description):
    """
    Calculate ATS (Applicant Tracking System) score based on resume
    and job description match.
    Score is out of 100.
    """
    score = 0
    feedback = []

    # Normalize text for comparison
    resume_text = ' '.join(resume_data.get('skills', [])).lower()

    # 1. Skills Match (35 points max)
    resume_skills = set([s.lower() for s in resume_data.get('skills', [])])
    job_skills = extract_skills(job_description)
    job_skills_set = set([s.lower() for s in job_skills])

    if job_skills_set:
        matched_skills = resume_skills.intersection(job_skills_set)
        skill_match_percentage = len(matched_skills) / len(job_skills_set)
        skills_score = skill_match_percentage * 35
        score += skills_score

        if matched_skills:
            matched_list = list(matched_skills)[:3]
            feedback.append(
                f"Matched {len(matched_skills)}/{len(job_skills_set)} "
                f"required skills: {', '.join(matched_list)}"
            )
        else:
            required_skills = list(job_skills_set)[:3]
            feedback.append(
                f"No matching skills found. Required: "
                f"{', '.join(required_skills)}"
            )

    # 2. Experience (30 points max)
    experience_count = len(resume_data.get('experience', []))
    if experience_count >= 4:
        score += 30
        feedback.append("Strong experience level (4+ years)")
    elif experience_count >= 2:
        score += 20
        feedback.append("Moderate experience level (2-4 years)")
    elif experience_count >= 1:
        score += 10
        feedback.append("Entry-level experience")

    # 3. Education (20 points max)
    education = resume_data.get('education', [])
    education_text = ' '.join([str(e) for e in education]).lower()

    has_bachelor = ('bachelor' in education_text or
                    'b.tech' in education_text or
                    'b.s.' in education_text)
    has_master = ('master' in education_text or
                  'm.tech' in education_text or
                  'diploma' in education_text)

    if has_bachelor:
        score += 15
        feedback.append("Bachelor's degree found")
    elif has_master:
        score += 20
        feedback.append("Advanced degree found")
    elif education:
        score += 10
        feedback.append("Education information provided")

    # 4. Contact Information (10 points max)
    contact_score = 0
    if resume_data.get('email'):
        contact_score += 5
    if resume_data.get('phone'):
        contact_score += 5
    score += contact_score

    if contact_score >= 10:
        feedback.append("Complete contact information provided")

    # 5. Keyword Presence (5 points max)
    keywords = ['python', 'javascript', 'api', 'database', 'agile', 'git']
    found_keywords = sum(1 for kw in keywords if kw in resume_text)
    keyword_score = (found_keywords / len(keywords)) * 5
    score += keyword_score

    # Normalize score to 0-100
    final_score = min(100, max(0, score))

    return {
        'score': round(final_score, 1),
        'feedback': feedback,
        'recommendation': 'PASS' if final_score >= 70 else 'REVIEW'
    }


@app.route('/analyze-resume', methods=['POST'])
def analyze_resume():
    if 'resume' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['resume']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Get job description from request
    job_description = request.form.get('jobDescription', '')

    if not job_description:
        return jsonify({'error': 'Job description is required'}), 400

    try:
        filename = file.filename.lower()
        file_stream = file.stream

        if filename.endswith('.pdf'):
            text = extract_text_from_pdf(file_stream)
        elif filename.endswith(('.doc', '.docx')):
            text = extract_text_from_docx(file_stream)
        else:
            error_msg = (
                'Unsupported file format. Please upload a PDF or '
                'Word document.'
            )
            return jsonify({'error': error_msg}), 400

        # Extract information
        resume_data = {
            'name': extract_name(text),
            'email': extract_email(text),
            'phone': '',
            'skills': extract_skills(text),
            'experience': extract_experience(text),
            'education': extract_education(text),
            'raw_text': text
        }

        # Calculate ATS score
        ats_result = calculate_ats_score(resume_data, job_description)

        # Prepare AI summary using the AI response function
        summary_prompt = (
            f"Provide a brief (2-3 sentences) summary of how well this "
            f"candidate matches the job description. Skills found: "
            f"{', '.join(resume_data['skills'][:5])}. "
            f"Experience count: {len(resume_data['experience'])}. "
            f"Focus on strengths relevant to: {job_description[:200]}"
        )

        ai_summary = "Resume analyzed. Candidate profile processed."
        try:
            ai_messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an HR AI assistant. Provide brief, "
                        "professional summaries."
                    )
                },
                {"role": "user", "content": summary_prompt}
            ]
            ai_response = generate_ai_response(
                ai_messages, max_tokens=150, temperature=0.7)
            if ai_response:
                ai_summary = ai_response
        except Exception as e:
            app.logger.warning(f"Could not generate AI summary: {str(e)}")
            ai_summary = (
                f"Candidate has {len(resume_data['skills'])} relevant skills "
                f"and {len(resume_data['experience'])} years of experience."
            )

        result = {
            'name': resume_data['name'],
            'email': resume_data['email'],
            'phone': resume_data['phone'],
            'skills': resume_data['skills'],
            'experience': resume_data['experience'],
            'education': resume_data['education'],
            'ats_score': ats_result['score'],
            'ats_feedback': ats_result['feedback'],
            'ats_recommendation': ats_result['recommendation'],
            'ai_summary': ai_summary,
            'pass_screening': ats_result['score'] >= 70
        }

        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error processing resume: {str(e)}")
        return jsonify(
            {'error': 'Error processing resume. Please try again.'}), 500

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


@app.route('/api/ai/generate-question', methods=['POST'])
@login_required(['hr', 'employee'])
def generate_ai_question():
    """Generate AI-powered interview question using Gemini"""
    try:
        data = request.get_json()
        training_type = data.get('type', 'interview')
        difficulty = data.get('difficulty', 'beginner')
        question_index = data.get('questionIndex', 0)
        previous_responses = data.get('previousResponses', [])
        
        # Create context for Gemini
        context = f"You are an AI interview trainer conducting a {difficulty} level {training_type} training session."
        
        if previous_responses:
            context += f" Previous responses show the candidate has answered {len(previous_responses)} questions."
        
        prompt = f"{context} Generate question {question_index + 1} that is appropriate for {training_type} skills at {difficulty} level. Make it engaging and relevant. Return only the question."
        
        # Generate question using Gemini
        ai_question = generate_ai_response([{"role": "user", "content": prompt}], max_tokens=100)
        
        return jsonify({
            'success': True,
            'question': ai_question
        })
        
    except Exception as e:
        app.logger.error(f'Error generating AI question: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Failed to generate question'
        }), 500

@app.route('/api/ai/generate-feedback', methods=['POST'])
@login_required(['hr', 'employee'])
def generate_ai_feedback():
    """Generate AI feedback for training responses using Gemini"""
    try:
        data = request.get_json()
        response_text = data.get('response', '')
        question = data.get('question', '')
        training_type = data.get('type', 'interview')
        difficulty = data.get('difficulty', 'beginner')
        
        # Create feedback prompt for Gemini
        prompt = f"""As an expert interview coach, analyze this {training_type} response at {difficulty} level:
        
Question: {question}
Response: {response_text}
        
Provide constructive feedback in 2-3 sentences focusing on:
1. What they did well
2. One specific improvement suggestion
3. Encouragement for next question
        
Keep it supportive and actionable."""
        
        # Generate feedback using Gemini
        ai_feedback = generate_ai_response([{"role": "user", "content": prompt}], max_tokens=150)
        
        return jsonify({
            'success': True,
            'feedback': ai_feedback
        })
        
    except Exception as e:
        app.logger.error(f'Error generating AI feedback: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Failed to generate feedback'
        }), 500

@app.route('/api/training/generate-feedback', methods=['POST'])
@login_required(['hr', 'employee'])
def generate_training_feedback():
    """Generate AI feedback for training responses"""
    try:
        data = request.get_json()
        response_text = data.get('response', '')
        question_type = data.get('type', 'general')
        
        # Generate contextual feedback based on response
        feedback = analyze_training_response(response_text, question_type)
        
        return jsonify({
            'success': True,
            'feedback': feedback
        })
        
    except Exception as e:
        app.logger.error(f'Error generating training feedback: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Failed to generate feedback'
        }), 500

def analyze_training_response(response, question_type):
    """Analyze training response and provide feedback"""
    word_count = len(response.split())
    has_examples = 'example' in response.lower() or 'instance' in response.lower()
    
    feedback = {
        'score': 0,
        'strengths': [],
        'improvements': [],
        'overall': ''
    }
    
    # Analyze word count
    if word_count >= 30:
        feedback['score'] += 25
        feedback['strengths'].append('Good response length')
    else:
        feedback['improvements'].append('Provide more detailed responses')
    
    # Check for examples
    if has_examples:
        feedback['score'] += 25
        feedback['strengths'].append('Included specific examples')
    else:
        feedback['improvements'].append('Add concrete examples to strengthen your answer')
    
    # Check structure
    sentences = response.split('.')
    if len(sentences) >= 3:
        feedback['score'] += 25
        feedback['strengths'].append('Well-structured response')
    else:
        feedback['improvements'].append('Organize your thoughts more clearly')
    
    # Question-specific analysis
    if question_type == 'behavioral':
        if 'situation' in response.lower() and 'action' in response.lower():
            feedback['score'] += 25
            feedback['strengths'].append('Used STAR method effectively')
        else:
            feedback['improvements'].append('Consider using the STAR method (Situation, Task, Action, Result)')
    else:
        feedback['score'] += 15  # Base score for other types
    
    # Generate overall feedback
    if feedback['score'] >= 80:
        feedback['overall'] = 'Excellent response! You demonstrated strong communication skills.'
    elif feedback['score'] >= 60:
        feedback['overall'] = 'Good response with room for improvement.'
    else:
        feedback['overall'] = 'Keep practicing! Focus on the suggested improvements.'
    
    return feedback

@app.route('/api/ai/generate-summary', methods=['POST'])
@login_required(['hr', 'employee'])
def generate_ai_summary():
    """Generate comprehensive HR interview summary using Gemini"""
    try:
        data = request.get_json()
        session_data = data.get('session', {})
        responses = data.get('responses', [])
        candidate_name = session_data.get('candidateName', 'Candidate')
        role = session_data.get('roleHiring', 'Position')
        
        # Create comprehensive analysis prompt
        responses_text = "\n".join([f"Q: {r.get('question', '')}\nA: {r.get('answer', '')}" for r in responses if not r.get('skipped')])
        
        prompt = f"""Generate a comprehensive HR interview summary for {candidate_name} applying for {role}:

{responses_text}

Provide detailed analysis in this format:

**EXECUTIVE SUMMARY**
- Overall Rating (1-10):
- Fit for Role:
- Hire Recommendation:

**SKILLS ANALYSIS** (Score 0-10 each)
- Technical Skills:
- Communication:
- Problem Solving:
- Leadership:
- Cultural Fit:

**TONE & MANNERISM**
- Confidence Level:
- Communication Style:
- Response Quality:

**ANSWER BREAKDOWN**
[For each major question, provide: Question, Summary, Score, Red flags/Highlights]

**RECOMMENDED ACTION**
[Proceed to next round/Hold/Reject/Skill test/HR round]

Be specific and professional."""
        
        # Generate comprehensive summary
        ai_summary = generate_ai_response([{"role": "user", "content": prompt}], max_tokens=800)
        
        return jsonify({
            'success': True,
            'summary': ai_summary,
            'candidate': candidate_name,
            'role': role
        })
        
    except Exception as e:
        app.logger.error(f'Error generating AI summary: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Failed to generate summary'
        }), 500

@app.route('/api/ai/analyze-response', methods=['POST'])
@login_required(['hr', 'employee'])
def analyze_response_realtime():
    """Real-time response analysis during interview"""
    try:
        data = request.get_json()
        response_text = data.get('response', '')
        question = data.get('question', '')
        
        # Analyze response characteristics
        word_count = len(response_text.split())
        hesitation_words = ['um', 'uh', 'like', 'you know', 'actually']
        hesitation_count = sum(response_text.lower().count(word) for word in hesitation_words)
        
        # AI analysis prompt
        prompt = f"""Analyze this interview response for:
1. Confidence (Low/Medium/High)
2. Clarity (Poor/Good/Excellent)
3. Relevance (Off-topic/Partial/Relevant)
4. Technical accuracy (if applicable)
5. Communication style

Question: {question}
Response: {response_text}

Provide brief analysis in JSON format with scores."""
        
        ai_analysis = generate_ai_response([{"role": "user", "content": prompt}], max_tokens=200)
        
        return jsonify({
            'success': True,
            'analysis': {
                'word_count': word_count,
                'hesitation_count': hesitation_count,
                'ai_feedback': ai_analysis
            }
        })
        
    except Exception as e:
        app.logger.error(f'Error analyzing response: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Failed to analyze response'
        }), 500

@app.route('/api/ai/send-interview-summary', methods=['POST'])
@login_required('hr')
def send_interview_summary():
    """Send interview summary to HR email and dashboard"""
    try:
        data = request.get_json()
        summary = data.get('summary', '')
        candidate_name = data.get('candidate', '')
        role = data.get('role', '')
        hr_email = session.get('email', 'hr@company.com')
        
        # Save to database (Interview model)
        interview_record = Interview(
            candidate_id=None,  # Link to candidate if exists
            responses={'summary': summary, 'candidate': candidate_name, 'role': role},
            summary=summary,
            created_at=datetime.utcnow()
        )
        db.session.add(interview_record)
        db.session.commit()
        
        # Generate email content
        email_subject = f"Interview Summary - {candidate_name} for {role}"
        email_body = f"""Interview Summary Report
        
Candidate: {candidate_name}
Position: {role}
Interview Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}
        
{summary}
        
This summary has been automatically generated and saved to your HR dashboard.
        
Best regards,
SmartHire AI System"""
        
        # In production, integrate with email service (SendGrid, AWS SES, etc.)
        # For now, log the email
        app.logger.info(f"Interview summary email sent to {hr_email}")
        
        return jsonify({
            'success': True,
            'message': 'Interview summary sent and saved',
            'interview_id': interview_record.id
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error sending interview summary: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'Failed to send summary'
        }), 500

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
        data = request.get_json(silent=True) or {}

        # Safely coerce ratings to integers
        try:
            mood_rating_raw = data.get('mood_rating')
            confidence_rating_raw = data.get('confidence_rating')

            mood_rating = int(mood_rating_raw) if mood_rating_raw is not None else None
            confidence_rating = int(confidence_rating_raw) if confidence_rating_raw is not None else None
        except (TypeError, ValueError):
            app.logger.warning(f"Invalid rating types in feedback payload: {data}")
            return jsonify({'status': 'error', 'message': 'Ratings must be numbers between 1 and 5'}), 400

        feedback = data.get('feedback', '') or ''

        # Validate presence
        if mood_rating is None or confidence_rating is None:
            return jsonify({'status': 'error', 'message': 'Both mood and confidence ratings are required'}), 400

        # Validate range (1-5)
        if not (1 <= mood_rating <= 5) or not (1 <= confidence_rating <= 5):
            return jsonify({'status': 'error', 'message': 'Ratings must be between 1 and 5'}), 400

        user_id = session.get('user_id')
        if not user_id:
            app.logger.warning('Feedback submit attempted without user in session')
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

        # Create new feedback entry
        new_feedback = EmployeeFeedback(
            user_id=user_id,
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
        db.session.rollback()
        app.logger.error(f"Error submitting feedback: {str(e)}", exc_info=True)
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


# ============ EMPLOYEE PROFILE, DOCUMENTS & SETTINGS ENDPOINTS ============

@app.route('/api/employee/profile', methods=['GET'])
@login_required('employee')
def get_employee_profile():
    """Get employee profile data"""
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'status': 'error',
                           'message': 'User not found'}), 404
        
        return jsonify({
            'status': 'success',
            'data': {
                'full_name': user.full_name,
                'email': user.email,
                'phone': user.phone or '',
                'department': user.department or '',
                'position': user.position or '',
                'employee_id': user.employee_id or f'EMP-{user.id:04d}',
                'hire_date': (
                    user.hire_date.strftime('%Y-%m-%d')
                    if user.hire_date else ''),
                'status': user.status or 'Active'
            }
        })
    except Exception as e:
        app.logger.error(f'Error fetching profile: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to fetch profile'}), 500


@app.route('/api/employee/profile', methods=['POST'])
@login_required('employee')
def update_employee_profile():
    """Update employee profile"""
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'status': 'error',
                           'message': 'User not found'}), 404
        
        # Update user profile
        user.phone = request.form.get('phone', user.phone)
        user.department = request.form.get(
            'department', user.department)
        user.position = request.form.get('position', user.position)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Profile updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating profile: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to update profile'}), 500


@app.route('/api/employee/documents', methods=['GET'])
@login_required('employee')
def get_employee_documents():
    """Get list of employee documents"""
    try:
        documents = EmployeeDocument.query.filter_by(
            user_id=session['user_id']
        ).order_by(EmployeeDocument.upload_date.desc()).all()
        
        docs_list = []
        for doc in documents:
            docs_list.append({
                'id': doc.id,
                'file_name': doc.file_name,
                'document_type': doc.document_type or 'Other',
                'upload_date': doc.upload_date.strftime('%Y-%m-%d %H:%M'),
                'file_size': doc.file_size,
                'description': doc.description or '',
                'is_verified': doc.is_verified
            })
        
        return jsonify({
            'status': 'success',
            'data': docs_list
        })
    except Exception as e:
        app.logger.error(f'Error fetching documents: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to fetch documents'}), 500


@app.route('/api/employee/documents/upload', methods=['POST'])
@login_required('employee')
def upload_employee_document():
    """Upload employee document"""
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error',
                           'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error',
                           'message': 'No file selected'}), 400
        
        # Allowed file extensions
        allowed_extensions = {
            'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'txt', 'xlsx'
        }
        
        if not ('.' in file.filename and
                file.filename.rsplit('.', 1)[1].lower()
                in allowed_extensions):
            return jsonify({
                'status': 'error',
                'message': 'File type not allowed'
            }), 400
        
        # Check file size (max 10MB)
        file_size = len(file.read())
        file.seek(0)
        if file_size > 10 * 1024 * 1024:
            return jsonify({
                'status': 'error',
                'message': 'File size exceeds 10MB limit'
            }), 400
        
        # Create documents directory if it doesn't exist
        doc_dir = os.path.join(app.root_path, 'uploads', 'documents')
        os.makedirs(doc_dir, exist_ok=True)
        
        # Generate unique filename
        user_id = session['user_id']
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{user_id}_{timestamp}_{file.filename}"
        file_path = os.path.join(doc_dir, filename)
        
        # Save file
        file.save(file_path)
        
        # Create database entry
        document = EmployeeDocument(
            user_id=user_id,
            file_name=file.filename,
            file_path=f"/uploads/documents/{filename}",
            document_type=request.form.get(
                'document_type', 'Other'),
            file_size=file_size,
            description=request.form.get('description', ''),
            is_verified=False
        )
        
        db.session.add(document)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Document uploaded successfully',
            'data': {
                'id': document.id,
                'file_name': document.file_name,
                'upload_date': document.upload_date.strftime(
                    '%Y-%m-%d %H:%M')
            }
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error uploading document: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to upload document'}), 500


@app.route('/api/employee/documents/<int:doc_id>', methods=['DELETE'])
@login_required('employee')
def delete_employee_document(doc_id):
    """Delete employee document"""
    try:
        document = EmployeeDocument.query.get_or_404(doc_id)
        
        # Verify ownership
        if document.user_id != session['user_id']:
            return jsonify({'status': 'error',
                           'message': 'Unauthorized'}), 403
        
        # Delete file
        file_path = os.path.join(
            app.root_path, 'uploads', 'documents',
            os.path.basename(document.file_path))
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database entry
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Document deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting document: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to delete document'}), 500


@app.route('/api/employee/settings', methods=['GET'])
@login_required('employee')
def get_employee_settings():
    """Get employee settings"""
    try:
        settings = EmployeeSettings.query.filter_by(
            user_id=session['user_id']
        ).first()
        
        if not settings:
            # Create default settings if not exists
            settings = EmployeeSettings(user_id=session['user_id'])
            db.session.add(settings)
            db.session.commit()
        
        return jsonify({
            'status': 'success',
            'data': {
                'email_notifications': settings.email_notifications,
                'sms_notifications': settings.sms_notifications,
                'notification_frequency': (
                    settings.notification_frequency),
                'theme': settings.theme,
                'language': settings.language,
                'two_factor_enabled': settings.two_factor_enabled
            }
        })
    except Exception as e:
        app.logger.error(f'Error fetching settings: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to fetch settings'}), 500


@app.route('/api/employee/settings', methods=['POST'])
@login_required('employee')
def update_employee_settings():
    """Update employee settings"""
    try:
        settings = EmployeeSettings.query.filter_by(
            user_id=session['user_id']
        ).first()
        
        if not settings:
            settings = EmployeeSettings(user_id=session['user_id'])
            db.session.add(settings)
        
        # Update settings
        settings.email_notifications = request.form.get(
            'email_notifications', 'false').lower() == 'true'
        settings.sms_notifications = request.form.get(
            'sms_notifications', 'false').lower() == 'true'
        settings.notification_frequency = request.form.get(
            'notification_frequency', 'immediately')
        settings.theme = request.form.get('theme', 'light')
        settings.language = request.form.get('language', 'en')
        settings.two_factor_enabled = request.form.get(
            'two_factor_enabled', 'false').lower() == 'true'
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Settings updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating settings: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to update settings'}), 500


@app.route('/api/employee/change-password', methods=['POST'])
@login_required('employee')
def change_employee_password():
    """Change employee password"""
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'status': 'error',
                           'message': 'User not found'}), 404
        
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate current password
        if not user.check_password(current_password):
            return jsonify({'status': 'error',
                           'message': 'Current password is incorrect'}), 401
        
        # Validate new password
        if len(new_password) < 8:
            return jsonify({
                'status': 'error',
                'message': 'Password must be at least 8 characters'
            }), 400
        
        # Validate passwords match
        if new_password != confirm_password:
            return jsonify({'status': 'error',
                           'message': 'Passwords do not match'}), 400
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Password changed successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error changing password: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to change password'}), 500

@app.route('/api/onboarding/tasks/<int:task_id>', methods=['DELETE'])
@login_required('hr')
def delete_onboarding_task(task_id):
    """Delete an onboarding task"""
    try:
        task = OnboardingTask.query.get_or_404(task_id)
        checklist = task.checklist
        
        # Ensure at least one task remains
        if len(checklist.tasks) <= 1:
            return jsonify({
                'status': 'error',
                'message': 'Cannot delete the last remaining task'
            }), 400
        
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Task deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting task: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete task'
        }), 500

@app.route('/api/onboarding/checklist/<int:checklist_id>/tasks', methods=['PUT'])
@login_required('hr')
def update_onboarding_tasks(checklist_id):
    """Update onboarding tasks for a checklist"""
    try:
        checklist = OnboardingChecklist.query.get_or_404(checklist_id)
        data = request.get_json()
        
        # Delete existing tasks
        OnboardingTask.query.filter_by(checklist_id=checklist_id).delete()
        
        # Add updated tasks
        for i, task_data in enumerate(data.get('tasks', [])):
            if task_data.get('name', '').strip():
                task = OnboardingTask(
                    checklist_id=checklist_id,
                    task_name=task_data['name'].strip(),
                    task_description=task_data.get('description', '').strip(),
                    order_index=i,
                    is_completed=task_data.get('completed', False)
                )
                db.session.add(task)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Tasks updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating tasks: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to update tasks'
        }), 500


@app.route('/uploads/documents/<path:filename>')
@login_required('employee')
def download_document(filename):
    """Download document (with access control)"""
    try:
        # Verify the user has access to this document
        document = EmployeeDocument.query.filter_by(
            file_path=f"/uploads/documents/{filename}"
        ).first()
        
        if not document:
            return jsonify({'status': 'error',
                           'message': 'Document not found'}), 404
        
        if document.user_id != session['user_id']:
            return jsonify({'status': 'error',
                           'message': 'Access denied'}), 403
        
        doc_dir = os.path.join(
            app.root_path, 'uploads', 'documents')
        return send_from_directory(doc_dir, filename)
    except Exception as e:
        app.logger.error(f'Error downloading document: {str(e)}')
        return jsonify({'status': 'error',
                       'message': 'Failed to download document'}), 500


if __name__ == '__main__':
    app.run(debug=True)
