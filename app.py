import os
import json
import logging
import random
import re
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from functools import wraps
from io import BytesIO
from pathlib import Path
from datetime import datetime, timedelta
from sqlalchemy import orm

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
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

# Encryption helper functions
def get_encryption_key():
    """Generate or retrieve encryption key for storing passwords"""
    # Use app secret key as base for encryption
    app_secret = app.config.get('SECRET_KEY', 'default-secret-key').encode()
    salt = b'smarthire_salt'  # Fixed salt for consistency
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(app_secret))
    return key

def encrypt_password(password):
    """Encrypt password for storage"""
    key = get_encryption_key()
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password):
    """Decrypt stored password"""
    if not encrypted_password:
        return None
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted_password = f.decrypt(encrypted_data).decode()
        return decrypted_password
    except Exception:
        return None

def get_device_info():
    """Get device/browser info for remembered credentials"""
    user_agent = request.headers.get('User-Agent', '')
    # Simple device fingerprint
    return user_agent[:100] if user_agent else 'Unknown'

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
    
    # Password reset fields
    reset_token = db.Column(db.String(255), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    
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
    
    def generate_reset_token(self, expires_in=3600):
        import secrets
        token = secrets.token_urlsafe(32)
        self.reset_token = token
        self.reset_token_expires = datetime.utcnow() + timedelta(seconds=expires_in)
        return token
    
    def verify_reset_token(self, token):
        if self.reset_token != token:
            return False
        if datetime.utcnow() > self.reset_token_expires:
            return False
        return True
    
    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expires = None


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

class RememberedCredential(db.Model):
    """Store remembered login credentials for users"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)  # Store username/email for easy lookup
    encrypted_password = db.Column(db.String(255), nullable=True)  # Store encrypted password
    device_info = db.Column(db.String(255), nullable=True)  # Store device/browser info
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # When to expire the remembered credentials
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('remembered_credentials', lazy=True))

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
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('settings', uselist=False))


class Task(db.Model):
    """General tasks table for various task types"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    task_type = db.Column(db.String(50), nullable=False)  # onboarding, offboarding, general
    status = db.Column(db.String(50), default='pending')  # pending, in_progress, completed, overdue
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, urgent
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    department = db.Column(db.String(50))
    due_date = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tasks')
    assigner = db.relationship('User', foreign_keys=[assigned_by], backref='created_tasks')


class AccessRecord(db.Model):
    """Track system access and login records"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_type = db.Column(db.String(50), nullable=False)  # login, logout, file_access, system_access
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.Text)
    resource_accessed = db.Column(db.String(200))  # What was accessed
    action = db.Column(db.String(100))  # CREATE, READ, UPDATE, DELETE
    success = db.Column(db.Boolean, default=True)
    failure_reason = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    session_id = db.Column(db.String(255))
    
    # Access management fields
    resource_name = db.Column(db.String(200))  # Name of the resource
    resource_description = db.Column(db.Text)  # Description of the resource
    status = db.Column(db.String(20), default='active')  # active, revoked, expired
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)  # When access was granted
    expires_at = db.Column(db.DateTime)  # When access expires
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who granted the access
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='access_records')
    granted_by_user = db.relationship('User', foreign_keys=[granted_by], backref='granted_access_records')


class Message(db.Model):
    """Internal messaging system"""
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_type = db.Column(db.String(50), default='message')  # message, notification, reminder
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, urgent
    status = db.Column(db.String(50), default='unread')  # unread, read, archived
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)
    parent_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)  # For replies
    notification_data = db.Column(db.JSON, nullable=True)  # Additional notification metadata
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')
    replies = db.relationship('Message', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')


# Make timedelta and datetime available in templates
@app.context_processor
def inject_datetime():
    return {
        'timedelta': timedelta,
        'now': datetime.utcnow
    }

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

@app.route('/api/remembered-credentials')
def get_remembered_credentials():
    """Get remembered credentials for the current device"""
    try:
        device_info = get_device_info()
        
        # Find active remembered credentials for this device
        credentials = RememberedCredential.query.filter_by(
            device_info=device_info,
            is_active=True
        ).filter(
            RememberedCredential.expires_at > datetime.utcnow()
        ).all()
        
        remembered_accounts = []
        for cred in credentials:
            user = User.query.get(cred.user_id)
            if user and user.is_active:
                remembered_accounts.append({
                    'id': cred.id,
                    'username': cred.username,
                    'full_name': user.full_name,
                    'role': user.role,
                    'department': user.department,
                    'has_password': bool(cred.encrypted_password),
                    'last_used': cred.last_used.isoformat() if cred.last_used else None
                })
        
        return jsonify({
            'status': 'success',
            'remembered_accounts': remembered_accounts
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/remembered-credentials/<int:credential_id>/login', methods=['POST'])
def login_with_remembered_credentials(credential_id):
    """Login using remembered credentials"""
    try:
        credential = RememberedCredential.query.get_or_404(credential_id)
        
        # Verify device matches
        if credential.device_info != get_device_info():
            return jsonify({
                'status': 'error',
                'message': 'Invalid device'
            }), 403
        
        # Check if credential is still valid
        if not credential.is_active or credential.expires_at < datetime.utcnow():
            return jsonify({
                'status': 'error',
                'message': 'Credentials expired'
            }), 400
        
        # Decrypt password
        password = decrypt_password(credential.encrypted_password)
        if not password:
            return jsonify({
                'status': 'error',
                'message': 'Could not decrypt password'
            }), 500
        
        # Get user
        user = User.query.get(credential.user_id)
        if not user or not user.is_active:
            return jsonify({
                'status': 'error',
                'message': 'User not found or inactive'
            }), 404
        
        # Verify password
        if not user.check_password(password):
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
        
        # Update last used
        credential.last_used = datetime.utcnow()
        db.session.commit()
        
        # Set session
        session['user_id'] = user.id
        session['role'] = user.role
        session.permanent = True
        session['username'] = user.full_name
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'redirect_url': url_for('hr_dashboard') if user.role == 'hr' else url_for('employee_dashboard')
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/remembered-credentials/<int:credential_id>', methods=['DELETE'])
def delete_remembered_credentials(credential_id):
    """Delete remembered credentials"""
    try:
        credential = RememberedCredential.query.get_or_404(credential_id)
        
        # Verify device matches
        if credential.device_info != get_device_info():
            return jsonify({
                'status': 'error',
                'message': 'Invalid device'
            }), 403
        
        db.session.delete(credential)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Credentials removed successfully'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

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
                flash('Please enter both username/email and password', 'danger')
                return redirect(url_for('login', role=role))
            
            try:
                # Check if input is email or username
                if '@' in username:
                    # Login with email
                    user = User.query.filter(
                        db.func.lower(User.email) == username.lower(),
                        User.role == role,
                        User.is_active == True
                    ).first()
                else:
                    # Login with username
                    user = User.query.filter(
                        db.func.lower(User.username) == username.lower(),
                        User.role == role,
                        User.is_active == True
                    ).first()
                
                # Check if user exists and password is correct
                if not user or not user.check_password(password):
                    app.logger.warning(f'Failed login attempt for: {username}')
                    flash('Invalid username/email or password', 'danger')
                    return redirect(url_for('login', role=role))
                
                # Handle remember me functionality
                if remember:
                    # Check if credentials already exist for this device
                    device_info = get_device_info()
                    existing_credential = RememberedCredential.query.filter_by(
                        user_id=user.id,
                        device_info=device_info,
                        is_active=True
                    ).first()
                    
                    if existing_credential:
                        # Update existing credential
                        existing_credential.encrypted_password = encrypt_password(password)
                        existing_credential.last_used = datetime.utcnow()
                        existing_credential.expires_at = datetime.utcnow() + timedelta(days=30)
                    else:
                        # Create new remembered credential
                        credential = RememberedCredential(
                            user_id=user.id,
                            username=username,
                            encrypted_password=encrypt_password(password),
                            device_info=device_info,
                            expires_at=datetime.utcnow() + timedelta(days=30)
                        )
                        db.session.add(credential)
                    
                    db.session.commit()
                    app.logger.info(f'Remembered credentials saved for user: {user.username}')
                else:
                    # Clean up any existing remembered credentials for this device if user unchecked remember me
                    device_info = get_device_info()
                    RememberedCredential.query.filter_by(
                        user_id=user.id,
                        device_info=device_info
                    ).delete()
                    db.session.commit()
                
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

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            role = request.form.get('role')
            
            if not email or not role:
                flash('Please provide both email and account type', 'danger')
                return redirect(url_for('forgot_password'))
            
            # Validate role
            valid_roles = ['hr', 'employee', 'candidate']
            if role not in valid_roles:
                flash('Invalid account type selected', 'danger')
                return redirect(url_for('forgot_password'))
            
            try:
                # Find user by email and role
                user = User.query.filter(
                    db.func.lower(User.email) == email.lower(),
                    User.role == role,
                    User.is_active == True
                ).first()
                
                if user:
                    # Generate reset token
                    reset_token = user.generate_reset_token()
                    db.session.commit()
                    
                    # In a real application, you would send an email with the reset link
                    # For now, we'll redirect directly to the reset page with the token
                    app.logger.info(f'Password reset token generated for user: {user.username} ({user.email})')
                    flash(f'Password reset link generated. You will be redirected to reset your password.', 'success')
                    return redirect(url_for('reset_password', token=reset_token))
                else:
                    # Don't reveal that the user doesn't exist for security
                    flash('If an account with that email exists, you would receive a reset link.', 'info')
                    return redirect(url_for('select_role'))
                
            except Exception as e:
                app.logger.error(f'Error during password reset: {str(e)}')
                flash('An error occurred. Please try again later.', 'danger')
                return redirect(url_for('forgot_password'))
        
        # For GET request, show forgot password form
        return render_template('forgot_password.html')
        
    except Exception as e:
        app.logger.error(f'Unexpected error in forgot_password route: {str(e)}')
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('select_role'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Find user with valid reset token
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.verify_reset_token(token):
            flash('Invalid or expired reset link. Please request a new password reset.', 'danger')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not password or not confirm_password:
                flash('Please provide both password fields', 'danger')
                return redirect(url_for('reset_password', token=token))
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('reset_password', token=token))
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('reset_password', token=token))
            
            try:
                # Update password and clear reset token
                user.set_password(password)
                user.clear_reset_token()
                db.session.commit()
                
                app.logger.info(f'Password reset successfully for user: {user.username}')
                flash('Your password has been reset successfully. You can now login with your new password.', 'success')
                return redirect(url_for('select_role'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error during password reset: {str(e)}')
                flash('An error occurred. Please try again.', 'danger')
                return redirect(url_for('reset_password', token=token))
        
        # For GET request, show reset password form
        return render_template('reset_password.html', token=token)
        
    except Exception as e:
        app.logger.error(f'Unexpected error in reset_password route: {str(e)}')
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
    """Mood Analytics Dashboard"""
    return render_template('mood_analytics_dashboard.html')

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
    
    # Build query - Only show employees, exclude HR users
    query = User.query.filter(User.role == 'employee')
    
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
    
    # Get unique departments for filter dropdown - only from employees, not HR
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
    
    # Get real counts from database - only count employees, not HR
    total_employees = User.query.filter_by(role='employee').count()
    onboarding_count = User.query.filter(User.role == 'employee', User.status == 'Onboarding').count()
    active_count = User.query.filter(User.role == 'employee', User.status == 'Active').count()
    
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
    
    # Get HR contact information - prioritize assigned HR or first available HR
    hr_contact = None
    
    # Try to get assigned HR from onboarding checklist
    onboarding_checklist = OnboardingChecklist.query.filter_by(employee_id=user.id).first()
    if onboarding_checklist and onboarding_checklist.assigned_hr_id:
        hr_contact = User.query.get(onboarding_checklist.assigned_hr_id)
    
    # Fallback to any HR user if no assigned HR found
    if not hr_contact:
        hr_contact = User.query.filter_by(role='hr', is_active=True).first()
    
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
            {'name': hr_contact.full_name if hr_contact else 'HR Department', 
             'role': 'HR Team', 
             'email': hr_contact.email if hr_contact else 'hr@company.com', 
             'phone': hr_contact.phone if hr_contact else '+1 (555) 123-4567'},
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
    
    # Generate employee journey timeline data
    employee_journey = {
        'offer_accepted': {
            'completed': True,
            'date': user.created_at.strftime('%Y-%m-%d') if user.created_at else '2024-01-15'
        },
        'documents_submitted': {
            'completed': documents_count > 0,
            'date': '2024-01-18' if documents_count > 0 else 'Pending'
        },
        'systems_created': {
            'completed': True,
            'date': user.created_at.strftime('%Y-%m-%d') if user.created_at else '2024-01-20'
        },
        'first_day': {
            'completed': user.hire_date and user.hire_date <= datetime.now().date(),
            'date': user.hire_date.strftime('%Y-%m-%d') if user.hire_date else '2024-02-01'
        },
        'orientation': {
            'completed': onboarding_progress >= 50,
            'date': '2024-02-02' if onboarding_progress >= 50 else 'Scheduled'
        },
        'training_modules': {
            'completed': onboarding_progress >= 80,
            'date': '2024-02-15' if onboarding_progress >= 80 else 'In Progress',
            'progress': min(onboarding_progress, 100)
        },
        'confirmation_letter': {
            'completed': False,  # Typically after probation period
            'date': 'Pending'
        }
    }
    
    return render_template('employee_dashboard.html', 
                         employee=employee_data, 
                         user=user,
                         hr_contact=hr_contact,
                         documents_count=documents_count,
                         onboarding_progress=onboarding_progress,
                         employee_journey=employee_journey,
                         current_user=user,  # For compatibility with existing templates
                         title=f'{user.full_name}\'s Dashboard')

@app.route('/hr/tasks')
@login_required('hr')
def tasks_management():
    """Task management page for HR"""
    # Get all tasks with user relationships
    tasks = db.session.query(Task, User).outerjoin(User, Task.assigned_to == User.id).all()
    
    # Format tasks for template
    formatted_tasks = []
    for task, assigned_user in tasks:
        formatted_tasks.append({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'priority': task.priority,
            'status': task.status,
            'task_type': task.task_type,
            'due_date': task.due_date,
            'assigned_to_user': assigned_user
        })
    
    # Get all users for assignment dropdown
    users = User.query.filter(User.role.in_(['hr', 'employee'])).all()
    
    return render_template('tasks.html', 
                         tasks=formatted_tasks, 
                         users=users,
                         current_user=User.query.get(session['user_id']))

@app.route('/hr/access-records')
@login_required('hr')
def access_records_management():
    """Access records management page for HR"""
    # Get all access records with user relationships
    # Create aliases for the User table
    user_alias = orm.aliased(User)
    granted_by_alias = orm.aliased(User)
    
    records = db.session.query(AccessRecord, user_alias, granted_by_alias).outerjoin(
        user_alias, AccessRecord.user_id == user_alias.id
    ).outerjoin(
        granted_by_alias, AccessRecord.granted_by == granted_by_alias.id
    ).all()
    
    # Format records for template
    formatted_records = []
    for record, user, granted_by_user in records:
        formatted_records.append({
            'id': record.id,
            'user': user,
            'resource_name': record.resource_name,
            'resource_description': record.resource_description,
            'access_type': record.access_type,
            'status': record.status,
            'granted_at': record.granted_at,
            'expires_at': record.expires_at,
            'granted_by_user': granted_by_user
        })
    
    # Calculate statistics
    total_records = len(formatted_records)
    active_count = len([r for r in formatted_records if r['status'] == 'active'])
    revoked_count = len([r for r in formatted_records if r['status'] == 'revoked'])
    pending_count = len([r for r in formatted_records if r['status'] == 'pending'])
    
    # Get all users for assignment dropdown
    users = User.query.filter(User.role.in_(['hr', 'employee'])).all()
    
    return render_template('access_records.html', 
                         access_records=formatted_records,
                         total_records=total_records,
                         active_count=active_count,
                         revoked_count=revoked_count,
                         pending_count=pending_count,
                         users=users,
                         current_user=User.query.get(session['user_id']))

@app.route('/hr/messages')
@login_required('hr')
def messages_management():
    """Messages management page for HR"""
    current_user_id = session['user_id']
    
    # Get conversations (unique users with messages)
    conversations = db.session.query(
        Message.recipient_id, Message.sender_id, User
    ).filter(
        (Message.sender_id == current_user_id) | (Message.recipient_id == current_user_id)
    ).outerjoin(
        User, 
        db.or_(
            (Message.sender_id == User.id) & (Message.recipient_id == current_user_id),
            (Message.recipient_id == User.id) & (Message.sender_id == current_user_id)
        )
    ).distinct().all()
    
    # Format conversations
    formatted_conversations = []
    for msg in conversations:
        # Get the other user ID
        other_user_id = msg.recipient_id if msg.sender_id == current_user_id else msg.sender_id
        
        # Get last message
        last_message = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.recipient_id == other_user_id)) |
            ((Message.sender_id == other_user_id) & (Message.recipient_id == current_user_id))
        ).order_by(Message.sent_at.desc()).first()
        
        # Get unread count
        unread_count = Message.query.filter(
            Message.sender_id == other_user_id,
            Message.recipient_id == current_user_id,
            Message.status == 'unread'
        ).count()
        
        formatted_conversations.append({
            'user_id': other_user_id,
            'user': User.query.get(other_user_id),
            'last_message_content': last_message.content if last_message else '',
            'last_message_time': last_message.sent_at if last_message else None,
            'unread_count': unread_count
        })
    
    # Sort by last message time
    formatted_conversations.sort(key=lambda x: x['last_message_time'] or datetime.min, reverse=True)
    
    # Calculate statistics
    total_messages = Message.query.filter(
        (Message.sender_id == current_user_id) | (Message.recipient_id == current_user_id)
    ).count()
    
    unread_count = Message.query.filter(
        Message.recipient_id == current_user_id,
        Message.status == 'unread'
    ).count()
    
    total_conversations = len(formatted_conversations)
    
    today_active = Message.query.filter(
        (Message.sender_id == current_user_id) | (Message.recipient_id == current_user_id),
        Message.sent_at >= datetime.now().date()
    ).count()
    
    # Get all users for messaging
    users = User.query.filter(User.role.in_(['hr', 'employee'])).all()
    
    return render_template('messages.html', 
                         conversations=formatted_conversations,
                         total_messages=total_messages,
                         unread_count=unread_count,
                         total_conversations=total_conversations,
                         today_active=today_active,
                         users=users,
                         current_user=User.query.get(current_user_id))

@app.route('/api/messages', methods=['POST'])
@login_required(['hr', 'employee'])
def create_message():
    """Create a new message"""
    try:
        message = Message(
            sender_id=session['user_id'],
            recipient_id=request.form.get('recipient_id'),
            subject=request.form.get('subject'),
            content=request.form.get('content'),
            is_priority=request.form.get('is_priority') == 'on'
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Message sent successfully',
            'message_id': message.id
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating message: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to send message'
        }), 500

@app.route('/api/messages/conversation/<int:user_id>', methods=['GET'])
@login_required(['hr', 'employee'])
def get_conversation_messages(user_id):
    """Get messages in a conversation with a specific user"""
    try:
        current_user_id = session['user_id']
        
        messages = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.recipient_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.recipient_id == current_user_id))
        ).order_by(Message.sent_at.asc()).all()
        
        message_list = []
        for msg in messages:
            message_list.append({
                'id': msg.id,
                'content': msg.content,
                'subject': msg.subject,
                'sent_at': msg.sent_at.isoformat(),
                'sender_id': msg.sender_id,
                'recipient_id': msg.recipient_id,
                'is_read': msg.status == 'read',
                'is_priority': msg.is_priority
            })
        
        user = User.query.get(user_id)
        
        return jsonify({
            'status': 'success',
            'messages': message_list,
            'user': {
                'id': user.id,
                'full_name': user.full_name,
                'username': user.username,
                'role': user.role
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error getting conversation: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to load conversation'
        }), 500

@app.route('/api/messages/mark-read/<int:user_id>', methods=['PUT'])
@login_required(['hr', 'employee'])
def mark_messages_as_read(user_id):
    """Mark messages from a user as read"""
    try:
        current_user_id = session['user_id']
        
        Message.query.filter(
            Message.sender_id == user_id,
            Message.recipient_id == current_user_id,
            Message.status == 'unread'
        ).update({'status': 'read'})
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Messages marked as read'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error marking messages as read: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to mark messages as read'
        }), 500

@app.route('/api/access-records', methods=['POST'])
@login_required('hr')
def create_access_record():
    """Create a new access record"""
    try:
        record = AccessRecord(
            user_id=request.form.get('user_id'),
            resource_name=request.form.get('resource_name'),
            resource_description=request.form.get('resource_description'),
            access_type=request.form.get('access_type'),
            granted_by=session['user_id'],
            expires_at=datetime.strptime(request.form.get('expires_at'), '%Y-%m-%d').date() if request.form.get('expires_at') else None
        )
        
        db.session.add(record)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Access granted successfully',
            'record_id': record.id
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating access record: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to grant access'
        }), 500

@app.route('/api/access-records/<int:record_id>/revoke', methods=['PUT'])
@login_required('hr')
def revoke_access_record(record_id):
    """Revoke an access record"""
    try:
        record = AccessRecord.query.get_or_404(record_id)
        record.status = 'revoked'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Access revoked successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error revoking access: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to revoke access'
        }), 500

@app.route('/api/access-records/<int:record_id>/grant', methods=['PUT'])
@login_required('hr')
def grant_access_record(record_id):
    """Grant an access record"""
    try:
        record = AccessRecord.query.get_or_404(record_id)
        record.status = 'active'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Access granted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error granting access: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to grant access'
        }), 500

@app.route('/api/access-records/<int:record_id>', methods=['DELETE'])
@login_required('hr')
def delete_access_record(record_id):
    """Delete an access record"""
    try:
        record = AccessRecord.query.get_or_404(record_id)
        db.session.delete(record)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Access record deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting access record: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete access record'
        }), 500

@app.route('/api/tasks', methods=['POST'])
@login_required('hr')
def create_task():
    """Create a new task"""
    try:
        assigned_to = request.form.get('assigned_to')
        current_user = User.query.get(session['user_id'])
        
        # Validate assignment rules
        if assigned_to:
            assigned_user = User.query.get(assigned_to)
            if not assigned_user:
                return jsonify({
                    'status': 'error',
                    'message': 'Assigned user not found'
                }), 400
            
            # Rule 1: Can only assign to employees (not HR)
            if assigned_user.role != 'employee':
                return jsonify({
                    'status': 'error',
                    'message': 'Tasks can only be assigned to employees'
                }), 400
            
            # Rule 2: Must be from different department
            if assigned_user.department == current_user.department:
                return jsonify({
                    'status': 'error',
                    'message': 'Cannot assign tasks to employees from the same department'
                }), 400
            
            # Rule 3: Employee must be under HR's chain of command
            # Check if the HR is in the management chain above this employee
            def is_in_management_chain(hr_user, employee_user):
                """Check if HR is in the management chain above employee"""
                current = employee_user
                while current and current.manager_id:
                    manager = User.query.get(current.manager_id)
                    if manager and manager.id == hr_user.id:
                        return True
                    current = manager
                return False
            
            if not is_in_management_chain(current_user, assigned_user):
                return jsonify({
                    'status': 'error',
                    'message': 'Can only assign tasks to employees under your chain of command'
                }), 400
        
        task = Task(
            title=request.form.get('title'),
            description=request.form.get('description'),
            assigned_to=assigned_to if assigned_to else None,
            assigned_by=session['user_id'],
            task_type=request.form.get('task_type', 'general'),
            priority=request.form.get('priority', 'medium'),
            status=request.form.get('status', 'pending'),
            due_date=datetime.strptime(request.form.get('due_date'), '%Y-%m-%d').date() if request.form.get('due_date') else None
        )
        
        db.session.add(task)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Task created successfully',
            'task_id': task.id
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating task: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create task'
        }), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required('hr')
def delete_task(task_id):
    """Delete a task"""
    try:
        task = Task.query.get_or_404(task_id)
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Task deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting task: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete task'
        }), 500

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

    # Get user's documents
    documents = EmployeeDocument.query.filter_by(user_id=user_id).all()
    
    # Get HR contact
    hr_contact = User.query.filter_by(role='hr', is_active=True).first()
    
    offboarding = {
        'status': user.status or 'Active',
        'exit_date': user.exit_date,
        'documents': documents,
        'hr_contact': hr_contact,
        'user': user
    }

    return render_template('offboarding_tasks.html', offboarding=offboarding)

@app.route('/download-document/<int:doc_id>')
@login_required(['employee', 'hr'])
def download_document(doc_id):
    """Download employee document"""
    try:
        document = EmployeeDocument.query.get_or_404(doc_id)
        
        # Check permissions
        if session.get('role') == 'employee' and document.user_id != session['user_id']:
            flash('You can only download your own documents.', 'danger')
            return redirect(url_for('employee_dashboard'))
        
        # Check if document is approved for download
        if document.status != 'approved':
            flash('Document is not yet available for download.', 'warning')
            return redirect(request.referrer or url_for('employee_dashboard'))
        
        # For demo purposes, return a simple response
        from flask import make_response
        response = make_response(f"Document: {document.file_name}\nType: {document.document_type}\nStatus: {document.status}")
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = f'attachment; filename="{document.file_name}"'
        
        return response
        
    except Exception as e:
        app.logger.error(f'Error downloading document: {str(e)}')
        flash('Error downloading document.', 'danger')
        return redirect(request.referrer or url_for('employee_dashboard'))

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
    # Check if employee_id is provided in URL parameters
    employee_id = request.args.get('employee_id')
    if employee_id:
        # Get employee and their onboarding checklist
        employee = User.query.get_or_404(employee_id)
        checklist = OnboardingChecklist.query.filter_by(employee_id=employee_id).first()
        
        # Create department-specific onboarding tasks if checklist doesn't exist
        if not checklist:
            checklist = OnboardingChecklist(
                employee_id=employee.id,
                assigned_hr_id=session['user_id'],
                status='Pending'
            )
            db.session.add(checklist)
            db.session.flush()
            
            # Create department-specific tasks
            dept_tasks = get_department_tasks(employee.department, employee.position)
            for i, task_data in enumerate(dept_tasks):
                task = OnboardingTask(
                    checklist_id=checklist.id,
                    task_name=task_data['name'],
                    task_description=task_data['description'],
                    order_index=i
                )
                db.session.add(task)
            
            db.session.commit()
        
        # Render onboarding template with employee's specific data
        return render_template('onboarding.html', 
                             selected_employee=employee,
                             checklist=checklist,
                             sample_candidates=[])
    
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

def get_department_tasks(department, position):
    """Get department-specific onboarding tasks"""
    base_tasks = [
        {'name': 'Document Collection', 'description': 'Collect ID proof, address proof, and educational certificates'},
        {'name': 'Welcome Email & Handbook', 'description': 'Send welcome email and employee handbook'},
        {'name': 'ID Card Creation', 'description': 'Create employee ID card and access badge'},
        {'name': 'Email Account Setup', 'description': 'Create company email account and configure access'},
    ]
    
    if department == 'Engineering':
        base_tasks.extend([
            {'name': 'Development Environment Setup', 'description': 'Install development tools, IDEs, and configure development environment'},
            {'name': 'Code Repository Access', 'description': 'Grant access to GitHub/GitLab repositories and development tools'},
            {'name': 'Technical Orientation', 'description': 'Introduction to tech stack, coding standards, and development processes'},
            {'name': 'Laptop & Equipment Assignment', 'description': 'Assign high-spec laptop, monitor, and development peripherals'}
        ])
    elif department == 'Marketing':
        base_tasks.extend([
            {'name': 'Marketing Tools Access', 'description': 'Setup access to marketing automation, CRM, and analytics tools'},
            {'name': 'Brand Guidelines Training', 'description': 'Review brand guidelines, style guide, and marketing materials'},
            {'name': 'Campaign Management Training', 'description': 'Introduction to current campaigns and marketing processes'},
            {'name': 'Creative Assets Access', 'description': 'Grant access to design tools and brand asset libraries'}
        ])
    elif department == 'HR':
        base_tasks.extend([
            {'name': 'HRIS System Training', 'description': 'Training on HR information systems and employee databases'},
            {'name': 'Compliance Training', 'description': 'Employment law, data privacy, and HR compliance training'},
            {'name': 'Recruitment Tools Access', 'description': 'Setup access to ATS, job boards, and recruitment platforms'}
        ])
    else:
        # General department tasks
        base_tasks.extend([
            {'name': 'Department Introduction', 'description': f'Meet with {department} team and understand department goals'},
            {'name': 'Role-Specific Training', 'description': f'Training specific to {position} responsibilities'},
            {'name': 'System Access Setup', 'description': 'Configure access to department-specific systems and tools'}
        ])
    
    # Add common final tasks
    base_tasks.extend([
        {'name': 'Team Introduction Meeting', 'description': 'Schedule meet-and-greet with immediate team members'},
        {'name': 'First Week Check-in', 'description': 'Schedule check-in meeting to address questions and concerns'}
    ])
    
    return base_tasks

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

@app.route('/api/interviews/<int:interview_id>', methods=['GET'])
@login_required('hr')
def get_interview_details(interview_id):
    """Get full details for a specific interview and its candidate for review."""
    try:
        interview = Interview.query.get_or_404(interview_id)
        candidate = interview.candidate

        if not candidate:
            return jsonify({
                'status': 'error',
                'message': 'Candidate not found for this interview'
            }), 404

        score = float(candidate.score) if candidate.score is not None else None

        if score is not None:
            if score >= 7.5:
                recommendation = 'Proceed to Next Round'
            elif score >= 6.0:
                recommendation = 'Hold for Review'
            else:
                recommendation = 'Reject'
        else:
            recommendation = 'Not Scored'

        return jsonify({
            'status': 'success',
            'data': {
                'interview_id': interview.id,
                'created_at': interview.created_at.strftime('%Y-%m-%d %H:%M:%S') if interview.created_at else None,
                'summary': interview.summary,
                'responses': interview.responses or {},
                'candidate': {
                    'id': candidate.id,
                    'name': candidate.name,
                    'job_desc': candidate.job_desc,
                    'resume_text': candidate.resume_text,
                    'score': score,
                    'recommendation': recommendation,
                    'created_at': candidate.created_at.strftime('%Y-%m-%d %H:%M:%S') if candidate.created_at else None
                }
            }
        })
    except Exception as e:
        app.logger.error(f'Error fetching interview details: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch interview details'
        }), 500

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
    
    # Get HR contact information - use current user if HR, otherwise find an HR user
    if session.get('role') == 'hr':
        hr_contact = User.query.get(session['user_id'])
    else:
        hr_contact = User.query.filter_by(role='hr', is_active=True).first()
        if not hr_contact:
            hr_contact = User.query.filter_by(role='hr').first()
    
    # Render the template with employee data, exit feedbacks, and HR contact
    return render_template('exit.html', employee=employee, exit_feedbacks=exit_feedbacks, hr_contact=hr_contact)



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
    # Look for job experience patterns and return concise highlights
    experience = []

    # Look for date patterns like 2020 - 2022 or 01/2020 - Present
    date_patterns = [
        r'(\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4})\s*[-–]\s*(\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4}|Present\b)',
        r'(\d{1,2}/\d{4})\s*[-–]\s*(\d{1,2}/\d{4}|Present\b)',
        r'(\d{4})\s*[-–]\s*(\d{4}|Present\b)'
    ]

    # Patterns for lines we want to ignore (personal/contact details, links, headers)
    ignore_patterns = [
        r'@',                          # emails
        r'https?://',                  # URLs
        r'linkedin\.com',
        r'github\.com',
        r'phone',
        r'contact',
        r'\baddress\b',
        r'\bsummary\b',
        r'\bobjective\b',
        r'\bskills?\b',
        r'\beducation\b',
        r'\bprojects?\b',
    ]

    def is_personal_or_header(line: str) -> bool:
        lower = line.lower()
        if len(lower) < 3:
            return True
        for pat in ignore_patterns:
            if re.search(pat, lower):
                return True
        # Lines that are mostly punctuation or links
        if len(re.sub(r'[^a-zA-Z]', '', lower)) < 3:
            return True
        return False

    # Collect contextual snippets around date ranges
    for pattern in date_patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        for i, match in enumerate(matches):
            if i >= 3:
                break  # Limit to first 3 experiences per pattern
            start = max(0, match.start() - 200)
            end = min(len(text), match.end() + 200)
            context = text[start:end]
            # Split context into lines and filter
            for raw_line in context.split('\n'):
                line = raw_line.strip()
                if not line:
                    continue
                if is_personal_or_header(line):
                    continue
                # Prefer lines that look like responsibilities/roles
                if any(kw in line.lower() for kw in ['developer', 'engineer', 'intern', 'manager', 'lead', 'built', 'developed', 'implemented', 'designed']):
                    experience.append(line)

    # Deduplicate while preserving order
    seen = set()
    unique_experience = []
    for line in experience:
        if line not in seen:
            seen.add(line)
            unique_experience.append(line)

    return unique_experience[:5] if unique_experience else ["Experience not found in standard format"]

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
        # Only include skills that are present in both the resume and
        # the job description
        job_skills = extract_skills(job_description)
        resume_skills_set = set(s.lower() for s in resume_data.get('skills', []))
        job_skills_set = set(s.lower() for s in job_skills)

        matching_skills = [
            s for s in resume_data.get('skills', [])
            if s.lower() in job_skills_set
        ]

        # Fallback to top resume skills if no explicit matches found
        display_skills = matching_skills if matching_skills else resume_data.get('skills', [])

        summary_prompt = (
            f"Provide a brief (2-3 sentences) summary of how well this "
            f"candidate matches the job description. Matching skills: "
            f"{', '.join(display_skills[:5])}. "
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
                f"Candidate has {len(matching_skills) if matching_skills else len(resume_data['skills'])} relevant skills "
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
            'pass_screening': ats_result['score'] >= 60
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
        
        # Create notification for HR users about new feedback
        user = User.query.get(user_id)
        if user:
            # Check if mood or confidence is low (<= 2)
            if mood_rating <= 2 or confidence_rating <= 2:
                notification_type = 'low_mood' if mood_rating <= 2 else 'low_confidence'
                priority = 'high'
                title = f"Low {notification_type.replace('_', ' ').title()} Alert"
                message = f"{user.full_name} reported {notification_type.replace('_', ' ')} (Mood: {mood_rating}, Confidence: {confidence_rating})"
            else:
                notification_type = 'feedback'
                priority = 'normal'
                title = "New Mood Feedback"
                message = f"{user.full_name} submitted mood feedback (Mood: {mood_rating}, Confidence: {confidence_rating})"
            
            # Send to all HR users
            hr_users = User.query.filter_by(role='hr').all()
            for hr_user in hr_users:
                notification = Message(
                    subject=title,
                    content=message,
                    sender_id=user_id,
                    recipient_id=hr_user.id,
                    message_type='hr_notification',
                    priority=priority,
                    notification_data={
                        'notification_type': notification_type,
                        'feedback_id': new_feedback.id,
                        'mood_rating': mood_rating,
                        'confidence_rating': confidence_rating
                    }
                )
                db.session.add(notification)
            
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

@app.route('/api/feedback/debug')
@login_required('hr')
def debug_feedback_data():
    """Debug endpoint to check database connection and feedback data"""
    try:
        # Test database connection
        feedback_count = EmployeeFeedback.query.count()
        recent_feedback = EmployeeFeedback.query.order_by(EmployeeFeedback.created_at.desc()).limit(5).all()
        
        debug_info = {
            'database_connected': True,
            'total_feedback_count': feedback_count,
            'recent_feedback_sample': []
        }
        
        for feedback in recent_feedback:
            debug_info['recent_feedback_sample'].append({
                'id': feedback.id,
                'user_id': feedback.user_id,
                'mood_rating': feedback.mood_rating,
                'confidence_rating': feedback.confidence_rating,
                'feedback': feedback.feedback,
                'created_at': feedback.created_at.isoformat() if feedback.created_at else None,
                'user_name': feedback.user.full_name if feedback.user else 'Unknown'
            })
        
        return jsonify({
            'status': 'success',
            'debug_info': debug_info
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'database_connected': False
        }), 500

@app.route('/api/feedback/recent')
@login_required('hr')
def get_recent_feedback():
    """Get recent feedback with employee details"""
    try:
        # Get feedback from the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_feedback = EmployeeFeedback.query.filter(
            EmployeeFeedback.created_at >= thirty_days_ago
        ).order_by(EmployeeFeedback.created_at.desc()).limit(20).all()
        
        feedback_list = []
        for feedback in recent_feedback:
            # Get mood emoji
            mood_emoji = "😊" if feedback.mood_rating >= 4 else "😐" if feedback.mood_rating >= 3 else "😞"
            
            feedback_list.append({
                'id': feedback.id,
                'date': feedback.created_at.strftime('%Y-%m-%d %H:%M'),
                'employee_name': feedback.user.full_name if feedback.user else 'Unknown',
                'mood_rating': feedback.mood_rating,
                'mood_emoji': mood_emoji,
                'confidence_rating': feedback.confidence_rating,
                'feedback_text': feedback.feedback or 'No comment provided',
                'department': feedback.user.department if feedback.user and feedback.user.department else 'N/A'
            })
        
        return jsonify({
            'status': 'success',
            'data': feedback_list
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
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

@app.route('/api/onboarding/tasks/<int:task_id>/toggle', methods=['PUT'])
@login_required('hr')
def toggle_onboarding_task(task_id):
    """Toggle onboarding task completion status"""
    try:
        task = OnboardingTask.query.get_or_404(task_id)
        data = request.get_json()
        
        task.is_completed = data.get('completed', False)
        if task.is_completed:
            task.completed_at = datetime.utcnow()
        else:
            task.completed_at = None
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Task updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error toggling task: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to update task'
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
            'message': 'Tasks updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating onboarding tasks: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to update tasks'
        }), 500


# ===== OFFBOARDING API ENDPOINTS =====

@app.route('/api/offboarding/candidates', methods=['GET'])
@login_required('hr')
def get_offboarding_candidates():
    """Get all offboarding candidates"""
    try:
        candidates = OffboardingCandidate.query.all()
        return jsonify({
            'status': 'success',
            'candidates': [{
                'id': c.id,
                'employee_id': c.employee_id,
                'employee_name': c.employee.full_name if c.employee else 'N/A',
                'exit_date': c.exit_date.isoformat() if c.exit_date else None,
                'exit_reason': c.exit_reason,
                'status': c.status,
                'assigned_hr': c.assigned_hr,
                'created_at': c.created_at.isoformat() if c.created_at else None
            } for c in candidates]
        })
    except Exception as e:
        app.logger.error(f'Error fetching offboarding candidates: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch candidates'
        }), 500


@app.route('/api/offboarding/candidates', methods=['POST'])
@login_required('hr')
def create_offboarding_candidate():
    """Create a new offboarding candidate"""
    try:
        data = request.get_json()
        
        candidate = OffboardingCandidate(
            employee_id=data['employee_id'],
            exit_date=datetime.fromisoformat(data['exit_date'].replace('Z', '+00:00')) if data.get('exit_date') else None,
            exit_reason=data.get('exit_reason', ''),
            assigned_hr=data.get('assigned_hr'),
            status=data.get('status', 'pending')
        )
        
        db.session.add(candidate)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Offboarding candidate created successfully',
            'candidate_id': candidate.id
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error creating offboarding candidate: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to create candidate'
        }), 500


@app.route('/api/offboarding/candidates/<int:candidate_id>', methods=['PUT'])
@login_required('hr')
def update_offboarding_candidate(candidate_id):
    """Update offboarding candidate"""
    try:
        candidate = OffboardingCandidate.query.get_or_404(candidate_id)
        data = request.get_json()
        
        if 'exit_date' in data and data['exit_date']:
            candidate.exit_date = datetime.fromisoformat(data['exit_date'].replace('Z', '+00:00'))
        if 'exit_reason' in data:
            candidate.exit_reason = data['exit_reason']
        if 'assigned_hr' in data:
            candidate.assigned_hr = data['assigned_hr']
        if 'status' in data:
            candidate.status = data['status']
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Candidate updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating offboarding candidate: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to update candidate'
        }), 500


@app.route('/api/offboarding/assets/<int:candidate_id>', methods=['GET'])
@login_required('hr')
def get_offboarding_assets(candidate_id):
    """Get assets for offboarding candidate"""
    try:
        assets = OffboardingAsset.query.filter_by(candidate_id=candidate_id).all()
        return jsonify({
            'status': 'success',
            'assets': [{
                'id': a.id,
                'asset_name': a.asset_name,
                'asset_type': a.asset_type,
                'serial_number': a.serial_number,
                'status': a.status,
                'return_date': a.return_date.isoformat() if a.return_date else None,
                'notes': a.notes
            } for a in assets]
        })
    except Exception as e:
        app.logger.error(f'Error fetching offboarding assets: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch assets'
        }), 500


@app.route('/api/offboarding/assets', methods=['POST'])
@login_required('hr')
def create_offboarding_asset():
    """Create offboarding asset record"""
    try:
        data = request.get_json()
        
        asset = OffboardingAsset(
            candidate_id=data['candidate_id'],
            asset_name=data['asset_name'],
            asset_type=data.get('asset_type', 'equipment'),
            serial_number=data.get('serial_number', ''),
            status=data.get('status', 'assigned'),
            return_date=datetime.fromisoformat(data['return_date'].replace('Z', '+00:00')) if data.get('return_date') else None,
            notes=data.get('notes', '')
        )
        
        db.session.add(asset)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Asset recorded successfully',
            'asset_id': asset.id
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error creating offboarding asset: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to record asset'
        }), 500


@app.route('/api/offboarding/clearance/<int:candidate_id>', methods=['GET'])
@login_required('hr')
def get_offboarding_clearance(candidate_id):
    """Get clearance status for offboarding candidate"""
    try:
        clearances = OffboardingClearance.query.filter_by(candidate_id=candidate_id).all()
        return jsonify({
            'status': 'success',
            'clearances': [{
                'id': c.id,
                'department': c.department,
                'clearance_type': c.clearance_type,
                'status': c.status,
                'cleared_by': c.cleared_by,
                'cleared_date': c.cleared_date.isoformat() if c.cleared_date else None,
                'notes': c.notes
            } for c in clearances]
        })
    except Exception as e:
        app.logger.error(f'Error fetching offboarding clearance: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch clearance status'
        }), 500


@app.route('/api/offboarding/clearance', methods=['POST'])
@login_required('hr')
def update_offboarding_clearance():
    """Update clearance status"""
    try:
        data = request.get_json()
        
        clearance = OffboardingClearance(
            candidate_id=data['candidate_id'],
            department=data['department'],
            clearance_type=data.get('clearance_type', 'general'),
            status=data.get('status', 'pending'),
            cleared_by=data.get('cleared_by'),
            cleared_date=datetime.utcnow() if data.get('status') == 'cleared' else None,
            notes=data.get('notes', '')
        )
        
        # Check if clearance already exists
        existing = OffboardingClearance.query.filter_by(
            candidate_id=data['candidate_id'],
            department=data['department'],
            clearance_type=data.get('clearance_type', 'general')
        ).first()
        
        if existing:
            existing.status = data.get('status', 'pending')
            existing.cleared_by = data.get('cleared_by')
            existing.cleared_date = datetime.utcnow() if data.get('status') == 'cleared' else None
            existing.notes = data.get('notes', '')
        else:
            db.session.add(clearance)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Clearance status updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating offboarding clearance: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to update clearance'
        }), 500


# ===== DASHBOARD API ENDPOINTS =====

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required('hr')
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Employee statistics
        total_employees = Employee.query.count()
        active_employees = Employee.query.filter_by(status='Active').count()
        new_hires_this_month = Employee.query.filter(
            Employee.hire_date >= datetime.utcnow().replace(day=1)
        ).count()
        
        # Onboarding statistics
        pending_onboarding = OnboardingChecklist.query.filter_by(status='Pending').count()
        completed_onboarding = OnboardingChecklist.query.filter_by(status='Completed').count()
        
        # Offboarding statistics
        active_offboarding = OffboardingCandidate.query.filter_by(status='active').count()
        completed_offboarding = OffboardingCandidate.query.filter_by(status='completed').count()
        
        # Document statistics
        total_documents = EmployeeDocument.query.count()
        pending_documents = EmployeeDocument.query.filter_by(status='pending').count()
        
        # Feedback statistics
        recent_feedback = EmployeeFeedback.query.filter(
            EmployeeFeedback.created_at >= datetime.utcnow() - timedelta(days=30)
        ).count()
        
        return jsonify({
            'status': 'success',
            'stats': {
                'employees': {
                    'total': total_employees,
                    'active': active_employees,
                    'new_hires_this_month': new_hires_this_month
                },
                'onboarding': {
                    'pending': pending_onboarding,
                    'completed': completed_onboarding,
                    'completion_rate': round((completed_onboarding / (completed_onboarding + pending_onboarding) * 100) if (completed_onboarding + pending_onboarding) > 0 else 0, 1)
                },
                'offboarding': {
                    'active': active_offboarding,
                    'completed': completed_offboarding
                },
                'documents': {
                    'total': total_documents,
                    'pending': pending_documents
                },
                'feedback': {
                    'recent_feedback': recent_feedback
                }
            }
        })
    except Exception as e:
        app.logger.error(f'Error fetching dashboard stats: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch dashboard statistics'
        }), 500


@app.route('/api/dashboard/onboarding-progress', methods=['GET'])
@login_required('hr')
def get_onboarding_progress():
    """Get onboarding progress data"""
    try:
        checklists = OnboardingChecklist.query.all()
        progress_data = []
        
        for checklist in checklists:
            completed_tasks = sum(1 for task in checklist.tasks if task.is_completed)
            total_tasks = len(checklist.tasks)
            progress = round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 1)
            
            progress_data.append({
                'employee_name': checklist.employee.full_name if checklist.employee else 'N/A',
                'department': checklist.employee.department if checklist.employee and checklist.employee.department else 'Unassigned',
                'progress': progress,
                'completed_tasks': completed_tasks,
                'total_tasks': total_tasks,
                'status': checklist.status,
                'start_date': checklist.created_at.isoformat() if checklist.created_at else None
            })
        
        return jsonify({
            'status': 'success',
            'data': progress_data
        })
    except Exception as e:
        app.logger.error(f'Error fetching onboarding progress: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch onboarding progress'
        }), 500


@app.route('/api/dashboard/department-stats', methods=['GET'])
@login_required('hr')
def get_department_stats():
    """Get department-wise statistics"""
    try:
        # Group employees by department
        dept_stats = {}
        employees = Employee.query.all()
        
        for emp in employees:
            dept = emp.department or 'Unassigned'
            if dept not in dept_stats:
                dept_stats[dept] = {
                    'total_employees': 0,
                    'active_employees': 0,
                    'new_hires': 0,
                    'pending_onboarding': 0,
                    'completed_onboarding': 0
                }
            
            dept_stats[dept]['total_employees'] += 1
            if emp.status == 'Active':
                dept_stats[dept]['active_employees'] += 1
            if emp.hire_date and emp.hire_date >= datetime.utcnow().replace(day=1):
                dept_stats[dept]['new_hires'] += 1
        
        # Add onboarding stats
        checklists = OnboardingChecklist.query.all()
        for checklist in checklists:
            dept = checklist.employee.department if checklist.employee and checklist.employee.department else 'Unassigned'
            if dept in dept_stats:
                if checklist.status == 'Pending':
                    dept_stats[dept]['pending_onboarding'] += 1
                elif checklist.status == 'Completed':
                    dept_stats[dept]['completed_onboarding'] += 1
        
        return jsonify({
            'status': 'success',
            'departments': dept_stats
        })
    except Exception as e:
        app.logger.error(f'Error fetching department stats: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch department statistics'
        }), 500


@app.route('/api/dashboard/recent-activities', methods=['GET'])
@login_required('hr')
def get_recent_activities():
    """Get recent system activities"""
    try:
        activities = []
        
        # Recent logins
        recent_logins = AccessRecord.query.filter_by(access_type='login').order_by(AccessRecord.timestamp.desc()).limit(5).all()
        for login in recent_logins:
            activities.append({
                'type': 'login',
                'description': f"{login.user.full_name if login.user else 'Unknown'} logged in",
                'timestamp': login.timestamp.isoformat(),
                'user': login.user.full_name if login.user else 'Unknown'
            })
        
        # Recent document uploads
        recent_docs = EmployeeDocument.query.order_by(EmployeeDocument.upload_date.desc()).limit(5).all()
        for doc in recent_docs:
            activities.append({
                'type': 'document',
                'description': f"{doc.user.full_name if doc.user else 'Unknown'} uploaded {doc.file_name}",
                'timestamp': doc.upload_date.isoformat(),
                'user': doc.user.full_name if doc.user else 'Unknown'
            })
        
        # Recent onboarding completions
        recent_onboarding = OnboardingChecklist.query.filter_by(status='Completed').order_by(OnboardingChecklist.completed_at.desc()).limit(5).all()
        for checklist in recent_onboarding:
            activities.append({
                'type': 'onboarding',
                'description': f"Onboarding completed for {checklist.employee.full_name if checklist.employee else 'Unknown'}",
                'timestamp': checklist.completed_at.isoformat(),
                'user': checklist.employee.full_name if checklist.employee else 'Unknown'
            })
        
        # Sort by timestamp
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'status': 'success',
            'activities': activities[:10]  # Return latest 10 activities
        })
    except Exception as e:
        app.logger.error(f'Error fetching recent activities: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch recent activities'
        }), 500


@app.route('/api/dashboard/feedback-summary', methods=['GET'])
@login_required('hr')
def get_dashboard_feedback_summary():
    """Get feedback summary and trends"""
    try:
        # Get last 6 months of feedback
        six_months_ago = datetime.utcnow() - timedelta(days=180)
        feedback_data = EmployeeFeedback.query.filter(
            EmployeeFeedback.created_at >= six_months_ago
        ).all()
        
        # Group by month and calculate average mood
        monthly_data = {}
        for feedback in feedback_data:
            month_key = feedback.created_at.strftime('%Y-%m')
            if month_key not in monthly_data:
                monthly_data[month_key] = {
                    'count': 0,
                    'total_mood': 0,
                    'avg_mood': 0
                }
            
            monthly_data[month_key]['count'] += 1
            if feedback.mood_rating:
                monthly_data[month_key]['total_mood'] += feedback.mood_rating
        
        # Calculate averages
        for month in monthly_data:
            if monthly_data[month]['count'] > 0:
                monthly_data[month]['avg_mood'] = round(
                    monthly_data[month]['total_mood'] / monthly_data[month]['count'], 2
                )
        
        # Get department-wise feedback
        dept_feedback = {}
        for feedback in feedback_data:
            dept = feedback.user.employee.department if feedback.user and feedback.user.employee and feedback.user.employee.department else 'Unassigned'
            if dept not in dept_feedback:
                dept_feedback[dept] = {
                    'count': 0,
                    'total_mood': 0,
                    'avg_mood': 0
                }
            
            dept_feedback[dept]['count'] += 1
            if feedback.mood_rating:
                dept_feedback[dept]['total_mood'] += feedback.mood_rating
        
        # Calculate department averages
        for dept in dept_feedback:
            if dept_feedback[dept]['count'] > 0:
                dept_feedback[dept]['avg_mood'] = round(
                    dept_feedback[dept]['total_mood'] / dept_feedback[dept]['count'], 2
                )
        
        return jsonify({
            'status': 'success',
            'data': {
                'monthly_trends': monthly_data,
                'department_feedback': dept_feedback,
                'total_feedback': len(feedback_data),
                'overall_avg_mood': round(
                    sum(f.mood_rating for f in feedback_data if f.mood_rating) / 
                    len([f for f in feedback_data if f.mood_rating]), 2
                ) if feedback_data else 0
            }
        })
    except Exception as e:
        app.logger.error(f'Error fetching feedback summary: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch feedback summary'
        }), 500


# ===== HR NOTIFICATION SYSTEM =====

def create_hr_notification(title, message, notification_type='info', priority='normal', action_url=None, recipient_id=None, sender_id=None):
    """Create an HR notification"""
    try:
        # If no sender specified, use system user or first HR user
        if sender_id is None:
            # Try to get from session if available, otherwise use first admin/system user
            try:
                sender_id = session.get('user_id')
            except RuntimeError:
                # No request context, use system or first HR user
                sender_id = None
            
            if sender_id is None:
                # Find system admin or first HR user
                system_user = User.query.filter_by(role='hr').first()
                sender_id = system_user.id if system_user else 1
        
        # If no recipient specified, send to all HR users
        if recipient_id is None:
            hr_users = User.query.filter_by(role='hr').all()
            recipients = [u.id for u in hr_users]
        else:
            recipients = [recipient_id]
        
        notifications = []
        for recip_id in recipients:
            notification = Message(
                subject=title,
                content=message,
                sender_id=sender_id,
                recipient_id=recip_id,
                message_type='hr_notification',
                priority=priority,
                status='unread'
            )
            notification.notification_data = {
                'notification_type': notification_type,
                'action_url': action_url
            }
            notifications.append(notification)
            db.session.add(notification)
        
        db.session.commit()
        app.logger.info(f'Created HR notification for {len(recipients)} recipients: {title}')
        return notifications
    except Exception as e:
        app.logger.error(f'Error creating HR notification: {str(e)}')
        db.session.rollback()
        return []

def check_overdue_onboarding_tasks():
    """Check for overdue onboarding tasks and create notifications"""
    try:
        overdue_tasks = []
        
        # Get all active onboarding checklists
        active_checklists = OnboardingChecklist.query.filter_by(status='Pending').all()
        
        for checklist in active_checklists:
            # Get incomplete tasks
            incomplete_tasks = OnboardingTask.query.filter_by(
                checklist_id=checklist.id,
                is_completed=False
            ).all()
            
            for task in incomplete_tasks:
                # Calculate days overdue
                days_overdue = (datetime.utcnow() - checklist.created_at).days
                
                # Consider tasks overdue after 7 days
                if days_overdue > 7:
                    overdue_tasks.append({
                        'employee_id': checklist.employee_id,
                        'employee_name': checklist.employee.full_name if checklist.employee else 'Unknown',
                        'task_title': task.task_name,
                        'task_id': task.id,
                        'days_overdue': days_overdue,
                        'assigned_date': checklist.created_at.isoformat()
                    })
        
        # Create notifications for overdue tasks
        for task in overdue_tasks:
            title = "Overdue Onboarding Task"
            message = f"Task '{task['task_title']}' for {task['employee_name']} is {task['days_overdue']} days overdue."
            action_url = f"/onboarding?employee={task['employee_id']}"
            
            create_hr_notification(
                title=title,
                message=message,
                notification_type='onboarding_overdue',
                priority='high' if task['days_overdue'] > 14 else 'normal',
                action_url=action_url
            )
        
        return overdue_tasks
    except Exception as e:
        app.logger.error(f'Error checking overdue onboarding tasks: {str(e)}')
        return []

def check_pending_access_revocation():
    """Check for pending access revocation and create notifications"""
    try:
        pending_revocations = []
        
        # Get employees who have exited but still have active access
        exited_employees = User.query.filter(
            User.exit_date.isnot(None),
            User.exit_date <= datetime.utcnow().date()
        ).all()
        
        for employee in exited_employees:
            # Check for active access records
            active_access = AccessRecord.query.filter_by(
                user_id=employee.id,
                status='active'
            ).all()
            
            for access in active_access:
                days_since_exit = (datetime.utcnow().date() - employee.exit_date).days
                
                # Alert if access is still active 3 days after exit
                if days_since_exit >= 3:
                    pending_revocations.append({
                        'employee_id': employee.id,
                        'employee_name': employee.full_name,
                        'access_id': access.id,
                        'system_name': access.resource_name,
                        'exit_date': employee.exit_date.isoformat(),
                        'days_since_exit': days_since_exit
                    })
        
        # Create notifications for pending revocations
        for revocation in pending_revocations:
            title = "Pending Access Revocation"
            message = f"Access to {revocation['system_name']} for {revocation['employee_name']} should be revoked ({revocation['days_since_exit']} days post-exit)."
            action_url = f"/access-records?employee={revocation['employee_id']}"
            
            create_hr_notification(
                title=title,
                message=message,
                notification_type='access_revocation',
                priority='urgent' if revocation['days_since_exit'] > 7 else 'high',
                action_url=action_url
            )
        
        return pending_revocations
    except Exception as e:
        app.logger.error(f'Error checking pending access revocation: {str(e)}')
        return []


# ===== HR NOTIFICATION API ENDPOINTS =====

@app.route('/api/hr/notifications', methods=['GET'])
@login_required('hr')
def get_hr_notifications():
    """Get HR notifications count and recent high-priority notifications"""
    try:
        # Get unread notifications for current HR user
        unread_notifications = Message.query.filter_by(
            recipient_id=session['user_id'],
            status='unread',
            message_type='hr_notification'
        ).order_by(Message.sent_at.desc()).limit(10).all()
        
        # Format notifications
        notifications = []
        for notif in unread_notifications:
            notification_data = notif.notification_data or {}
            notifications.append({
                'id': notif.id,
                'title': notif.subject,
                'message': notif.content,
                'type': notification_data.get('notification_type', 'info'),
                'priority': notif.priority,
                'created_at': notif.sent_at.isoformat(),
                'action_url': notification_data.get('action_url'),
                'is_read': notif.status == 'read'
            })
        
        return jsonify({
            'status': 'success',
            'count': len(unread_notifications),
            'notifications': notifications
        })
    except Exception as e:
        app.logger.error(f'Error getting HR notifications: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to get notifications'
        }), 500

@app.route('/api/hr/notifications/all', methods=['GET'])
@login_required('hr')
def get_all_hr_notifications():
    """Get all HR notifications"""
    try:
        # Get all notifications for current HR user
        all_notifications = Message.query.filter_by(
            recipient_id=session['user_id'],
            message_type='hr_notification'
        ).order_by(Message.sent_at.desc()).limit(50).all()
        
        # Format notifications
        notifications = []
        for notif in all_notifications:
            notification_data = notif.notification_data or {}
            notifications.append({
                'id': notif.id,
                'title': notif.subject,
                'message': notif.content,
                'type': notification_data.get('notification_type', 'info'),
                'priority': notif.priority,
                'created_at': notif.sent_at.isoformat(),
                'action_url': notification_data.get('action_url'),
                'is_read': notif.status == 'read'
            })
        
        return jsonify({
            'status': 'success',
            'notifications': notifications
        })
    except Exception as e:
        app.logger.error(f'Error getting all HR notifications: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to get notifications'
        }), 500

@app.route('/api/hr/daily-summary', methods=['POST'])
@login_required('hr')
def generate_daily_hr_summary():
    """Generate daily summary of pending work"""
    try:
        # Check for overdue tasks
        overdue_onboarding = check_overdue_onboarding_tasks()
        
        # Check for pending access revocation
        pending_access_revocation = check_pending_access_revocation()
        
        # Get other stats
        stats = {
            'pending_tasks': Task.query.filter_by(status='pending').count(),
            'pending_documents': EmployeeDocument.query.filter_by(status='pending').count(),
            'upcoming_interviews': Interview.query.filter(
                Interview.created_at >= datetime.utcnow(),
                Interview.created_at <= datetime.utcnow() + timedelta(days=7)
            ).count(),
            'completed_onboarding': OnboardingChecklist.query.filter_by(status='Completed').count()
        }
        
        summary = {
            'overdue_onboarding': overdue_onboarding,
            'pending_access_revocation': pending_access_revocation,
            'stats': stats,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        # Create daily summary notification
        title = "Daily HR Summary"
        message = f"Daily summary generated with {len(overdue_onboarding)} overdue tasks and {len(pending_access_revocation)} pending revocations."
        create_hr_notification(
            title=title,
            message=message,
            notification_type='daily_summary',
            priority='normal'
        )
        
        return jsonify({
            'status': 'success',
            'summary': summary
        })
    except Exception as e:
        app.logger.error(f'Error generating daily HR summary: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate daily summary'
        }), 500

@app.route('/api/hr/notifications/<int:notification_id>/read', methods=['PUT'])
@login_required('hr')
def mark_hr_notification_read(notification_id):
    """Mark HR notification as read"""
    try:
        notification = Message.query.filter_by(
            id=notification_id,
            recipient_id=session['user_id']
        ).first_or_404()
        
        notification.status = 'read'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Notification marked as read'
        })
    except Exception as e:
        app.logger.error(f'Error marking HR notification as read: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to mark notification as read'
        }), 500

@app.route('/api/hr/notifications/mark-all-read', methods=['PUT'])
@login_required('hr')
def mark_all_hr_notifications_read():
    """Mark all HR notifications as read"""
    try:
        Message.query.filter_by(
            recipient_id=session['user_id'],
            message_type='hr_notification',
            status='unread'
        ).update({'status': 'read'})
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'All notifications marked as read'
        })
    except Exception as e:
        app.logger.error(f'Error marking all HR notifications as read: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to mark notifications as read'
        }), 500


# ===== NOTIFICATION HELPERS =====

def create_notification(recipient_id, subject, content, message_type='notification', priority='normal', sender_id=None):
    """Create a new notification message"""
    try:
        # If no sender specified, use system user (ID 1) or create a system notification
        if sender_id is None:
            # Try to find an HR user or use the first user as system
            system_user = User.query.filter_by(role='hr').first()
            sender_id = system_user.id if system_user else 1
        
        notification = Message(
            subject=subject,
            content=content,
            sender_id=sender_id,
            recipient_id=recipient_id,
            message_type=message_type,
            priority=priority,
            status='unread'
        )
        
        db.session.add(notification)
        db.session.commit()
        
        app.logger.info(f'Created notification for user {recipient_id}: {subject}')
        return notification
        
    except Exception as e:
        app.logger.error(f'Error creating notification: {str(e)}')
        db.session.rollback()
        return None

def notify_task_assigned(employee_id, task_title, task_description):
    """Notify employee when a new task is assigned"""
    employee = User.query.get(employee_id)
    if employee:
        subject = "New Task Assigned"
        content = f"You have been assigned a new task: {task_title}\n\n{task_description}"
        create_notification(
            recipient_id=employee_id,
            subject=subject,
            content=content,
            message_type='task',
            priority='normal'
        )

def notify_document_approved(employee_id, document_name):
    """Notify employee when a document is approved"""
    employee = User.query.get(employee_id)
    if employee:
        subject = "Document Approved"
        content = f"Your document '{document_name}' has been approved by HR."
        create_notification(
            recipient_id=employee_id,
            subject=subject,
            content=content,
            message_type='document',
            priority='normal'
        )

def notify_interview_scheduled(employee_id, interview_details):
    """Notify employee when an interview is scheduled"""
    employee = User.query.get(employee_id)
    if employee:
        subject = "Interview Scheduled"
        content = f"An interview has been scheduled for you:\n\n{interview_details}"
        create_notification(
            recipient_id=employee_id,
            subject=subject,
            content=content,
            message_type='interview',
            priority='high'
        )

def notify_exit_summary_ready(employee_id):
    """Notify employee when exit summary is ready"""
    employee = User.query.get(employee_id)
    if employee:
        subject = "Exit Summary Ready"
        content = "Your exit interview summary and final documents are ready for review."
        create_notification(
            recipient_id=employee_id,
            subject=subject,
            content=content,
            message_type='exit',
            priority='high'
        )


# ===== NOTIFICATION API ENDPOINTS =====

@app.route('/api/notifications', methods=['GET'])
@login_required(['hr', 'employee'])
def get_notifications():
    """Get notifications for the current user"""
    try:
        user_id = session['user_id']
        messages = Message.query.filter_by(recipient_id=user_id, status='unread').order_by(Message.sent_at.desc()).limit(20).all()
        
        notifications = []
        for msg in messages:
            notifications.append({
                'id': msg.id,
                'subject': msg.subject,
                'content': msg.content[:100] + '...' if len(msg.content) > 100 else msg.content,
                'message_type': msg.message_type,
                'priority': msg.priority,
                'sent_at': msg.sent_at.isoformat(),
                'sender': msg.sender.full_name if msg.sender else 'System'
            })
        
        return jsonify({
            'status': 'success',
            'notifications': notifications,
            'unread_count': len(notifications)
        })
    except Exception as e:
        app.logger.error(f'Error fetching notifications: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch notifications'
        }), 500


@app.route('/api/notifications/<int:message_id>/read', methods=['PUT'])
@login_required(['hr', 'employee'])
def mark_notification_read(message_id):
    """Mark notification as read"""
    try:
        user_id = session['user_id']
        message = Message.query.filter_by(id=message_id, recipient_id=user_id).first_or_404()
        
        message.status = 'read'
        message.read_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Notification marked as read'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error marking notification as read: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to mark notification as read'
        }), 500


@app.route('/api/notifications/send', methods=['POST'])
@login_required('hr')
def send_notification():
    """Send notification to users"""
    try:
        data = request.get_json()
        
        recipients = data.get('recipients', [])  # Array of user IDs
        subject = data.get('subject', '')
        content = data.get('content', '')
        message_type = data.get('message_type', 'notification')
        priority = data.get('priority', 'normal')
        
        if not recipients or not subject or not content:
            return jsonify({
                'status': 'error',
                'message': 'Recipients, subject, and content are required'
            }), 400
        
        sender_id = session['user_id']
        sent_messages = []
        
        for recipient_id in recipients:
            message = Message(
                subject=subject,
                content=content,
                sender_id=sender_id,
                recipient_id=recipient_id,
                message_type=message_type,
                priority=priority,
                status='unread'
            )
            db.session.add(message)
            sent_messages.append(recipient_id)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Notification sent to {len(sent_messages)} recipients',
            'recipients': sent_messages
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error sending notification: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to send notification'
        }), 500


@app.route('/api/notifications/reminders', methods=['GET'])
@login_required('hr')
def get_reminders():
    """Get system reminders and upcoming tasks"""
    try:
        reminders = []
        
        # Onboarding reminders
        pending_onboarding = OnboardingChecklist.query.filter_by(status='pending').all()
        for checklist in pending_onboarding:
            days_since_start = (datetime.utcnow() - checklist.created_at).days
            if days_since_start > 7:  # Remind about pending onboarding older than 7 days
                reminders.append({
                    'type': 'onboarding',
                    'title': f'Pending Onboarding: {checklist.employee.full_name if checklist.employee else "Unknown"}',
                    'description': f'Onboarding started {days_since_start} days ago',
                    'priority': 'high' if days_since_start > 14 else 'medium',
                    'action_url': f'/onboarding/{checklist.id}',
                    'created_at': checklist.created_at.isoformat()
                })
        
        # Document reminders
        pending_docs = EmployeeDocument.query.filter_by(status='pending').all()
        for doc in pending_docs:
            days_pending = (datetime.utcnow() - doc.upload_date).days
            if days_pending > 3:  # Remind about pending documents older than 3 days
                reminders.append({
                    'type': 'document',
                    'title': f'Pending Document: {doc.file_name}',
                    'description': f'Document uploaded {days_pending} days ago awaiting approval',
                    'priority': 'medium',
                    'action_url': f'/documents/review/{doc.id}',
                    'created_at': doc.upload_date.isoformat()
                })
        
        # Offboarding reminders
        active_offboarding = OffboardingCandidate.query.filter_by(status='active').all()
        for candidate in active_offboarding:
            if candidate.exit_date:
                days_until_exit = (candidate.exit_date - datetime.utcnow().date()).days
                if days_until_exit <= 3 and days_until_exit >= 0:  # Remind about upcoming exit
                    reminders.append({
                        'type': 'offboarding',
                        'title': f'Upcoming Exit: {candidate.employee.full_name if candidate.employee else "Unknown"}',
                        'description': f'Exit date in {days_until_exit} days',
                        'priority': 'high' if days_until_exit <= 1 else 'medium',
                        'action_url': f'/offboarding/{candidate.id}',
                        'created_at': candidate.created_at.isoformat()
                    })
        
        # Sort reminders by priority and date
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        reminders.sort(key=lambda x: (priority_order.get(x['priority'], 3), x['created_at']), reverse=True)
        
        return jsonify({
            'status': 'success',
            'reminders': reminders[:20],  # Return latest 20 reminders
            'total_count': len(reminders)
        })
    except Exception as e:
        app.logger.error(f'Error fetching reminders: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch reminders'
        }), 500


@app.route('/api/notifications/messages', methods=['GET'])
@login_required(['hr', 'employee'])
def get_messages():
    """Get messages (conversation thread)"""
    try:
        user_id = session['user_id']
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get messages where user is either sender or recipient
        messages = Message.query.filter(
            (Message.sender_id == user_id) | (Message.recipient_id == user_id)
        ).order_by(Message.sent_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        message_list = []
        for msg in messages.items:
            message_list.append({
                'id': msg.id,
                'subject': msg.subject,
                'content': msg.content,
                'message_type': msg.message_type,
                'priority': msg.priority,
                'status': msg.status,
                'sent_at': msg.sent_at.isoformat(),
                'read_at': msg.read_at.isoformat() if msg.read_at else None,
                'sender': msg.sender.full_name if msg.sender else 'System',
                'recipient': msg.recipient.full_name if msg.recipient else 'Unknown',
                'is_sent': msg.sender_id == user_id,
                'is_reply': msg.parent_id is not None
            })
        
        return jsonify({
            'status': 'success',
            'messages': message_list,
            'pagination': {
                'page': messages.page,
                'pages': messages.pages,
                'per_page': messages.per_page,
                'total': messages.total,
                'has_next': messages.has_next,
                'has_prev': messages.has_prev
            }
        })
    except Exception as e:
        app.logger.error(f'Error fetching messages: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch messages'
        }), 500


@app.route('/api/notifications/messages', methods=['POST'])
@login_required(['hr', 'employee'])
def send_message():
    """Send a message to another user"""
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        subject = data.get('subject', '')
        content = data.get('content', '')
        parent_id = data.get('parent_id')  # For replies
        
        if not recipient_id or not content:
            return jsonify({
                'status': 'error',
                'message': 'Recipient and content are required'
            }), 400
        
        # Verify recipient exists
        recipient = User.query.get(recipient_id)
        if not recipient:
            return jsonify({
                'status': 'error',
                'message': 'Recipient not found'
            }), 404
        
        sender_id = session['user_id']
        
        message = Message(
            subject=subject or 'No Subject',
            content=content,
            sender_id=sender_id,
            recipient_id=recipient_id,
            message_type='message',
            priority='normal',
            status='unread',
            parent_id=parent_id
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Message sent successfully',
            'message_id': message.id
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error sending message: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to send message'
        }), 500


@app.route('/api/employee/documents/<int:document_id>/approve', methods=['PUT'])
@login_required('hr')
def approve_employee_document(document_id):
    """Approve or reject employee document"""
    try:
        data = request.get_json()
        status = data.get('status', 'approved')  # approved or rejected
        remarks = data.get('remarks', '')
        
        document = EmployeeDocument.query.get_or_404(document_id)
        
        if document.status != 'pending':
            return jsonify({
                'status': 'error',
                'message': 'Document has already been processed'
            }), 400
        
        document.status = status
        document.remarks = remarks
        document.reviewed_by = session['user_id']
        document.reviewed_at = datetime.utcnow()
        
        db.session.commit()
        
        # Send notification to employee
        if status == 'approved':
            notify_document_approved(document.employee_id, document.document_name)
        else:
            # Create rejection notification
            employee = User.query.get(document.employee_id)
            if employee:
                subject = "Document Rejected"
                content = f"Your document '{document.document_name}' has been rejected."
                if remarks:
                    content += f"\n\nRemarks: {remarks}"
                create_notification(
                    recipient_id=document.employee_id,
                    subject=subject,
                    content=content,
                    message_type='document',
                    priority='high'
                )
        
        return jsonify({
            'status': 'success',
            'message': f'Document {status} successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error approving document: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to process document'
        }), 500


@app.route('/api/interviews', methods=['POST'])
@login_required('hr')
def schedule_interview():
    """Schedule an interview for a candidate"""
    try:
        data = request.get_json()
        
        candidate_id = data.get('candidate_id')
        employee_id = data.get('employee_id')  # For internal interviews
        interview_type = data.get('type', 'technical')
        scheduled_date = data.get('scheduled_date')
        scheduled_time = data.get('scheduled_time')
        location = data.get('location', 'Video Call')
        notes = data.get('notes', '')
        
        if not scheduled_date or not scheduled_time:
            return jsonify({
                'status': 'error',
                'message': 'Date and time are required'
            }), 400
        
        # Parse date and time
        try:
            date_obj = datetime.strptime(scheduled_date, '%Y-%m-%d').date()
            time_obj = datetime.strptime(scheduled_time, '%H:%M').time()
            scheduled_datetime = datetime.combine(date_obj, time_obj)
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Invalid date or time format'
            }), 400
        
        # Create interview record
        interview = Interview(
            candidate_id=candidate_id,
            scheduled_at=scheduled_datetime,
            interview_type=interview_type,
            location=location,
            notes=notes,
            status='scheduled'
        )
        
        db.session.add(interview)
        db.session.commit()
        
        # Send notification to employee if it's an internal interview
        if employee_id:
            interview_details = f"""
Type: {interview_type.title()}
Date: {scheduled_date}
Time: {scheduled_time}
Location: {location}
{notes if notes else ''}
"""
            notify_interview_scheduled(employee_id, interview_details)
        
        return jsonify({
            'status': 'success',
            'message': 'Interview scheduled successfully',
            'data': {
                'id': interview.id,
                'scheduled_at': interview.scheduled_at.isoformat(),
                'type': interview.interview_type,
                'location': interview.location
            }
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error scheduling interview: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to schedule interview'
        }), 500


@app.route('/api/exit/summary/<int:employee_id>', methods=['POST'])
@login_required('hr')
def generate_exit_summary(employee_id):
    """Generate and notify about exit summary"""
    try:
        employee = User.query.get(employee_id)
        if not employee:
            return jsonify({
                'status': 'error',
                'message': 'Employee not found'
            }), 404
        
        # In a real app, generate comprehensive exit summary
        # For now, just create a notification
        notify_exit_summary_ready(employee_id)
        
        return jsonify({
            'status': 'success',
            'message': 'Exit summary generated and employee notified'
        })
    except Exception as e:
        app.logger.error(f'Error generating exit summary: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate exit summary'
        }), 500


# Initialize APScheduler
scheduler = BackgroundScheduler()

def scheduled_notification_check():
    """Scheduled task to check for overdue tasks and pending revocations"""
    with app.app_context():
        try:
            app.logger.info("Running scheduled notification check...")
            check_overdue_onboarding_tasks()
            check_pending_access_revocation()
            app.logger.info("Scheduled notification check completed")
        except Exception as e:
            app.logger.error(f'Error in scheduled notification check: {str(e)}')

# Schedule the notification check to run every hour
scheduler.add_job(
    func=scheduled_notification_check,
    trigger=IntervalTrigger(hours=1),
    id='notification_check_job',
    name='Check for overdue tasks and pending revocations',
    replace_existing=True
)

# Start the scheduler
scheduler.start()

# Shut down the scheduler when the app exits
import atexit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(debug=True)
