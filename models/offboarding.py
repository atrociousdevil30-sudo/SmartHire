from datetime import datetime, timedelta
from app import db


class OffboardingCandidate(db.Model):
    """Model for employees going through the offboarding process"""
    __tablename__ = 'offboarding_candidates'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    hire_date = db.Column(db.Date, nullable=False)
    last_working_day = db.Column(db.Date, nullable=False)
    reason_for_leaving = db.Column(db.String(200), nullable=True)
    exit_interview_scheduled = db.Column(db.Boolean, default=False)
    exit_interview_date = db.Column(db.DateTime, nullable=True)
    exit_interview_notes = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('User', foreign_keys=[employee_id], backref=db.backref('offboarding', uselist=False))
    manager = db.relationship('User', foreign_keys=[manager_id])
    assets = db.relationship('OffboardingAsset', backref='offboarding', lazy=True, cascade='all, delete-orphan')
    documents = db.relationship('OffboardingDocument', backref='offboarding', lazy=True, cascade='all, delete-orphan')
    clearances = db.relationship('OffboardingClearance', backref='offboarding', lazy=True, cascade='all, delete-orphan')


class OffboardingAsset(db.Model):
    """Assets to be returned during offboarding"""
    __tablename__ = 'offboarding_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    offboarding_id = db.Column(db.Integer, db.ForeignKey('offboarding_candidates.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    asset_type = db.Column(db.String(50), nullable=False)
    asset_id = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=True)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, returned, not_returned
    returned_date = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OffboardingDocument(db.Model):
    """Documents related to offboarding"""
    __tablename__ = 'offboarding_documents'
    
    id = db.Column(db.Integer, primary_key=True)
    offboarding_id = db.Column(db.Integer, db.ForeignKey('offboarding_candidates.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    doc_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, available, processing
    file_path = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OffboardingClearance(db.Model):
    """Department clearances for offboarding"""
    __tablename__ = 'offboarding_clearances'
    
    id = db.Column(db.Integer, primary_key=True)
    offboarding_id = db.Column(db.Integer, db.ForeignKey('offboarding_candidates.id'), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, cleared
    cleared_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    cleared_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
