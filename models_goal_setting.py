from datetime import datetime, timedelta
from sqlalchemy import Text, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

# Import db from app to avoid circular imports
def get_db():
    from app import db
    return db

class GoalTemplate(db.Model):
    """Template for 30-60-90 day goals by department/role"""
    __tablename__ = 'goal_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    department = db.Column(db.String(50), nullable=False)
    position = db.Column(db.String(100), nullable=True)
    milestone_days = db.Column(db.Integer, nullable=False)  # 30, 60, or 90
    category = db.Column(db.String(50), nullable=False)  # 'technical', 'cultural', 'performance', 'development'
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = relationship('User', foreign_keys=[created_by], backref='goal_templates')
    employee_goals = relationship('EmployeeGoal', back_populates='template')

class EmployeeGoal(db.Model):
    """Individual goals assigned to employees"""
    __tablename__ = 'employee_goals'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    template_id = db.Column(db.Integer, ForeignKey('goal_templates.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    milestone_days = db.Column(db.Integer, nullable=False)  # 30, 60, or 90
    category = db.Column(db.String(50), nullable=False)
    target_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'in_progress', 'completed', 'overdue'
    priority = db.Column(db.String(10), default='medium')  # 'low', 'medium', 'high'
    progress_percentage = db.Column(db.Integer, default=0)
    assigned_by = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    employee = relationship('User', foreign_keys=[employee_id], backref='assigned_goals')
    template = relationship('GoalTemplate', back_populates='employee_goals')
    assigner = relationship('User', foreign_keys=[assigned_by], backref='assigned_employee_goals')
    check_ins = relationship('GoalCheckIn', back_populates='goal', order_by='GoalCheckIn.scheduled_date')

class GoalCheckIn(db.Model):
    """Scheduled and completed check-ins for goals"""
    __tablename__ = 'goal_check_ins'
    
    id = db.Column(db.Integer, primary_key=True)
    goal_id = db.Column(db.Integer, ForeignKey('employee_goals.id'), nullable=False)
    scheduled_date = db.Column(db.DateTime, nullable=False)
    actual_date = db.Column(db.DateTime, nullable=True)
    check_in_type = db.Column(db.String(20), default='review')  # 'review', 'update', 'final'
    status = db.Column(db.String(20), default='scheduled')  # 'scheduled', 'completed', 'cancelled', 'missed'
    notes = db.Column(db.Text, nullable=True)
    employee_notes = db.Column(db.Text, nullable=True)
    hr_feedback = db.Column(db.Text, nullable=True)
    next_steps = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Integer, nullable=True)  # 1-5 scale
    created_by = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    goal = relationship('EmployeeGoal', back_populates='check_ins')
    creator = relationship('User', backref='created_check_ins')

class GoalProgress(db.Model):
    """Progress updates for goals"""
    __tablename__ = 'goal_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    goal_id = db.Column(db.Integer, ForeignKey('employee_goals.id'), nullable=False)
    progress_percentage = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    attachments = db.Column(db.Text, nullable=True)  # JSON string of file paths
    created_by = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    goal = relationship('EmployeeGoal', backref='progress_updates')
    creator = relationship('User', backref='goal_progress_updates')
