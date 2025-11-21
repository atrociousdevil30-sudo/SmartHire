"""
Create goal setting tables for 30-60-90 day goal management
"""
from app import app, db
from app import GoalTemplate, EmployeeGoal, GoalCheckIn, GoalProgress
from datetime import datetime, timedelta

def create_goal_setting_tables():
    """Create goal setting tables and populate with initial data"""
    with app.app_context():
        # Drop existing tables if they exist (for fresh creation)
        try:
            GoalProgress.__table__.drop(db.engine)
            GoalCheckIn.__table__.drop(db.engine)
            EmployeeGoal.__table__.drop(db.engine)
            GoalTemplate.__table__.drop(db.engine)
            print("✅ Dropped existing goal setting tables")
        except:
            print("ℹ️ Tables didn't exist, creating new ones")
        
        # Create tables
        db.create_all()
        print("✅ Created goal setting tables")
        
        # Create initial goal templates
        create_initial_templates()
        print("✅ Created initial goal templates")

def create_initial_templates():
    """Create initial goal templates for different departments"""
    templates = [
        # Engineering Department Templates
        {
            'title': 'Complete Development Environment Setup',
            'description': 'Set up local development environment, IDE, and necessary tools',
            'department': 'Engineering',
            'position': 'Software Engineer',
            'milestone_days': 30,
            'category': 'technical',
            'created_by': 1  # HR user
        },
        {
            'title': 'Understand Codebase Architecture',
            'description': 'Review and understand the main application architecture and codebase structure',
            'department': 'Engineering',
            'position': 'Software Engineer',
            'milestone_days': 30,
            'category': 'technical',
            'created_by': 1
        },
        {
            'title': 'Complete First Bug Fix',
            'description': 'Successfully implement and deploy a bug fix to production',
            'department': 'Engineering',
            'position': 'Software Engineer',
            'milestone_days': 60,
            'category': 'technical',
            'created_by': 1
        },
        {
            'title': 'Participate in Code Review',
            'description': 'Actively participate in team code reviews and provide constructive feedback',
            'department': 'Engineering',
            'position': 'Software Engineer',
            'milestone_days': 60,
            'category': 'cultural',
            'created_by': 1
        },
        {
            'title': 'Contribute to Feature Development',
            'description': 'Contribute meaningfully to a new feature from design to deployment',
            'department': 'Engineering',
            'position': 'Software Engineer',
            'milestone_days': 90,
            'category': 'technical',
            'created_by': 1
        },
        {
            'title': 'Present Technical Solution',
            'description': 'Present a technical solution or design to the team',
            'department': 'Engineering',
            'position': 'Software Engineer',
            'milestone_days': 90,
            'category': 'development',
            'created_by': 1
        },
        
        # Marketing Department Templates
        {
            'title': 'Learn Marketing Tools and Systems',
            'description': 'Master company marketing automation tools, CRM, and analytics platforms',
            'department': 'Marketing',
            'position': 'Marketing Specialist',
            'milestone_days': 30,
            'category': 'technical',
            'created_by': 1
        },
        {
            'title': 'Understand Brand Guidelines',
            'description': 'Study and apply company brand guidelines and voice in all communications',
            'department': 'Marketing',
            'position': 'Marketing Specialist',
            'milestone_days': 30,
            'category': 'cultural',
            'created_by': 1
        },
        {
            'title': 'Create First Campaign',
            'description': 'Plan and execute a complete marketing campaign from concept to analysis',
            'department': 'Marketing',
            'position': 'Marketing Specialist',
            'milestone_days': 60,
            'category': 'performance',
            'created_by': 1
        },
        {
            'title': 'Analyze Campaign Performance',
            'description': 'Analyze and report on campaign performance with actionable insights',
            'department': 'Marketing',
            'position': 'Marketing Specialist',
            'milestone_days': 60,
            'category': 'performance',
            'created_by': 1
        },
        {
            'title': 'Develop Content Strategy',
            'description': 'Develop and implement a content strategy aligned with business goals',
            'department': 'Marketing',
            'position': 'Marketing Specialist',
            'milestone_days': 90,
            'category': 'development',
            'created_by': 1
        },
        {
            'title': 'Mentor New Team Member',
            'description': 'Assist in onboarding and mentoring a new team member',
            'department': 'Marketing',
            'position': 'Marketing Specialist',
            'milestone_days': 90,
            'category': 'cultural',
            'created_by': 1
        },
        
        # HR Department Templates
        {
            'title': 'Master HR Systems',
            'description': 'Become proficient in all HRIS, ATS, and employee management systems',
            'department': 'HR',
            'position': 'HR Specialist',
            'milestone_days': 30,
            'category': 'technical',
            'created_by': 1
        },
        {
            'title': 'Understand Company Policies',
            'description': 'Study and understand all company policies, procedures, and compliance requirements',
            'department': 'HR',
            'position': 'HR Specialist',
            'milestone_days': 30,
            'category': 'cultural',
            'created_by': 1
        },
        {
            'title': 'Handle Employee Relations Case',
            'description': 'Successfully manage an employee relations case from start to finish',
            'department': 'HR',
            'position': 'HR Specialist',
            'milestone_days': 60,
            'category': 'performance',
            'created_by': 1
        },
        {
            'title': 'Improve Onboarding Process',
            'description': 'Identify and implement improvements to the employee onboarding process',
            'department': 'HR',
            'position': 'HR Specialist',
            'milestone_days': 60,
            'category': 'development',
            'created_by': 1
        },
        {
            'title': 'Lead HR Initiative',
            'description': 'Lead and implement a strategic HR initiative (wellness, engagement, etc.)',
            'department': 'HR',
            'position': 'HR Specialist',
            'milestone_days': 90,
            'category': 'development',
            'created_by': 1
        },
        {
            'title': 'Develop Training Program',
            'description': 'Design and implement a training program for managers or employees',
            'department': 'HR',
            'position': 'HR Specialist',
            'milestone_days': 90,
            'category': 'development',
            'created_by': 1
        }
    ]
    
    for template_data in templates:
        template = GoalTemplate(**template_data)
        db.session.add(template)
    
    db.session.commit()
    print(f"✅ Created {len(templates)} goal templates")

if __name__ == '__main__':
    create_goal_setting_tables()
