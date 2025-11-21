#!/usr/bin/env python3
"""
Create Social Integration Events Database Tables
This script creates all necessary tables for social integration features.
"""

import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, TeamBuildingActivity, ActivityParticipant, CrossDepartmentIntroduction
from app import SocialEvent, SocialEventAttendee, BuddyMentorSystem, BuddyMentorMeeting
from app import CommunicationSkillsTraining, TrainingParticipant

def create_social_integration_tables():
    """Create all social integration related tables"""
    print("🚀 Starting social integration table creation...")
    print("=" * 50)
    
    success = True
    
    try:
        with app.app_context():
            # List of all social integration tables to create
            tables = [
                TeamBuildingActivity,
                ActivityParticipant,
                CrossDepartmentIntroduction,
                SocialEvent,
                SocialEventAttendee,
                BuddyMentorSystem,
                BuddyMentorMeeting,
                CommunicationSkillsTraining,
                TrainingParticipant
            ]
            
            print("Creating social integration communication tables...")
            
            for table in tables:
                try:
                    table.__table__.create(db.engine, checkfirst=True)
                    print(f"✅ {table.__tablename__} - created")
                except Exception as e:
                    print(f"❌ {table.__tablename__} - error: {e}")
                    success = False
            
            print("=" * 50)
            if success:
                print("✅ All social integration tables created successfully!")
                
                # Verify table creation
                print("\n📋 Table Verification:")
                inspector = db.inspect(db.engine)
                existing_tables = inspector.get_table_names()
                
                table_names = [
                    'team_building_activity',
                    'activity_participant',
                    'cross_department_introduction',
                    'social_event',
                    'social_event_attendee',
                    'buddy_mentor_system',
                    'buddy_mentor_meeting',
                    'communication_skills_training',
                    'training_participant'
                ]
                
                for table_name in table_names:
                    if table_name in existing_tables:
                        print(f"✅ {table_name} - exists")
                    else:
                        print(f"❌ {table_name} - missing")
                        success = False
                
                print(f"\n📊 Total tables in database: {len(existing_tables)}")
                
            else:
                print("❌ Some tables failed to create. Please check the error above.")
                sys.exit(1)
                
    except Exception as e:
        print(f"❌ Critical error: {e}")
        sys.exit(1)
    
    return success

if __name__ == "__main__":
    success = create_social_integration_tables()
    
    print("=" * 50)
    if success:
        print("🎉 Social integration events system is ready!")
        
        print("\n📝 Features added:")
        print("   • Team-building activities scheduling")
        print("   • Cross-departmental introductions")
        print("   • Social events coordination")
        print("   • Buddy/mentor system beyond HR")
        print("   • Communication skills training")
        print("   • Comprehensive statistics tracking")
        
        print("\n🌐 Access the system at: /social-integration")
        print("\n📊 Industry Standard: 44% of employees desire more communication skills training")
    else:
        print("❌ Table creation failed. Please check the error above.")
        sys.exit(1)
