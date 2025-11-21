#!/usr/bin/env python3
"""
Create pre-onboarding communication tables
"""

import os
import sys
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, PreOnboardingTask, WelcomePackage, FirstDayAgenda, TeamIntroduction

def create_pre_onboarding_tables():
    """Create all pre-onboarding related tables"""
    with app.app_context():
        print("Creating pre-onboarding communication tables...")
        
        try:
            # Create all tables
            db.create_all()
            print("✅ All pre-onboarding tables created successfully!")
            
            # Verify tables exist
            tables_to_check = [
                'pre_onboarding_task',
                'welcome_package', 
                'first_day_agenda',
                'team_introduction'
            ]
            
            print("\n📋 Table Verification:")
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            for table in tables_to_check:
                if table in existing_tables:
                    print(f"✅ {table} - exists")
                else:
                    print(f"❌ {table} - missing")
                    
            print(f"\n📊 Total tables in database: {len(existing_tables)}")
            
        except Exception as e:
            print(f"❌ Error creating tables: {e}")
            return False
            
        return True

if __name__ == "__main__":
    print("🚀 Starting pre-onboarding table creation...")
    print("=" * 50)
    
    success = create_pre_onboarding_tables()
    
    print("=" * 50)
    if success:
        print("🎉 Pre-onboarding communication system is ready!")
        print("\n📝 Features added:")
        print("   • Welcome packages & swag tracking")
        print("   • Pre-first-day administrative tasks")
        print("   • First-day agenda sharing")
        print("   • Early team introductions")
        print("   • Communication timeline")
        print("\n🌐 Access the enhanced system at: /pre-onboarding")
    else:
        print("❌ Table creation failed. Please check the error above.")
        sys.exit(1)
