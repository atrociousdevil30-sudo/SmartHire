#!/usr/bin/env python3
"""
Migrate document templates to add the 'code' field
"""

from app import app, db, DocumentTemplate
from sqlalchemy import text

def migrate_document_templates():
    """Add code column to document_templates table"""
    
    try:
        # Add the code column using raw SQL
        with app.app_context():
            # Check if column already exists
            result = db.session.execute(text("PRAGMA table_info(document_templates)"))
            columns = [row[1] for row in result]
            
            if 'code' not in columns:
                print("Adding 'code' column to document_templates table...")
                db.session.execute(text("ALTER TABLE document_templates ADD COLUMN code VARCHAR(50)"))
                print("✅ Code column added successfully!")
            else:
                print("✅ Code column already exists!")
            
            # Update existing templates with default codes
            existing_templates = DocumentTemplate.query.all()
            for template in existing_templates:
                if not template.code:
                    # Generate code based on template name and type
                    base_code = template.name.lower().replace(' ', '_').replace('-', '_')
                    # Remove special characters
                    import re
                    base_code = re.sub(r'[^a-z0-9_]', '', base_code)
                    
                    # Make sure code is unique
                    counter = 1
                    code = base_code
                    while DocumentTemplate.query.filter_by(code=code).first():
                        code = f"{base_code}_{counter}"
                        counter += 1
                    
                    template.code = code
                    print(f"Updated template '{template.name}' with code: {code}")
            
            try:
                db.session.commit()
                print("✅ Database migration completed successfully!")
            except Exception as e:
                db.session.rollback()
                print(f"❌ Error updating templates: {e}")
                
    except Exception as e:
        print(f"❌ Migration error: {e}")

if __name__ == '__main__':
    migrate_document_templates()
