#!/usr/bin/env python3
"""
Initialize default document templates for SmartHire HR Assistant
"""

from app import app, db, User, DocumentTemplate
from datetime import datetime

def create_default_templates():
    """Create default document templates"""
    
    # Get or create HR user for template ownership
    hr_user = User.query.filter_by(role='hr').first()
    if not hr_user:
        print("No HR user found. Please create an HR user first.")
        return
    
    templates = [
        {
            'name': 'Offer Letter',
            'code': 'offer_letter',
            'template_type': 'onboarding',
            'description': 'Standard employment offer letter',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>Offer Letter</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SmartHire AI Solutions</h1>
        <p>123 Tech Park, Bangalore - 560001<br>
        Phone: +91-80-1234-5678 | Email: hr@smarthire.ai</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p><strong>To,</strong><br>
        {{ employee_name }}<br>
        {{ employee_address }}</p>
        
        <p><strong>Subject: Offer of Employment</strong></p>
        
        <p>Dear <span class="highlight">{{ employee_name }}</span>,</p>
        
        <p>We are pleased to offer you the position of <span class="highlight">{{ designation }}</span> at <strong>SmartHire AI Solutions</strong>, with a starting date of <span class="highlight">{{ joining_date }}</span>.</p>
        
        <p><strong>Employment Details:</strong></p>
        <ul>
            <li><strong>Designation:</strong> {{ designation }}</li>
            <li><strong>Department:</strong> {{ department }}</li>
            <li><strong>Employee ID:</strong> {{ employee_id }}</li>
            <li><strong>CTC:</strong> {{ ctc }} per annum</li>
            <li><strong>Probation Period:</strong> 3 months</li>
            <li><strong>Working Hours:</strong> 9:30 AM - 6:30 PM, Monday - Friday</li>
        </ul>
        
        <p>This offer is conditional upon:</p>
        <ol>
            <li>Successful completion of background verification</li>
            <li>Submission of all required documents</li>
            <li>Medical fitness clearance</li>
        </ol>
        
        <p>Please confirm your acceptance of this offer by signing and returning a copy of this letter within 7 days.</p>
        
        <p>We look forward to welcoming you to the SmartHire team!</p>
        
        <div class="signature">
            <p>Warm regards,<br>
            <strong>{{ hr_name }}</strong><br>
            HR Department<br>
            SmartHire AI Solutions</p>
        </div>
    </div>
</body>
</html>'''
        },
        {
            'name': 'NDA - Non-Disclosure Agreement',
            'code': 'nda',
            'template_type': 'onboarding',
            'description': 'Confidentiality agreement for new employees',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>Non-Disclosure Agreement</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Non-Disclosure Agreement</h1>
        <p>SmartHire AI Solutions</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p>This Non-Disclosure Agreement ("Agreement") is entered into on <strong>{{ today }}</strong> between:</p>
        
        <p><strong>SmartHire AI Solutions</strong> (hereinafter "Company")</p>
        <p>AND</p>
        <p><span class="highlight">{{ employee_name }}</span> (hereinafter "Employee")</p>
        
        <h3>1. Confidential Information</h3>
        <p>Employee agrees that all information, whether written or oral, relating to the Company's business, including but not limited to:</p>
        <ul>
            <li>Trade secrets and proprietary information</li>
            <li>Customer lists and business strategies</li>
            <li>Financial information and business plans</li>
            <li>Technical processes and source code</li>
            <li>Employee information and salary data</li>
        </ul>
        
        <h3>2. Obligations</h3>
        <p>Employee shall:</p>
        <ul>
            <li>Keep all confidential information strictly private</li>
            <li>Not disclose confidential information to any third party</li>
            <li>Use confidential information only for Company business purposes</li>
            <li>Return all confidential materials upon termination</li>
        </ul>
        
        <h3>3. Duration</h3>
        <p>This Agreement shall remain in effect during Employee's employment and for 2 years after termination.</p>
        
        <h3>4. Remedies</h3>
        <p>Employee acknowledges that any breach of this Agreement may cause irreparable harm to the Company.</p>
        
        <div class="signature">
            <p><strong>Employee:</strong></p>
            <p>_________________________<br>
            {{ employee_name }}<br>
            Date: {{ today }}</p>
            
            <p><strong>Company Representative:</strong></p>
            <p>_________________________<br>
            {{ hr_name }}<br>
            HR Department<br>
            Date: {{ today }}</p>
        </div>
    </div>
</body>
</html>'''
        },
        {
            'name': 'Joining Letter',
            'code': 'joining_letter',
            'template_type': 'onboarding',
            'description': 'Welcome letter for new employee on first day',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>Joining Letter</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to SmartHire AI Solutions!</h1>
        <p>Your Journey Begins Today</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p>Dear <span class="highlight">{{ employee_name }}</span>,</p>
        
        <p>On behalf of the entire SmartHire team, I'd like to extend a warm welcome to you! We are thrilled to have you join us as <span class="highlight">{{ designation }}</span>.</p>
        
        <h3>Your First Week Schedule:</h3>
        <ul>
            <li><strong>Day 1:</strong> Orientation and IT setup</li>
            <li><strong>Day 2:</strong> Team introductions and project overview</li>
            <li><strong>Day 3:</strong> Training sessions and tool access</li>
            <li><strong>Day 4-5:</strong> Initial project assignments</li>
        </ul>
        
        <h3>Important Information:</h3>
        <ul>
            <li><strong>Employee ID:</strong> {{ employee_id }}</li>
            <li><strong>Department:</strong> {{ department }}</li>
            <li><strong>Reporting Manager:</strong> Will be introduced on Day 1</li>
            <li><strong>Work Location:</strong> 123 Tech Park, Bangalore - 560001</li>
            <li><strong>Work Hours:</strong> 9:30 AM - 6:30 PM</li>
        </ul>
        
        <h3>What to Bring on Day 1:</h3>
        <ul>
            <li>Government ID proof (Original + Copy)</li>
            <li>Pan Card (Original + Copy)</li>
            <li>Last 3 months salary slips (if applicable)</li>
            <li>Relieving letter from previous employer (if applicable)</li>
            <li>Passport size photographs (2 copies)</li>
        </ul>
        
        <p>Your buddy/mentor will be assigned to help you settle in and answer any questions during your onboarding period.</p>
        
        <p>We're excited to see you grow with us and contribute to our mission!</p>
        
        <div class="signature">
            <p>Best regards,<br>
            <strong>{{ hr_name }}</strong><br>
            HR Department<br>
            SmartHire AI Solutions</p>
        </div>
    </div>
</body>
</html>'''
        },
        {
            'name': 'Welcome Letter',
            'code': 'welcome_letter',
            'template_type': 'onboarding',
            'description': 'Personal welcome message from the CEO',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>Welcome Letter</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to the SmartHire Family!</h1>
        <p>A Message from Our CEO</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p>Dear <span class="highlight">{{ employee_name }}</span>,</p>
        
        <p>Welcome to SmartHire AI Solutions! I'm delighted to have you join our team as <span class="highlight">{{ designation }}</span>.</p>
        
        <p>At SmartHire, we believe in the power of innovation, collaboration, and continuous learning. You've chosen to be part of a team that's transforming the HR technology landscape, and your contribution will be invaluable to our journey.</p>
        
        <h3>Our Culture:</h3>
        <ul>
            <li><strong>Innovation First:</strong> We encourage creative thinking and new ideas</li>
            <li><strong>Learning Together:</strong> We grow as individuals and as a team</li>
            <li><strong>Customer Obsessed:</strong> We exist to solve our customers' problems</li>
            <li><strong>Work-Life Harmony:</strong> We believe in sustainable high performance</li>
        </ul>
        
        <h3>Your Growth Path:</h3>
        <p>Over the next 90 days, you'll go through our comprehensive onboarding program designed to help you:</p>
        <ul>
            <li>Understand our products and customers deeply</li>
            <li>Build meaningful relationships with your team</li>
            <li>Contribute to real projects from day one</li>
            <li>Develop skills that will accelerate your career</li>
        </ul>
        
        <p>Remember, every expert was once a beginner. Be curious, ask questions, and don't be afraid to make mistakes - that's how we learn and improve.</p>
        
        <p>I'm personally excited to see the impact you'll make at SmartHire. Let's build something amazing together!</p>
        
        <div class="signature">
            <p>With warm regards,<br>
            <strong>CEO, SmartHire AI Solutions</strong><br>
            Date: {{ today }}</p>
        </div>
    </div>
</body>
</html>'''
        },
        {
            'name': 'Relieving Letter',
            'code': 'relieving_letter',
            'template_type': 'offboarding',
            'description': 'Relieving letter for exiting employee',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>Relieving Letter</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Relieving Letter</h1>
        <p>SmartHire AI Solutions</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p><strong>To Whom It May Concern:</strong></p>
        
        <p>This is to certify that <span class="highlight">{{ employee_name }}</span> was employed with SmartHire AI Solutions from <strong>{{ joining_date }}</strong> until <strong>{{ today }}</strong>.</p>
        
        <p><strong>Employment Details:</strong></p>
        <ul>
            <li><strong>Employee ID:</strong> {{ employee_id }}</li>
            <li><strong>Designation:</strong> {{ designation }}</li>
            <li><strong>Department:</strong> {{ department }}</li>
            <li><strong>Last Working Day:</strong> {{ today }}</li>
        </ul>
        
        <p>During their tenure with us, {{ employee_name }} was responsible for [brief description of responsibilities]. They demonstrated professionalism, dedication, and commitment to their role.</p>
        
        <p><strong>Key Contributions:</strong></p>
        <ul>
            <li>Successfully completed multiple projects with high quality standards</li>
            <li>Maintained excellent relationships with team members and stakeholders</li>
            <li>Contributed to team goals and organizational objectives</li>
            <li>Demonstrated strong work ethic and integrity</li>
        </ul>
        
        <p>{{ employee_name }} has been relieved from their duties effective <strong>{{ today }}</strong>. All company property has been returned, and all dues have been cleared.</p>
        
        <p>We wish {{ employee_name }} the very best in their future endeavors and thank them for their valuable contributions to SmartHire AI Solutions.</p>
        
        <div class="signature">
            <p>For SmartHire AI Solutions,<br>
            <strong>{{ hr_name }}</strong><br>
            HR Department<br>
            Date: {{ today }}</p>
        </div>
    </div>
</body>
</html>'''
        },
        {
            'name': 'Experience Letter',
            'code': 'experience_letter',
            'template_type': 'offboarding',
            'description': 'Experience certificate for former employee',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>Experience Letter</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Experience Certificate</h1>
        <p>SmartHire AI Solutions</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p><strong>To Whom It May Concern:</strong></p>
        
        <p>This is to certify that <span class="highlight">{{ employee_name }}</span> has worked with SmartHire AI Solutions from <strong>{{ joining_date }}</strong> to <strong>{{ today }}</strong>.</p>
        
        <h3>Employment Summary:</h3>
        <ul>
            <li><strong>Period of Employment:</strong> {{ joining_date }} to {{ today }}</li>
            <li><strong>Total Experience:</strong> [Calculated years/months]</li>
            <li><strong>Designation:</strong> {{ designation }}</li>
            <li><strong>Department:</strong> {{ department }}</li>
            <li><strong>Employee ID:</strong> {{ employee_id }}</li>
        </ul>
        
        <h3>Job Responsibilities:</h3>
        <p>During their employment, {{ employee_name }} was responsible for:</p>
        <ul>
            <li>Developing and implementing [specific technologies/methodologies]</li>
            <li>Managing projects and ensuring timely delivery</li>
            <li>Collaborating with cross-functional teams</li>
            <li>Maintaining high standards of quality and performance</li>
            <li>Contributing to process improvements and innovations</li>
        </ul>
        
        <h3>Performance Assessment:</h3>
        <p>{{ employee_name }} demonstrated excellent performance throughout their tenure. Key strengths include:</p>
        <ul>
            <li>Strong technical skills and problem-solving abilities</li>
            <li>Effective communication and teamwork</li>
            <li>Adaptability and willingness to learn</li>
            <li>Professionalism and work ethics</li>
            <li>Leadership qualities and initiative</li>
        </ul>
        
        <p>{{ employee_name }} was a valuable member of our team and contributed significantly to our projects and organizational goals.</p>
        
        <p>We wish them continued success in their future career endeavors.</p>
        
        <div class="signature">
            <p>For SmartHire AI Solutions,<br>
            <strong>{{ hr_name }}</strong><br>
            HR Department<br>
            Date: {{ today }}</p>
        </div>
    </div>
</body>
</html>'''
        },
        {
            'name': 'No Dues Certificate',
            'code': 'no_dues_certificate',
            'template_type': 'offboarding',
            'description': 'Clearance certificate for exiting employee',
            'content': '''<!DOCTYPE html>
<html>
<head>
    <title>No Dues Certificate</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .content { margin: 30px 0; }
        .signature { margin-top: 50px; }
        .highlight { font-weight: bold; color: #2563eb; }
        .clearance-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .clearance-table th, .clearance-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .clearance-table th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>No Dues Certificate</h1>
        <p>SmartHire AI Solutions</p>
    </div>
    
    <div class="content">
        <p><strong>Date:</strong> {{ today }}</p>
        
        <p>This is to certify that <span class="highlight">{{ employee_name }}</span> (Employee ID: {{ employee_id }}) has cleared all dues with SmartHire AI Solutions as of <strong>{{ today }}</strong>.</p>
        
        <h3>Department Clearance Status:</h3>
        <table class="clearance-table">
            <tr>
                <th>Department</th>
                <th>Status</th>
                <th>Remarks</th>
            </tr>
            <tr>
                <td>IT Department</td>
                <td>CLEAR</td>
                <td>All company assets returned</td>
            </tr>
            <tr>
                <td>Admin Department</td>
                <td>CLEAR</td>
                <td>ID card and access card returned</td>
            </tr>
            <tr>
                <td>Finance Department</td>
                <td>CLEAR</td>
                <td>All financial dues cleared</td>
            </tr>
            <tr>
                <td>HR Department</td>
                <td>CLEAR</td>
                <td>All documents submitted</td>
            </tr>
            <tr>
                <td>Project Team</td>
                <td>CLEAR</td>
                <td>All project deliverables completed</td>
            </tr>
        </table>
        
        <h3>Items Returned:</h3>
        <ul>
            <li>Laptop and accessories</li>
            <li>Mobile phone (if provided)</li>
            <li>ID card and access card</li>
            <li>Company documents and files</li>
            <li>Any other company property</li>
        </ul>
        
        <h3>Final Settlement:</h3>
        <ul>
            <li><strong>Final Salary:</strong> Processed and cleared</li>
            <li><strong>Reimbursements:</strong> All claims settled</li>
            <li><strong>Bonus/Incentives:</strong> As per company policy</li>
            <li><strong>Provident Fund:</strong> Transfer initiated</li>
        </ul>
        
        <p>There are no pending dues or liabilities from either side. The employee has been relieved from all obligations and responsibilities towards the company.</p>
        
        <p>This certificate can be used for future employment verification and other official purposes.</p>
        
        <div class="signature">
            <p>For SmartHire AI Solutions,<br>
            <strong>{{ hr_name }}</strong><br>
            HR Department<br>
            Date: {{ today }}</p>
        </div>
    </div>
</body>
</html>'''
        }
    ]
    
    for template_data in templates:
        # Check if template already exists
        existing = DocumentTemplate.query.filter_by(code=template_data['code']).first()
        if existing:
            print(f"Template '{template_data['name']}' already exists. Skipping...")
            continue
        
        # Create new template
        template = DocumentTemplate(
            name=template_data['name'],
            code=template_data['code'],
            template_type=template_data['template_type'],
            description=template_data['description'],
            content=template_data['content'],
            created_by=hr_user.id,
            is_active=True
        )
        
        # Add placeholders
        placeholders = ['{{today}}', '{{employee_name}}', '{{employee_address}}', '{{designation}}', 
                       '{{company_name}}', '{{joining_date}}', '{{ctc}}', '{{hr_name}}', 
                       '{{department}}', '{{employee_id}}', '{{phone}}', '{{email}}']
        template.placeholders = str(placeholders)
        
        db.session.add(template)
        print(f"Created template: {template_data['name']}")
    
    try:
        db.session.commit()
        print("✅ All default document templates created successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating templates: {e}")

if __name__ == '__main__':
    with app.app_context():
        create_default_templates()
