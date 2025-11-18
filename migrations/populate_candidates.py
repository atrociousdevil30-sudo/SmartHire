import os
import sys
from datetime import datetime

# Add the parent directory to the path so we can import app
dir_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(dir_path)

from app import app, db, Candidate

def create_sample_candidates():
    """Create sample candidates in the database."""
    sample_candidates = [
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
- Machine Learning, Data Analysis""",
            'score': 92.5,
            'summary': 'Experienced Python developer with expertise in building scalable applications and leading development teams.'
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
- HTML, CSS, JavaScript""",
            'score': 88.2,
            'summary': 'Creative UX/UI designer with a strong background in user-centered design and research.'
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
- Data Visualization, Big Data""",
            'score': 95.0,
            'summary': 'Data scientist with expertise in machine learning, statistical analysis, and big data technologies.'
        }
    ]

    # Add candidates to database
    for candidate_data in sample_candidates:
        candidate = Candidate(
            name=candidate_data['name'],
            job_desc=candidate_data['job_desc'],
            resume_text=candidate_data['resume_text'],
            score=candidate_data['score'],
            summary=candidate_data['summary'],
            created_at=datetime.utcnow()
        )
        db.session.add(candidate)
    
    try:
        db.session.commit()
        print("Successfully added sample candidates to the database.")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding sample candidates: {str(e)}")
        raise

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables if they don't exist
        db.create_all()
        
        # Clear existing candidates to avoid duplicates
        Candidate.query.delete()
        db.session.commit()
        
        # Add sample candidates
        create_sample_candidates()
