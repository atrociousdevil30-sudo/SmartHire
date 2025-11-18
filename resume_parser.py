import os
import re
import json
import magic
import spacy
import PyPDF2
import docx
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict

# Load the English language model for spaCy
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("Downloading language model for the spaCy (en_core_web_sm)...")
    from spacy.cli import download
    download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

@dataclass
class ResumeData:
    """Class to store parsed resume data"""
    name: str = ""
    email: str = ""
    phone: str = ""
    skills: List[str] = None
    experience: List[Dict] = None
    education: List[Dict] = None
    raw_text: str = ""

class ResumeParser:
    def __init__(self):
        self.nlp = nlp
        self.skills = self._load_skills_list()
        
    def _load_skills_list(self) -> set:
        """Load a predefined list of technical skills"""
        skills = {
            # Programming Languages
            'Python', 'JavaScript', 'Java', 'C++', 'C#', 'Ruby', 'PHP',
            'Swift', 'Kotlin', 'Go', 'Rust', 'TypeScript', 'HTML', 'CSS',
            # Frameworks
            'Django', 'Flask', 'React', 'Angular', 'Vue', 'Node.js',
            'Spring', 'Ruby on Rails', 'Laravel', '.NET', 'TensorFlow',
            'PyTorch', 'scikit-learn', 'Pandas', 'NumPy', 'Docker', 'Kubernetes',
            # Tools & Platforms
            'Git', 'AWS', 'Azure', 'Google Cloud', 'MongoDB', 'PostgreSQL',
            'MySQL', 'SQL', 'NoSQL', 'Linux', 'Docker', 'Kubernetes',
            'CI/CD', 'Jenkins', 'GitHub Actions', 'REST API', 'GraphQL'
        }
        return skills

    def extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from PDF file"""
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
        return text

    def extract_text_from_docx(self, file_path: str) -> str:
        """Extract text from DOCX file"""
        doc = docx.Document(file_path)
        return "\n".join([paragraph.text for paragraph in doc.paragraphs])

    def extract_text(self, file_path: str) -> str:
        """Extract text from file based on its type"""
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        
        if file_type == 'application/pdf':
            return self.extract_text_from_pdf(file_path)
        elif file_type in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                          'application/msword']:
            return self.extract_text_from_docx(file_path)
        else:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()

    def extract_name(self, text: str) -> str:
        """Extract candidate name from resume text"""
        doc = self.nlp(text[:1000])  # Only check the first 1000 characters for name
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                return ent.text
        return ""

    def extract_email(self, text: str) -> str:
        """Extract email address from resume text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        match = re.search(email_pattern, text)
        return match.group(0) if match else ""

    def extract_phone(self, text: str) -> str:
        """Extract phone number from resume text"""
        phone_pattern = r'(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        match = re.search(phone_pattern, text)
        return match.group(0) if match else ""

    def extract_skills(self, text: str) -> List[str]:
        """Extract skills from resume text"""
        doc = self.nlp(text.lower())
        found_skills = set()
        
        # Check for exact matches
        for token in doc:
            if token.text in self.skills:
                found_skills.add(token.text)
        
        # Check for n-grams (phrases)
        for i in range(len(doc) - 1):
            phrase = f"{doc[i].text} {doc[i+1].text}"
            if phrase in self.skills:
                found_skills.add(phrase)
        
        return list(found_skills)

    def extract_experience(self, text: str) -> List[Dict]:
        """Extract work experience from resume text"""
        # This is a simplified version - in production, you'd want to use more sophisticated NLP
        experience = []
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        current_exp = {}
        for i, line in enumerate(lines):
            # Look for job title patterns
            if any(role in line.lower() for role in ['developer', 'engineer', 'manager', 'analyst', 'specialist']):
                if current_exp:
                    experience.append(current_exp)
                    current_exp = {}
                current_exp['title'] = line
            
            # Look for company names (very basic pattern matching)
            elif ' at ' in line.lower() and 'company' not in current_exp:
                current_exp['company'] = line.split(' at ')[-1]
            
            # Look for date ranges (simplified)
            elif re.search(r'\d{4}\s*[-–]\s*(?:Present|\d{4})', line):
                current_exp['duration'] = line
        
        if current_exp:
            experience.append(current_exp)
            
        return experience

    def parse_resume(self, file_path: str) -> ResumeData:
        """Parse resume file and return structured data"""
        try:
            text = self.extract_text(file_path)
            resume_data = ResumeData()
            resume_data.raw_text = text
            resume_data.name = self.extract_name(text)
            resume_data.email = self.extract_email(text)
            resume_data.phone = self.extract_phone(text)
            resume_data.skills = self.extract_skills(text)
            resume_data.experience = self.extract_experience(text)
            # Note: Education extraction would be implemented similarly to experience
            
            return resume_data
            
        except Exception as e:
            print(f"Error parsing resume: {str(e)}")
            return ResumeData()

    def to_json(self, resume_data: ResumeData) -> str:
        """Convert ResumeData object to JSON"""
        return json.dumps(asdict(resume_data), indent=2)

# Example usage
if __name__ == "__main__":
    parser = ResumeParser()
    resume_path = input("Enter path to resume file: ")
    if os.path.exists(resume_path):
        result = parser.parse_resume(resume_path)
        print("\nParsed Resume Data:")
        print(parser.to_json(result))
    else:
        print("File not found. Please check the file path.")
