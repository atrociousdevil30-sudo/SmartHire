import os
from datetime import datetime, timedelta
from flask import jsonify
import google.generativeai as genai
from dotenv import load_dotenv
from app import db
from app import User  # Import User from app where it's defined

# Load environment variables
load_dotenv()

# Configure Gemini
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY or GEMINI_API_KEY == 'your-gemini-api-key-here':
    raise ValueError("GEMINI_API_KEY is not properly configured in .env file")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

def generate_onboarding_checklist(employee_name, position, department):
    """Generate a personalized onboarding checklist using AI"""
    try:
        prompt = f"""
        Create a detailed onboarding checklist for a new {position} in the {department} department.
        Include tasks for:
        1. First day activities
        2. First week tasks
        3. First month goals
        4. Department-specific training
        5. Company policies to review
        
        Format as a list of tasks with descriptions. Keep each task concise but clear.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error generating onboarding checklist: {str(e)}")
        return None

def analyze_employee_sentiment(feedback_text):
    """Analyze employee feedback for sentiment and key themes"""
    try:
        prompt = f"""
        Analyze the following employee feedback and provide:
        1. Overall sentiment (positive, neutral, negative)
        2. Key themes mentioned
        3. Suggested actions for HR
        
        Feedback: {feedback_text}
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error analyzing sentiment: {str(e)}")
        return None

def generate_interview_feedback(interview_responses):
    """Generate detailed feedback on interview responses"""
    try:
        prompt = f"""
        As an HR professional, provide detailed feedback on these interview responses.
        For each response, evaluate:
        1. Clarity and structure
        2. Relevance to the question
        3. Evidence of skills/experience
        4. Areas for improvement
        
        Interview Responses:
        {interview_responses}
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error generating interview feedback: {str(e)}")
        return None

def generate_employee_report(employee_data):
    """Generate a comprehensive employee performance report"""
    try:
        prompt = f"""
        Create a detailed performance report for an employee with the following data:
        {employee_data}
        
        Include:
        1. Performance summary
        2. Key achievements
        3. Areas for improvement
        4. Development recommendations
        5. Next steps for growth
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error generating employee report: {str(e)}")
        return None
