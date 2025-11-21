import os
from datetime import datetime, timedelta
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY or GEMINI_API_KEY == 'your-gemini-api-key-here':
    raise ValueError("GEMINI_API_KEY is not properly configured in .env file")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')  # Using the updated model name

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

def generate_interview_questions(difficulty_level, training_type, job_role=None, previous_responses=None):
    """Generate AI-powered interview questions based on difficulty and training type"""
    try:
        context = ""
        if previous_responses:
            context = f"\nPrevious responses for context: {previous_responses}"
        
        job_context = f"\nTarget Role: {job_role}" if job_role else ""
        
        prompt = f"""
        Generate 3-5 interview questions for {training_type} training at {difficulty_level} difficulty level.{job_context}{context}
        
        Requirements:
        1. Questions should be appropriate for {difficulty_level} level (beginner/intermediate/advanced)
        2. Focus on {training_type} skills (behavioral/technical/situational/leadership)
        3. Each question should be clear and specific
        4. Include a mix of question types if appropriate
        5. Consider previous responses to avoid repetition and build upon them
        
        Format the response as a numbered list of questions only.
        """
        
        print(f"Generating questions with prompt: {prompt[:100]}...")  # Debug log
        
        response = model.generate_content(prompt)
        print(f"Gemini response received: {response.text[:100]}...")  # Debug log
        
        return response.text
    except Exception as e:
        print(f"Error generating interview questions: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        # Return fallback questions if AI fails
        fallback_questions = get_fallback_questions(difficulty_level, training_type)
        return fallback_questions

def get_fallback_questions(difficulty_level, training_type):
    """Provide fallback questions when AI generation fails"""
    questions = {
        'behavioral': {
            'beginner': [
                "1. Tell me about a time you worked well in a team.",
                "2. Describe a situation where you had to learn something new.",
                "3. How do you handle stress at work?"
            ],
            'intermediate': [
                "1. Tell me about a time you had to resolve a conflict with a coworker.",
                "2. Describe a situation where you took initiative on a project.",
                "3. How do you prioritize your tasks when facing multiple deadlines?"
            ],
            'advanced': [
                "1. Describe a time you had to make a difficult decision with limited information.",
                "2. Tell me about a situation where you had to influence senior management.",
                "3. How do you handle failure and what do you learn from it?"
            ]
        },
        'technical': {
            'beginner': [
                "1. What programming languages are you most comfortable with?",
                "2. How do you approach debugging a problem?",
                "3. Describe a recent technical project you worked on."
            ],
            'intermediate': [
                "1. How do you ensure code quality in your projects?",
                "2. Describe a complex technical problem you solved recently.",
                "3. How do you stay updated with new technologies?"
            ],
            'advanced': [
                "1. Describe a time you had to optimize a system for performance.",
                "2. How do you approach system design challenges?",
                "3. Tell me about a time you had to make architectural decisions."
            ]
        },
        'situational': {
            'beginner': [
                "1. How would you handle a missed deadline?",
                "2. What would you do if you disagreed with your manager's decision?",
                "3. How would you handle receiving constructive criticism?"
            ],
            'intermediate': [
                "1. How would you handle a project that's falling behind schedule?",
                "2. What would you do if you noticed a security vulnerability in the code?",
                "3. How would you mediate a conflict between team members?"
            ],
            'advanced': [
                "1. How would you handle a major system outage during peak hours?",
                "2. What would you do if you discovered ethical issues in a project?",
                "3. How would you handle a situation where you need to cut features to meet deadlines?"
            ]
        },
        'leadership': {
            'beginner': [
                "1. How do you motivate team members?",
                "2. Describe your leadership style.",
                "3. How do you delegate tasks effectively?"
            ],
            'intermediate': [
                "1. How do you handle underperforming team members?",
                "2. Describe a time you had to lead a project without formal authority.",
                "3. How do you balance team needs with project requirements?"
            ],
            'advanced': [
                "1. How do you build and maintain team culture?",
                "2. Describe a time you had to make an unpopular decision for the team.",
                "3. How do you develop leadership skills in your team members?"
            ]
        }
    }
    
    return '\n'.join(questions.get(training_type, {}).get(difficulty_level, questions['behavioral']['intermediate']))

def generate_follow_up_question(original_question, candidate_answer, difficulty_level, training_type):
    """Generate follow-up questions based on candidate responses"""
    try:
        prompt = f"""
        Generate a relevant follow-up question based on this exchange:
        
        Original Question: {original_question}
        Candidate's Answer: {candidate_answer}
        Difficulty Level: {difficulty_level}
        Training Type: {training_type}
        
        Requirements:
        1. The follow-up should dig deeper into the candidate's response
        2. Maintain the same difficulty level
        3. Be relevant to the training type
        4. Be specific and actionable
        5. Help assess the candidate's capabilities more thoroughly
        
        Provide only the follow-up question, nothing else.
        """
        
        print(f"Generating follow-up question...")  # Debug log
        
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"Error generating follow-up question: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        # Return fallback follow-up question
        fallback_followups = [
            "Can you provide more specific details about that experience?",
            "How did that situation impact the project outcome?",
            "What would you do differently in a similar situation?",
            "Can you elaborate on the technical aspects you mentioned?",
            "How did you collaborate with your team on this?"
        ]
        return fallback_followups[0]  # Return first fallback

def analyze_interview_response(question, answer, difficulty_level, training_type):
    """Analyze interview response and provide constructive feedback"""
    try:
        prompt = f"""
        Analyze this interview response and provide comprehensive feedback:
        
        Question: {question}
        Candidate's Answer: {answer}
        Difficulty Level: {difficulty_level}
        Training Type: {training_type}
        
        Provide feedback in the following format:
        
        **Response Quality Assessment:**
        - Clarity: [Rate 1-5 with brief explanation]
        - Relevance: [Rate 1-5 with brief explanation]
        - Depth: [Rate 1-5 with brief explanation]
        
        **Strengths:**
        - [List 2-3 specific strengths demonstrated]
        
        **Areas for Improvement:**
        - [List 2-3 specific areas with actionable suggestions]
        
        **Overall Score:** [1-10]
        
        **Next Steps:**
        - [Specific recommendations for improvement]
        """
        
        print(f"Analyzing interview response...")  # Debug log
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error analyzing interview response: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        # Return fallback feedback
        fallback_feedback = f"""
        **Response Quality Assessment:**
        - Clarity: 3/5 - Response is moderately clear
        - Relevance: 3/5 - Response addresses the question
        - Depth: 3/5 - Response provides basic information
        
        **Strengths:**
        - Provided a response to the question
        - Showed willingness to engage
        
        **Areas for Improvement:**
        - Provide more specific examples
        - Structure your response more clearly
        - Add more detail to your answers
        
        **Overall Score:** 6/10
        
        **Next Steps:**
        - Practice with the STAR method (Situation, Task, Action, Result)
        - Prepare specific examples before interviews
        - Focus on quantifiable achievements
        """
        return fallback_feedback

def generate_interview_summary(interview_data, overall_score=None):
    """Generate a comprehensive interview summary with actionable insights"""
    try:
        score_context = f"\nOverall Score: {overall_score}" if overall_score else ""
        
        prompt = f"""
        Generate a comprehensive interview summary based on this data:
        
        {interview_data}{score_context}
        
        Include the following sections:
        
        **Interview Overview:**
        - Brief summary of the interview session
        
        **Key Strengths Demonstrated:**
        - Top 3-5 strengths shown during the interview
        
        **Areas Needing Development:**
        - Specific areas that need improvement
        
        **Skill Assessment:**
        - Technical skills evaluation
        - Soft skills evaluation
        
        **Recommendations:**
        - Specific actionable recommendations for improvement
        - Suggested training or practice areas
        
        **Next Steps:**
        - Clear next steps for the candidate
        """
        
        print(f"Generating interview summary...")  # Debug log
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error generating interview summary: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        # Return fallback summary
        fallback_summary = """
        **Interview Overview:**
        - The interview session has been completed with multiple question-response interactions.
        
        **Key Strengths Demonstrated:**
        - Active participation throughout the interview
        - Willingness to provide detailed responses
        - Engagement with the interview process
        
        **Areas Needing Development:**
        - Providing more specific examples and metrics
        - Structuring responses using frameworks like STAR
        - Demonstrating deeper technical knowledge where applicable
        
        **Skill Assessment:**
        - Communication Skills: Moderate - Clear expression with room for improvement
        - Problem-Solving: Developing - Shows basic approach to challenges
        - Technical Knowledge: Varies by role - Continue building domain expertise
        
        **Recommendations:**
        - Practice behavioral questions using the STAR method
        - Prepare 3-5 specific examples with quantifiable results
        - Research common interview questions for your target role
        - Consider mock interviews with peers or mentors
        
        **Next Steps:**
        - Review the feedback from each question response
        - Focus on areas where improvement was suggested
        - Practice with similar questions to build confidence
        - Consider additional training in identified weak areas
        """
        return fallback_summary

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
