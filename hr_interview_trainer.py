import os
import json
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

@dataclass
class CandidateEvaluation:
    """Class to store candidate evaluation results"""
    candidate_name: str
    interview_type: str
    evaluation_summary: str
    strengths: List[str]
    areas_for_improvement: List[str]
    recommendation: str
    confidence_score: float
    interview_date: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class HRInterviewTrainer:
    def __init__(self, gemini_api_key: str = None):
        """Initialize the HR Interview Trainer with Gemini API"""
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        if not self.gemini_api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable.")
        
        genai.configure(api_key=self.gemini_api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        self.training_data = []
        self.research_data = {}

    def research_hr_practices(self) -> Dict[str, Any]:
        """
        Research HR interview practices for onboarding and offboarding
        Returns a structured dictionary with research findings
        """
        research_prompt = """
        Research and provide detailed information about HR interview practices for onboarding and offboarding processes.
        Focus on:
        1. Common interview questions for onboarding interviews
        2. Key assessment criteria for onboarding candidates
        3. Best practices for evaluating cultural fit
        4. Red flags to watch for during interviews
        5. Effective offboarding interview questions
        6. How to assess candidate potential and fit during onboarding interviews
        
        Format the response as a JSON object with the following structure:
        {
            "onboarding": {
                "purpose": "...",
                "key_questions": ["...", "..."],
                "assessment_criteria": ["...", "..."],
                "red_flags": ["...", "..."]
            },
            "offboarding": {
                "purpose": "...",
                "key_questions": ["...", "..."],
                "insights_gained": ["...", "..."]
            },
            "evaluation_metrics": {
                "cultural_fit": ["...", "..."],
                "potential_assessment": ["...", "..."]
            }
        }
        
        Return only the JSON object with no additional text or markdown formatting.
        """
        
        try:
            response = self.model.generate_content(research_prompt)
            # Clean and parse the response
            response_text = response.text.strip()
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                response_text = response_text.split('```')[1].strip()
                
            self.research_data = json.loads(response_text)
            return self.research_data
            
        except Exception as e:
            print(f"Error during HR practices research: {str(e)}")
            return {}

    def train_on_hr_practices(self):
        """Train the model on HR interview practices"""
        if not self.research_data:
            self.research_hr_practices()
            
        training_prompt = f"""
        You are now trained as an expert HR interviewer with the following knowledge:
        
        ONBOARDING INTERVIEWS:
        Purpose: {self.research_data.get('onboarding', {}).get('purpose', '')}
        Key Questions: {', '.join(self.research_data.get('onboarding', {}).get('key_questions', []))}
        Assessment Criteria: {', '.join(self.research_data.get('onboarding', {}).get('assessment_criteria', []))}
        
        OFFBOARDING INTERVIEWS:
        Purpose: {self.research_data.get('offboarding', {}).get('purpose', '')}
        Key Questions: {', '.join(self.research_data.get('offboarding', {}).get('key_questions', []))}
        
        EVALUATION METRICS:
        Cultural Fit: {', '.join(self.research_data.get('evaluation_metrics', {}).get('cultural_fit', []))}
        Potential Assessment: {', '.join(self.research_data.get('evaluation_metrics', {}).get('potential_assessment', []))}
        
        You will use this knowledge to conduct and evaluate HR interviews effectively.
        """
        
        # In a real implementation, this would fine-tune the model
        # For now, we'll just store the training data
        self.training_data.append({
            "training_prompt": training_prompt,
            "timestamp": datetime.now().isoformat()
        })
        
        return {"status": "training_complete", "trained_on": len(self.training_data), "last_trained": datetime.now().isoformat()}

    def evaluate_candidate(self, interview_transcript: str, candidate_info: Dict[str, Any]) -> CandidateEvaluation:
        """
        Evaluate a candidate based on interview transcript and provide detailed analysis
        """
        evaluation_prompt = f"""
        You are an expert HR interviewer. Analyze the following candidate interview and provide a comprehensive evaluation.
        
        CANDIDATE INFORMATION:
        {json.dumps(candidate_info, indent=2)}
        
        INTERVIEW TRANSCRIPT:
        {interview_transcript}
        
        SCORING GUIDELINES for confidence_score (0-1):
        - 0.8-1.0: Excellent response - comprehensive, articulate, with specific examples
        - 0.6-0.7: Good response - relevant and clear with some examples
        - 0.4-0.5: Average response - basic information, minimal examples
        - 0.2-0.3: Weak response - vague, incomplete, or irrelevant
        - 0.0-0.1: Poor response - no meaningful content
        
        Provide a detailed evaluation with the following sections:
        1. Summary of the interview
        2. Key strengths demonstrated
        3. Areas for improvement
        4. Recommendation (Strong Hire, Hire, No Hire, Needs Further Evaluation)
        5. Confidence score (0-1) - use the guidelines above
        
        Format your response as a JSON object with these exact keys:
        {{
            "summary": "...",
            "strengths": ["...", "..."],
            "areas_for_improvement": ["...", "..."],
            "recommendation": "...",
            "confidence_score": 0.0,
            "next_steps": ["...", "..."]
        }}
        
        Return only the JSON object with no additional text or markdown formatting.
        """
        
        try:
            response = self.model.generate_content(evaluation_prompt)
            response_text = response.text.strip()
            
            # Clean the response
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                response_text = response_text.split('```')[1].strip()
                
            evaluation_data = json.loads(response_text)
            
            # Create evaluation object
            return CandidateEvaluation(
                candidate_name=candidate_info.get("name", "Unknown"),
                interview_type=candidate_info.get("interview_type", "onboarding"),
                evaluation_summary=evaluation_data.get("summary", ""),
                strengths=evaluation_data.get("strengths", []),
                areas_for_improvement=evaluation_data.get("areas_for_improvement", []),
                recommendation=evaluation_data.get("recommendation", "Needs Further Evaluation"),
                confidence_score=float(evaluation_data.get("confidence_score", 0.5))
            )
            
        except Exception as e:
            print(f"Error during candidate evaluation: {str(e)}")
            # Return a default evaluation in case of error
            return CandidateEvaluation(
                candidate_name=candidate_info.get("name", "Unknown"),
                interview_type=candidate_info.get("interview_type", "onboarding"),
                evaluation_summary="Error occurred during evaluation.",
                strengths=[],
                areas_for_improvement=[],
                recommendation="Needs Further Evaluation",
                confidence_score=0.0
            )

    def generate_hr_interview_questions(self, interview_type: str = "onboarding", experience_level: str = "entry") -> List[str]:
        """Generate HR interview questions based on type and experience level"""
        prompt = f"""
        Generate 10 {interview_type} interview questions suitable for a {experience_level}-level candidate.
        Focus on assessing cultural fit, work ethic, and potential.
        
        Return the questions as a JSON array of strings.
        Example: ["Question 1", "Question 2", ...]
        
        Return only the JSON array with no additional text or markdown formatting.
        """
        
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                response_text = response_text.split('```')[1].strip()
                
            return json.loads(response_text)
            
        except Exception as e:
            print(f"Error generating questions: {str(e)}")
            return [
                "Tell me about yourself and your background.",
                "Why are you interested in this position?",
                "What are your strengths and weaknesses?",
                "How do you handle workplace conflicts?",
                "Where do you see yourself in 5 years?"
            ]

# Example usage
if __name__ == "__main__":
    # Initialize the trainer
    trainer = HRInterviewTrainer()
    
    # Research HR practices
    print("Researching HR interview practices...")
    research = trainer.research_hr_practices()
    print("Research completed!")
    
    # Train the model
    print("Training model on HR practices...")
    training_result = trainer.train_on_hr_practices()
    print(f"Training complete: {training_result}")
    
    # Example: Generate onboarding questions
    print("\nSample Onboarding Questions:")
    questions = trainer.generate_hr_interview_questions("onboarding", "entry")
    for i, q in enumerate(questions, 1):
        print(f"{i}. {q}")
    
    # Example: Evaluate a candidate
    print("\nEvaluating sample candidate...")
    sample_transcript = """
    INTERVIEWER: Tell me about yourself.
    CANDIDATE: I recently graduated with a degree in Computer Science and have been working on personal projects.
    I'm particularly interested in your company's work in AI and would love to contribute to your team.
    INTERVIEWER: How do you handle tight deadlines?
    CANDIDATE: I prioritize tasks and break them into smaller, manageable parts. I also communicate early if I see potential delays.
    """
    
    candidate_info = {
        "name": "John Doe",
        "position": "Junior AI Developer",
        "experience": "0-1 years",
        "interview_type": "onboarding"
    }
    
    evaluation = trainer.evaluate_candidate(sample_transcript, candidate_info)
    print("\nEvaluation Summary:")
    print(f"Candidate: {evaluation.candidate_name}")
    print(f"Recommendation: {evaluation.recommendation}")
    print(f"Confidence: {evaluation.confidence_score:.1%}")
    print("\nStrengths:")
    for strength in evaluation.strengths:
        print(f"- {strength}")
    print("\nAreas for Improvement:")
    for area in evaluation.areas_for_improvement:
        print(f"- {area}")
