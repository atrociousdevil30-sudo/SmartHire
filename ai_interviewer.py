import os
import json
import openai
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

@dataclass
class InterviewQuestion:
    """Class to store interview questions and candidate responses"""
    question: str
    answer: str = ""
    analysis: Dict = None

class AIInterviewer:
    def __init__(self, openai_api_key: str = None):
        self.api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass it to the constructor.")
        
        openai.api_key = self.api_key
        self.conversation_history = []
        self.job_description = ""
        self.resume_data = None
        
    def set_job_description(self, job_description: str):
        """Set the job description for context"""
        self.job_description = job_description
        
    def set_resume_data(self, resume_data: dict):
        """Set the parsed resume data"""
        self.resume_data = resume_data
        
    def generate_initial_greeting(self) -> str:
        """Generate an initial greeting message"""
        return "Hello! Thank you for joining this interview. I'll be asking you some questions to better understand your experience and skills. Let's get started!"
    
    def generate_question(self) -> str:
        """Generate an interview question based on the conversation history"""
        try:
            prompt = self._build_prompt()
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=prompt,
                temperature=0.7,
                max_tokens=150
            )
            
            question = response.choices[0].message['content'].strip()
            self.conversation_history.append({"role": "assistant", "content": question})
            
            return question
            
        except Exception as e:
            print(f"Error generating question: {str(e)}")
            return "Could you tell me more about your experience?"
    
    def analyze_response(self, question: str, answer: str) -> Dict:
        """Analyze the candidate's response to a question"""
        try:
            prompt = [
                {"role": "system", "content": "You are an expert interviewer analyzing a candidate's response. Provide a brief analysis of the response's quality, relevance, and any red flags."},
                {"role": "user", "content": f"Job Description:\n{self.job_description}\n\nQuestion: {question}\nCandidate's Answer: {answer}"}
            ]
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=prompt,
                temperature=0.5,
                max_tokens=200
            )
            
            analysis_text = response.choices[0].message['content'].strip()
            
            score_prompt = [
                {"role": "system", "content": "Rate the candidate's response on a scale of 1-5 based on relevance, clarity, and depth of answer. Return only the number."},
                {"role": "user", "content": f"Question: {question}\nAnswer: {answer}"}
            ]
            
            score_response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=score_prompt,
                temperature=0.2,
                max_tokens=2
            )
            
            try:
                score = min(max(1, int(score_response.choices[0].message['content'].strip())), 5)
            except (ValueError, KeyError):
                score = 3
            
            return {
                "text": analysis_text,
                "score": score,
                "suggested_follow_up": self._generate_follow_up(question, answer, analysis_text)
            }
            
        except Exception as e:
            print(f"Error analyzing response: {str(e)}")
            return {"text": "Analysis unavailable", "score": 3, "suggested_follow_up": ""}
    
    def generate_summary(self) -> Dict:
        """Generate a summary of the interview"""
        if not self.conversation_history:
            return {"summary": "No interview data available.", "overall_score": 0, "recommendation": "No recommendation possible."}
        
        try:
            conversation = "\n".join([f"{msg['role']}: {msg['content']}" for msg in self.conversation_history])
            
            prompt = [
                {"role": "system", "content": "You are an expert HR professional. Provide a concise summary of this interview, highlighting the candidate's strengths, weaknesses, and overall fit for the role."},
                {"role": "user", "content": f"Job Description:\n{self.job_description}\n\nInterview Conversation:\n{conversation}"}
            ]
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=prompt,
                temperature=0.5,
                max_tokens=500
            )
            
            summary = response.choices[0].message['content'].strip()
            
            recommendation_prompt = [
                {"role": "system", "content": "Based on the interview summary, provide an overall score (1-10) and a hiring recommendation. Format as JSON with 'score' and 'recommendation' keys."},
                {"role": "user", "content": summary}
            ]
            
            rec_response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=recommendation_prompt,
                temperature=0.3,
                max_tokens=100
            )
            
            try:
                rec_data = json.loads(rec_response.choices[0].message['content'].strip())
                overall_score = rec_data.get('score', 5)
                recommendation = rec_data.get('recommendation', 'No specific recommendation provided.')
            except (json.JSONDecodeError, KeyError):
                overall_score = 5
                recommendation = 'Consider for the next round.'
            
            return {
                "summary": summary,
                "overall_score": overall_score,
                "recommendation": recommendation,
                "skills_assessed": self._extract_skills_from_interview()
            }
            
        except Exception as e:
            print(f"Error generating summary: {str(e)}")
            return {"summary": "Error generating summary.", "overall_score": 0, "recommendation": "No recommendation available."}
    
    def _build_prompt(self) -> List[Dict]:
        """Build the prompt for generating the next question"""
        prompt = [
            {"role": "system", "content": """You are a professional interviewer conducting a technical interview. 
            Ask relevant questions based on the job description and the candidate's resume. 
            Make the questions clear and specific. Ask one question at a time."""}
        ]
        
        if self.job_description:
            prompt.append({"role": "system", "content": f"Job Description: {self.job_description}"})
        
        if self.resume_data:
            resume_context = "\n".join([f"{k}: {v}" for k, v in self.resume_data.items() if v])
            prompt.append({"role": "system", "content": f"Candidate's Resume: {resume_context}"})
        
        prompt.extend(self.conversation_history)
        
        return prompt
    
    def _generate_follow_up(self, question: str, answer: str, analysis: str) -> str:
        """Generate a follow-up question based on the candidate's response"""
        try:
            prompt = [
                {"role": "system", "content": "Generate a concise follow-up question based on the candidate's answer. Keep it to one sentence."},
                {"role": "user", "content": f"Question: {question}\nAnswer: {answer}\nAnalysis: {analysis}"}
            ]
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=prompt,
                temperature=0.7,
                max_tokens=50
            )
            
            return response.choices[0].message['content'].strip()
            
        except Exception:
            return ""
    
    def _extract_skills_from_interview(self) -> List[Dict]:
        """Extract and rate skills demonstrated during the interview"""
        if not self.conversation_history:
            return []
            
        try:
            conversation = "\n".join([f"{msg['role']}: {msg['content']}" for msg in self.conversation_history])
            
            prompt = [
                {"role": "system", "content": """Analyze the interview conversation and identify the technical and soft skills demonstrated by the candidate. 
                For each skill, provide a confidence level (1-5) and a brief explanation. Format as a JSON array of objects with 'skill', 'confidence', and 'evidence' keys."""},
                {"role": "user", "content": conversation}
            ]
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=prompt,
                temperature=0.3,
                max_tokens=500
            )
            
            try:
                return json.loads(response.choices[0].message['content'].strip())
            except json.JSONDecodeError:
                return [{"skill": "Error parsing skills", "confidence": 0, "evidence": "Could not extract skills from interview."}]
                
        except Exception as e:
            print(f"Error extracting skills: {str(e)}")
            return [{"skill": "Error", "confidence": 0, "evidence": "Error processing skills analysis."}]
