import os
import json
import google.generativeai as genai
from typing import List, Dict, Optional, Union, Any, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from hr_interview_trainer import HRInterviewTrainer, CandidateEvaluation

@dataclass
class InterviewQuestion:
    """Class to store interview questions and candidate responses"""
    question: str
    answer: str = ""
    analysis: Dict = None

@dataclass
class InterviewResult:
    """Class to store interview results and analysis"""
    questions: List[Dict[str, str]] = field(default_factory=list)
    answers: List[Dict[str, str]] = field(default_factory=list)
    analysis: Dict[str, Any] = field(default_factory=dict)
    evaluation: Optional[CandidateEvaluation] = None
    recommendation: str = ""
    confidence_score: float = 0.0

class AIInterviewer:
    def __init__(self, gemini_api_key: str = None, is_fresher: bool = False):
        # Initialize Gemini
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        if not self.gemini_api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable or pass it to the constructor.")
        
        genai.configure(api_key=self.gemini_api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
        # Initialize HR Interview Trainer
        self.hr_trainer = HRInterviewTrainer(gemini_api_key=self.gemini_api_key)
        
        self.conversation_history: List[Dict[str, str]] = []
        self.job_description = ""
        self.resume_data: Dict[str, Any] = {}
        self.is_fresher = is_fresher
        self.interview_type = "technical"  # Can be 'technical', 'hr', or 'behavioral'
        self.interview_phase = "introduction"  # Tracks interview progress
        self.interview_result = InterviewResult()
        
    def set_job_description(self, job_description: str):
        """Set the job description for context"""
        self.job_description = job_description
        
    def set_resume_data(self, resume_data: dict):
        """Set the parsed resume data"""
        self.resume_data = resume_data
        
    def generate_initial_greeting(self) -> str:
        """Generate an initial greeting message"""
        if self.is_fresher:
            return "Hello! Welcome to your interview. I'll be asking you some questions to better understand your potential, academic background, and eagerness to learn. Don't worry if you don't have work experience - we're interested in your knowledge and attitude. Let's get started!"
        return "Hello! Thank you for joining this interview. I'll be asking you some questions to better understand your experience and skills. Let's get started!"
    
    def generate_question(self) -> str:
        """Generate an interview question based on the conversation history"""
        try:
            if self.interview_type == "hr":
                return self._generate_hr_question()
            return self._generate_gemini_question()
            
        except Exception as e:
            print(f"Error generating question: {str(e)}")
            return "Could you tell me more about your experience?"
    
    def analyze_response(self, question: str, answer: str) -> Dict[str, Any]:
        """Analyze the candidate's response to a question"""
        try:
            if self.interview_type == "hr":
                # Use HR trainer for HR interviews
                return self._analyze_hr_response(question, answer)
            return self._analyze_with_gemini(question, answer)
            
        except Exception as e:
            print(f"Error analyzing response: {str(e)}")
            return {
                "text": "Error analyzing response. Please try again.",
                "score": 3,
                "suggested_follow_up": "",
                "strengths": [],
                "areas_for_improvement": []
            }
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of the interview using Gemini"""
        if not self.conversation_history:
            return {
                "summary": "No interview data available.",
                "overall_score": 0,
                "recommendation": "No recommendation possible.",
                "strengths": [],
                "areas_for_improvement": [],
                "confidence_score": 0
            }
        
        try:
            # Format conversation history
            conversation = "\n".join([f"{msg['role']}: {msg['content']}" for msg in self.conversation_history])
            
            # Build the prompt for Gemini
            prompt = f"""
            You are an expert HR professional. Provide a concise summary of this interview, 
            highlighting the candidate's strengths, weaknesses, and overall fit for the role.
            
            Job Title: {self.job_description.split('\n')[0] if self.job_description else 'Not specified'}
            
            Interview Conversation:
            {conversation}
            
            Please provide a structured response with the following sections:
            1. Overall assessment
            2. Key strengths
            3. Areas for improvement
            4. Recommendation (Strong Hire, Hire, No Hire, or Needs Further Evaluation)
            5. Confidence score (0-100%)
            
            Format your response as a JSON object with these exact keys:
            {{
                "summary": "Overall assessment of the candidate's performance",
                "overall_score": 85,
                "recommendation": "Hire",
                "strengths": ["list", "of", "strengths"],
                "areas_for_improvement": ["list", "of", "areas", "for", "improvement"],
                "confidence_score": 85
            }}
            """
            
            # Generate the summary using Gemini
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Parse the response
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                response_text = response_text.split('```')[1].strip()
                
            summary = json.loads(response_text)
            
            # Ensure all required fields are present
            return {
                "summary": summary.get("summary", "No summary available"),
                "overall_score": summary.get("overall_score", 0),
                "recommendation": summary.get("recommendation", "Needs Further Evaluation"),
                "strengths": summary.get("strengths", []),
                "areas_for_improvement": summary.get("areas_for_improvement", []),
                "confidence_score": summary.get("confidence_score", 0),
                "skills_assessed": self._extract_skills_from_interview()
            }
            
        except Exception as e:
            print(f"Error generating summary: {str(e)}")
            return {"summary": "Error generating summary.", "overall_score": 0, "recommendation": "No recommendation available."}
    
    def _build_gemini_prompt(self) -> str:
        """Build a prompt for the Gemini model"""
        role = ""
        
        if self.interview_type == "hr":
            if self.is_fresher:
                role = """You are an experienced HR professional conducting an interview for a fresher candidate. 
                Focus on assessing their potential, attitude, communication skills, and cultural fit.
                Ask behavioral and situational questions to understand their problem-solving approach and work ethic.
                Be supportive and help them feel comfortable. Ask one question at a time."""
            else:
                role = """You are an experienced HR professional conducting an interview. 
                Focus on assessing the candidate's experience, problem-solving abilities, and cultural fit.
                Ask about their past experiences, challenges they've faced, and how they've handled workplace situations.
                Make the questions clear and specific. Ask one question at a time."""
        elif self.is_fresher:
            role = """You are a friendly and encouraging technical interviewer for a fresher candidate. 
            Focus on assessing their potential, academic knowledge, and problem-solving skills.
            Ask questions that help evaluate their understanding of fundamental concepts and ability to learn.
            Be supportive and make the candidate feel comfortable. Ask one question at a time."""
        else:
            role = """You are a professional technical interviewer. 
            Ask relevant technical questions based on the job description and the candidate's experience. 
            Make the questions clear, specific, and progressively challenging. Ask one question at a time."""
        
        # Build context
        context = []
        if self.job_description:
            context.append(f"Job Description: {self.job_description}")
            
        if self.resume_data:
            resume_context = "\n".join([f"{k}: {v}" for k, v in self.resume_data.items() if v])
            context_label = "Candidate's Academic Background" if self.is_fresher else "Candidate's Resume"
            context.append(f"{context_label}: {resume_context}")
        
        # Format conversation history
        conversation = "\n".join([
            f"{'Interviewer' if msg['role'] == 'assistant' else 'Candidate'}: {msg['content']}" 
            for msg in self.conversation_history
        ])
        
        # Combine everything into a single prompt
        prompt = f"""{role}
        
        Context:
        {chr(10).join(context) if context else 'No additional context provided.'}
        
        Conversation so far:
        {conversation if conversation else 'No conversation history yet.'}
        
        Generate a single, clear interview question based on the context and conversation so far.
        The question should be relevant to the candidate's background and the job requirements.
        
        Return only the question with no additional text or formatting.
        """
        
        return prompt
    
    def _generate_follow_up(self, question: str, answer: str, analysis: str) -> str:
        """Generate a follow-up question based on the candidate's response"""
        try:
            prompt = f"""Based on the candidate's response to the interview question, generate a relevant follow-up question.
            
            Interview Type: {self.interview_type}
            Original Question: {question}
            Candidate's Answer: {answer}
            Analysis: {analysis}
            
            Generate a concise follow-up question (one sentence) that digs deeper into their response.
            Focus on understanding their thought process, experience, or skills better.
            
            Return only the follow-up question with no additional text.
            """
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
                
        except Exception as e:
            print(f"Error generating follow-up: {str(e)}")
            return ""
    
    def set_interview_type(self, interview_type: str):
        """Set the type of interview (technical, hr, behavioral)"""
        valid_types = ["technical", "hr", "behavioral"]
        if interview_type.lower() not in valid_types:
            raise ValueError(f"Invalid interview type. Must be one of: {', '.join(valid_types)}")
        self.interview_type = interview_type.lower()
        
        # Initialize HR trainer if this is an HR interview
        if self.interview_type == "hr":
            self.hr_trainer.research_hr_practices()
            self.hr_trainer.train_on_hr_practices()
    
    def _generate_gemini_question(self) -> str:
        """Generate a question using Gemini model"""
        try:
            prompt = f"""
            You are conducting a {'fresher' if self.is_fresher else 'professional'} {self.interview_type} interview for the following position:
            
            Job Description: {self.job_description}
            
            Candidate's Background:
            {self._format_resume_for_prompt()}
            
            Previous conversation:
            {self._format_conversation_history()}
            
            Generate a relevant, insightful question that helps assess the candidate's suitability for this role.
            Focus on {self._get_interview_focus()}.
            
            Return only the question, no additional text or formatting.
            """
            
            response = self.gemini_model.generate_content(prompt)
            question = response.text.strip()
            self.conversation_history.append({"role": "assistant", "content": question})
            return question
            
        except Exception as e:
            print(f"Error generating Gemini question: {str(e)}")
            # Fall back to OpenAI if Gemini fails
            return self._generate_openai_question()
    
    def get_interview_summary(self) -> Dict[str, Any]:
        """Get a summary of the completed interview"""
        if not self.interview_result.questions:
            return {"error": "No interview data available"}
            
        # Calculate average score if available
        if self.interview_result.answers:
            scores = [ans.get("analysis", {}).get("score", 0) for ans in self.interview_result.answers]
            avg_score = sum(scores) / len(scores) if scores else 0
        else:
            avg_score = self.interview_result.confidence_score * 5  # Convert 0-1 to 0-5 scale
        
        # Get all strengths and areas for improvement
        all_strengths = []
        all_improvements = []
        
        if self.interview_result.evaluation:
            all_strengths = self.interview_result.evaluation.strengths
            all_improvements = self.interview_result.evaluation.areas_for_improvement
        else:
            for ans in self.interview_result.answers:
                analysis = ans.get("analysis", {})
                all_strengths.extend(analysis.get("strengths", []))
                all_improvements.extend(analysis.get("areas_for_improvement", []))
        
        # Remove duplicates while preserving order
        all_strengths = list(dict.fromkeys(all_strengths))
        all_improvements = list(dict.fromkeys(all_improvements))
        
        return {
            "interview_type": self.interview_type,
            "candidate_type": "Fresher" if self.is_fresher else "Experienced",
            "total_questions": len(self.interview_result.questions),
            "average_score": round(avg_score, 1),
            "recommendation": self.interview_result.recommendation or "Needs Further Evaluation",
            "confidence_score": round(self.interview_result.confidence_score * 100, 1) if hasattr(self.interview_result, 'confidence_score') else 0,
            "key_strengths": all_strengths[:5],  # Top 5 strengths
            "areas_for_improvement": all_improvements[:5],  # Top 5 areas for improvement
            "questions_asked": [q["question"] for q in self.interview_result.questions],
            "detailed_analysis": self.interview_result.analysis or {}
        }
    
    def _build_gemini_prompt(self) -> str:
        """Build a prompt for Gemini model"""
        prompt = f"""You are conducting a {'fresher' if self.is_fresher else 'professional'} {self.interview_type} interview.
        
Job Description: {self.job_description}

Candidate's Background:
{self._format_resume_for_prompt()}

Previous conversation:
{self._format_conversation_history()}

Generate a relevant, insightful question that helps assess the candidate's suitability for this role.
Focus on {self._get_interview_focus()}.

Return only the question, no additional text or formatting."""
        return prompt
    
    def _analyze_hr_response(self, question: str, answer: str) -> Dict[str, Any]:
        """Analyze HR interview response using HR trainer"""
        # Add to conversation history
        self.conversation_history.append({"role": "user", "content": answer})
        
        # Format the interview transcript
        transcript = "\n".join([
            f"{'Interviewer' if msg['role'] == 'assistant' else 'Candidate'}: {msg['content']}"
            for msg in self.conversation_history
        ])
        
        # Debug: Print what's being sent to HR trainer
        print(f"DEBUG - HR Trainer Transcript:\n{transcript}")
        print(f"DEBUG - Conversation History: {self.conversation_history}")
        
        # Create candidate info
        candidate_info = {
            "name": self.resume_data.get("name", "Candidate"),
            "position": self.job_description.split("\n")[0] if self.job_description else "Position not specified",
            "experience": "0-1 years" if self.is_fresher else "Experienced",
            "interview_type": "onboarding" if "onboard" in self.interview_phase.lower() else "offboarding"
        }
        
        # Debug: Print candidate info
        print(f"DEBUG - Candidate Info: {candidate_info}")
        
        # Get evaluation from HR trainer
        evaluation = self.hr_trainer.evaluate_candidate(transcript, candidate_info)
        
        # Debug: Print evaluation result
        print(f"DEBUG - HR Evaluation: {evaluation}")
        
        # Store evaluation results
        self.interview_result.evaluation = evaluation
        self.interview_result.recommendation = evaluation.recommendation
        self.interview_result.confidence_score = evaluation.confidence_score
        
        # Format analysis result
        analysis = {
            "text": evaluation.evaluation_summary,
            "score": int(evaluation.confidence_score * 10),  # Convert 0-1 to 1-10 scale
            "strengths": evaluation.strengths,
            "areas_for_improvement": evaluation.areas_for_improvement,
            "recommendation": evaluation.recommendation,
            "confidence_score": evaluation.confidence_score,
            "suggested_follow_up": ""  # Will be set by generate_question
        }
        
        # Add to interview results
        self.interview_result.analysis = analysis
        self.interview_result.answers.append({
            "question": question,
            "answer": answer,
            "analysis": analysis
        })
        
        return analysis
        
    def _analyze_with_gemini(self, question: str, answer: str) -> Dict[str, Any]:
        """Analyze response using Gemini model for non-HR interviews"""
        try:
            prompt = f"""Analyze the candidate's response to this {self.interview_type} interview question.
            
            Job Description: {self.job_description}
            Candidate Type: {'Fresher' if self.is_fresher else 'Experienced'}
            
            Question: {question}
            Candidate's Answer: {answer}
            
            Provide a detailed analysis focusing on:
            1. Relevance and completeness of the answer
            2. Demonstrated knowledge and skills
            3. Communication skills
            4. Areas for improvement
            
            Also provide a score from 1-10 (1=Poor, 10=Excellent) and a brief justification.
            
            Format your response as a JSON object with these fields:
            {{
                "analysis": "Detailed analysis of the response",
                "score": 7,
                "strengths": ["list", "of", "strengths"],
                "areas_for_improvement": ["list", "of", "areas"],
                "follow_up_suggestion": "Suggested follow-up question"
            }}
            
            Return only the JSON object with no additional text or markdown formatting.
            """
            
            response = self.model.generate_content(prompt)
            
            # Extract JSON from response
            response_text = response.text.strip()
            if '```json' in response_text:
                # Extract JSON from markdown code block
                json_str = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                # Extract JSON from code block without json specifier
                json_str = response_text.split('```')[1].strip()
            else:
                json_str = response_text
                
            result = json.loads(json_str)
            
            # Store in interview results
            analysis = {
                "text": result.get("analysis", "Analysis not available"),
                "score": result.get("score", 7),
                "suggested_follow_up": result.get("follow_up_suggestion", ""),
                "strengths": result.get("strengths", []),
                "areas_for_improvement": result.get("areas_for_improvement", [])
            }
            
            self.interview_result.answers.append({
                "question": question,
                "answer": answer,
                "analysis": analysis
            })
            
            return analysis
            
        except Exception as e:
            print(f"Error in analysis: {str(e)}")
            return {
                "text": "Error analyzing response. Please try again.",
                "score": 7,
                "suggested_follow_up": "",
                "strengths": [],
                "areas_for_improvement": []
            }
    
    def _generate_hr_question(self) -> str:
        """Generate an HR interview question using HR trainer"""
        try:
            # Get questions based on interview phase
            questions = self.hr_trainer.generate_hr_interview_questions(
                interview_type="onboarding" if "onboard" in self.interview_phase.lower() else "offboarding",
                experience_level="entry" if self.is_fresher else "experienced"
            )
            
            # Select a question that hasn't been asked yet
            asked_questions = [q["question"] for q in self.interview_result.questions]
            for question in questions:
                if question not in asked_questions:
                    # Add to conversation history
                    self.conversation_history.append({"role": "assistant", "content": question})
                    
                    # Add to interview results
                    self.interview_result.questions.append({
                        "question": question,
                        "type": self.interview_type,
                        "phase": self.interview_phase
                    })
                    
                    return question
            
            # If no new questions, generate a follow-up
            return self._generate_follow_up_question()
            
        except Exception as e:
            print(f"Error generating HR question: {str(e)}")
            return "Could you tell me more about your experience?"
            
    def _generate_follow_up_question(self) -> str:
        """Generate a follow-up question based on the last response"""
        if not self.conversation_history:
            return "Could you tell me more about yourself?"
            
        last_question = next((msg["content"] for msg in reversed(self.conversation_history) 
                             if msg["role"] == "assistant"), "")
        last_answer = next((msg["content"] for msg in reversed(self.conversation_history) 
                           if msg["role"] == "user"), "")
        
        prompt = f"""
        Based on the candidate's last response, generate a relevant follow-up question.
        
        Last Question: {last_question}
        Candidate's Response: {last_answer}
        
        Generate a single, clear follow-up question that digs deeper into their response.
        Focus on understanding their thought process, experience, or skills better.
        
        Return only the question with no additional text or formatting.
        """
        
        try:
            response = self.model.generate_content(prompt)
            question = response.text.strip()
            self.conversation_history.append({"role": "assistant", "content": question})
            
            # Add to interview results
            self.interview_result.questions.append({
                "question": question,
                "type": "follow_up",
                "phase": self.interview_phase
            })
            
            return question
            
        except Exception as e:
            print(f"Error generating follow-up question: {str(e)}")
            return "Could you elaborate on that?"
    
    def _generate_gemini_question(self) -> str:
        """Generate a question using Gemini model for non-HR interviews"""
        try:
            prompt = self._build_gemini_prompt()
            response = self.model.generate_content(prompt)
            question = response.text.strip()
            
            # Add to conversation history
            self.conversation_history.append({"role": "assistant", "content": question})
            
            # Add to interview results
            self.interview_result.questions.append({
                "question": question,
                "type": self.interview_type,
                "phase": self.interview_phase
            })
            
            return question
            
        except Exception as e:
            print(f"Error generating question: {str(e)}")
            return "Could you tell me more about your experience?"
    
    def _format_resume_for_prompt(self) -> str:
        """Format resume data for the prompt"""
        if not self.resume_data:
            return "No resume information available."
        
        return "\n".join([f"- {k}: {v}" for k, v in self.resume_data.items() if v])
    
    def _format_conversation_history(self, max_messages: int = 5) -> str:
        """Format the conversation history for the prompt"""
        if not self.conversation_history:
            return "No previous conversation."
            
        # Get the most recent messages
        recent_messages = self.conversation_history[-max_messages:]
        return "\n".join([f"{msg['role'].capitalize()}: {msg['content']}" for msg in recent_messages])
    
    def _get_interview_focus(self) -> str:
        """Get the focus area for the interview based on type"""
        focus_map = {
            "technical": "technical skills, problem-solving abilities, and knowledge of relevant technologies",
            "hr": "communication skills, cultural fit, work ethic, and behavioral competencies",
            "behavioral": "past experiences, decision-making processes, and how they handle various work situations"
        }
        return focus_map.get(self.interview_type, "relevant skills and experiences")
    
    def _extract_skills_from_interview(self) -> List[Dict[str, Any]]:
        """Extract and rate skills demonstrated during the interview using Gemini"""
        if not self.conversation_history:
            return []
            
        try:
            conversation = "\n".join([f"{msg['role']}: {msg['content']}" for msg in self.conversation_history])
            
            prompt = f"""Analyze the following interview conversation and identify the technical and soft skills demonstrated by the candidate.
            
            Conversation:
            {conversation}
            
            For each skill, provide:
            - skill: The name of the skill
            - type: Either 'technical' or 'soft'
            - confidence: A score from 1-5 (1=low, 5=high)
            - example: A brief example from the conversation
            
            Format your response as a JSON array of objects. Example:
            [
                {
                    "skill": "Python Programming",
                    "type": "technical",
                    "confidence": 4,
                    "example": "Candidate mentioned using Python for data analysis"
                }
            ]
            
            Return only the JSON array with no additional text or markdown formatting.
            """
            
            response = self.gemini_model.generate_content(prompt)
            
            # Extract JSON from response
            response_text = response.text.strip()
            if '```json' in response_text:
                json_str = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                json_str = response_text.split('```')[1].strip()
            else:
                json_str = response_text
                
            try:
                skills = json.loads(json_str)
                return skills if isinstance(skills, list) else []
            except json.JSONDecodeError as e:
                print(f"Error parsing skills JSON: {str(e)}")
                return []
                
        except Exception as e:
            print(f"Error extracting skills: {str(e)}")
            return []
