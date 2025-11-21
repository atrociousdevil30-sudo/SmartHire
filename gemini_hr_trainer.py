import os
import google.generativeai as genai
from typing import List, Dict, Optional
import json
from datetime import datetime

class GeminiHRTrainer:
    def __init__(self, api_key: str = None):
        """Initialize the Gemini HR Trainer with API key"""
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable or pass it to the constructor.")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        self.training_data = []
        
    def add_training_example(self, role: str, context: str, question: str, ideal_answer: str, 
                           evaluation_criteria: List[str], is_fresher: bool = False):
        """Add a training example to the dataset"""
        self.training_data.append({
            'role': role,
            'context': context,
            'question': question,
            'ideal_answer': ideal_answer,
            'evaluation_criteria': evaluation_criteria,
            'is_fresher': is_fresher,
            'timestamp': datetime.now().isoformat()
        })
    
    def generate_hr_interview_questions(self, job_title: str, is_fresher: bool = False) -> List[Dict]:
        """Generate HR interview questions based on job title and candidate type"""
        prompt = f"""
        You are an experienced HR professional. Generate 10 interview questions for a {job_title} position.
        The candidate is a {'fresher' if is_fresher else 'professional'}.
        
        For each question, provide:
        1. The question
        2. What the interviewer should look for in the answer
        3. Sample ideal answer
        4. Evaluation criteria
        
        Format the response as a JSON array of objects with these fields:
        - question
        - what_to_look_for
        - ideal_answer
        - evaluation_criteria (array of strings)
        """
        
        try:
            response = self.model.generate_content(prompt)
            questions = json.loads(response.text)
            
            # Add to training data
            for q in questions:
                self.add_training_example(
                    role="HR Interviewer",
                    context=f"Interview for {job_title} position",
                    question=q['question'],
                    ideal_answer=q['ideal_answer'],
                    evaluation_criteria=q['evaluation_criteria'],
                    is_fresher=is_fresher
                )
                
            return questions
            
        except Exception as e:
            print(f"Error generating questions: {str(e)}")
            return []
    
    def train_model(self):
        """Train the model using the collected training data"""
        if not self.training_data:
            print("No training data available. Add examples first.")
            return None
        
        try:
            # Fine-tune the model with the training data
            # Note: Actual fine-tuning would require using the Gemini API's fine-tuning endpoint
            # This is a simplified version that just creates a prompt template
            
            training_prompt = """
            You are an expert HR interviewer. Based on the following training data, 
            learn how to conduct effective HR interviews.
            
            Training Examples:
            """
            
            for i, example in enumerate(self.training_data, 1):
                training_prompt += f"""
                Example {i}:
                - Role: {example['role']}
                - Context: {example['context']}
                - Question: {example['question']}
                - Ideal Answer: {example['ideal_answer']}
                - Evaluation Criteria: {', '.join(example['evaluation_criteria'])}
                - Candidate Type: {'Fresher' if example['is_fresher'] else 'Experienced'}
                """
            
            training_prompt += """
            
            Based on these examples, learn to:
            1. Ask relevant HR interview questions
            2. Evaluate candidate responses effectively
            3. Adapt your approach based on candidate experience level
            4. Provide constructive feedback
            """
            
            # In a real implementation, you would save this prompt or use it with the fine-tuning API
            return {
                'status': 'success',
                'training_examples': len(self.training_data),
                'last_trained': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error in training: {str(e)}")
            return None
    
    def save_training_data(self, filename: str = 'hr_training_data.json'):
        """Save the training data to a file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.training_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving training data: {str(e)}")
            return False
    
    def load_training_data(self, filename: str = 'hr_training_data.json'):
        """Load training data from a file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.training_data = json.load(f)
            return True
        except FileNotFoundError:
            print("Training data file not found. Starting with empty dataset.")
            self.training_data = []
            return False
        except Exception as e:
            print(f"Error loading training data: {str(e)}")
            return False

# Example usage
if __name__ == "__main__":
    # Initialize with your Gemini API key
    trainer = GeminiHRTrainer(api_key="YOUR_GEMINI_API_KEY")
    
    # Generate some example questions
    questions = trainer.generate_hr_interview_questions("Software Engineer", is_fresher=True)
    print(f"Generated {len(questions)} HR interview questions for freshers.")
    
    # Train the model
    training_result = trainer.train_model()
    if training_result:
        print(f"Training completed with {training_result['training_examples']} examples.")
    
    # Save the training data
    if trainer.save_training_data():
        print("Training data saved successfully.")
    else:
        print("Failed to save training data.")
