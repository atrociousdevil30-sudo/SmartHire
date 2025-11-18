document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const startInterviewSection = document.getElementById('startInterview');
    const interviewContainer = document.getElementById('interviewContainer');
    const chatContainer = document.getElementById('chatContainer');
    const interviewForm = document.getElementById('interviewForm');
    const candidateResponse = document.getElementById('candidateResponse');
    const submitBtn = document.getElementById('submitResponseBtn');
    const submitText = document.getElementById('submitText');
    const submitSpinner = document.getElementById('submitSpinner');
    const summaryCard = document.getElementById('summaryCard');
    const interviewSummary = document.getElementById('interviewSummary');
    const downloadPdfBtn = document.getElementById('downloadPdfBtn');
    
    // Interview questions
    const questions = [
        "Can you tell me about yourself and your experience?",
        "What interests you about this position and our company?",
        "Can you describe a challenging project you worked on and how you handled it?",
        "How do you approach problem-solving when you encounter a technical challenge?",
        "Where do you see yourself in 5 years?"
    ];
    
    // Interview state
    let currentQuestionIndex = 0;
    let interviewData = {
        startTime: null,
        endTime: null,
        responses: [],
        analysis: {}
    };
    
    // Start the interview
    document.getElementById('startInterviewBtn')?.addEventListener('click', startInterview);
    
    // Handle form submission
    if (interviewForm) {
        interviewForm.addEventListener('submit', handleResponse);
    }
    
    // Auto-resize textarea
    if (candidateResponse) {
        candidateResponse.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    }
    
    // Download PDF button
    if (downloadPdfBtn) {
        downloadPdfBtn.addEventListener('click', generatePdf);
    }
    
    // Start the interview
    function startInterview() {
        // Update UI
        startInterviewSection.classList.add('d-none');
        interviewContainer.classList.remove('d-none');
        interviewForm.classList.remove('d-none');
        
        // Initialize interview data
        interviewData.startTime = new Date();
        interviewData.responses = [];
        
        // Add welcome message
        addMessage("Hello! Welcome to your interview. I'll be asking you a few questions to learn more about your experience and skills. Let's get started!", 'ai');
        
        // Ask first question
        setTimeout(() => {
            askQuestion();
        }, 1000);
    }
    
    // Ask the current question
    function askQuestion() {
        if (currentQuestionIndex < questions.length) {
            const question = questions[currentQuestionIndex];
            addMessage(question, 'ai');
        } else {
            // Interview complete
            completeInterview();
        }
    }
    
    // Handle candidate's response
    function handleResponse(e) {
        e.preventDefault();
        
        const response = candidateResponse.value.trim();
        if (!response) return;
        
        // Disable form while processing
        candidateResponse.disabled = true;
        submitBtn.disabled = true;
        submitText.textContent = 'Processing...';
        submitSpinner.classList.remove('d-none');
        
        // Add user's response to chat
        addMessage(response, 'user');
        
        // Save response
        interviewData.responses.push({
            question: questions[currentQuestionIndex],
            answer: response,
            timestamp: new Date()
        });
        
        // Clear input
        candidateResponse.value = '';
        candidateResponse.style.height = 'auto';
        
        // Simulate AI processing
        setTimeout(() => {
            // Move to next question
            currentQuestionIndex++;
            
            // Re-enable form for next question
            candidateResponse.disabled = false;
            submitBtn.disabled = false;
            submitText.textContent = 'Submit';
            submitSpinner.classList.add('d-none');
            
            // Ask next question or complete interview
            if (currentQuestionIndex < questions.length) {
                askQuestion();
            } else {
                completeInterview();
            }
            
            // Focus on the input field
            candidateResponse.focus();
        }, 1000);
    }
    
    // Complete the interview and show summary
    function completeInterview() {
        interviewData.endTime = new Date();
        interviewForm.classList.add('d-none');
        
        // Add completion message
        addMessage("Thank you for completing the interview! Here's a summary of your responses.", 'ai');
        
        // Generate and display summary
        generateSummary();
        
        // Show summary card
        summaryCard.classList.remove('d-none');
        
        // Save interview data (in a real app, this would be an API call)
        saveInterviewData();
    }
    
    // Generate interview summary
    function generateSummary() {
        // Simple analysis (in a real app, this would be more sophisticated)
        const wordCounts = interviewData.responses.map(r => r.answer.split(/\s+/).length);
        const totalWords = wordCounts.reduce((a, b) => a + b, 0);
        const avgWords = Math.round(totalWords / wordCounts.length);
        
        // Check for keywords
        const keywords = {
            'team': 0,
            'problem': 0,
            'solution': 0,
            'learn': 0,
            'improve': 0,
            'challenge': 0,
            'success': 0
        };
        
        interviewData.responses.forEach(response => {
            const answer = response.answer.toLowerCase();
            Object.keys(keywords).forEach(keyword => {
                if (answer.includes(keyword)) {
                    keywords[keyword]++;
                }
            });
        });
        
        // Generate summary HTML
        let summaryHTML = `
            <div class="mb-4">
                <h5 class="mb-3">Interview Summary</h5>
                <div class="row">
                    <div class="col-md-4">
                        <div class="card bg-light">
                            <div class="card-body">
                                <h6 class="card-title">Overview</h6>
                                <p class="mb-1"><small>Questions Answered:</small> ${interviewData.responses.length}</p>
                                <p class="mb-1"><small>Total Words:</small> ${totalWords}</p>
                                <p class="mb-0"><small>Avg. Words per Answer:</small> ${avgWords}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-8">
                        <div class="card bg-light">
                            <div class="card-body">
                                <h6 class="card-title">Key Themes</h6>
                                <div class="d-flex flex-wrap gap-2">
                                    ${Object.entries(keywords)
                                        .filter(([_, count]) => count > 0)
                                        .map(([word, count]) => 
                                            `<span class="badge bg-primary">${word} (${count})</span>`
                                        ).join('')}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <h5 class="mt-4 mb-3">Question & Answer Review</h5>
        `;
        
        // Add each Q&A
        interviewData.responses.forEach((response, index) => {
            summaryHTML += `
                <div class="card mb-3">
                    <div class="card-header bg-light">
                        <strong>Question ${index + 1}:</strong> ${response.question}
                    </div>
                    <div class="card-body">
                        <p class="mb-0">${response.answer}</p>
                        <div class="mt-2 text-muted">
                            <small>Response length: ${wordCounts[index]} words</small>
                        </div>
                    </div>
                </div>
            `;
        });
        
        // Add overall feedback
        summaryHTML += `
            <div class="card border-success">
                <div class="card-header bg-success text-white">
                    <strong>Overall Feedback</strong>
                </div>
                <div class="card-body">
                    <p>${generateOverallFeedback()}</p>
                    <div class="alert alert-info mb-0">
                        <i class="bi bi-info-circle me-2"></i>
                        This feedback is generated automatically. A member of our team will review your responses and contact you with next steps.
                    </div>
                </div>
            </div>
        `;
        
        interviewSummary.innerHTML = summaryHTML;
    }
    
    // Generate overall feedback based on responses
    function generateOverallFeedback() {
        const wordCounts = interviewData.responses.map(r => r.answer.split(/\s+/).length);
        const totalWords = wordCounts.reduce((a, b) => a + b, 0);
        const avgWords = Math.round(totalWords / wordCounts.length);
        
        let feedback = "";
        
        // Feedback based on response length
        if (avgWords < 30) {
            feedback += "Your responses were quite brief. In future interviews, try to provide more detailed examples to better showcase your experience and skills. ";
        } else if (avgWords > 100) {
            feedback += "Your responses were very detailed, which is great! Just be mindful of being too verbose to ensure you're directly answering the questions. ";
        } else {
            feedback += "Your responses were well-balanced in terms of detail and conciseness. ";
        }
        
        // Check for specific content
        const allText = interviewData.responses.map(r => r.answer.toLowerCase()).join(' ');
        
        if (allText.includes('i ') && allText.includes(' we ')) {
            feedback += "You effectively balanced discussing both individual contributions and teamwork, which is excellent. ";
        } else if (allText.includes('i ')) {
            feedback += "You focused primarily on your individual contributions. Consider also highlighting how you've worked in team settings. ";
        } else if (allText.includes(' we ')) {
            feedback += "You emphasized teamwork, which is great. Don't forget to also highlight your specific contributions and achievements. ";
        }
        
        // Check for problem-solving approach
        if (allText.includes('problem') && allText.includes('solution')) {
            feedback += "You demonstrated strong problem-solving skills by clearly explaining challenges and how you addressed them. ";
        }
        
        // Check for learning/growth
        if (allText.includes('learn') || allText.includes('grow') || allText.includes('improve')) {
            feedback += "Your responses show a growth mindset and willingness to learn, which are valuable traits. ";
        }
        
        // Final encouragement
        feedback += "Overall, you presented yourself professionally. We appreciate the time you took to complete this interview.";
        
        return feedback;
    }
    
    // Save interview data (mock function)
    function saveInterviewData() {
        // In a real app, this would be an API call to your backend
        console.log('Saving interview data:', interviewData);
        
        // Store in localStorage for demo purposes
        const interviews = JSON.parse(localStorage.getItem('interviews') || '[]');
        interviews.push({
            id: 'interview-' + Date.now(),
            ...interviewData,
            candidate: {
                name: 'Demo Candidate',
                position: 'Software Engineer',
                applicationDate: new Date().toISOString()
            }
        });
        localStorage.setItem('interviews', JSON.stringify(interviews));
    }
    
    // Generate PDF (mock function)
    function generatePdf() {
        // In a real app, this would use a library like jsPDF or make an API call
        alert('In a real application, this would generate and download a PDF of your interview summary.');
        
        // Example of what you might do:
        /*
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Add content to PDF
        doc.text('Interview Summary', 20, 20);
        // ... more PDF generation code ...
        
        // Save the PDF
        doc.save('interview-summary.pdf');
        */
    }
    
    // Helper function to add a message to the chat
    function addMessage(text, sender) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message message-${sender}`;
        
        // Format the message with line breaks
        const formattedText = text.replace(/\n/g, '<br>');
        
        // Add avatar for AI
        if (sender === 'ai') {
            messageDiv.innerHTML = `
                <div class="d-flex">
                    <div class="flex-shrink-0 me-2">
                        <div class="avatar-sm bg-primary text-white rounded-circle d-flex align-items-center justify-content-center" style="width: 32px; height: 32px;">
                            <i class="bi bi-robot"></i>
                        </div>
                    </div>
                    <div>
                        <div class="message-content">${formattedText}</div>
                        <div class="text-muted small mt-1">${formatTime(new Date())}</div>
                    </div>
                </div>
            `;
        } else {
            // User message
            messageDiv.innerHTML = `
                <div class="d-flex justify-content-end">
                    <div class="text-end" style="max-width: 80%;">
                        <div class="message-content">${formattedText}</div>
                        <div class="text-muted small mt-1">${formatTime(new Date())}</div>
                    </div>
                    <div class="flex-shrink-0 ms-2">
                        <div class="avatar-sm bg-secondary text-white rounded-circle d-flex align-items-center justify-content-center" style="width: 32px; height: 32px;">
                            <i class="bi bi-person"></i>
                        </div>
                    </div>
                </div>
            `;
        }
        
        chatContainer.appendChild(messageDiv);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
    
    // Helper function to format time
    function formatTime(date) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
});
