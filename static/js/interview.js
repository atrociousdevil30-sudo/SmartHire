document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const trainingSetupForm = document.getElementById('trainingSetupForm');
    const chatContainer = document.getElementById('chatContainer');
    const responseForm = document.getElementById('responseForm');
    const userResponse = document.getElementById('userResponse');
    const submitResponse = document.getElementById('submitResponse');
    const submitText = document.getElementById('submitText');
    const submitSpinner = document.getElementById('submitSpinner');
    const typingIndicator = document.getElementById('typingIndicator');
    const trainingSummary = document.getElementById('trainingSummary');
    const summaryContent = document.getElementById('summaryContent');
    const sessionStatus = document.getElementById('sessionStatus');
    const questionCounter = document.getElementById('questionCounter');
    const totalQuestions = document.getElementById('totalQuestions');
    const skipQuestion = document.getElementById('skipQuestion');
    const resetSession = document.getElementById('resetSession');
    const startNewSession = document.getElementById('startNewSession');
    const downloadReport = document.getElementById('downloadReport');
    
    // Training configurations
    const trainingQuestions = {
        interview: {
            beginner: [
                "Tell me about yourself.",
                "Why are you interested in this position?",
                "What are your strengths?",
                "Where do you see yourself in 5 years?"
            ],
            intermediate: [
                "Describe a challenging situation you faced and how you handled it.",
                "How do you handle working under pressure?",
                "Tell me about a time you had to work with a difficult team member.",
                "What motivates you in your work?",
                "How do you prioritize multiple tasks?"
            ],
            advanced: [
                "Describe a time when you had to make a difficult decision with limited information.",
                "How would you handle a situation where you disagree with your manager?",
                "Tell me about a time you failed and what you learned from it.",
                "How do you stay current with industry trends?",
                "Describe your leadership style."
            ]
        },
        technical: {
            beginner: [
                "Explain the difference between a class and an object.",
                "What is a database and why is it important?",
                "Describe what an API is in simple terms."
            ],
            intermediate: [
                "How would you optimize a slow database query?",
                "Explain the concept of version control.",
                "What are the benefits of automated testing?"
            ],
            advanced: [
                "Design a system to handle 1 million concurrent users.",
                "Explain microservices architecture and its trade-offs.",
                "How would you implement a caching strategy?"
            ]
        }
    };
    
    // Training state
    let currentSession = {
        type: null,
        difficulty: null,
        questions: [],
        currentIndex: 0,
        responses: [],
        startTime: null,
        focusAreas: []
    };
    
    // Event Listeners
    if (trainingSetupForm) {
        trainingSetupForm.addEventListener('submit', startTrainingSession);
    }
    
    if (responseForm) {
        responseForm.addEventListener('submit', handleResponse);
    }
    
    if (skipQuestion) {
        skipQuestion.addEventListener('click', skipCurrentQuestion);
    }
    
    if (resetSession) {
        resetSession.addEventListener('click', resetTrainingSession);
    }
    
    if (startNewSession) {
        startNewSession.addEventListener('click', resetTrainingSession);
    }
    
    if (downloadReport) {
        downloadReport.addEventListener('click', downloadTrainingReport);
    }
    
    // Auto-resize textarea
    if (userResponse) {
        userResponse.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    }
    
    // Start training session
    function startTrainingSession(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const type = document.getElementById('trainingType').value;
        const difficulty = document.getElementById('difficultyLevel').value;
        
        // Get focus areas
        const focusAreas = [];
        if (document.getElementById('communication').checked) focusAreas.push('communication');
        if (document.getElementById('problemSolving').checked) focusAreas.push('problemSolving');
        if (document.getElementById('leadership').checked) focusAreas.push('leadership');
        
        // Initialize session
        currentSession = {
            type,
            difficulty,
            questions: trainingQuestions[type]?.[difficulty] || trainingQuestions.interview.beginner,
            currentIndex: 0,
            responses: [],
            startTime: new Date(),
            focusAreas
        };
        
        // Update UI
        clearChat();
        sessionStatus.textContent = 'Active';
        sessionStatus.className = 'badge bg-success';
        responseForm.classList.remove('d-none');
        trainingSummary.classList.add('d-none');
        
        // Update counters
        totalQuestions.textContent = currentSession.questions.length;
        questionCounter.textContent = '1';
        
        // Start session
        addMessage(`Welcome to your ${type} training session! I'll help you practice and improve your skills. Let's begin with the first question.`, 'ai');
        
        setTimeout(() => {
            askQuestion();
        }, 1500);
    }
    
    // Ask the current question
    async function askQuestion() {
        if (currentSession.currentIndex < currentSession.questions.length) {
            showTypingIndicator();
            
            try {
                const questionResponse = await fetch('/api/ai/generate-question', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        type: currentSession.type,
                        difficulty: currentSession.difficulty,
                        questionIndex: currentSession.currentIndex,
                        previousResponses: currentSession.responses
                    })
                });
                
                const data = await questionResponse.json();
                hideTypingIndicator();
                
                if (data.success) {
                    addMessage(data.question, 'ai');
                } else {
                    // Fallback to predefined questions
                    const question = currentSession.questions[currentSession.currentIndex];
                    addMessage(question, 'ai');
                }
            } catch (error) {
                hideTypingIndicator();
                console.error('Error generating question:', error);
                // Fallback to predefined questions
                const question = currentSession.questions[currentSession.currentIndex];
                addMessage(question, 'ai');
            }
            
            userResponse.focus();
        } else {
            completeTraining();
        }
    }
    
    // Handle user response
    function handleResponse(e) {
        e.preventDefault();
        
        const response = userResponse.value.trim();
        if (!response) return;
        
        // Disable form while processing
        userResponse.disabled = true;
        submitResponse.disabled = true;
        submitText.textContent = 'Processing...';
        submitSpinner.classList.remove('d-none');
        
        // Add user's response to chat
        addMessage(response, 'user');
        
        // Save response
        currentSession.responses.push({
            question: currentSession.questions[currentSession.currentIndex],
            answer: response,
            timestamp: new Date(),
            skipped: false
        });
        
        // Clear input
        userResponse.value = '';
        userResponse.style.height = 'auto';
        
        // Generate AI feedback
        generateAIFeedback(response).then(() => {
            // Move to next question
            currentSession.currentIndex++;
            questionCounter.textContent = currentSession.currentIndex + 1;
            
            // Re-enable form
            userResponse.disabled = false;
            submitResponse.disabled = false;
            submitText.textContent = 'Submit';
            submitSpinner.classList.add('d-none');
            
            // Continue or complete
            setTimeout(() => {
                if (currentSession.currentIndex < currentSession.questions.length) {
                    askQuestion();
                } else {
                    completeTraining();
                }
            }, 1500);
        });
    }
    
    // Skip current question
    function skipCurrentQuestion() {
        currentSession.responses.push({
            question: currentSession.questions[currentSession.currentIndex],
            answer: '[Skipped]',
            timestamp: new Date(),
            skipped: true
        });
        
        addMessage('Question skipped. Let\'s move to the next one.', 'ai');
        
        currentSession.currentIndex++;
        questionCounter.textContent = currentSession.currentIndex + 1;
        
        setTimeout(() => {
            if (currentSession.currentIndex < currentSession.questions.length) {
                askQuestion();
            } else {
                completeTraining();
            }
        }, 1000);
    }
    
    // Complete training session
    async function completeTraining() {
        responseForm.classList.add('d-none');
        sessionStatus.textContent = 'Completed';
        sessionStatus.className = 'badge bg-success';
        
        addMessage('Excellent work! You\'ve completed the training session. Let me analyze your responses and provide comprehensive feedback.', 'ai');
        
        showTypingIndicator();
        
        try {
            const summaryResponse = await fetch('/api/ai/generate-summary', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    session: currentSession,
                    responses: currentSession.responses
                })
            });
            
            const data = await summaryResponse.json();
            hideTypingIndicator();
            
            if (data.success) {
                generateTrainingSummaryWithAI(data.summary);
            } else {
                generateTrainingSummary();
            }
        } catch (error) {
            hideTypingIndicator();
            console.error('Error generating AI summary:', error);
            generateTrainingSummary();
        }
        
        trainingSummary.classList.remove('d-none');
    }
    
    // Generate AI feedback for response
    async function generateAIFeedback(response) {
        showTypingIndicator();
        
        try {
            const feedbackResponse = await fetch('/api/ai/generate-feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    response: response,
                    question: currentSession.questions[currentSession.currentIndex],
                    type: currentSession.type,
                    difficulty: currentSession.difficulty
                })
            });
            
            const data = await feedbackResponse.json();
            hideTypingIndicator();
            
            if (data.success) {
                addMessage(data.feedback, 'ai');
            } else {
                addMessage('I\'m having trouble generating feedback right now. Let\'s continue with the next question.', 'ai');
            }
        } catch (error) {
            hideTypingIndicator();
            console.error('Error generating AI feedback:', error);
            addMessage('Let\'s continue with the next question.', 'ai');
        }
    }
    
    // Generate contextual feedback
    function generateContextualFeedback(response) {
        const wordCount = response.split(/\s+/).length;
        const hasExamples = response.toLowerCase().includes('example') || response.toLowerCase().includes('instance');
        const isStructured = response.includes('.') && response.split('.').length > 2;
        
        let feedback = "Good response! ";
        
        if (wordCount < 20) {
            feedback += "Try to provide more detail and specific examples to strengthen your answer. ";
        } else if (wordCount > 100) {
            feedback += "Great detail! Just ensure you stay focused on the key points. ";
        }
        
        if (hasExamples) {
            feedback += "I appreciate that you included specific examples - this makes your response much stronger. ";
        } else {
            feedback += "Consider adding a specific example to illustrate your point. ";
        }
        
        if (isStructured) {
            feedback += "Your response is well-structured and easy to follow.";
        } else {
            feedback += "Try organizing your thoughts with clear beginning, middle, and end.";
        }
        
        return feedback;
    }
    
    // Generate training summary
    function generateTrainingSummary() {
        const completedResponses = currentSession.responses.filter(r => !r.skipped);
        const skippedCount = currentSession.responses.filter(r => r.skipped).length;
        const avgWordCount = completedResponses.length > 0 ? 
            Math.round(completedResponses.reduce((sum, r) => sum + r.answer.split(/\s+/).length, 0) / completedResponses.length) : 0;
        
        const duration = Math.round((new Date() - currentSession.startTime) / 1000 / 60);
        
        let summaryHTML = `
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-primary">${completedResponses.length}</div>
                        <small class="text-muted">Questions Completed</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-success">${avgWordCount}</div>
                        <small class="text-muted">Avg Words/Response</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-info">${duration}</div>
                        <small class="text-muted">Minutes</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-warning">${Math.max(85 - skippedCount * 10, 60)}</div>
                        <small class="text-muted">Performance Score</small>
                    </div>
                </div>
            </div>
            
            <div class="mb-4">
                <h6>Key Strengths:</h6>
                <ul class="list-unstyled">
                    ${avgWordCount > 30 ? '<li><i class="bi bi-check-circle text-success me-2"></i>Detailed responses</li>' : ''}
                    ${skippedCount === 0 ? '<li><i class="bi bi-check-circle text-success me-2"></i>Completed all questions</li>' : ''}
                    <li><i class="bi bi-check-circle text-success me-2"></i>Engaged throughout the session</li>
                </ul>
            </div>
            
            <div class="mb-4">
                <h6>Areas for Improvement:</h6>
                <ul class="list-unstyled">
                    ${avgWordCount < 25 ? '<li><i class="bi bi-arrow-right text-warning me-2"></i>Provide more detailed examples</li>' : ''}
                    ${skippedCount > 0 ? '<li><i class="bi bi-arrow-right text-warning me-2"></i>Practice answering all questions</li>' : ''}
                    <li><i class="bi bi-arrow-right text-info me-2"></i>Continue practicing ${currentSession.type} skills</li>
                </ul>
            </div>
            
            <div class="alert alert-success">
                <h6 class="alert-heading">Recommendation:</h6>
                <p class="mb-0">Great job completing this ${currentSession.difficulty} level ${currentSession.type} training! 
                ${avgWordCount > 40 ? 'Your responses show good depth and understanding.' : 'Focus on providing more specific examples in future practice sessions.'}
                Keep practicing to build confidence!</p>
            </div>
        `;
        
        summaryContent.innerHTML = summaryHTML;
    }
    
    // Generate training summary with AI feedback
    function generateTrainingSummaryWithAI(aiSummary) {
        const completedResponses = currentSession.responses.filter(r => !r.skipped);
        const skippedCount = currentSession.responses.filter(r => r.skipped).length;
        const avgWordCount = completedResponses.length > 0 ? 
            Math.round(completedResponses.reduce((sum, r) => sum + r.answer.split(/\s+/).length, 0) / completedResponses.length) : 0;
        
        const duration = Math.round((new Date() - currentSession.startTime) / 1000 / 60);
        
        let summaryHTML = `
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-primary">${completedResponses.length}</div>
                        <small class="text-muted">Questions Completed</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-success">${avgWordCount}</div>
                        <small class="text-muted">Avg Words/Response</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-info">${duration}</div>
                        <small class="text-muted">Minutes</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="text-center">
                        <div class="display-6 text-warning">${Math.max(85 - skippedCount * 10, 60)}</div>
                        <small class="text-muted">Performance Score</small>
                    </div>
                </div>
            </div>
            
            <div class="alert alert-info">
                <h6 class="alert-heading"><i class="bi bi-robot me-2"></i>AI Analysis:</h6>
                <div style="white-space: pre-line;">${aiSummary}</div>
            </div>
        `;
        
        summaryContent.innerHTML = summaryHTML;
    }
    
    // Reset training session
    function resetTrainingSession() {
        currentSession = {
            type: null,
            difficulty: null,
            questions: [],
            currentIndex: 0,
            responses: [],
            startTime: null,
            focusAreas: []
        };
        
        clearChat();
        responseForm.classList.add('d-none');
        trainingSummary.classList.add('d-none');
        sessionStatus.textContent = 'Ready';
        sessionStatus.className = 'badge bg-primary';
        
        // Reset form
        if (trainingSetupForm) {
            trainingSetupForm.reset();
        }
        
        // Show welcome message
        addMessage('Welcome to AI Training! Configure your training session and click "Start Training Session" to begin.', 'ai');
    }
    
    // Download training report
    function downloadTrainingReport() {
        const reportData = {
            session: currentSession,
            completedAt: new Date(),
            summary: summaryContent.innerHTML
        };
        
        // In a real app, this would generate a proper PDF
        const dataStr = JSON.stringify(reportData, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `training-report-${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
    }
    
    // Show/hide typing indicator
    function showTypingIndicator() {
        if (typingIndicator) {
            typingIndicator.classList.remove('d-none');
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
    }
    
    function hideTypingIndicator() {
        if (typingIndicator) {
            typingIndicator.classList.add('d-none');
        }
    }
    
    // Clear chat container
    function clearChat() {
        if (chatContainer) {
            chatContainer.innerHTML = '';
        }
    }
    
    // Add message to chat
    function addMessage(text, sender) {
        if (!chatContainer) return;
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `mb-3`;
        
        const formattedText = text.replace(/\n/g, '<br>');
        
        if (sender === 'ai') {
            messageDiv.innerHTML = `
                <div class="d-flex">
                    <div class="flex-shrink-0 me-3">
                        <div class="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center" style="width: 40px; height: 40px;">
                            <i class="bi bi-robot"></i>
                        </div>
                    </div>
                    <div class="flex-grow-1">
                        <div class="bg-dark bg-opacity-50 text-light p-3 rounded border border-secondary">
                            <div class="fw-bold mb-1 text-primary">AI Trainer</div>
                            <div>${formattedText}</div>
                        </div>
                        <small class="text-muted">${formatTime(new Date())}</small>
                    </div>
                </div>
            `;
        } else {
            messageDiv.innerHTML = `
                <div class="d-flex justify-content-end">
                    <div class="flex-grow-1 text-end">
                        <div class="bg-primary text-white p-3 rounded d-inline-block" style="max-width: 80%;">
                            <div>${formattedText}</div>
                        </div>
                        <div><small class="text-muted">${formatTime(new Date())}</small></div>
                    </div>
                    <div class="flex-shrink-0 ms-3">
                        <div class="bg-secondary text-white rounded-circle d-flex align-items-center justify-content-center" style="width: 40px; height: 40px;">
                            <i class="bi bi-person"></i>
                        </div>
                    </div>
                </div>
            `;
        }
        
        chatContainer.appendChild(messageDiv);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
    
    // Format time helper
    function formatTime(date) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // Initialize the page
    resetTrainingSession();
});
