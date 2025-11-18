document.addEventListener('DOMContentLoaded', function() {
    // Form submission
    const exitForm = document.getElementById('exitForm');
    if (exitForm) {
        exitForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show loading state
            const submitBtn = document.getElementById('submitExitForm');
            const submitText = document.getElementById('submitText');
            const submitSpinner = document.getElementById('submitSpinner');
            
            submitBtn.disabled = true;
            submitText.textContent = 'Submitting...';
            submitSpinner.classList.remove('d-none');
            
            // Collect form data
            const formData = {
                employeeName: document.getElementById('employeeName')?.value,
                employeeId: document.getElementById('employeeId')?.value,
                department: document.getElementById('department')?.value,
                position: document.getElementById('position')?.value,
                startDate: document.getElementById('startDate')?.value,
                lastWorkingDay: document.getElementById('lastWorkingDay')?.value,
                leavingReason: document.querySelector('input[name="leavingReason"]:checked')?.value,
                otherReason: document.getElementById('otherReason')?.value,
                jobSatisfaction: document.getElementById('jobSatisfaction')?.value,
                managementFeedback: document.getElementById('managementFeedback')?.value,
                suggestions: document.getElementById('suggestions')?.value,
                newEmployer: document.getElementById('newEmployer')?.value,
                newRole: document.getElementById('newRole')?.value,
                rehireEligible: document.getElementById('rehireEligible')?.checked,
                contactForDetails: document.getElementById('contactForDetails')?.checked
            };
            
            // Here you would typically send the data to your backend
            console.log('Form submitted:', formData);
            
            // Simulate API call
            setTimeout(() => {
                // Reset form and show success message
                if (submitBtn && submitText && submitSpinner) {
                    submitBtn.disabled = false;
                    submitText.textContent = 'Submit Feedback';
                    submitSpinner.classList.add('d-none');
                }
                
                // Show success message
                if (exitForm) {
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert alert-success mt-3';
                    alertDiv.role = 'alert';
                    alertDiv.innerHTML = `
                        <i class="bi bi-check-circle-fill me-2"></i>
                        Thank you for your feedback! Your exit interview has been submitted successfully.
                    `;
                    
                    // Insert after form
                    exitForm.parentNode.insertBefore(alertDiv, exitForm.nextSibling);
                    
                    // Scroll to success message
                    alertDiv.scrollIntoView({ behavior: 'smooth' });
                    
                    // Mark exit interview as completed in the checklist
                    const exitInterviewCheckbox = document.getElementById('exitInterview');
                    if (exitInterviewCheckbox) {
                        exitInterviewCheckbox.checked = true;
                        updateProgress();
                    }
                }
            }, 1500);
        });
    }
    
    // Initialize checklist items from localStorage or server
    const checklistItems = document.querySelectorAll('.checklist-item');
    
    // Load saved state
    checklistItems.forEach(item => {
        const savedState = localStorage.getItem(item.id);
        if (savedState === 'true') {
            item.checked = true;
        }
        
        // Add event listener for HR to update status
        if (item.disabled === false) {
            item.addEventListener('change', updateProgress);
        }
    });
    
    // Download summary for HR
    document.getElementById('downloadSummary')?.addEventListener('click', function() {
        // This would typically make an API call to generate a PDF
        alert('Generating exit summary PDF...');
        // In a real implementation, this would trigger a download
        // window.location.href = '/api/exit/summary';
    });
    
    // Initial progress update
    updateProgress();
    
    // Handle exit interview modal
    const exitInterviewModal = document.getElementById('exitInterviewModal');
    if (exitInterviewModal) {
        exitInterviewModal.addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            const name = button.getAttribute('data-name');
            const role = button.getAttribute('data-role');
            const department = button.getAttribute('data-department');
            const rating = parseFloat(button.getAttribute('data-rating'));
            const feedback = button.getAttribute('data-feedback');
            
            // Update modal content
            const modalTitle = exitInterviewModal.querySelector('.modal-title');
            const modalName = document.getElementById('modalName');
            const modalRole = document.getElementById('modalRole');
            const modalDepartment = document.getElementById('modalDepartment');
            const modalRating = document.getElementById('modalRating');
            const modalFeedback = document.getElementById('modalFeedback');
            const modalAvatar = document.getElementById('modalAvatar').querySelector('.avatar-text');
            
            // Set avatar initials
            const initials = name.split(' ').map(n => n[0]).join('');
            modalAvatar.textContent = initials;
            
            // Set other details
            modalTitle.textContent = `${name}'s Exit Interview`;
            modalName.textContent = name;
            modalRole.textContent = role;
            modalDepartment.textContent = department;
            modalFeedback.textContent = feedback;
            
            // Generate star rating
            const fullStars = Math.floor(rating);
            const hasHalfStar = rating % 1 >= 0.5;
            
            let starsHtml = '';
            
            // Add full stars
            for (let i = 1; i <= 5; i++) {
                if (i <= fullStars) {
                    starsHtml += '<i class="bi bi-star-fill text-warning me-1"></i>';
                } else if (i === fullStars + 1 && hasHalfStar) {
                    starsHtml += '<i class="bi bi-star-half text-warning me-1"></i>';
                } else {
                    starsHtml += '<i class="bi bi-star text-warning me-1"></i>';
                }
            }
            
            // Add rating text
            starsHtml += `<span class="ms-2">${rating}/5</span>`;
            
            modalRating.innerHTML = starsHtml;
            
            // Set random background color for avatar
            const colors = ['primary', 'success', 'info', 'warning', 'danger'];
            const randomColor = colors[Math.floor(Math.random() * colors.length)];
            modalAvatar.parentElement.className = `avatar avatar-xl me-3 bg-${randomColor} bg-opacity-10 text-${randomColor}`;
        });
    }
    
    // Update progress bar and percentage
    function updateProgress() {
        const checklistItems = document.querySelectorAll('.checklist-item');
        const totalItems = checklistItems.length;
        const completedItems = Array.from(checklistItems).filter(item => item.checked).length;
        const progress = Math.round((completedItems / totalItems) * 100);
        
        // Update progress bar
        const progressBar = document.getElementById('exitProgressBar');
        const progressPercentage = document.getElementById('progressPercentage');
        const checklistStatus = document.getElementById('checklistStatus');
        
        if (progressBar && progressPercentage && checklistStatus) {
            progressBar.style.width = `${progress}%`;
            progressBar.setAttribute('aria-valuenow', progress);
            progressPercentage.textContent = `${progress}%`;
            
            // Update status badge
            if (progress === 100) {
                progressBar.classList.add('bg-success');
                checklistStatus.textContent = 'Completed';
                checklistStatus.className = 'badge bg-success';
            } else if (progress > 50) {
                progressBar.classList.remove('bg-success');
                progressBar.classList.add('bg-primary');
                checklistStatus.textContent = 'In Progress';
                checklistStatus.className = 'badge bg-primary';
            } else {
                progressBar.classList.remove('bg-success', 'bg-primary');
                progressBar.classList.add('bg-warning');
                checklistStatus.textContent = 'Pending';
                checklistStatus.className = 'badge bg-warning';
            }
            
            // Save state
            checklistItems.forEach(item => {
                localStorage.setItem(item.id, item.checked);
            });
        }
    }
    // Toggle collapse state for exit interview details
    document.addEventListener('click', function(e) {
        if (e.target.matches('[data-bs-toggle="collapse"]')) {
            const targetId = e.target.getAttribute('data-bs-target');
            const targetElement = document.querySelector(targetId);
            const icon = e.target.querySelector('i.bi');
            
            if (targetElement) {
                // Toggle the collapse state
                const bsCollapse = new bootstrap.Collapse(targetElement, {
                    toggle: true
                });
                
                // Toggle the chevron icon
                if (icon) {
                    if (targetElement.classList.contains('show')) {
                        icon.classList.remove('bi-chevron-up');
                        icon.classList.add('bi-chevron-down');
                    } else {
                        icon.classList.remove('bi-chevron-down');
                        icon.classList.add('bi-chevron-up');
                    }
                }
            }
        }
    });

    // DOM Elements - safely initialize only if they exist
    const elements = {
        exitForm: document.getElementById('exitForm'),
        feedbackTableBody: document.getElementById('feedbackTableBody'),
        feedbackModal: document.getElementById('feedbackModal'),
        feedbackModalBody: document.getElementById('feedbackModalBody'),
        exportDataBtn: document.getElementById('exportDataBtn')
    };

    // Only initialize feedback functionality if the table body exists
    if (elements.feedbackTableBody) {
        // Initialize feedback data loading
        loadFeedbackData(elements);
        
        // Set up export button if it exists
        if (elements.exportDataBtn) {
            elements.exportDataBtn.addEventListener('click', () => exportFeedbackData(elements));
        }
    }
    
    // Sample data for demonstration
    const sampleFeedbackData = [
        {
            id: 1,
            employeeName: 'John Smith',
            position: 'Senior Developer',
            department: 'Engineering',
            employmentLength: '3 years, 4 months',
            exitDate: '2025-10-15',
            reason: 'Career Advancement',
            feedback: 'I enjoyed working at the company, but I found a role with more growth opportunities and better compensation. The team was great to work with, and I learned a lot during my time here.',
            sentiment: 'positive',
            contactForDetails: true,
            submissionDate: '2025-10-10T14:30:00Z'
        },
        {
            id: 2,
            employeeName: 'Sarah Johnson',
            position: 'UX Designer',
            department: 'Design',
            employmentLength: '1 year, 8 months',
            exitDate: '2025-10-20',
            reason: 'Relocation',
            feedback: 'I had to move to another city due to personal reasons. I really enjoyed my time here and would consider returning if I move back. The work-life balance and team culture were excellent.',
            sentiment: 'positive',
            contactForDetails: false,
            submissionDate: '2025-10-15T09:15:00Z'
        },
        {
            id: 3,
            employeeName: 'Michael Chen',
            position: 'Product Manager',
            department: 'Product',
            employmentLength: '2 years',
            exitDate: '2025-10-25',
            reason: 'Better Opportunity',
            feedback: 'I received an offer for a more senior role with a higher salary. While I appreciate the experience I gained here, I felt there were limited opportunities for career growth in my current position.',
            sentiment: 'neutral',
            contactForDetails: true,
            submissionDate: '2025-10-18T16:45:00Z'
        },
        {
            id: 4,
            employeeName: 'Emily Rodriguez',
            position: 'Marketing Specialist',
            department: 'Marketing',
            employmentLength: '11 months',
            exitDate: '2025-11-01',
            reason: 'Work Environment',
            feedback: 'I found the work environment to be quite stressful with unrealistic deadlines. There was a lack of clear communication from management, which made it difficult to meet expectations. I hope the company can work on improving these aspects.',
            sentiment: 'negative',
            contactForDetails: false,
            submissionDate: '2025-10-20T11:20:00Z'
        },
        {
            id: 5,
            employeeName: 'David Kim',
            position: 'DevOps Engineer',
            department: 'Engineering',
            employmentLength: '4 years, 2 months',
            exitDate: '2025-11-05',
            reason: 'Career Change',
            feedback: 'I\'ve decided to pursue a different career path outside of technology. My time at the company has been valuable, and I\'ve grown both professionally and personally. Thank you for the opportunity.',
            sentiment: 'positive',
            contactForDetails: true,
            submissionDate: '2025-10-22T13:10:00Z'
        }
    ];
    
    // Initialize the page
    function initPage() {
        // No need to initialize here anymore as we handle it in the main DOMContentLoaded
        // This function can be used for other initialization if needed
    }
    
    // Load feedback data into the table
    function loadFeedbackData(elements) {
        const { feedbackTableBody } = elements;
        if (!feedbackTableBody) return;
        
        // In a real app, this would be an API call to your backend
        const feedbackData = getFeedbackData();
        
        if (feedbackData.length === 0) {
            feedbackTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-4">
                        <i class="bi bi-inbox" style="font-size: 2rem; opacity: 0.5;"></i>
                        <p class="mt-2 mb-0">No exit feedback available yet.</p>
                    </td>
                </tr>
            `;
            return;
        }
        
        // Sort by submission date (newest first)
        feedbackData.sort((a, b) => new Date(b.submissionDate) - new Date(a.submissionDate));
        
        // Add rows to the table
        feedbackData.forEach(feedback => {
            const row = document.createElement('tr');
            
            // Format date
            const submissionDate = new Date(feedback.submissionDate);
            const formattedDate = submissionDate.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
            
            // Determine sentiment badge
            let sentimentBadge = '';
            if (feedback.sentiment === 'positive') {
                sentimentBadge = '<span class="badge bg-success">Positive</span>';
            } else if (feedback.sentiment === 'negative') {
                sentimentBadge = '<span class="badge bg-danger">Negative</span>';
            } else {
                sentimentBadge = '<span class="badge bg-secondary">Neutral</span>';
            }
            
            // Create row HTML
            row.innerHTML = `
                <td>${formattedDate}</td>
                <td>${feedback.employeeName}</td>
                <td>${feedback.position}</td>
                <td>${feedback.reason}</td>
                <td>${sentimentBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary view-feedback" data-id="${feedback.id}">
                        <i class="bi bi-eye"></i> View
                    </button>
                </td>
            `;
            
            // Add click event to view feedback
            const viewBtn = row.querySelector('.view-feedback');
            if (viewBtn) {
                viewBtn.addEventListener('click', () => showFeedbackDetails(feedback.id));
            }
            
            feedbackTableBody.appendChild(row);
        });
    }
    
    // Set up form submission
    function setupFormSubmission() {
        exitForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const formData = {
                employeeName: document.getElementById('employeeName').value.trim(),
                position: document.getElementById('position').value.trim(),
                department: document.getElementById('department').value,
                employmentLength: document.getElementById('employmentLength').value,
                exitDate: document.getElementById('exitDate').value,
                reason: document.getElementById('reason').value,
                otherReason: document.getElementById('otherReason').value.trim(),
                feedback: document.getElementById('feedback').value.trim(),
                contactForDetails: document.getElementById('contactForDetails').checked,
                submissionDate: new Date().toISOString()
            };
            
            // Validate required fields
            if (!formData.employeeName || !formData.position || !formData.reason || !formData.feedback) {
                showToast('warning', 'Missing Information', 'Please fill in all required fields.');
                return;
            }
            
            // If "Other" reason is selected but no details provided
            if (formData.reason === 'Other' && !formData.otherReason) {
                showToast('warning', 'Missing Information', 'Please specify the reason for leaving.');
                return;
            }
            
            // Analyze sentiment of feedback
            formData.sentiment = analyzeSentiment(formData.feedback);
            
            // Show loading state
            const submitBtn = exitForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Submitting...';
            
            // In a real app, this would be an API call to your backend
            setTimeout(() => {
                // Save the feedback
                saveFeedback(formData);
                
                // Reset form
                exitForm.reset();
                
                // Reset button
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtnText;
                
                // Show success message
                showToast('success', 'Thank You!', 'Your feedback has been submitted successfully.');
                
                // Reload feedback data
                loadFeedbackData();
                
                // Scroll to top
                window.scrollTo({ top: 0, behavior: 'smooth' });
                
            }, 1500);
        });
        
        // Show/hide other reason field based on selection
        const reasonSelect = document.getElementById('reason');
        const otherReasonGroup = document.getElementById('otherReasonGroup');
        
        if (reasonSelect && otherReasonGroup) {
            reasonSelect.addEventListener('change', function() {
                otherReasonGroup.style.display = this.value === 'Other' ? 'block' : 'none';
            });
            
            // Initialize visibility
            otherReasonGroup.style.display = reasonSelect.value === 'Other' ? 'block' : 'none';
        }
    }
    
    // Analyze sentiment of feedback text (simple implementation)
    function analyzeSentiment(text) {
        const positiveWords = ['good', 'great', 'excellent', 'enjoy', 'happy', 'satisfied', 'appreciate', 'thank', 'thanks', 'wonderful', 'amazing', 'fantastic', 'pleasure'];
        const negativeWords = ['bad', 'poor', 'terrible', 'awful', 'stress', 'stressful', 'difficult', 'hard', 'challenging', 'issue', 'problem', 'concern', 'disappoint'];
        
        const textLower = text.toLowerCase();
        let positiveCount = 0;
        let negativeCount = 0;
        
        // Count positive and negative words
        positiveWords.forEach(word => {
            const regex = new RegExp(`\\b${word}\\b`, 'g');
            const matches = textLower.match(regex);
            if (matches) positiveCount += matches.length;
        });
        
        negativeWords.forEach(word => {
            const regex = new RegExp(`\\b${word}\\b`, 'g');
            const matches = textLower.match(regex);
            if (matches) negativeCount += matches.length;
        });
        
        // Determine overall sentiment
        if (positiveCount > negativeCount) {
            return 'positive';
        } else if (negativeCount > positiveCount) {
            return 'negative';
        } else {
            return 'neutral';
        }
    }
    
    // Show feedback details in modal
    function showFeedbackDetails(feedbackId) {
        // In a real app, this would be an API call to fetch the specific feedback
        const feedbackData = getFeedbackData();
        const feedback = feedbackData.find(item => item.id === feedbackId);
        
        if (!feedback) {
            showToast('danger', 'Error', 'Feedback not found.');
            return;
        }
        
        // Format dates
        const submissionDate = new Date(feedback.submissionDate);
        const exitDate = new Date(feedback.exitDate);
        
        const formattedSubmissionDate = submissionDate.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        
        const formattedExitDate = exitDate.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
        
        // Determine sentiment badge
        let sentimentBadge = '';
        let sentimentClass = '';
        
        if (feedback.sentiment === 'positive') {
            sentimentBadge = 'Positive';
            sentimentClass = 'success';
        } else if (feedback.sentiment === 'negative') {
            sentimentBadge = 'Negative';
            sentimentClass = 'danger';
        } else {
            sentimentBadge = 'Neutral';
            sentimentClass = 'secondary';
        }
        
        // Create modal content
        const modalContent = `
            <div class="mb-4">
                <h5 class="mb-3">Employee Information</h5>
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Employee Name</p>
                        <p class="mb-0">${feedback.employeeName}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Position</p>
                        <p class="mb-0">${feedback.position}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Department</p>
                        <p class="mb-0">${feedback.department}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Employment Length</p>
                        <p class="mb-0">${feedback.employmentLength}</p>
                    </div>
                </div>
            </div>
            
            <div class="mb-4">
                <h5 class="mb-3">Exit Details</h5>
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Reason for Leaving</p>
                        <p class="mb-0">${feedback.reason}${feedback.otherReason ? `: ${feedback.otherReason}` : ''}</p>
                    </div>
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Last Working Day</p>
                        <p class="mb-0">${formattedExitDate}</p>
                    </div>
                    <div class="col-12 mb-3">
                        <p class="mb-1 text-muted">Feedback</p>
                        <div class="p-3 bg-light rounded">
                            ${feedback.feedback.replace(/\n/g, '<br>')}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="mb-4">
                <h5 class="mb-3">Analysis</h5>
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Sentiment</p>
                        <span class="badge bg-${sentimentClass}">${sentimentBadge}</span>
                    </div>
                    <div class="col-md-6 mb-3">
                        <p class="mb-1 text-muted">Submitted On</p>
                        <p class="mb-0">${formattedSubmissionDate}</p>
                    </div>
                    <div class="col-12">
                        <p class="mb-1 text-muted">Willing to be contacted</p>
                        <p class="mb-0">${feedback.contactForDetails ? 'Yes' : 'No'}</p>
                    </div>
                </div>
            </div>
        `;
        
        // Update modal content
        feedbackModalBody.innerHTML = modalContent;
        
        // Show the modal
        const modal = new bootstrap.Modal(feedbackModal);
        modal.show();
    }
    
    // Export feedback data
    function exportFeedbackData() {
        const feedbackData = getFeedbackData();
        
        if (feedbackData.length === 0) {
            showToast('info', 'No Data', 'There is no feedback data to export.');
            return;
        }
        
        // Create CSV content
        let csvContent = 'data:text/csv;charset=utf-8,';
        
        // Add headers
        const headers = [
            'Employee Name',
            'Position',
            'Department',
            'Employment Length',
            'Exit Date',
            'Reason for Leaving',
            'Other Reason',
            'Sentiment',
            'Feedback',
            'Contact for Details',
            'Submission Date'
        ];
        
        csvContent += headers.join(',') + '\r\n';
        
        // Add data rows
        feedbackData.forEach(item => {
            const row = [
                `"${item.employeeName}"`,
                `"${item.position}"`,
                `"${item.department}"`,
                `"${item.employmentLength}"`,
                `"${item.exitDate}"`,
                `"${item.reason}"`,
                `"${item.otherReason || ''}"`,
                `"${item.sentiment}"`,
                `"${item.feedback.replace(/"/g, '""')}"`,
                `"${item.contactForDetails ? 'Yes' : 'No'}"`,
                `"${item.submissionDate}"`
            ];
            
            csvContent += row.join(',') + '\r\n';
        });
        
        // Create download link
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement('a');
        link.setAttribute('href', encodedUri);
        link.setAttribute('download', `exit-feedback-${new Date().toISOString().split('T')[0]}.csv`);
        document.body.appendChild(link);
        
        // Trigger download
        link.click();
        
        // Clean up
        document.body.removeChild(link);
        
        showToast('success', 'Export Complete', 'Feedback data has been exported successfully.');
    }
    
    // Helper function to get feedback data (mocked for this example)
    function getFeedbackData() {
        // In a real app, this would be an API call to your backend
        // For this example, we'll use the sample data and any saved feedback
        const savedFeedback = JSON.parse(localStorage.getItem('exitFeedback') || '[]');
        return [...sampleFeedbackData, ...savedFeedback];
    }
    
    // Helper function to save feedback (mocked for this example)
    function saveFeedback(feedback) {
        // In a real app, this would be an API call to your backend
        // For this example, we'll save to localStorage
        const savedFeedback = JSON.parse(localStorage.getItem('exitFeedback') || '[]');
        
        // Generate a unique ID for the new feedback
        const newId = savedFeedback.length > 0 ? Math.max(...savedFeedback.map(f => f.id)) + 1 : 1;
        
        // Add the new feedback with an ID
        savedFeedback.push({
            id: newId,
            ...feedback
        });
        
        // Save back to localStorage
        localStorage.setItem('exitFeedback', JSON.stringify(savedFeedback));
    }
    
    // Helper function to show toast notifications
    function showToast(type, title, message) {
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) return;
        
        const toastId = 'toast-' + Date.now();
        const toast = document.createElement('div');
        toast.id = toastId;
        toast.className = 'toast align-items-center text-white bg-' + type + ' border-0';
        toast.role = 'alert';
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <strong>${title}</strong><br>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        `;
        
        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        // Remove toast after it's hidden
        toast.addEventListener('hidden.bs.toast', function() {
            toast.remove();
        });
    }
    
    // Initialize the page
    initPage();
});
