// Sample candidates data
const sampleCandidates = [
    {
        id: 1,
        name: 'John Smith',
        email: 'john.smith@example.com',
        position: 'Senior Software Engineer',
        experience: '5+ years',
        skills: 'JavaScript, Python, React, Node.js, AWS',
        status: 'Offer Accepted'
    },
    {
        id: 2,
        name: 'Sarah Johnson',
        email: 'sarah.j@example.com',
        position: 'UX/UI Designer',
        experience: '4 years',
        skills: 'Figma, Sketch, Adobe XD, User Research',
        status: 'Offer Pending'
    },
    {
        id: 3,
        name: 'Michael Chen',
        email: 'michael.chen@example.com',
        position: 'Data Scientist',
        experience: '3 years',
        skills: 'Python, Machine Learning, SQL, Data Visualization',
        status: 'Interview Completed'
    }
];

// Initialize application when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the candidates list
    initializeCandidatesList();
    
    // Set up any additional event listeners
    setupEventListeners();
});

// Initialize the candidates list
function initializeCandidatesList() {
    const candidatesList = document.getElementById('candidatesList');
    if (!candidatesList) return;

    candidatesList.innerHTML = ''; // Clear existing content

    sampleCandidates.forEach(candidate => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${candidate.name}</td>
            <td>${candidate.position}</td>
            <td>${candidate.experience}</td>
            <td><span class="badge bg-info">${candidate.status}</span></td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="startOnboarding(${candidate.id})">
                    <i class="fas fa-user-plus me-1"></i>Select
                </button>
            </td>
        `;
        candidatesList.appendChild(row);
    });
}

// Set up event listeners
function setupEventListeners() {
    // Add any event listeners here
    // For example:
    // document.getElementById('someButton').addEventListener('click', someFunction);
}

// Start onboarding for the selected candidate
window.startOnboarding = function(candidateId) {
    const candidate = sampleCandidates.find(c => c.id === candidateId);
    if (!candidate) return;

    // Update the UI with candidate details
    updateCandidateDetails(candidate);
    
    // Show the new hire card and pre-fill the form
    showNewHireCard(candidate);
    
    // Close the modal
    closeModal('selectCandidateModal');
};

// Update candidate details in the UI
function updateCandidateDetails(candidate) {
    const elements = {
        'candidateName': candidate.name,
        'candidateEmail': candidate.email,
        'candidatePosition': candidate.position,
        'candidateExperience': candidate.experience,
        'candidateSkills': candidate.skills,
        'hireDate': new Date().toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
        })
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    });
}

// Show the new hire card and pre-fill the form
function showNewHireCard(candidate) {
    const newHireCard = document.getElementById('newHireCard');
    if (newHireCard) newHireCard.classList.remove('d-none');
    
    // Auto-fill the new hire form
    const formElements = {
        'newHireName': candidate.name,
        'newHireEmail': candidate.email,
        'newHireDepartment': getDepartmentFromPosition(candidate.position)
    };
    
    Object.entries(formElements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.value = value;
    });
    
    // Set start date to next Monday
    const nextMonday = getNextMonday();
    const startDateInput = document.getElementById('newHireStartDate');
    if (startDateInput) startDateInput.valueAsDate = nextMonday;
}

// Get department based on position
function getDepartmentFromPosition(position) {
    if (!position) return 'engineering';
    if (position.includes('Design')) return 'design';
    if (position.includes('Data')) return 'data';
    return 'engineering';
}

// Get next Monday's date
function getNextMonday() {
    const nextMonday = new Date();
    const dayOfWeek = nextMonday.getDay();
    const daysUntilMonday = dayOfWeek === 0 ? 1 : 8 - dayOfWeek;
    nextMonday.setDate(nextMonday.getDate() + daysUntilMonday);
    return nextMonday;
}

// Close a modal by ID
function closeModal(modalId) {
    const modalEl = document.getElementById(modalId);
    if (!modalEl) return;
    
    const modal = bootstrap.Modal.getInstance(modalEl);
    if (modal) modal.hide();
}

// Reset the onboarding process
window.resetOnboarding = function() {
    // Hide the new hire card
    const newHireCard = document.getElementById('newHireCard');
    if (newHireCard) newHireCard.classList.add('d-none');
    
    // Reset the new hire form
    const newHireForm = document.getElementById('newHireForm');
    if (newHireForm) newHireForm.reset();
    
    // Focus the select candidate button
    const selectButton = document.querySelector('[data-bs-target="#selectCandidateModal"]');
    if (selectButton) selectButton.focus();
};

// Analyze resume and extract information
async function analyzeResume() {
    const resumeFile = document.getElementById('resumeFile').files[0];
    if (!resumeFile) {
        showToast('error', 'Error', 'Please select a resume file first');
        return;
    }

    const formData = new FormData();
    formData.append('resume', resumeFile);

    try {
        // Show loading state
        const analyzeBtn = document.querySelector('button[onclick="analyzeResume()"]');
        const originalBtnText = analyzeBtn.innerHTML;
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Analyzing...';

        const response = await fetch('/analyze-resume', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error('Failed to analyze resume');
        }
        
        const data = await response.json();
        
        // Update the form with extracted data
        if (data.name) document.getElementById('newHireName').value = data.name;
        if (data.email) document.getElementById('newHireEmail').value = data.email;
        
        // Display the analysis results
        displayResumeAnalysis(data);
        
        showToast('success', 'Success', 'Resume analyzed successfully!');
    } catch (error) {
        console.error('Error analyzing resume:', error);
        showToast('error', 'Error', 'Failed to analyze resume. Please try again.');
    } finally {
        // Reset button state
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = originalBtnText;
        }
    }
}

// Display resume analysis results in the UI
function displayResumeAnalysis(data) {
    const resultsContainer = document.getElementById('resumeAnalysisResults');
    if (!resultsContainer) return;
    
    // Show the results container
    resultsContainer.classList.remove('d-none');
    
    // Update skills
    const skillsContainer = document.getElementById('extractedSkills');
    if (data.skills && data.skills.length > 0) {
        skillsContainer.innerHTML = data.skills.map(skill => 
            `<span class="badge bg-primary me-1 mb-1">${skill}</span>`
        ).join('');
    } else {
        skillsContainer.innerHTML = '<span class="text-muted">No skills found</span>';
    }
    
    // Update experience
    const experienceContainer = document.getElementById('extractedExperience');
    if (data.experience && data.experience.length > 0) {
        experienceContainer.innerHTML = data.experience.map(exp => 
            `<div class="list-group-item">${exp}</div>`
        ).join('');
    } else {
        experienceContainer.innerHTML = '<div class="list-group-item text-muted">No experience found</div>';
    }
    
    // Update education
    const educationContainer = document.getElementById('extractedEducation');
    if (data.education && data.education.length > 0) {
        educationContainer.innerHTML = data.education.map(edu => 
            `<div class="list-group-item">${edu}</div>`
        ).join('');
    } else {
        educationContainer.innerHTML = '<div class="list-group-item text-muted">No education found</div>';
    }
}

// Show toast notification
function showToast(type, title, message) {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;
    
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
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
    
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 5000
    });
    
    bsToast.show();
    
    // Remove the toast from DOM after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Mark task as complete
window.markComplete = function(button) {
    const row = button.closest('tr');
    if (!row) return;
    
    const statusBadge = row.querySelector('.badge');
    if (!statusBadge) return;
    
    // Toggle completion status
    if (statusBadge.classList.contains('bg-success')) {
        statusBadge.className = 'badge bg-secondary';
        statusBadge.textContent = 'Pending';
        button.innerHTML = '<i class="fas fa-check"></i>';
        button.classList.remove('btn-success');
        button.classList.add('btn-outline-primary');
    } else {
        statusBadge.className = 'badge bg-success';
        statusBadge.textContent = 'Completed';
        button.innerHTML = '<i class="fas fa-undo"></i>';
        button.classList.remove('btn-outline-primary');
        button.classList.add('btn-success');
    }
    
    updateProgress();
    showToast('success', 'Task Updated', 'Task status has been updated successfully.');
};

// Update progress bar
function updateProgress() {
    const totalTasks = document.querySelectorAll('#onboardingTasks tbody tr').length;
    if (totalTasks === 0) return;
    
    const completedTasks = document.querySelectorAll('#onboardingTasks .bg-success').length;
    const progress = Math.round((completedTasks / totalTasks) * 100);
    
    const progressBar = document.querySelector('.progress-bar');
    if (progressBar) {
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
        progressBar.textContent = `${progress}%`;
    }
}
