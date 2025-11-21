// Enhanced Pre-Onboarding Communication System with ATS Screening
let currentEmployeeId = null;
let currentEmployeeData = null;
let analysisData = null;

// Initialize the system
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    loadTeamMembers();
    initializeATSScreening();
});

// Initialize event listeners
function initializeEventListeners() {
    // Employee selection
    const employeeSelect = document.getElementById('employeeSelect');
    const loadEmployeeDataBtn = document.getElementById('loadEmployeeData');
    
    if (employeeSelect) {
        employeeSelect.addEventListener('change', function() {
            loadEmployeeDataBtn.disabled = !this.value;
        });
    }
    
    if (loadEmployeeDataBtn) {
        loadEmployeeDataBtn.addEventListener('click', loadEmployeePreOnboardingData);
    }
    
    // Welcome Package
    const saveWelcomePackageBtn = document.getElementById('saveWelcomePackage');
    if (saveWelcomePackageBtn) {
        saveWelcomePackageBtn.addEventListener('click', saveWelcomePackage);
    }
    
    // Administrative Task
    const saveAdminTaskBtn = document.getElementById('saveAdminTask');
    if (saveAdminTaskBtn) {
        saveAdminTaskBtn.addEventListener('click', saveAdminTask);
    }
    
    // First-Day Agenda
    const saveAgendaBtn = document.getElementById('saveAgenda');
    if (saveAgendaBtn) {
        saveAgendaBtn.addEventListener('click', saveFirstDayAgenda);
    }
    
    const shareAgendaBtn = document.getElementById('shareAgendaBtn');
    if (shareAgendaBtn) {
        shareAgendaBtn.addEventListener('click', shareAgendaWithEmployee);
    }
    
    // Team Introduction
    const saveTeamIntroBtn = document.getElementById('saveTeamIntro');
    if (saveTeamIntroBtn) {
        saveTeamIntroBtn.addEventListener('click', saveTeamIntroduction);
    }
}

// Initialize ATS Screening functionality (EXACTLY like the original)
function initializeATSScreening() {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const clearFormBtn = document.getElementById('clearForm');
    const startOnboardingBtn = document.getElementById('startOnboardingBtn');
    const reviewBtn = document.getElementById('reviewBtn');
    
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async function() {
            const candidateName = document.getElementById('candidateName');
            const jobDescription = document.getElementById('jobDescription');
            const resumeFile = document.getElementById('resumeFile');
            
            if (!resumeFile || !resumeFile.files || !resumeFile.files[0]) {
                alert('Please upload a resume file first');
                return;
            }

            if (!jobDescription || !jobDescription.value.trim()) {
                alert('Please enter a job description');
                return;
            }

            const file = resumeFile.files[0];
            const formData = new FormData();
            formData.append('resume', file);
            formData.append('jobDescription', jobDescription.value);

            const analyzeText = analyzeBtn.querySelector('#analyzeText');
            const analyzeSpinner = analyzeBtn.querySelector('#analyzeSpinner');
            analyzeBtn.disabled = true;
            analyzeText.textContent = 'Analyzing...';
            analyzeSpinner.classList.remove('d-none');

            try {
                const response = await fetch('/analyze-resume', {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Failed to analyze resume');
                }

                const data = await response.json();
                analysisData = data;

                // Display ATS score (EXACTLY like the original)
                const score = data.ats_score;
                const scoreProgress = document.getElementById('scoreProgress');
                const scoreValue = document.getElementById('scoreValue');
                const aiSummary = document.getElementById('aiSummary');
                const resultCard = document.getElementById('resultCard');
                const startOnboardingBtns = document.querySelectorAll('#startOnboardingBtn');
                
                scoreProgress.style.width = score + '%';
                scoreProgress.setAttribute('aria-valuenow', score);
                scoreValue.textContent = score + '%';

                // Set color based on score (EXACTLY like the original)
                const HIRING_THRESHOLD = 60;
                if (score >= HIRING_THRESHOLD) {
                    scoreProgress.className = 'progress-bar bg-success';
                } else if (score >= 50) {
                    scoreProgress.className = 'progress-bar bg-warning';
                } else {
                    scoreProgress.className = 'progress-bar bg-danger';
                }

                // Display AI summary
                aiSummary.textContent = data.ai_summary || 'Resume analysis completed.';

                // Show feedback (EXACTLY like the original)
                let feedbackHtml = '<div class="mt-3">';
                feedbackHtml += '<h5 class="h6">Screening Feedback:</h5>';
                feedbackHtml += '<ul class="small mb-0">';
                
                if (data.ats_feedback && data.ats_feedback.length > 0) {
                    data.ats_feedback.forEach(feedback => {
                        const icon = score >= 70 ? '✓' : '○';
                        feedbackHtml += `<li>${icon} ${feedback}</li>`;
                    });
                }
                
                feedbackHtml += '</ul></div>';

                // Insert feedback after summary
                const summaryDiv = aiSummary.parentElement;
                if (summaryDiv) {
                    const existingFeedback = summaryDiv.querySelector('[class*="mt-3"]');
                    if (existingFeedback) {
                        existingFeedback.remove();
                    }
                    summaryDiv.insertAdjacentHTML('afterend', feedbackHtml);
                }

                // Show result card
                resultCard.classList.remove('d-none');

                // Show/hide start onboarding button (EXACTLY like the original)
                const passedScreening = data.pass_screening;
                startOnboardingBtns.forEach(btn => {
                    if (passedScreening) {
                        btn.classList.remove('d-none');
                    } else {
                        btn.classList.add('d-none');
                    }
                });

            } catch (error) {
                console.error('Error analyzing resume:', error);
                alert(`Failed to analyze resume: ${error.message}`);
            } finally {
                analyzeText.textContent = '🤖 Analyze Resume with AI';
                analyzeSpinner.classList.add('d-none');
                analyzeBtn.disabled = false;
            }
        });
    }
    
    if (clearFormBtn) {
        clearFormBtn.addEventListener('click', function() {
            const candidateName = document.getElementById('candidateName');
            const jobDescription = document.getElementById('jobDescription');
            const resumeFile = document.getElementById('resumeFile');
            const resultCard = document.getElementById('resultCard');
            
            candidateName.value = '';
            jobDescription.value = '';
            resumeFile.value = '';
            resultCard.classList.add('d-none');
            analysisData = null;
        });
    }
    
    if (startOnboardingBtn) {
        startOnboardingBtn.addEventListener('click', startPreOnboardingFromATS);
    }
    
    if (reviewBtn) {
        reviewBtn.addEventListener('click', reviewCandidateDetails);
    }
}

// Review candidate details
function reviewCandidateDetails() {
    if (!analysisData) {
        alert('Please analyze a resume first to review candidate details.');
        return;
    }
    
    const details = analysisData;
    const candidateName = document.getElementById('candidateName');
    
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">🤖 AI Candidate Analysis Review</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <h6 class="text-primary">Basic Information</h6>
                            <p class="mb-1"><strong>Name:</strong> ${details.name || candidateName.value || 'N/A'}</p>
                            <p class="mb-1"><strong>Email:</strong> ${details.email || 'N/A'}</p>
                            <p class="mb-1"><strong>Phone:</strong> ${details.phone || 'N/A'}</p>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-primary">AI Screening Summary</h6>
                            <p class="mb-1"><strong>ATS Match Score:</strong> ${details.ats_score != null ? details.ats_score + '%' : 'N/A'}</p>
                            <p class="mb-1"><strong>Qualified for Onboarding:</strong> ${details.pass_screening ? '✅ Yes' : '❌ No'}</p>
                        </div>
                    </div>
                    <hr>
                    <h6 class="text-primary">🤖 AI Analysis Summary</h6>
                    <p class="small">${details.ai_summary || 'No AI summary available.'}</p>
                    <hr>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <h6 class="text-primary">Key Skills</h6>
                            <ul class="small mb-0">
                                ${(details.skills || []).map(skill => `<li>${skill}</li>`).join('') || '<li>No skills extracted.</li>'}
                            </ul>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6 class="text-primary">Education</h6>
                            <ul class="small mb-0">
                                ${(details.education || []).map(item => `<li>${item}</li>`).join('') || '<li>No education details extracted.</li>'}
                            </ul>
                        </div>
                    </div>
                    <div class="mt-3">
                        <h6 class="text-primary">Experience Highlights</h6>
                        <ul class="small mb-0">
                            ${(details.experience || []).map(item => `<li>${item}</li>`).join('') || '<li>No experience details extracted.</li>'}
                        </ul>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
    
    modal.addEventListener('hidden.bs.modal', function() {
        document.body.removeChild(modal);
    });
}

// Start pre-onboarding from ATS results
function startPreOnboardingFromATS() {
    if (!analysisData) {
        alert('Please analyze a resume first');
        return;
    }
    
    const jobDescription = document.getElementById('jobDescription');
    
    // Prepare candidate data (exactly like the original)
    const candidateData = {
        name: analysisData.name,
        email: analysisData.email,
        phone: analysisData.phone,
        skills: analysisData.skills,
        experience: analysisData.experience,
        education: analysisData.education,
        ats_score: analysisData.ats_score,
        job_description: jobDescription.value
    };
    
    // Store in session storage (exactly like the original)
    sessionStorage.setItem('selectedCandidate', JSON.stringify(candidateData));
    
    // Navigate to onboarding page (exactly like the original)
    window.location.href = '/onboarding';
}

// Load team members for introduction selection
async function loadTeamMembers() {
    try {
        const response = await fetch('/api/team-members');
        const data = await response.json();
        
        if (data.status === 'success') {
            const select = document.getElementById('teamMemberSelect');
            if (select) {
                select.innerHTML = '<option value="">Select team member...</option>';
                data.team_members.forEach(member => {
                    select.innerHTML += `<option value="${member.id}">${member.full_name} - ${member.position}</option>`;
                });
            }
        }
    } catch (error) {
        console.error('Error loading team members:', error);
    }
}

// Load employee pre-onboarding data
async function loadEmployeePreOnboardingData() {
    const employeeSelect = document.getElementById('employeeSelect');
    currentEmployeeId = employeeSelect.value;
    
    if (!currentEmployeeId) return;
    
    const selectedOption = employeeSelect.options[employeeSelect.selectedIndex];
    currentEmployeeData = {
        id: currentEmployeeId,
        name: selectedOption.dataset.name,
        email: selectedOption.dataset.email
    };
    
    // Show content section
    document.getElementById('preOnboardingContent').classList.remove('d-none');
    
    // Load all pre-onboarding data
    await Promise.all([
        loadWelcomePackages(),
        loadAdminTasks(),
        loadFirstDayAgenda(),
        loadTeamIntroductions(),
        loadCommunicationTimeline()
    ]);
    
    // Update progress indicators
    updateProgressIndicators();
}

// Load welcome packages
async function loadWelcomePackages() {
    try {
        const response = await fetch(`/api/pre-onboarding/welcome-packages/${currentEmployeeId}`);
        const data = await response.json();
        
        const container = document.getElementById('welcomePackagesList');
        if (data.packages && data.packages.length > 0) {
            container.innerHTML = data.packages.map(pkg => createWelcomePackageCard(pkg)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No welcome packages configured.</p>';
        }
    } catch (error) {
        console.error('Error loading welcome packages:', error);
    }
}

// Load administrative tasks
async function loadAdminTasks() {
    try {
        const response = await fetch(`/api/pre-onboarding/admin-tasks/${currentEmployeeId}`);
        const data = await response.json();
        
        const container = document.getElementById('adminTasksList');
        if (data.tasks && data.tasks.length > 0) {
            container.innerHTML = data.tasks.map(task => createAdminTaskCard(task)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No administrative tasks configured.</p>';
        }
    } catch (error) {
        console.error('Error loading admin tasks:', error);
    }
}

// Load first-day agenda
async function loadFirstDayAgenda() {
    try {
        const response = await fetch(`/api/pre-onboarding/agenda/${currentEmployeeId}`);
        const data = await response.json();
        
        const container = document.getElementById('agendaStatus');
        const shareBtn = document.getElementById('shareAgendaBtn');
        
        if (data.agenda) {
            container.innerHTML = createAgendaStatusCard(data.agenda);
            shareBtn.disabled = data.agenda.is_shared;
            document.getElementById('agendaStatusIcon').className = 'fas fa-check-circle fa-2x text-success mb-2';
            document.getElementById('agendaStatusText').textContent = data.agenda.is_shared ? 'Shared with employee' : 'Created, not shared';
        } else {
            container.innerHTML = '<p class="text-muted">No agenda created yet.</p>';
            shareBtn.disabled = true;
            document.getElementById('agendaStatusIcon').className = 'fas fa-clock fa-2x text-muted mb-2';
            document.getElementById('agendaStatusText').textContent = 'Not created';
        }
    } catch (error) {
        console.error('Error loading agenda:', error);
    }
}

// Load team introductions
async function loadTeamIntroductions() {
    try {
        const response = await fetch(`/api/pre-onboarding/team-introductions/${currentEmployeeId}`);
        const data = await response.json();
        
        const container = document.getElementById('teamIntroductionsList');
        if (data.introductions && data.introductions.length > 0) {
            container.innerHTML = data.introductions.map(intro => createTeamIntroCard(intro)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No team introductions configured.</p>';
        }
    } catch (error) {
        console.error('Error loading team introductions:', error);
    }
}

// Load communication timeline
async function loadCommunicationTimeline() {
    try {
        const response = await fetch(`/api/pre-onboarding/timeline/${currentEmployeeId}`);
        const data = await response.json();
        
        const container = document.getElementById('communicationTimeline');
        if (data.timeline && data.timeline.length > 0) {
            container.innerHTML = createTimelineHTML(data.timeline);
        } else {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-comments fa-3x mb-3"></i>
                    <p>No communications sent yet. Start by adding welcome packages or scheduling introductions.</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading timeline:', error);
    }
}

// Save welcome package
async function saveWelcomePackage() {
    const formData = {
        employee_id: currentEmployeeId,
        package_name: document.getElementById('packageName').value,
        items: document.getElementById('packageItems').value.split('\n').filter(item => item.trim()),
        shipping_address: document.getElementById('shippingAddress').value,
        estimated_delivery: document.getElementById('estimatedDelivery').value,
        notes: document.getElementById('packageNotes').value
    };
    
    try {
        const response = await fetch('/api/pre-onboarding/welcome-package', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('welcomePackageModal')).hide();
            document.getElementById('welcomePackageForm').reset();
            await loadWelcomePackages();
            await loadCommunicationTimeline();
            updateProgressIndicators();
            showNotification('success', 'Welcome package added successfully!');
        }
    } catch (error) {
        console.error('Error saving welcome package:', error);
        showNotification('danger', 'Error saving welcome package');
    }
}

// Save administrative task
async function saveAdminTask() {
    const formData = {
        employee_id: currentEmployeeId,
        task_name: document.getElementById('taskName').value,
        task_description: document.getElementById('taskDescription').value,
        task_type: document.getElementById('taskType').value,
        due_date: document.getElementById('taskDueDate').value,
        assigned_to: document.getElementById('taskAssignedTo').value
    };
    
    try {
        const response = await fetch('/api/pre-onboarding/admin-task', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('adminTaskModal')).hide();
            document.getElementById('adminTaskForm').reset();
            await loadAdminTasks();
            await loadCommunicationTimeline();
            updateProgressIndicators();
            showNotification('success', 'Administrative task added successfully!');
        }
    } catch (error) {
        console.error('Error saving admin task:', error);
        showNotification('danger', 'Error saving administrative task');
    }
}

// Save first-day agenda
async function saveFirstDayAgenda() {
    const formData = {
        employee_id: currentEmployeeId,
        agenda_date: document.getElementById('agendaDate').value,
        start_time: document.getElementById('agendaStartTime').value,
        end_time: document.getElementById('agendaEndTime').value,
        location: document.getElementById('agendaLocation').value,
        agenda_items: document.getElementById('agendaItems').value.split('\n').filter(item => item.trim()),
        meeting_links: document.getElementById('meetingLinks').value.split('\n').filter(item => item.trim()),
        preparation_notes: document.getElementById('preparationNotes').value
    };
    
    try {
        const response = await fetch('/api/pre-onboarding/first-day-agenda', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('agendaModal')).hide();
            document.getElementById('agendaForm').reset();
            await loadFirstDayAgenda();
            await loadCommunicationTimeline();
            showNotification('success', 'First-day agenda created successfully!');
        }
    } catch (error) {
        console.error('Error saving agenda:', error);
        showNotification('danger', 'Error saving first-day agenda');
    }
}

// Share agenda with employee
async function shareAgendaWithEmployee() {
    try {
        const response = await fetch(`/api/pre-onboarding/share-agenda/${currentEmployeeId}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            await loadFirstDayAgenda();
            await loadCommunicationTimeline();
            showNotification('success', 'Agenda shared with employee successfully!');
        }
    } catch (error) {
        console.error('Error sharing agenda:', error);
        showNotification('danger', 'Error sharing agenda');
    }
}

// Save team introduction
async function saveTeamIntroduction() {
    const formData = {
        employee_id: currentEmployeeId,
        team_member_id: document.getElementById('teamMemberSelect').value,
        introduction_type: document.getElementById('introType').value,
        message: document.getElementById('introMessage').value,
        scheduled_date: document.getElementById('introScheduledDate').value
    };
    
    try {
        const response = await fetch('/api/pre-onboarding/team-introduction', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('teamIntroModal')).hide();
            document.getElementById('teamIntroForm').reset();
            await loadTeamIntroductions();
            await loadCommunicationTimeline();
            updateProgressIndicators();
            showNotification('success', 'Team introduction scheduled successfully!');
        }
    } catch (error) {
        console.error('Error saving team introduction:', error);
        showNotification('danger', 'Error scheduling team introduction');
    }
}

// Update progress indicators
async function updateProgressIndicators() {
    try {
        const response = await fetch(`/api/pre-onboarding/progress/${currentEmployeeId}`);
        const data = await response.json();
        
        if (data.progress) {
            // Update welcome package progress
            updateProgressBar('packageProgress', data.progress.welcome_packages);
            document.getElementById('packageStatusText').textContent = 
                `${data.progress.welcome_packages.completed}/${data.progress.welcome_packages.total} packages`;
            
            // Update admin tasks progress
            updateProgressBar('adminTasksProgress', data.progress.admin_tasks);
            document.getElementById('adminTasksStatusText').textContent = 
                `${data.progress.admin_tasks.completed}/${data.progress.admin_tasks.total} tasks`;
            
            // Update team intro progress
            updateProgressBar('teamIntroProgress', data.progress.team_introductions);
            document.getElementById('teamIntroStatusText').textContent = 
                `${data.progress.team_introductions.completed}/${data.progress.team_introductions.total} introductions`;
        }
    } catch (error) {
        console.error('Error updating progress indicators:', error);
    }
}

// Update progress bar
function updateProgressBar(elementId, progress) {
    const progressBar = document.getElementById(elementId);
    if (progressBar && progress.total > 0) {
        const percentage = (progress.completed / progress.total) * 100;
        progressBar.style.width = percentage + '%';
    }
}

// Create welcome package card HTML
function createWelcomePackageCard(pkg) {
    const statusColors = {
        pending: 'warning',
        ordered: 'info',
        shipped: 'primary',
        delivered: 'success'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${pkg.package_name}</h6>
                        <small class="text-muted">Items: ${pkg.items ? pkg.items.length : 0}</small>
                    </div>
                    <span class="badge bg-${statusColors[pkg.status] || 'secondary'}">${pkg.status}</span>
                </div>
                ${pkg.tracking_number ? `<small class="text-muted">Tracking: ${pkg.tracking_number}</small>` : ''}
            </div>
        </div>
    `;
}

// Create admin task card HTML
function createAdminTaskCard(task) {
    const typeIcons = {
        admin: 'fa-cogs',
        documentation: 'fa-file-alt',
        preparation: 'fa-clipboard-check'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">
                            <i class="fas ${typeIcons[task.task_type] || 'fa-tasks'} me-2"></i>
                            ${task.task_name}
                        </h6>
                        <small class="text-muted">Assigned to: ${task.assigned_to}</small>
                        ${task.due_date ? `<br><small class="text-muted">Due: ${new Date(task.due_date).toLocaleDateString()}</small>` : ''}
                    </div>
                    <span class="badge bg-${task.is_completed ? 'success' : 'warning'}">
                        ${task.is_completed ? 'Completed' : 'Pending'}
                    </span>
                </div>
            </div>
        </div>
    `;
}

// Create agenda status card HTML
function createAgendaStatusCard(agenda) {
    return `
        <div class="card">
            <div class="card-body">
                <h6 class="card-title mb-2">First-Day Agenda</h6>
                <p class="mb-1"><strong>Date:</strong> ${new Date(agenda.agenda_date).toLocaleDateString()}</p>
                <p class="mb-1"><strong>Location:</strong> ${agenda.location || 'TBD'}</p>
                <p class="mb-1"><strong>Items:</strong> ${agenda.agenda_items ? agenda.agenda_items.length : 0}</p>
                <p class="mb-0"><strong>Status:</strong> 
                    <span class="badge bg-${agenda.is_shared ? 'success' : 'info'}">
                        ${agenda.is_shared ? 'Shared with employee' : 'Not shared'}
                    </span>
                </p>
            </div>
        </div>
    `;
}

// Create team introduction card HTML
function createTeamIntroCard(intro) {
    const typeColors = {
        peer: 'primary',
        manager: 'success',
        mentor: 'info',
        buddy: 'warning'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${intro.team_member_name}</h6>
                        <small class="text-muted">${intro.introduction_type}</small>
                        ${intro.scheduled_date ? `<br><small class="text-muted">Scheduled: ${new Date(intro.scheduled_date).toLocaleDateString()}</small>` : ''}
                    </div>
                    <span class="badge bg-${typeColors[intro.introduction_type] || 'secondary'}">
                        ${intro.is_sent ? 'Sent' : 'Scheduled'}
                    </span>
                </div>
            </div>
        </div>
    `;
}

// Create timeline HTML
function createTimelineHTML(timeline) {
    return `
        <div class="timeline">
            ${timeline.map(item => `
                <div class="timeline-item mb-3">
                    <div class="d-flex">
                        <div class="timeline-marker me-3">
                            <i class="fas ${getTimelineIcon(item.type)} text-${getTimelineColor(item.type)}"></i>
                        </div>
                        <div class="timeline-content flex-grow-1">
                            <h6 class="mb-1">${item.title}</h6>
                            <p class="mb-1">${item.description}</p>
                            <small class="text-muted">${new Date(item.date).toLocaleString()}</small>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

// Get timeline icon based on type
function getTimelineIcon(type) {
    const icons = {
        welcome_package: 'fa-gift',
        admin_task: 'fa-tasks',
        agenda: 'fa-calendar-day',
        team_intro: 'fa-users'
    };
    return icons[type] || 'fa-circle';
}

// Get timeline color based on type
function getTimelineColor(type) {
    const colors = {
        welcome_package: 'success',
        admin_task: 'warning',
        agenda: 'info',
        team_intro: 'primary'
    };
    return colors[type] || 'secondary';
}

// Show notification (using console.log since popups are disabled)
function showNotification(type, message) {
    console.log(`${type.toUpperCase()}: ${message}`);
}
