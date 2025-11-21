// Social Integration Events Management System
let currentEmployees = [];
let currentDepartments = [];

// Initialize the system
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    loadEmployees();
    loadSocialIntegrationData();
});

// Initialize event listeners
function initializeEventListeners() {
    // Team Building
    const saveTeamBuildingBtn = document.getElementById('saveTeamBuilding');
    if (saveTeamBuildingBtn) {
        saveTeamBuildingBtn.addEventListener('click', saveTeamBuildingActivity);
    }
    
    // Cross-Departmental
    const saveCrossDeptIntroBtn = document.getElementById('saveCrossDeptIntro');
    if (saveCrossDeptIntroBtn) {
        saveCrossDeptIntroBtn.addEventListener('click', saveCrossDepartmentalIntroduction);
    }
    
    // Social Events
    const saveSocialEventBtn = document.getElementById('saveSocialEvent');
    if (saveSocialEventBtn) {
        saveSocialEventBtn.addEventListener('click', saveSocialEvent);
    }
    
    // Buddy/Mentor
    const saveBuddyMentorBtn = document.getElementById('saveBuddyMentor');
    if (saveBuddyMentorBtn) {
        saveBuddyMentorBtn.addEventListener('click', saveBuddyMentorPartnership);
    }
    
    // Communication Training
    const saveTrainingBtn = document.getElementById('saveTraining');
    if (saveTrainingBtn) {
        saveTrainingBtn.addEventListener('click', saveCommunicationTraining);
    }
    
    // Department change handler for cross-departmental introductions
    const targetDepartmentSelect = document.getElementById('targetDepartment');
    if (targetDepartmentSelect) {
        targetDepartmentSelect.addEventListener('change', loadDepartmentEmployees);
    }
}

// Load employees for dropdowns
async function loadEmployees() {
    try {
        const response = await fetch('/api/employees');
        const data = await response.json();
        
        if (data.status === 'success') {
            currentEmployees = data.employees;
            populateEmployeeDropdowns();
        }
    } catch (error) {
        console.error('Error loading employees:', error);
    }
}

// Populate employee dropdowns
function populateEmployeeDropdowns() {
    const dropdowns = [
        'crossDeptEmployee',
        'targetEmployee', 
        'mentorSelect',
        'menteeSelect',
        'hrSupervisor',
        'instructorSelect'
    ];
    
    dropdowns.forEach(dropdownId => {
        const select = document.getElementById(dropdownId);
        if (select) {
            const currentValue = select.value;
            select.innerHTML = '<option value="">Select...</option>';
            
            currentEmployees.forEach(employee => {
                const option = document.createElement('option');
                option.value = employee.id;
                option.textContent = `${employee.full_name} - ${employee.department}`;
                select.appendChild(option);
            });
            
            // Restore previous selection if any
            if (currentValue) {
                select.value = currentValue;
            }
        }
    });
}

// Load department employees when department changes
async function loadDepartmentEmployees() {
    const targetDepartment = document.getElementById('targetDepartment').value;
    const targetEmployeeSelect = document.getElementById('targetEmployee');
    
    if (!targetDepartment || !targetEmployeeSelect) return;
    
    const employeesInDept = currentEmployees.filter(emp => emp.department === targetDepartment);
    
    targetEmployeeSelect.innerHTML = '<option value="">Any employee in department</option>';
    employeesInDept.forEach(employee => {
        const option = document.createElement('option');
        option.value = employee.id;
        option.textContent = employee.full_name;
        targetEmployeeSelect.appendChild(option);
    });
}

// Load all social integration data
async function loadSocialIntegrationData() {
    await Promise.all([
        loadTeamBuildingActivities(),
        loadCrossDepartmentalIntroductions(),
        loadSocialEvents(),
        loadBuddyMentorPrograms(),
        loadCommunicationTraining()
    ]);
    
    updateStatistics();
}

// Load team-building activities
async function loadTeamBuildingActivities() {
    try {
        const response = await fetch('/api/social-integration/team-building');
        const data = await response.json();
        
        const container = document.getElementById('teamBuildingActivities');
        if (data.activities && data.activities.length > 0) {
            container.innerHTML = data.activities.map(activity => createTeamBuildingCard(activity)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No team-building activities scheduled.</p>';
        }
    } catch (error) {
        console.error('Error loading team-building activities:', error);
    }
}

// Load cross-departmental introductions
async function loadCrossDepartmentalIntroductions() {
    try {
        const response = await fetch('/api/social-integration/cross-departmental');
        const data = await response.json();
        
        const container = document.getElementById('crossDeptIntroductions');
        if (data.introductions && data.introductions.length > 0) {
            container.innerHTML = data.introductions.map(intro => createCrossDeptCard(intro)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No cross-departmental introductions scheduled.</p>';
        }
    } catch (error) {
        console.error('Error loading cross-departmental introductions:', error);
    }
}

// Load social events
async function loadSocialEvents() {
    try {
        const response = await fetch('/api/social-integration/social-events');
        const data = await response.json();
        
        const container = document.getElementById('socialEvents');
        if (data.events && data.events.length > 0) {
            container.innerHTML = data.events.map(event => createSocialEventCard(event)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No social events planned.</p>';
        }
    } catch (error) {
        console.error('Error loading social events:', error);
    }
}

// Load buddy/mentor programs
async function loadBuddyMentorPrograms() {
    try {
        const response = await fetch('/api/social-integration/buddy-mentor');
        const data = await response.json();
        
        const container = document.getElementById('buddyMentorPrograms');
        if (data.programs && data.programs.length > 0) {
            container.innerHTML = data.programs.map(program => createBuddyMentorCard(program)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No buddy/mentor partnerships established.</p>';
        }
    } catch (error) {
        console.error('Error loading buddy/mentor programs:', error);
    }
}

// Load communication training
async function loadCommunicationTraining() {
    try {
        const response = await fetch('/api/social-integration/communication-training');
        const data = await response.json();
        
        const container = document.getElementById('communicationTraining');
        if (data.trainings && data.trainings.length > 0) {
            container.innerHTML = data.trainings.map(training => createTrainingCard(training)).join('');
        } else {
            container.innerHTML = '<p class="text-muted">No communication training sessions scheduled.</p>';
        }
    } catch (error) {
        console.error('Error loading communication training:', error);
    }
}

// Save team-building activity
async function saveTeamBuildingActivity() {
    const formData = {
        activity_name: document.getElementById('activityName').value,
        activity_type: document.getElementById('activityType').value,
        description: document.getElementById('activityDescription').value,
        scheduled_date: document.getElementById('activityDate').value,
        start_time: document.getElementById('activityStartTime').value,
        end_time: document.getElementById('activityEndTime').value,
        location: document.getElementById('activityLocation').value,
        virtual_link: document.getElementById('activityVirtualLink').value,
        max_participants: document.getElementById('maxParticipants').value,
        budget: document.getElementById('activityBudget').value,
        requirements: document.getElementById('activityRequirements').value.split('\n').filter(req => req.trim())
    };
    
    try {
        const response = await fetch('/api/social-integration/team-building', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('teamBuildingModal')).hide();
            document.getElementById('teamBuildingForm').reset();
            await loadTeamBuildingActivities();
            updateStatistics();
            showNotification('success', 'Team-building activity scheduled successfully!');
        }
    } catch (error) {
        console.error('Error saving team-building activity:', error);
        showNotification('danger', 'Error scheduling activity');
    }
}

// Save cross-departmental introduction
async function saveCrossDepartmentalIntroduction() {
    const formData = {
        employee_id: document.getElementById('crossDeptEmployee').value,
        target_department: document.getElementById('targetDepartment').value,
        target_employee_id: document.getElementById('targetEmployee').value || null,
        introduction_type: document.getElementById('introductionType').value,
        purpose: document.getElementById('introductionPurpose').value,
        scheduled_date: document.getElementById('introScheduledDate').value,
        meeting_format: document.getElementById('meetingFormat').value
    };
    
    try {
        const response = await fetch('/api/social-integration/cross-departmental', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('crossDeptModal')).hide();
            document.getElementById('crossDeptForm').reset();
            await loadCrossDepartmentalIntroductions();
            updateStatistics();
            showNotification('success', 'Cross-departmental introduction scheduled successfully!');
        }
    } catch (error) {
        console.error('Error saving cross-departmental introduction:', error);
        showNotification('danger', 'Error scheduling introduction');
    }
}

// Save social event
async function saveSocialEvent() {
    const formData = {
        event_name: document.getElementById('eventName').value,
        event_type: document.getElementById('eventType').value,
        description: document.getElementById('eventDescription').value,
        event_date: document.getElementById('eventDate').value,
        start_time: document.getElementById('eventStartTime').value,
        end_time: document.getElementById('eventEndTime').value,
        location: document.getElementById('eventLocation').value,
        virtual_link: document.getElementById('eventVirtualLink').value,
        max_attendees: document.getElementById('maxAttendees').value,
        budget_per_person: document.getElementById('budgetPerPerson').value,
        registration_deadline: document.getElementById('registrationDeadline').value,
        dress_code: document.getElementById('dressCode').value,
        dietary_accommodations: document.getElementById('dietaryAccommodations').value,
        recurring_event: document.getElementById('recurringEvent').checked,
        recurring_frequency: document.getElementById('recurringFrequency').value
    };
    
    try {
        const response = await fetch('/api/social-integration/social-events', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('socialEventModal')).hide();
            document.getElementById('socialEventForm').reset();
            await loadSocialEvents();
            updateStatistics();
            showNotification('success', 'Social event planned successfully!');
        }
    } catch (error) {
        console.error('Error saving social event:', error);
        showNotification('danger', 'Error planning event');
    }
}

// Save buddy/mentor partnership
async function saveBuddyMentorPartnership() {
    const formData = {
        mentor_id: document.getElementById('mentorSelect').value,
        mentee_id: document.getElementById('menteeSelect').value,
        relationship_type: document.getElementById('relationshipType').value,
        program_name: document.getElementById('programName').value,
        start_date: document.getElementById('partnershipStartDate').value,
        end_date: document.getElementById('partnershipEndDate').value,
        meeting_frequency: document.getElementById('meetingFrequency').value,
        meeting_duration: document.getElementById('meetingDuration').value,
        matching_reason: document.getElementById('matchingReason').value,
        goals: document.getElementById('developmentGoals').value.split('\n').filter(goal => goal.trim()),
        hr_supervisor_id: document.getElementById('hrSupervisor').value || null
    };
    
    try {
        const response = await fetch('/api/social-integration/buddy-mentor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('buddyMentorModal')).hide();
            document.getElementById('buddyMentorForm').reset();
            await loadBuddyMentorPrograms();
            updateStatistics();
            showNotification('success', 'Buddy/Mentor partnership created successfully!');
        }
    } catch (error) {
        console.error('Error saving buddy/mentor partnership:', error);
        showNotification('danger', 'Error creating partnership');
    }
}

// Save communication training
async function saveCommunicationTraining() {
    const formData = {
        training_name: document.getElementById('trainingName').value,
        training_type: document.getElementById('trainingType').value,
        description: document.getElementById('trainingDescription').value,
        instructor_id: document.getElementById('instructorSelect').value || null,
        scheduled_date: document.getElementById('trainingDate').value,
        start_time: document.getElementById('trainingStartTime').value,
        end_time: document.getElementById('trainingEndTime').value,
        location: document.getElementById('trainingLocation').value,
        virtual_link: document.getElementById('trainingVirtualLink').value,
        max_participants: document.getElementById('trainingMaxParticipants').value,
        skill_focus: document.getElementById('skillFocus').value,
        difficulty_level: document.getElementById('difficultyLevel').value,
        prerequisites: document.getElementById('prerequisites').value.split('\n').filter(req => req.trim()),
        materials: document.getElementById('trainingMaterials').value.split('\n').filter(mat => mat.trim()),
        assessment_required: document.getElementById('assessmentRequired').checked,
        certificate_offered: document.getElementById('certificateOffered').checked
    };
    
    try {
        const response = await fetch('/api/social-integration/communication-training', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            bootstrap.Modal.getInstance(document.getElementById('trainingModal')).hide();
            document.getElementById('trainingForm').reset();
            await loadCommunicationTraining();
            updateStatistics();
            showNotification('success', 'Communication training scheduled successfully!');
        }
    } catch (error) {
        console.error('Error saving communication training:', error);
        showNotification('danger', 'Error scheduling training');
    }
}

// Update statistics
async function updateStatistics() {
    try {
        const response = await fetch('/api/social-integration/statistics');
        const data = await response.json();
        
        if (data.statistics) {
            document.getElementById('totalActivities').textContent = data.statistics.team_building.total || 0;
            document.getElementById('participantCount').textContent = data.statistics.team_building.participants || 0;
            
            document.getElementById('totalIntroductions').textContent = data.statistics.cross_departmental.total || 0;
            document.getElementById('departmentsConnected').textContent = data.statistics.cross_departmental.departments || 0;
            
            document.getElementById('totalEvents').textContent = data.statistics.social_events.total || 0;
            document.getElementById('eventAttendance').textContent = data.statistics.social_events.attendance || 0;
            
            document.getElementById('activePartnerships').textContent = data.statistics.buddy_mentor.active || 0;
            document.getElementById('totalMeetings').textContent = data.statistics.buddy_mentor.meetings || 0;
            
            document.getElementById('totalTrainings').textContent = data.statistics.communication_training.total || 0;
            document.getElementById('certificationsIssued').textContent = data.statistics.communication_training.certifications || 0;
        }
    } catch (error) {
        console.error('Error updating statistics:', error);
    }
}

// Card creation functions
function createTeamBuildingCard(activity) {
    const statusColors = {
        scheduled: 'primary',
        ongoing: 'warning', 
        completed: 'success',
        cancelled: 'danger'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${activity.activity_name}</h6>
                        <p class="mb-1 small text-muted">${activity.activity_type} · ${new Date(activity.scheduled_date).toLocaleDateString()}</p>
                        <p class="mb-1">${activity.location || activity.virtual_link || 'Location TBD'}</p>
                    </div>
                    <span class="badge bg-${statusColors[activity.status] || 'secondary'}">${activity.status}</span>
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        ${activity.current_participants || 0}/${activity.max_participants || '∞'} participants
                    </small>
                </div>
            </div>
        </div>
    `;
}

function createCrossDeptCard(intro) {
    const statusColors = {
        pending: 'warning',
        scheduled: 'info',
        completed: 'success',
        cancelled: 'danger'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${intro.employee_name} → ${intro.target_department}</h6>
                        <p class="mb-1 small text-muted">${intro.introduction_type} · ${intro.meeting_format}</p>
                        ${intro.target_employee_name ? `<p class="mb-1 small">With: ${intro.target_employee_name}</p>` : ''}
                        ${intro.scheduled_date ? `<p class="mb-1 small">Scheduled: ${new Date(intro.scheduled_date).toLocaleDateString()}</p>` : ''}
                    </div>
                    <span class="badge bg-${statusColors[intro.status] || 'secondary'}">${intro.status}</span>
                </div>
            </div>
        </div>
    `;
}

function createSocialEventCard(event) {
    const statusColors = {
        planning: 'secondary',
        open_registration: 'primary',
        confirmed: 'info',
        completed: 'success',
        cancelled: 'danger'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${event.event_name}</h6>
                        <p class="mb-1 small text-muted">${event.event_type} · ${new Date(event.event_date).toLocaleDateString()}</p>
                        <p class="mb-1">${event.location || event.virtual_link || 'Location TBD'}</p>
                        ${event.recurring_event ? '<span class="badge bg-info me-1">Recurring</span>' : ''}
                    </div>
                    <span class="badge bg-${statusColors[event.status] || 'secondary'}">${event.status}</span>
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        ${event.current_attendees || 0}/${event.max_attendees || '∞'} attendees
                    </small>
                </div>
            </div>
        </div>
    `;
}

function createBuddyMentorCard(program) {
    const statusColors = {
        active: 'success',
        completed: 'primary',
        paused: 'warning',
        terminated: 'danger'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${program.mentor_name} ↔ ${program.mentee_name}</h6>
                        <p class="mb-1 small text-muted">${program.relationship_type} · ${program.meeting_frequency}</p>
                        <p class="mb-1 small">Started: ${new Date(program.start_date).toLocaleDateString()}</p>
                    </div>
                    <span class="badge bg-${statusColors[program.status] || 'secondary'}">${program.status}</span>
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        ${program.meetings_count || 0} meetings held
                    </small>
                </div>
            </div>
        </div>
    `;
}

function createTrainingCard(training) {
    const statusColors = {
        scheduled: 'primary',
        in_progress: 'warning',
        completed: 'success',
        cancelled: 'danger'
    };
    
    return `
        <div class="card mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">${training.training_name}</h6>
                        <p class="mb-1 small text-muted">${training.training_type} · ${training.skill_focus}</p>
                        <p class="mb-1">${new Date(training.scheduled_date).toLocaleDateString()}</p>
                        ${training.certificate_offered ? '<span class="badge bg-success me-1">Certificate</span>' : ''}
                    </div>
                    <span class="badge bg-${statusColors[training.status] || 'secondary'}">${training.status}</span>
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        ${training.current_participants || 0}/${training.max_participants || '∞'} participants
                    </small>
                </div>
            </div>
        </div>
    `;
}

// Show notification (using console.log since popups are disabled)
function showNotification(type, message) {
    console.log(`${type.toUpperCase()}: ${message}`);
}
