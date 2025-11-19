/**
 * Onboarding - Employee/Candidate Selection Handler
 * Handles selecting employees and auto-filling their details and job descriptions
 */

let allCandidates = [];
let selectedCandidate = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadCandidates();
    setupSearchListener();
});

/**
 * Load all candidates from the backend
 */
function loadCandidates() {
    fetch('/api/candidates', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            allCandidates = data.data;
            displayEmployeeList(allCandidates);
        } else {
            console.error('Error loading candidates:', data.message);
            displayNoEmployees();
        }
    })
    .catch(error => {
        console.error('Error fetching candidates:', error);
        displayNoEmployees();
    });
}

/**
 * Display list of employees/candidates
 */
function displayEmployeeList(employees) {
    const employeeList = document.getElementById('employeeList');
    if (!employeeList) return;

    if (employees.length === 0) {
        displayNoEmployees();
        return;
    }

    employeeList.innerHTML = '';
    
    employees.forEach(employee => {
        const scoreClass = employee.score ? 
            (employee.score >= 80 ? 'success' : 
             employee.score >= 60 ? 'warning' : 'danger') : 'secondary';
        
        const scoreHtml = employee.score ? 
            `<span class="badge bg-${scoreClass}">${employee.score}%</span>` : 
            '<span class="badge bg-secondary">No Score</span>';

        const employeeItem = document.createElement('div');
        employeeItem.className = 'list-group-item bg-dark bg-opacity-25 border-secondary cursor-pointer ' +
                                'hover-bg-opacity-50 p-3 mb-2';
        employeeItem.style.cursor = 'pointer';
        employeeItem.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <h6 class="mb-1 text-light">${escapeHtml(employee.name)}</h6>
                    <small class="text-muted d-block">${escapeHtml(employee.email)}</small>
                    ${employee.summary ? 
                        `<small class="text-muted d-block mt-1">${escapeHtml(employee.summary.substring(0, 80))}...</small>` : 
                        ''}
                </div>
                <div class="ms-2">
                    ${scoreHtml}
                </div>
            </div>
        `;

        employeeItem.addEventListener('click', function() {
            selectCandidate(employee);
        });

        employeeList.appendChild(employeeItem);
    });
}

/**
 * Display when no employees are found
 */
function displayNoEmployees() {
    const employeeList = document.getElementById('employeeList');
    if (!employeeList) return;

    employeeList.innerHTML = `
        <div class="text-muted text-center py-3">
            <i class="fas fa-user-slash fa-2x mb-2"></i>
            <p>No employees/candidates found</p>
            <small>Add candidates from the pre-onboarding page</small>
        </div>
    `;
}

/**
 * Setup search listener
 */
function setupSearchListener() {
    const searchInput = document.getElementById('employeeSearch');
    if (!searchInput) return;

    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        
        if (searchTerm === '') {
            displayEmployeeList(allCandidates);
            return;
        }

        const filtered = allCandidates.filter(employee =>
            employee.name.toLowerCase().includes(searchTerm) ||
            employee.email.toLowerCase().includes(searchTerm)
        );

        displayEmployeeList(filtered);
    });
}

/**
 * Select a candidate and display their details
 */
function selectCandidate(candidate) {
    selectedCandidate = candidate;

    // Update selected employee card
    const selectedCard = document.getElementById('selectedEmployeeCard');
    if (selectedCard) {
        selectedCard.classList.remove('d-none');
        document.getElementById('selectedName').textContent = candidate.name;
        document.getElementById('selectedEmail').textContent = candidate.email;
        
        // Parse job description to extract position
        const positionMatch = candidate.job_desc.match(
            /Position:\s*([^\n]*)/i);
        const position = positionMatch ? 
            positionMatch[1].trim() : 'Software Developer';
        document.getElementById('selectedPosition').textContent = position;

        // Parse job description to extract company
        const companyMatch = candidate.job_desc.match(
            /Company:\s*([^\n]*)/i);
        const company = companyMatch ? 
            companyMatch[1].trim() : 'Lakshya Company';
        document.getElementById('selectedDepartment').textContent = 
            company;
    }

    // Display job description
    displayJobDescription(candidate.job_desc);

    // Auto-fill form fields
    autoFillFormFields(candidate);

    // Highlight selected employee
    document.querySelectorAll('#employeeList .list-group-item')
        .forEach(item => {
            item.classList.remove('bg-info', 'bg-opacity-25');
        });
    event.target.closest('.list-group-item')?.classList.add(
        'bg-info', 'bg-opacity-25');

    showToast('success', 'Employee Selected', 
        `${candidate.name} has been selected for onboarding`);
}

/**
 * Display job description in formatted way
 */
function displayJobDescription(jobDesc) {
    const jobDescCard = document.getElementById('jobDescriptionCard');
    const jobDescContent = document.getElementById(
        'jobDescriptionContent');

    if (!jobDescCard || !jobDescContent) return;

    // Show the job description card
    jobDescCard.classList.remove('d-none');

    // Format job description
    const formattedDesc = formatJobDescription(jobDesc);
    jobDescContent.innerHTML = formattedDesc;
}

/**
 * Format job description with proper styling
 */
function formatJobDescription(jobDesc) {
    if (!jobDesc) {
        return '<p class="text-muted">No job description available</p>';
    }

    let html = '<div class="small">';
    
    const lines = jobDesc.split('\n');
    lines.forEach(line => {
        const trimmed = line.trim();
        
        if (!trimmed) {
            html += '<div class="mb-2"></div>';
        } else if (trimmed.match(/^(Position|Company|Required|Responsibilities|Nice to Have):/i)) {
            html += `<div class="fw-bold text-info mt-2 mb-1">${escapeHtml(trimmed)}</div>`;
        } else if (trimmed.match(/^-\s/)) {
            html += `<div class="ms-2 text-muted">
                <i class="fas fa-check-circle fa-xs text-success me-2"></i>
                ${escapeHtml(trimmed.substring(2))}
            </div>`;
        } else {
            html += `<div class="text-light">${escapeHtml(trimmed)}</div>`;
        }
    });

    html += '</div>';
    return html;
}

/**
 * Auto-fill form fields with candidate data
 */
function autoFillFormFields(candidate) {
    // Parse candidate information
    const nameMatch = candidate.name;
    const emailMatch = candidate.email;
    
    // Parse position from job description
    const positionMatch = candidate.job_desc.match(
        /Position:\s*([^\n]*)/i);
    const position = positionMatch ? 
        positionMatch[1].trim() : 'Software Developer';

    // Try to fill the new hire form if it exists
    const newHireForm = document.getElementById('newHireForm');
    if (newHireForm) {
        const nameInput = newHireForm.querySelector('#newHireName');
        const emailInput = newHireForm.querySelector('#newHireEmail');
        const positionInput = newHireForm.querySelector(
            '#newHirePosition');
        
        if (nameInput) nameInput.value = nameMatch;
        if (emailInput) emailInput.value = emailMatch;
        if (positionInput) positionInput.value = position;
    }

    // Update page title
    const pageTitle = document.querySelector('h1');
    if (pageTitle) {
        pageTitle.innerHTML = `
            <i class="fas fa-user-clock me-2"></i>
            Employee Onboarding - ${escapeHtml(candidate.name)}
        `;
    }

    // Update the onboarding checklist header
    const checklistHeader = document.querySelector(
        '.card-header h5');
    if (checklistHeader) {
        checklistHeader.innerHTML = `
            <i class="fas fa-clipboard-list me-2"></i>
            Onboarding Checklist - ${escapeHtml(candidate.name)}
        `;
    }
}

/**
 * Clear selection
 */
function clearSelection() {
    selectedCandidate = null;

    // Hide selected employee card
    const selectedCard = document.getElementById(
        'selectedEmployeeCard');
    if (selectedCard) {
        selectedCard.classList.add('d-none');
    }

    // Hide job description card
    const jobDescCard = document.getElementById('jobDescriptionCard');
    if (jobDescCard) {
        jobDescCard.classList.add('d-none');
    }

    // Reset page title
    const pageTitle = document.querySelector('h1');
    if (pageTitle) {
        pageTitle.innerHTML = `
            <i class="fas fa-user-clock me-2"></i>
            Employee Onboarding
        `;
    }

    // Clear search
    const searchInput = document.getElementById('employeeSearch');
    if (searchInput) {
        searchInput.value = '';
    }

    // Reload employee list
    displayEmployeeList(allCandidates);

    showToast('info', 'Selection Cleared', 
        'Employee selection has been cleared');
}

/**
 * Show toast notification
 */
function showToast(type, title, message) {
    const toastContainer = document.getElementById('toastContainer') || 
        (() => {
            const container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'position-fixed top-0 end-0 p-3';
            container.style.zIndex = '9999';
            document.body.appendChild(container);
            return container;
        })();

    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `toast align-items-center text-white 
        bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong><br>
                ${message}
            </div>
            <button type="button" 
                class="btn-close btn-close-white me-2 m-auto" 
                data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;

    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Add CSS for hover effect
const style = document.createElement('style');
style.textContent = `
    .list-group-item.hover-bg-opacity-50:hover {
        background-color: rgba(0, 0, 0, 0.5) !important;
    }
    
    #employeeList .list-group-item {
        transition: all 0.2s ease;
    }
    
    #employeeList .list-group-item:hover {
        transform: translateX(5px);
        background-color: rgba(79, 39, 245, 0.1) !important;
    }
`;
document.head.appendChild(style);
