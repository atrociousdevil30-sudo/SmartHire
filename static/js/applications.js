/**
 * SmartHire AI - Candidate Applications Management
 * Handles all application-related actions: view, withdraw, accept offer, and delete
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // View Application
    document.querySelectorAll('.view-application').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            viewApplication(applicationId);
        });
    });

    // Withdraw Application
    document.querySelectorAll('.withdraw-application').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            const applicationRow = this.closest('tr');
            const position = applicationRow.cells[0].textContent;
            const company = applicationRow.cells[1].textContent;
            
            if (confirm(`Are you sure you want to withdraw your application for ${position} at ${company}?`)) {
                withdrawApplication(applicationId, applicationRow);
            }
        });
    });

    // Accept Offer
    document.querySelectorAll('.accept-offer').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            const applicationRow = this.closest('tr');
            const position = applicationRow.cells[0].textContent;
            const company = applicationRow.cells[1].textContent;
            
            if (confirm(`Are you sure you want to accept the offer for ${position} at ${company}?`)) {
                acceptOffer(applicationId, applicationRow);
            }
        });
    });

    // Delete Application
    document.querySelectorAll('.delete-application').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            const applicationRow = this.closest('tr');
            const position = applicationRow.cells[0].textContent;
            const company = applicationRow.cells[1].textContent;
            
            if (confirm(`Are you sure you want to delete your application for ${position} at ${company}?`)) {
                deleteApplication(applicationId, applicationRow);
            }
        });
    });
});

/**
 * Mock data for applications
 */
const mockApplications = {
    '1': {
        position: 'Senior Full Stack Developer',
        company: 'TechNova Solutions',
        status: 'Application Submitted',
        statusClass: 'bg-primary',
        applicationDate: 'October 25, 2023',
        jobType: 'Full-time',
        location: 'Remote (US Timezones)',
        salary: '$120,000 - $150,000 per year',
        jobDescription: 'We are looking for an experienced Full Stack Developer to join our team. You will be responsible for developing and maintaining web applications using modern JavaScript frameworks. The ideal candidate has a strong understanding of both front-end and back-end development, with experience in React, Node.js, and cloud services.',
        notes: 'Technical interview scheduled for November 2nd, 2:00 PM EST.',
        nextSteps: [
            'Application submitted',
            'Initial screening completed',
            'Technical assessment pending'
        ],
        documents: [
            { name: 'Resume.pdf', type: 'pdf' },
            { name: 'Cover_Letter.pdf', type: 'pdf' },
            { name: 'Portfolio.pdf', type: 'pdf' }
        ]
    },
    '2': {
        position: 'Product Manager',
        company: 'DesignHub Inc.',
        status: 'Interview Scheduled',
        statusClass: 'bg-warning',
        applicationDate: 'October 23, 2023',
        jobType: 'Full-time',
        location: 'San Francisco, CA',
        salary: '$130,000 - $160,000 per year',
        jobDescription: 'We are seeking an experienced Product Manager to lead our product development initiatives. The ideal candidate will work closely with engineering, design, and marketing teams to deliver high-quality products that meet customer needs and drive business growth.',
        notes: 'Second round interview scheduled with the product team on November 1st.',
        nextSteps: [
            'Application submitted',
            'Initial interview completed',
            'Product case study review scheduled'
        ],
        documents: [
            { name: 'Resume.pdf', type: 'pdf' },
            { name: 'Product_Strategy.pdf', type: 'pdf' }
        ]
    },
    '5': {
        position: 'DevOps Engineer',
        company: 'CloudScale Technologies',
        status: 'Offer Received',
        statusClass: 'bg-dark',
        applicationDate: 'October 15, 2023',
        jobType: 'Full-time',
        location: 'Austin, TX',
        salary: '$140,000 - $170,000 per year + 10% bonus',
        jobDescription: 'Join our DevOps team to build and maintain our cloud infrastructure. You will be responsible for CI/CD pipelines, infrastructure as code, and ensuring high availability of our services. Experience with AWS, Kubernetes, and Terraform is required.',
        notes: 'Offer letter received. Please review and respond by November 5th.',
        nextSteps: [
            'Application submitted',
            'Technical interviews completed',
            'Offer extended - pending acceptance'
        ],
        documents: [
            { name: 'Resume.pdf', type: 'pdf' },
            { name: 'Offer_Letter.pdf', type: 'pdf' }
        ]
    },
    '6': {
        position: 'Marketing Specialist',
        company: 'GrowthHack Media',
        status: 'Not Selected',
        statusClass: 'bg-secondary',
        applicationDate: 'October 10, 2023',
        jobType: 'Contract',
        location: 'New York, NY',
        salary: '$45 - $65 per hour',
        jobDescription: 'We are looking for a creative Marketing Specialist to develop and implement marketing campaigns. The role requires strong writing skills, social media expertise, and experience with marketing automation tools.',
        notes: 'Position filled internally. Would like to keep your resume on file for future opportunities.',
        nextSteps: [
            'Application submitted',
            'Initial screening completed',
            'Position filled'
        ],
        documents: [
            { name: 'Resume.pdf', type: 'pdf' },
            { name: 'Writing_Samples.pdf', type: 'pdf' }
        ]
    }
};

/**
 * Get icon class based on file type
 */
function getFileIcon(type) {
    const icons = {
        'pdf': 'far fa-file-pdf text-danger',
        'doc': 'far fa-file-word text-primary',
        'docx': 'far fa-file-word text-primary',
        'xls': 'far fa-file-excel text-success',
        'xlsx': 'far fa-file-excel text-success',
        'ppt': 'far fa-file-powerpoint text-warning',
        'pptx': 'far fa-file-powerpoint text-warning',
        'jpg': 'far fa-file-image text-info',
        'jpeg': 'far fa-file-image text-info',
        'png': 'far fa-file-image text-info',
        'zip': 'far fa-file-archive text-muted',
        'default': 'far fa-file-alt text-secondary'
    };
    return icons[type] || icons['default'];
}

/**
 * View application details
 * @param {string} applicationId - The ID of the application
 */
function viewApplication(applicationId) {
    const appData = mockApplications[applicationId] || {
        position: 'Unknown Position',
        company: 'Unknown Company',
        status: 'Unknown Status',
        statusClass: 'bg-secondary',
        applicationDate: 'N/A',
        jobType: 'N/A',
        location: 'N/A',
        salary: 'N/A',
        jobDescription: 'No description available.',
        notes: 'No additional notes available.',
        nextSteps: ['No next steps available.'],
        documents: []
    };

    // Update modal content
    document.getElementById('modal-position').textContent = appData.position;
    document.getElementById('modal-company').textContent = appData.company;
    
    const statusBadge = document.getElementById('modal-status');
    statusBadge.textContent = appData.status;
    statusBadge.className = 'badge ' + appData.statusClass;
    
    document.getElementById('modal-application-date').textContent = appData.applicationDate;
    document.getElementById('modal-job-type').textContent = appData.jobType;
    document.getElementById('modal-location').textContent = appData.location;
    document.getElementById('modal-salary').textContent = appData.salary;
    document.getElementById('modal-application-id').textContent = `APP-${applicationId.padStart(6, '0')}`;
    document.getElementById('modal-job-description').innerHTML = `<p class="mb-0">${appData.jobDescription}</p>`;
    
    // Update notes
    const notesElement = document.getElementById('modal-notes');
    if (appData.notes) {
        notesElement.innerHTML = `<p class="mb-0">${appData.notes}</p>`;
    }
    
    // Update next steps
    const nextStepsList = document.getElementById('modal-next-steps');
    nextStepsList.innerHTML = appData.nextSteps.map((step, index) => {
        const icon = index < 1 ? 'check-circle text-success' : 
                   index === appData.nextSteps.length - 1 ? 'arrow-right text-primary' : 'dot-circle text-muted';
        return `<li><i class="fas fa-${icon} me-2"></i> ${step}</li>`;
    }).join('');
    
    // Update documents
    const documentsList = document.getElementById('modal-documents');
    if (appData.documents && appData.documents.length > 0) {
        documentsList.innerHTML = appData.documents.map(doc => {
            const ext = doc.name.split('.').pop().toLowerCase();
            const icon = getFileIcon(ext);
            return `
                <div class="list-group-item d-flex justify-content-between align-items-center">
                    <span><i class="${icon} me-2"></i> ${doc.name}</span>
                    <a href="#" class="btn btn-sm btn-outline-primary">Download</a>
                </div>`;
        }).join('');
    } else {
        documentsList.innerHTML = `
            <div class="list-group-item">
                <p class="text-muted mb-0">No documents uploaded.</p>
            </div>`;
    }
    
    // Update primary action button based on status
    const primaryAction = document.getElementById('modal-primary-action');
    if (appData.status === 'Offer Received') {
        primaryAction.innerHTML = '<i class="fas fa-check-circle me-1"></i> Accept Offer';
        primaryAction.className = 'btn btn-success';
        primaryAction.onclick = () => acceptOffer(applicationId, document.querySelector(`tr[data-application-id="${applicationId}"]`));
    } else if (appData.status === 'Not Selected') {
        primaryAction.innerHTML = '<i class="fas fa-trash-alt me-1"></i> Delete Application';
        primaryAction.className = 'btn btn-danger';
        primaryAction.onclick = () => deleteApplication(applicationId, document.querySelector(`tr[data-application-id="${applicationId}"]`));
    } else {
        primaryAction.innerHTML = '<i class="fas fa-print me-1"></i> Print Application';
        primaryAction.className = 'btn btn-primary';
        primaryAction.onclick = () => window.print();
    }
    
    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('applicationDetailsModal'));
    modal.show();
}

/**
 * Withdraw an application
 * @param {string} applicationId - The ID of the application
 * @param {HTMLElement} rowElement - The table row element
 */
function withdrawApplication(applicationId, rowElement) {
    // In a real application, this would make an API call
    console.log(`Withdrawing application ${applicationId}`);
    
    // Simulate API call with timeout
    setTimeout(() => {
        // Update the status in the UI
        const statusCell = rowElement.cells[3];
        statusCell.innerHTML = '<span class="badge bg-secondary">Withdrawn</span>';
        
        // Update the action buttons
        const actionsCell = rowElement.cells[4];
        actionsCell.innerHTML = `
            <button class="btn btn-sm btn-outline-primary view-application" data-application-id="${applicationId}">View</button>
            <button class="btn btn-sm btn-outline-danger delete-application" data-application-id="${applicationId}">Delete</button>
        `;
        
        // Re-attach event listeners to the new buttons
        attachEventListeners();
        
        // Show success message
        showAlert('Application withdrawn successfully!', 'success');
    }, 500);
}

/**
 * Accept a job offer
 * @param {string} applicationId - The ID of the application
 * @param {HTMLElement} rowElement - The table row element
 */
function acceptOffer(applicationId, rowElement) {
    // In a real application, this would make an API call
    console.log(`Accepting offer for application ${applicationId}`);
    
    // Simulate API call with timeout
    setTimeout(() => {
        // Update the status in the UI
        const statusCell = rowElement.cells[3];
        statusCell.innerHTML = '<span class="badge bg-success">Offer Accepted</span>';
        
        // Update the action buttons
        const actionsCell = rowElement.cells[4];
        actionsCell.innerHTML = `
            <button class="btn btn-sm btn-outline-primary view-application" data-application-id="${applicationId}">View</button>
            <button class="btn btn-sm btn-outline-secondary" disabled>Offer Accepted</button>
        `;
        
        // Re-attach event listeners to the new buttons
        attachEventListeners();
        
        // Show success message
        showAlert('Offer accepted successfully!', 'success');
    }, 500);
}

/**
 * Delete an application
 * @param {string} applicationId - The ID of the application
 * @param {HTMLElement} rowElement - The table row element
 */
function deleteApplication(applicationId, rowElement) {
    // In a real application, this would make an API call
    console.log(`Deleting application ${applicationId}`);
    
    // Simulate API call with timeout
    setTimeout(() => {
        // Remove the row from the table
        rowElement.remove();
        
        // Show success message
        showAlert('Application deleted successfully!', 'success');
    }, 500);
}

/**
 * Show a bootstrap alert message
 * @param {string} message - The message to display
 * @param {string} type - The type of alert (success, danger, warning, info)
 */
function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // Add the alert to the page (before the table)
    const container = document.querySelector('.container-fluid .px-4');
    const table = document.querySelector('table');
    container.insertBefore(alertDiv, table);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const alert = bootstrap.Alert.getOrCreateInstance(alertDiv);
        alert.close();
    }, 5000);
}

/**
 * Re-attach event listeners to dynamically added elements
 */
function attachEventListeners() {
    // View Application
    document.querySelectorAll('.view-application').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            viewApplication(applicationId);
        });
    });

    // Withdraw Application
    document.querySelectorAll('.withdraw-application').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            const applicationRow = this.closest('tr');
            const position = applicationRow.cells[0].textContent;
            const company = applicationRow.cells[1].textContent;
            
            if (confirm(`Are you sure you want to withdraw your application for ${position} at ${company}?`)) {
                withdrawApplication(applicationId, applicationRow);
            }
        });
    });

    // Accept Offer
    document.querySelectorAll('.accept-offer').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            const applicationRow = this.closest('tr');
            const position = applicationRow.cells[0].textContent;
            const company = applicationRow.cells[1].textContent;
            
            if (confirm(`Are you sure you want to accept the offer for ${position} at ${company}?`)) {
                acceptOffer(applicationId, applicationRow);
            }
        });
    });

    // Delete Application
    document.querySelectorAll('.delete-application').forEach(button => {
        button.addEventListener('click', function() {
            const applicationId = this.getAttribute('data-application-id');
            const applicationRow = this.closest('tr');
            const position = applicationRow.cells[0].textContent;
            const company = applicationRow.cells[1].textContent;
            
            if (confirm(`Are you sure you want to delete your application for ${position} at ${company}?`)) {
                deleteApplication(applicationId, applicationRow);
            }
        });
    });
}
