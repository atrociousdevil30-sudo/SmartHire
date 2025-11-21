// HR Notification System
let hrNotificationPolling;
let lastHRNotificationCount = 0;

// Initialize HR notification system
document.addEventListener('DOMContentLoaded', function() {
    // Start polling for HR notifications
    startHRNotificationPolling();
    
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Start polling for HR notifications
function startHRNotificationPolling() {
    // Initial load
    checkHRNotifications();
    
    // Poll every 30 seconds
    hrNotificationPolling = setInterval(function() {
        checkHRNotifications();
    }, 30000);
}

// Check for new HR notifications
function checkHRNotifications() {
    fetch('/api/hr/notifications', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Filter out daily summary notifications but keep interview_ready notifications
            const filteredNotifications = (data.notifications || []).filter(notification => {
                return notification.message_type === 'interview_ready' || 
                       !(notification.notification_data && notification.notification_data.notification_type === 'daily_summary');
            });
            
            // Update badge with count of non-daily summary notifications
            updateHRNotificationBadge(filteredNotifications.length);
            
            // Show toast for new high-priority notifications (DISABLED)
            // filteredNotifications.forEach(notification => {
            //     if ((notification.priority === 'urgent' || notification.priority === 'high') && 
            //         notification.message_type === 'interview_ready') {
            //         showHRNotificationToast(notification);
            //     }
            // });
        }
    })
    .catch(error => {
        console.error('Error checking HR notifications:', error);
    });
}

// Update HR notification badge
function updateHRNotificationBadge(count) {
    const badge = document.getElementById('hrNotificationBadge');
    if (badge) {
        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : count;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    }
}

// Show HR notification as toast
function showHRNotificationToast(notification) {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;
    
    const toastId = 'hr-toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = 'toast align-items-center text-white bg-' + getHRToastColor(notification.priority) + ' border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    const icon = getHRNotificationIcon(notification.type);
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <div class="d-flex align-items-center mb-2">
                    <i class="${icon} me-2"></i>
                    <strong>${notification.title}</strong>
                </div>
                <div>${notification.message}</div>
                ${notification.action_url ? `<div class="mt-2"><a href="${notification.action_url}" class="btn btn-sm btn-light">Take Action</a></div>` : ''}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" 
                    data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast, { delay: 8000 });
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Get toast color based on priority
function getHRToastColor(priority) {
    switch(priority) {
        case 'urgent': return 'danger';
        case 'high': return 'warning';
        case 'normal': return 'info';
        case 'low': return 'secondary';
        default: return 'primary';
    }
}

// Get icon for notification type
function getHRNotificationIcon(type) {
    switch(type) {
        case 'onboarding_overdue': return 'fas fa-exclamation-triangle';
        case 'access_revocation': return 'fas fa-key';
        case 'daily_summary': return 'fas fa-calendar-day';
        case 'task_pending': return 'fas fa-tasks';
        case 'document_pending': return 'fas fa-file-alt';
        case 'interview_scheduled': return 'fas fa-calendar-check';
        case 'exit_pending': return 'fas fa-door-open';
        default: return 'fas fa-info-circle';
    }
}

// Load all HR notifications
function loadHRNotifications() {
    fetch('/api/hr/notifications/all', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Apply same filtering: include interview_ready, exclude daily summaries
            const filteredNotifications = (data.notifications || []).filter(notification => {
                return notification.message_type === 'interview_ready' || 
                       !(notification.notification_data && notification.notification_data.notification_type === 'daily_summary');
            });
            displayHRNotificationsModal(filteredNotifications);
        }
    })
    .catch(error => {
        console.error('Error loading HR notifications:', error);
        showToast('danger', 'Error', 'Failed to load notifications');
    });
}

// Display HR notifications in a modal
function displayHRNotificationsModal(notifications) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('hrNotificationsModal');
    if (!modal) {
        const modalHtml = `
            <div class="modal fade" id="hrNotificationsModal" tabindex="-1" aria-labelledby="hrNotificationsModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="hrNotificationsModalLabel"><i class="fas fa-bell me-2"></i>HR Notifications</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div id="hrNotificationsList">
                                <p class="text-muted">Loading notifications...</p>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" onclick="generateDailySummary()">Generate Daily Summary</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }
    
    const notificationsList = document.getElementById('hrNotificationsList');
    if (!notifications || notifications.length === 0) {
        notificationsList.innerHTML = '<p class="text-center text-muted">No notifications at this time.</p>';
    } else {
        let html = '';
        notifications.forEach(notification => {
            const icon = getHRNotificationIcon(notification.message_type || notification.type);
            const badgeClass = getHRBadgeClass(notification.priority || 'normal');
            const createdAt = new Date(notification.sent_at || notification.created_at).toLocaleString();
            const title = notification.subject || notification.title || 'Notification';
            const message = notification.content || notification.message || '';
            const isInterviewReady = (notification.message_type || '').toLowerCase() === 'interview_ready';
            
            // Create action button based on notification type
            let actionButton = '';
            if (isInterviewReady) {
                // For interview ready notifications, add a button to start the interview
                const employeeName = notification.subject.replace('Employee Ready for Interview - ', '');
                actionButton = `
                    <button class="btn btn-sm btn-success" 
                            onclick="openInterviewModal('${employeeName}'); 
                                     document.getElementById('hrNotificationsModal').querySelector('.btn-close').click();">
                        <i class="fas fa-video me-1"></i> Start Interview
                    </button>
                `;
            } else if (notification.action_url) {
                actionButton = `<a href="${notification.action_url}" class="btn btn-sm btn-outline-primary">View Details</a>`;
            }
            
            html += `
                <div class="card mb-2 ${notification.status === 'read' ? 'opacity-75' : 'border-primary'}">
                    <div class="card-body">
                        <div class="d-flex align-items-start">
                            <div class="me-3">
                                <i class="${icon} fs-4 text-${getHRToastColor(notification.priority || 'normal')}"></i>
                            </div>
                            <div class="flex-grow-1">
                                <div class="d-flex justify-content-between align-items-start">
                                    <h6 class="card-title mb-1">${title}</h6>
                                    <span class="badge ${badgeClass}">${notification.priority || 'normal'}</span>
                                </div>
                                <p class="card-text">${message}</p>
                                <div class="d-flex justify-content-between align-items-center">
                                    <small class="text-muted">${createdAt}</small>
                                    ${actionButton}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        notificationsList.innerHTML = html;
    }
    
    // Show modal
    const modalInstance = new bootstrap.Modal(document.getElementById('hrNotificationsModal'));
    modalInstance.show();
}

// Get badge class for priority
function getHRBadgeClass(priority) {
    switch(priority) {
        case 'urgent': return 'bg-danger';
        case 'high': return 'bg-warning text-dark';
        case 'normal': return 'bg-info';
        case 'low': return 'bg-secondary';
        default: return 'bg-primary';
    }
}

// Generate daily summary
function generateDailySummary() {
    fetch('/api/hr/daily-summary', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showDailySummaryModal(data.summary);
        } else {
            showToast('danger', 'Error', data.message || 'Failed to generate daily summary');
        }
    })
    .catch(error => {
        console.error('Error generating daily summary:', error);
        showToast('danger', 'Error', 'Failed to generate daily summary');
    });
}

// Show daily summary in modal
function showDailySummaryModal(summary) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('dailySummaryModal');
    if (!modal) {
        const modalHtml = `
            <div class="modal fade" id="dailySummaryModal" tabindex="-1" aria-labelledby="dailySummaryModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="dailySummaryModalLabel"><i class="fas fa-calendar-day me-2"></i>Daily HR Summary</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div id="dailySummaryContent">
                                <p class="text-muted">Generating summary...</p>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" onclick="exportDailySummary()">Export Summary</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }
    
    const content = document.getElementById('dailySummaryContent');
    let html = `
        <div class="row">
            <div class="col-md-12">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    Generated on ${new Date().toLocaleString()}
                </div>
            </div>
        </div>
    `;
    
    // Summary sections
    if (summary.overdue_onboarding && summary.overdue_onboarding.length > 0) {
        html += `
            <div class="row mb-4">
                <div class="col-md-12">
                    <h6 class="text-danger"><i class="fas fa-exclamation-triangle me-2"></i>Overdue Onboarding Tasks (${summary.overdue_onboarding.length})</h6>
                    <div class="table-responsive">
                        <table class="table table-sm table-striped">
                            <thead>
                                <tr>
                                    <th>Employee</th>
                                    <th>Task</th>
                                    <th>Days Overdue</th>
                                    <th>Assigned Date</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
        `;
        summary.overdue_onboarding.forEach(item => {
            html += `
                <tr>
                    <td>${item.employee_name}</td>
                    <td>${item.task_title}</td>
                    <td>${item.days_overdue}</td>
                    <td>${new Date(item.assigned_date).toLocaleDateString()}</td>
                    <td><a href="/onboarding" class="btn btn-sm btn-outline-primary">View</a></td>
                </tr>
            `;
        });
        html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }
    
    if (summary.pending_access_revocation && summary.pending_access_revocation.length > 0) {
        html += `
            <div class="row mb-4">
                <div class="col-md-12">
                    <h6 class="text-warning"><i class="fas fa-key me-2"></i>Pending Access Revocation (${summary.pending_access_revocation.length})</h6>
                    <div class="table-responsive">
                        <table class="table table-sm table-striped">
                            <thead>
                                <tr>
                                    <th>Employee</th>
                                    <th>System</th>
                                    <th>Exit Date</th>
                                    <th>Days Since Exit</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
        `;
        summary.pending_access_revocation.forEach(item => {
            html += `
                <tr>
                    <td>${item.employee_name}</td>
                    <td>${item.system_name}</td>
                    <td>${new Date(item.exit_date).toLocaleDateString()}</td>
                    <td>${item.days_since_exit}</td>
                    <td><a href="/access-records" class="btn btn-sm btn-outline-warning">Revoke</a></td>
                </tr>
            `;
        });
        html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Add other summary sections...
    html += `
        <div class="row">
            <div class="col-md-12">
                <h6><i class="fas fa-chart-line me-2"></i>Quick Stats</h6>
                <div class="row">
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title text-primary">${summary.stats?.pending_tasks || 0}</h5>
                                <p class="card-text">Pending Tasks</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title text-warning">${summary.stats?.pending_documents || 0}</h5>
                                <p class="card-text">Pending Documents</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title text-info">${summary.stats?.upcoming_interviews || 0}</h5>
                                <p class="card-text">Upcoming Interviews</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title text-success">${summary.stats?.completed_onboarding || 0}</h5>
                                <p class="card-text">Completed Onboarding</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    content.innerHTML = html;
    
    // Show modal
    const modalInstance = new bootstrap.Modal(document.getElementById('dailySummaryModal'));
    modalInstance.show();
}

// Export daily summary
function exportDailySummary() {
    window.print();
}

// Expose functions to global scope
window.loadHRNotifications = loadHRNotifications;
window.generateDailySummary = generateDailySummary;
window.exportDailySummary = exportDailySummary;
