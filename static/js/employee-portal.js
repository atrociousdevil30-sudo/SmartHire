// Employee Portal - Modal Handlers for Profile, Documents, and Settings

// ============ PROFILE MODAL FUNCTIONS ============

function loadProfileModal() {
    // Fetch profile data from backend
    fetch('/api/employee/profile', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Populate form with user data
            document.getElementById('fullName').value = data.data.full_name;
            document.getElementById('email').value = data.data.email;
            document.getElementById('phone').value = data.data.phone;
            document.getElementById('department').value = data.data.department;
            document.getElementById('position').value = data.data.position;
        } else {
            showToast('danger', 'Error', 'Failed to load profile data');
        }
    })
    .catch(error => {
        console.error('Error loading profile:', error);
        showToast('danger', 'Error', 'An error occurred while loading profile');
    });
}

function saveProfile() {
    console.log('saveProfile function called');
    
    const phone = document.getElementById('phone').value;
    const department = document.getElementById('department').value;
    const position = document.getElementById('position').value;
    
    console.log('Form values:', { phone, department, position });
    
    const formData = new FormData();
    formData.append('phone', phone);
    formData.append('department', department);
    formData.append('position', position);
    
    const submitBtn = document.querySelector('#profileModal .btn-primary');
    if (!submitBtn) {
        console.error('Submit button not found');
        return;
    }
    
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';
    
    fetch('/api/employee/profile', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => {
        console.log('Response status:', response.status);
        return response.json();
    })
    .then(data => {
        console.log('Response data:', data);
        if (data.status === 'success') {
            showToast('success', 'Success', data.message);
            setTimeout(() => {
                const modal = bootstrap.Modal.getInstance(document.getElementById('profileModal'));
                if (modal) modal.hide();
            }, 1000);
        } else {
            showToast('danger', 'Error', data.message || 'Failed to save profile');
        }
    })
    .catch(error => {
        console.error('Error saving profile:', error);
        showToast('danger', 'Error', 'Failed to save profile');
    })
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    });
}

// ============ DOCUMENTS MODAL FUNCTIONS ============

function loadDocumentsModal() {
    // Fetch documents list
    fetch('/api/employee/documents', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            displayDocuments(data.data);
        } else {
            showToast('danger', 'Error', 'Failed to load documents');
        }
    })
    .catch(error => {
        console.error('Error loading documents:', error);
        showToast('danger', 'Error', 'An error occurred while loading documents');
    });
}

function displayDocuments(documents) {
    const documentsList = document.getElementById('documentsList');
    
    if (documents.length === 0) {
        documentsList.innerHTML = '<p class="text-muted">No documents uploaded yet.</p>';
        return;
    }
    
    let html = '';
    documents.forEach(doc => {
        const verifiedBadge = doc.is_verified ? 
            '<span class="badge bg-success ms-2"><i class="fas fa-check-circle me-1"></i>Verified</span>' : 
            '<span class="badge bg-warning ms-2"><i class="fas fa-clock me-1"></i>Pending</span>';
        
        const fileSizeMB = (doc.file_size / (1024 * 1024)).toFixed(2);
        
        html += `
            <div class="list-group-item list-group-item-action">
                <div class="d-flex w-100 justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="d-flex align-items-center">
                            <h6 class="mb-1"><i class="fas fa-file me-2"></i>${doc.file_name}</h6>
                            ${verifiedBadge}
                        </div>
                        <p class="mb-1 small text-muted">
                            Type: ${doc.document_type} | Size: ${fileSizeMB} MB | Uploaded: ${doc.upload_date}
                        </p>
                        ${doc.description ? `<p class="mb-0 small">${doc.description}</p>` : ''}
                    </div>
                    <div class="btn-group btn-group-sm ms-2" role="group">
                        <a href="/uploads/documents/${doc.file_name}" class="btn btn-outline-primary" 
                           title="Download" target="_blank">
                            <i class="fas fa-download"></i>
                        </a>
                        <button type="button" class="btn btn-outline-danger" 
                                onclick="deleteDocument(${doc.id}, '${doc.file_name}')" 
                                title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    });
    
    documentsList.innerHTML = `<div class="list-group">${html}</div>`;
}

function uploadDocument() {
    const fileInput = document.getElementById('documentFile');
    const documentType = document.getElementById('documentType').value;
    const description = document.getElementById('documentDescription').value;
    
    if (!fileInput.files[0]) {
        showToast('warning', 'Warning', 'Please select a file to upload');
        return;
    }
    
    if (!documentType) {
        showToast('warning', 'Warning', 'Please select a document type');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('document_type', documentType);
    formData.append('description', description);
    
    const uploadBtn = document.querySelector('#documentsModal .btn-primary');
    const originalText = uploadBtn.innerHTML;
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Uploading...';
    
    fetch('/api/employee/documents/upload', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('success', 'Success', data.message);
            // Clear form
            fileInput.value = '';
            document.getElementById('documentType').value = '';
            document.getElementById('documentDescription').value = '';
            // Reload documents
            loadDocumentsModal();
        } else {
            showToast('danger', 'Error', data.message);
        }
    })
    .catch(error => {
        console.error('Error uploading document:', error);
        showToast('danger', 'Error', 'Failed to upload document');
    })
    .finally(() => {
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = originalText;
    });
}

function deleteDocument(docId, fileName) {
    if (!confirm(`Are you sure you want to delete "${fileName}"?`)) {
        return;
    }
    
    fetch(`/api/employee/documents/${docId}`, {
        method: 'DELETE',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('success', 'Success', 'Document deleted successfully');
            loadDocumentsModal();
        } else {
            showToast('danger', 'Error', data.message);
        }
    })
    .catch(error => {
        console.error('Error deleting document:', error);
        showToast('danger', 'Error', 'Failed to delete document');
    });
}

// ============ SETTINGS MODAL FUNCTIONS ============

function loadSettingsModal() {
    fetch('/api/employee/settings', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Populate form with settings
            document.getElementById('emailNotifications').checked = 
                data.data.email_notifications;
            document.getElementById('smsNotifications').checked = 
                data.data.sms_notifications;
            document.getElementById('notificationFrequency').value = 
                data.data.notification_frequency;
            document.getElementById('theme').value = data.data.theme;
            document.getElementById('language').value = data.data.language;
            document.getElementById('twoFactorAuth').checked = 
                data.data.two_factor_enabled;
        } else {
            showToast('danger', 'Error', 'Failed to load settings');
        }
    })
    .catch(error => {
        console.error('Error loading settings:', error);
        showToast('danger', 'Error', 'An error occurred while loading settings');
    });
}

function saveSettings() {
    const formData = new FormData();
    formData.append('email_notifications', 
        document.getElementById('emailNotifications').checked);
    formData.append('sms_notifications', 
        document.getElementById('smsNotifications').checked);
    formData.append('notification_frequency', 
        document.getElementById('notificationFrequency').value);
    formData.append('theme', document.getElementById('theme').value);
    formData.append('language', document.getElementById('language').value);
    formData.append('two_factor_enabled', 
        document.getElementById('twoFactorAuth').checked);
    
    const submitBtn = document.querySelector('#settingsModal .btn-primary');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';
    
    fetch('/api/employee/settings', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('success', 'Success', data.message);
            // Apply theme if changed
            const newTheme = document.getElementById('theme').value;
            document.documentElement.setAttribute('data-theme', newTheme);
            
            // Close modal after 1 second
            setTimeout(() => {
                bootstrap.Modal.getInstance(
                    document.getElementById('settingsModal')).hide();
            }, 1000);
        } else {
            showToast('danger', 'Error', data.message);
        }
    })
    .catch(error => {
        console.error('Error saving settings:', error);
        showToast('danger', 'Error', 'Failed to save settings');
    })
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    });
}

function changePassword() {
    // Close settings modal and open change password modal
    const settingsModal = bootstrap.Modal.getInstance(
        document.getElementById('settingsModal'));
    if (settingsModal) {
        settingsModal.hide();
    }
    
    // Open change password modal
    const changePasswordModal = new bootstrap.Modal(
        document.getElementById('changePasswordModal'));
    changePasswordModal.show();
}

function submitPasswordChange() {
    const currentPassword = document.getElementById(
        'currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById(
        'confirmPassword').value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
        showToast('warning', 'Warning', 'Please fill in all fields');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showToast('danger', 'Error', 'New passwords do not match');
        return;
    }
    
    if (newPassword.length < 8) {
        showToast('danger', 'Error', 
            'Password must be at least 8 characters');
        return;
    }
    
    const formData = new FormData();
    formData.append('current_password', currentPassword);
    formData.append('new_password', newPassword);
    formData.append('confirm_password', confirmPassword);
    
    const submitBtn = document.querySelector('#changePasswordModal .btn-primary');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Updating...';
    
    fetch('/api/employee/change-password', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('success', 'Success', data.message);
            // Close modal and reset form
            setTimeout(() => {
                bootstrap.Modal.getInstance(
                    document.getElementById('changePasswordModal')).hide();
                document.getElementById('changePasswordForm').reset();
            }, 1000);
        } else {
            showToast('danger', 'Error', data.message);
        }
    })
    .catch(error => {
        console.error('Error changing password:', error);
        showToast('danger', 'Error', 'Failed to change password');
    })
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    });
}

// ============ NOTIFICATION SYSTEM ============

let notificationCheckInterval;
let lastNotificationCount = 0;

// Initialize notification system
function initializeNotifications() {
    // Check for notifications immediately
    checkNotifications();
    
    // Then check every 30 seconds
    notificationCheckInterval = setInterval(checkNotifications, 30000);
}

// Check for new notifications
function checkNotifications() {
    fetch('/api/notifications', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const unreadCount = data.unread_count || 0;
            
            // Update notification badge if it exists
            updateNotificationBadge(unreadCount);
            
            // Show toast for new notifications
            if (unreadCount > lastNotificationCount) {
                const newNotifications = data.notifications.slice(0, unreadCount - lastNotificationCount);
                newNotifications.forEach(notification => {
                    showNotificationToast(notification);
                });
            }
            
            lastNotificationCount = unreadCount;
        }
    })
    .catch(error => {
        console.error('Error checking notifications:', error);
    });
}

// Update notification badge in navbar
function updateNotificationBadge(count) {
    const badge = document.getElementById('notificationBadge');
    if (badge) {
        badge.textContent = count;
        badge.style.display = count > 0 ? 'inline-block' : 'none';
    }
}

// Show toast for new notification
function showNotificationToast(notification) {
    const type = notification.priority === 'urgent' ? 'danger' : 
                 notification.priority === 'high' ? 'warning' : 
                 notification.priority === 'low' ? 'info' : 'primary';
    
    const icon = notification.message_type === 'task' ? 'fa-tasks' :
                notification.message_type === 'document' ? 'fa-file-alt' :
                notification.message_type === 'interview' ? 'fa-calendar-check' :
                notification.message_type === 'exit' ? 'fa-door-open' :
                'fa-bell';
    
    const title = `<i class="fas ${icon} me-2"></i>${notification.subject}`;
    
    showToast(type, title, notification.content);
}

// Load and display all notifications
function loadNotifications() {
    fetch('/api/notifications', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            displayNotificationsModal(data.notifications);
        }
    })
    .catch(error => {
        console.error('Error loading notifications:', error);
        showToast('danger', 'Error', 'Failed to load notifications');
    });
}

// Display notifications in a modal
function displayNotificationsModal(notifications) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('notificationsModal');
    if (!modal) {
        const modalHtml = `
            <div class="modal fade" id="notificationsModal" tabindex="-1" aria-labelledby="notificationsModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="notificationsModalLabel"><i class="fas fa-bell me-2"></i>All Notifications</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div id="notificationsList">
                                <p class="text-muted">Loading notifications...</p>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" onclick="markAllNotificationsRead()">Mark All as Read</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        modal = document.getElementById('notificationsModal');
    }
    
    const notificationsList = document.getElementById('notificationsList');
    
    if (notifications.length === 0) {
        notificationsList.innerHTML = '<p class="text-muted text-center">No notifications</p>';
    } else {
        let html = '';
        notifications.forEach(notification => {
            const icon = notification.message_type === 'task' ? 'fa-tasks' :
                        notification.message_type === 'document' ? 'fa-file-alt' :
                        notification.message_type === 'interview' ? 'fa-calendar-check' :
                        notification.message_type === 'exit' ? 'fa-door-open' :
                        'fa-bell';
            
            const badgeClass = notification.priority === 'urgent' ? 'danger' :
                              notification.priority === 'high' ? 'warning' :
                              notification.priority === 'low' ? 'info' :
                              'primary';
            
            html += `
                <div class="card mb-2 notification-item ${notification.status === 'read' ? 'opacity-50' : ''}" data-id="${notification.id}">
                    <div class="card-body">
                        <div class="d-flex align-items-start">
                            <div class="me-3">
                                <i class="fas ${icon} text-${badgeClass} fs-4"></i>
                            </div>
                            <div class="flex-grow-1">
                                <h6 class="card-title mb-1">${notification.subject}</h6>
                                <p class="card-text small text-muted">${notification.content}</p>
                                <small class="text-muted">
                                    <i class="fas fa-clock me-1"></i>
                                    ${new Date(notification.sent_at).toLocaleString()}
                                    <span class="ms-2">
                                        <span class="badge bg-${badgeClass}">${notification.priority}</span>
                                        <span class="badge bg-secondary ms-1">${notification.message_type}</span>
                                    </span>
                                </small>
                            </div>
                            <div class="ms-2">
                                ${notification.status === 'unread' ? 
                                    `<button class="btn btn-sm btn-outline-primary" onclick="markNotificationRead(${notification.id})">
                                        <i class="fas fa-check"></i>
                                    </button>` : 
                                    '<span class="text-success"><i class="fas fa-check-circle"></i></span>'
                                }
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        notificationsList.innerHTML = html;
    }
    
    // Show modal
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
}

// Mark notification as read
function markNotificationRead(notificationId) {
    fetch(`/api/notifications/${notificationId}/read`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Update UI
            const notificationItem = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
            if (notificationItem) {
                notificationItem.classList.add('opacity-50');
                const button = notificationItem.querySelector('button');
                if (button) {
                    button.innerHTML = '<i class="fas fa-check-circle"></i>';
                    button.disabled = true;
                }
            }
            // Update badge
            checkNotifications();
        }
    })
    .catch(error => {
        console.error('Error marking notification as read:', error);
    });
}

// Mark all notifications as read
function markAllNotificationsRead() {
    const unreadNotifications = document.querySelectorAll('.notification-item:not(.opacity-50)');
    const notificationIds = Array.from(unreadNotifications).map(item => item.dataset.id);
    
    if (notificationIds.length === 0) {
        showToast('info', 'Info', 'All notifications are already marked as read');
        return;
    }
    
    // Mark each notification as read
    const promises = notificationIds.map(id => 
        fetch(`/api/notifications/${id}/read`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
    );
    
    Promise.all(promises)
    .then(responses => Promise.all(responses.map(r => r.json())))
    .then(results => {
        const successCount = results.filter(r => r.status === 'success').length;
        if (successCount > 0) {
            showToast('success', 'Success', `Marked ${successCount} notifications as read`);
            // Update UI
            unreadNotifications.forEach(item => {
                item.classList.add('opacity-50');
                const button = item.querySelector('button');
                if (button) {
                    button.innerHTML = '<i class="fas fa-check-circle"></i>';
                    button.disabled = true;
                }
            });
            // Update badge
            checkNotifications();
        }
    })
    .catch(error => {
        console.error('Error marking notifications as read:', error);
        showToast('danger', 'Error', 'Failed to mark notifications as read');
    });
}

// Clean up notification system when page unloads
window.addEventListener('beforeunload', () => {
    if (notificationCheckInterval) {
        clearInterval(notificationCheckInterval);
    }
});

// ============ UTILITY FUNCTIONS ============

function showToast(type, title, message) {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        // Create toast container if it doesn't exist
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'position-fixed top-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }
    
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = 'toast align-items-center text-white bg-' + 
        type + ' border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong><br>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" 
                    data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    const container = document.getElementById('toastContainer');
    container.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Make functions globally available
window.loadProfileModal = loadProfileModal;
window.saveProfile = saveProfile;
window.loadDocumentsModal = loadDocumentsModal;
window.uploadDocument = uploadDocument;
window.deleteDocument = deleteDocument;
window.loadSettingsModal = loadSettingsModal;
window.saveSettings = saveSettings;
window.changePassword = changePassword;
window.submitPasswordChange = submitPasswordChange;
window.loadNotifications = loadNotifications;
window.markNotificationRead = markNotificationRead;
window.markAllNotificationsRead = markAllNotificationsRead;

// Initialize page when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize notification system
    initializeNotifications();
    
    // Load user profile
    loadProfile();
    
    // Add event listeners for modal forms if needed
    const profileModal = document.getElementById('profileModal');
    if (profileModal) {
        profileModal.addEventListener('show.bs.modal', function() {
            loadProfileModal();
        });
    }
    
    const documentsModal = document.getElementById('documentsModal');
    if (documentsModal) {
        documentsModal.addEventListener('show.bs.modal', function() {
            loadDocumentsModal();
        });
    }
    
    const settingsModal = document.getElementById('settingsModal');
    if (settingsModal) {
        settingsModal.addEventListener('show.bs.modal', function() {
            loadSettingsModal();
        });
    }
});
