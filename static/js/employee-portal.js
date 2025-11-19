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

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', function() {
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
