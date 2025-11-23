/**
 * SmartHire Interactive Tour System
 * Provides guided tours for new users
 */

class SmartHireTour {
    constructor() {
        this.currentStep = 0;
        this.tourSteps = [];
        this.isActive = false;
        this.tourOverlay = null;
        this.highlightElement = null;
        this.tourTooltip = null;
        this.userProgress = this.loadTourProgress();
    }

    // Load user's tour progress from localStorage
    loadTourProgress() {
        const saved = localStorage.getItem('smarthire_tour_progress');
        return saved ? JSON.parse(saved) : {
            dashboard: false,
            employees: false,
            documents: false,
            onboarding: false,
            interviews: false
        };
    }

    // Save tour progress
    saveTourProgress() {
        localStorage.setItem('smarthire_tour_progress', JSON.stringify(this.userProgress));
    }

    // Define tour steps for different pages
    getTourSteps(page) {
        const tours = {
            dashboard: [
                {
                    target: '.dashboard-welcome',
                    title: 'Welcome to SmartHire! 👋',
                    content: 'This is your main dashboard. Let us show you around the most important features.',
                    position: 'bottom',
                    action: 'next'
                },
                {
                    target: '.quick-actions',
                    title: 'Quick Actions',
                    content: 'Start here for your most common HR tasks. These are prioritized based on what you use most.',
                    position: 'right',
                    action: 'next'
                },
                {
                    target: '.priority-tasks',
                    title: "Today's Priorities",
                    content: 'See what needs your attention right now. We highlight urgent tasks and upcoming deadlines.',
                    position: 'left',
                    action: 'next'
                },
                {
                    target: '.employee-directory-card',
                    title: 'Employee Management',
                    content: 'View, edit, and manage all your employees. Click to see detailed profiles and management options.',
                    position: 'top',
                    action: 'next'
                },
                {
                    target: '.help-button',
                    title: 'Need Help?',
                    content: 'Click this question mark anytime you need assistance or want to learn more about a feature.',
                    position: 'left',
                    action: 'finish'
                }
            ],
            employees: [
                {
                    target: '.add-employee-btn',
                    title: 'Add New Employee',
                    content: 'Start here to add a new team member. We\'ll guide you through all the required information.',
                    position: 'bottom',
                    action: 'next'
                },
                {
                    target: '.employee-search',
                    title: 'Smart Search',
                    content: 'Find employees quickly by name, department, or role. The search works instantly as you type.',
                    position: 'bottom',
                    action: 'next'
                },
                {
                    target: '.employee-filters',
                    title: 'Quick Filters',
                    content: 'Filter employees by department, status, or role to find exactly who you\'re looking for.',
                    position: 'right',
                    action: 'finish'
                }
            ],
            documents: [
                {
                    target: '.template-gallery',
                    title: 'Document Templates',
                    content: 'Choose from our library of professional HR templates. Each one is customizable and ready to use.',
                    position: 'top',
                    action: 'next'
                },
                {
                    target: '.generate-document-btn',
                    title: 'Generate Documents',
                    content: 'Create personalized documents for employees in seconds. Just fill in the details and we\'ll handle the rest.',
                    position: 'bottom',
                    action: 'finish'
                }
            ]
        };

        return tours[page] || [];
    }

    // Start a tour for a specific page
    startTour(page) {
        if (this.userProgress[page]) {
            this.showTourCompletionMessage(page);
            return;
        }

        this.tourSteps = this.getTourSteps(page);
        if (this.tourSteps.length === 0) return;

        this.isActive = true;
        this.currentStep = 0;
        this.createTourOverlay();
        this.showCurrentStep();
    }

    // Create tour overlay and tooltip
    createTourOverlay() {
        // Remove existing tour elements
        this.endTour();

        // Create overlay
        this.tourOverlay = document.createElement('div');
        this.tourOverlay.className = 'tour-overlay';
        this.tourOverlay.innerHTML = `
            <style>
                .tour-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.7);
                    z-index: 9998;
                    pointer-events: none;
                }
                
                .tour-highlight {
                    position: relative;
                    z-index: 9999;
                    box-shadow: 0 0 0 4px #7b2cbf, 0 0 20px rgba(123, 44, 191, 0.5);
                    border-radius: 8px;
                    pointer-events: auto;
                }
                
                .tour-tooltip {
                    position: absolute;
                    background: white;
                    color: #333;
                    padding: 20px;
                    border-radius: 12px;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                    z-index: 10000;
                    max-width: 350px;
                    pointer-events: auto;
                }
                
                .tour-tooltip::before {
                    content: '';
                    position: absolute;
                    width: 0;
                    height: 0;
                    border: 10px solid transparent;
                }
                
                .tour-tooltip.top::before {
                    bottom: -20px;
                    left: 50%;
                    transform: translateX(-50%);
                    border-top-color: white;
                }
                
                .tour-tooltip.bottom::before {
                    top: -20px;
                    left: 50%;
                    transform: translateX(-50%);
                    border-bottom-color: white;
                }
                
                .tour-tooltip.left::before {
                    right: -20px;
                    top: 50%;
                    transform: translateY(-50%);
                    border-left-color: white;
                }
                
                .tour-tooltip.right::before {
                    left: -20px;
                    top: 50%;
                    transform: translateY(-50%);
                    border-right-color: white;
                }
                
                .tour-title {
                    font-size: 18px;
                    font-weight: 600;
                    margin-bottom: 10px;
                    color: #7b2cbf;
                }
                
                .tour-content {
                    font-size: 14px;
                    line-height: 1.5;
                    margin-bottom: 20px;
                }
                
                .tour-actions {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .tour-progress {
                    font-size: 12px;
                    color: #666;
                }
                
                .tour-buttons {
                    display: flex;
                    gap: 10px;
                }
                
                .tour-btn {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 14px;
                    transition: all 0.3s ease;
                }
                
                .tour-btn-primary {
                    background: #7b2cbf;
                    color: white;
                }
                
                .tour-btn-primary:hover {
                    background: #6a1fa8;
                }
                
                .tour-btn-secondary {
                    background: #e9ecef;
                    color: #333;
                }
                
                .tour-btn-secondary:hover {
                    background: #dee2e6;
                }
                
                .tour-skip-link {
                    font-size: 12px;
                    color: #666;
                    text-decoration: underline;
                    cursor: pointer;
                }
                
                .tour-skip-link:hover {
                    color: #333;
                }
            </style>
        `;

        document.body.appendChild(this.tourOverlay);

        // Create tooltip
        this.tourTooltip = document.createElement('div');
        this.tourTooltip.className = 'tour-tooltip';
        document.body.appendChild(this.tourTooltip);
    }

    // Show current tour step
    showCurrentStep() {
        if (!this.isActive || this.currentStep >= this.tourSteps.length) {
            this.completeTour();
            return;
        }

        const step = this.tourSteps[this.currentStep];
        const targetElement = document.querySelector(step.target);

        if (!targetElement) {
            this.nextStep();
            return;
        }

        // Highlight target element
        this.highlightTarget(targetElement);

        // Position and show tooltip
        this.positionTooltip(targetElement, step);
        this.updateTooltipContent(step);
    }

    // Highlight the target element
    highlightTarget(element) {
        // Remove previous highlight
        if (this.highlightElement) {
            this.highlightElement.classList.remove('tour-highlight');
        }

        // Add highlight to current element
        element.classList.add('tour-highlight');
        this.highlightElement = element;

        // Scroll element into view if needed
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'center',
            inline: 'center'
        });
    }

    // Position tooltip relative to target
    positionTooltip(target, step) {
        const rect = target.getBoundingClientRect();
        const tooltip = this.tourTooltip;
        
        // Reset classes
        tooltip.className = 'tour-tooltip';

        let top, left;

        switch (step.position) {
            case 'top':
                top = rect.top - tooltip.offsetHeight - 20;
                left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2);
                tooltip.classList.add('top');
                break;
            case 'bottom':
                top = rect.bottom + 20;
                left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2);
                tooltip.classList.add('bottom');
                break;
            case 'left':
                top = rect.top + (rect.height / 2) - (tooltip.offsetHeight / 2);
                left = rect.left - tooltip.offsetWidth - 20;
                tooltip.classList.add('left');
                break;
            case 'right':
                top = rect.top + (rect.height / 2) - (tooltip.offsetHeight / 2);
                left = rect.right + 20;
                tooltip.classList.add('right');
                break;
            default:
                top = rect.bottom + 20;
                left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2);
                tooltip.classList.add('bottom');
        }

        // Adjust if tooltip goes outside viewport
        if (left < 10) left = 10;
        if (left + tooltip.offsetWidth > window.innerWidth - 10) {
            left = window.innerWidth - tooltip.offsetWidth - 10;
        }
        if (top < 10) top = 10;
        if (top + tooltip.offsetHeight > window.innerHeight - 10) {
            top = window.innerHeight - tooltip.offsetHeight - 10;
        }

        tooltip.style.top = top + 'px';
        tooltip.style.left = left + 'px';
        tooltip.style.display = 'block';
    }

    // Update tooltip content
    updateTooltipContent(step) {
        const isLastStep = this.currentStep === this.tourSteps.length - 1;
        
        this.tourTooltip.innerHTML = `
            <div class="tour-title">${step.title}</div>
            <div class="tour-content">${step.content}</div>
            <div class="tour-actions">
                <div class="tour-progress">
                    Step ${this.currentStep + 1} of ${this.tourSteps.length}
                </div>
                <div class="tour-buttons">
                    ${this.currentStep > 0 ? '<button class="tour-btn tour-btn-secondary" onclick="tourManager.previousStep()">Previous</button>' : ''}
                    <a href="#" class="tour-skip-link" onclick="tourManager.skipTour()">Skip Tour</a>
                    <button class="tour-btn tour-btn-primary" onclick="tourManager.nextStep()">
                        ${isLastStep ? 'Finish' : 'Next'}
                    </button>
                </div>
            </div>
        `;
    }

    // Navigate to next step
    nextStep() {
        this.currentStep++;
        this.showCurrentStep();
    }

    // Navigate to previous step
    previousStep() {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.showCurrentStep();
        }
    }

    // Skip the tour
    skipTour() {
        if (confirm('Are you sure you want to skip this tour? You can always restart it later from the help menu.')) {
            this.endTour();
        }
    }

    // Complete the tour
    completeTour() {
        const currentPage = this.getCurrentPage();
        this.userProgress[currentPage] = true;
        this.saveTourProgress();
        
        this.showCompletionMessage();
        this.endTour();
    }

    // Show completion message
    showCompletionMessage() {
        const message = document.createElement('div');
        message.className = 'tour-completion-toast';
        message.innerHTML = `
            <style>
                .tour-completion-toast {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: #28a745;
                    color: white;
                    padding: 15px 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                    z-index: 10001;
                    animation: slideIn 0.3s ease;
                }
                
                @keyframes slideIn {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
            </style>
            <div style="display: flex; align-items: center;">
                <i class="fas fa-check-circle me-2"></i>
                <div>
                    <strong>Tour Completed!</strong><br>
                    <small>You're ready to use SmartHire like a pro!</small>
                </div>
            </div>
        `;
        
        document.body.appendChild(message);
        
        setTimeout(() => {
            message.remove();
        }, 5000);
    }

    // Show tour completion message for already completed tours
    showTourCompletionMessage(page) {
        const message = document.createElement('div');
        message.className = 'tour-already-completed-toast';
        message.innerHTML = `
            <style>
                .tour-already-completed-toast {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: #17a2b8;
                    color: white;
                    padding: 15px 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                    z-index: 10001;
                    animation: slideIn 0.3s ease;
                }
            </style>
            <div style="display: flex; align-items: center;">
                <i class="fas fa-info-circle me-2"></i>
                <div>
                    <strong>Tour Already Completed</strong><br>
                    <small>You've already taken the ${page} tour. Check the help menu for more guidance.</small>
                </div>
            </div>
        `;
        
        document.body.appendChild(message);
        
        setTimeout(() => {
            message.remove();
        }, 4000);
    }

    // End the tour
    endTour() {
        this.isActive = false;
        
        // Remove highlight
        if (this.highlightElement) {
            this.highlightElement.classList.remove('tour-highlight');
        }
        
        // Remove overlay
        if (this.tourOverlay) {
            this.tourOverlay.remove();
            this.tourOverlay = null;
        }
        
        // Remove tooltip
        if (this.tourTooltip) {
            this.tourTooltip.remove();
            this.tourTooltip = null;
        }
    }

    // Get current page name
    getCurrentPage() {
        const path = window.location.pathname;
        if (path.includes('/dashboard') || path === '/') return 'dashboard';
        if (path.includes('/employees')) return 'employees';
        if (path.includes('/documents') || path.includes('/templates')) return 'documents';
        if (path.includes('/onboarding')) return 'onboarding';
        if (path.includes('/interview')) return 'interviews';
        return 'dashboard';
    }

    // Check if tour should auto-start
    checkAutoStart() {
        const page = this.getCurrentPage();
        const userVisits = parseInt(localStorage.getItem(`smarthire_visits_${page}`) || '0');
        
        // Auto-start tour on first visit to each page
        if (userVisits === 0 && !this.userProgress[page]) {
            setTimeout(() => {
                this.startTour(page);
            }, 2000); // Wait 2 seconds after page load
        }
        
        // Increment visit counter
        localStorage.setItem(`smarthire_visits_${page}`, userVisits + 1);
    }

    // Reset tour progress
    resetProgress() {
        this.userProgress = {
            dashboard: false,
            employees: false,
            documents: false,
            onboarding: false,
            interviews: false
        };
        this.saveTourProgress();
        
        // Reset visit counters
        Object.keys(this.userProgress).forEach(page => {
            localStorage.removeItem(`smarthire_visits_${page}`);
        });
    }
}

// Initialize tour manager
const tourManager = new SmartHireTour();

// Auto-start tour check when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    tourManager.checkAutoStart();
});

// Make available globally
window.tourManager = tourManager;
