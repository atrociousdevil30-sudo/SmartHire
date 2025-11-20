// ===== THEME TOGGLE FUNCTIONALITY =====

class ThemeToggle {
    constructor() {
        this.THEME_KEY = 'app-theme';
        this.DARK_MODE = 'dark';
        this.LIGHT_MODE = 'light';
        this.init();
    }

    init() {
        // Get saved theme or use system preference
        const savedTheme = this.getSavedTheme();
        const preferredTheme = savedTheme || this.getSystemPreference();
        
        // Set initial theme
        this.setTheme(preferredTheme);
        
        // Listen for system theme changes
        this.listenToSystemPreference();
    }

    /**
     * Get saved theme from localStorage
     */
    getSavedTheme() {
        try {
            return localStorage.getItem(this.THEME_KEY);
        } catch (e) {
            console.warn('localStorage not available:', e);
            return null;
        }
    }

    /**
     * Save theme to localStorage
     */
    saveTheme(theme) {
        try {
            localStorage.setItem(this.THEME_KEY, theme);
        } catch (e) {
            console.warn('Could not save theme to localStorage:', e);
        }
    }

    /**
     * Get system preference for dark mode
     */
    getSystemPreference() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return this.DARK_MODE;
        }
        return this.LIGHT_MODE;
    }

    /**
     * Set theme and update DOM
     */
    setTheme(theme) {
        const validTheme = [this.DARK_MODE, this.LIGHT_MODE].includes(theme) ? theme : this.LIGHT_MODE;
        
        // Update data-theme attribute
        document.documentElement.setAttribute('data-theme', validTheme);
        
        // Update body class
        document.body.classList.remove('theme-dark', 'theme-light');
        document.body.classList.add(`theme-${validTheme}`);
        
        // Save preference
        this.saveTheme(validTheme);
        
        // Update toggle button icon
        this.updateToggleButton(validTheme);
        
        // Dispatch custom event for other components
        window.dispatchEvent(new CustomEvent('theme-changed', { detail: { theme: validTheme } }));
        
        return validTheme;
    }

    /**
     * Toggle between light and dark mode
     */
    toggle() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || this.LIGHT_MODE;
        const newTheme = currentTheme === this.DARK_MODE ? this.LIGHT_MODE : this.DARK_MODE;
        return this.setTheme(newTheme);
    }

    /**
     * Get current theme
     */
    getCurrentTheme() {
        return document.documentElement.getAttribute('data-theme') || this.LIGHT_MODE;
    }

    /**
     * Update toggle button icon
     */
    updateToggleButton(theme) {
        const toggleBtn = document.querySelector('.theme-toggle-btn');
        if (!toggleBtn) return;
        
        if (theme === this.DARK_MODE) {
            toggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
            toggleBtn.setAttribute('title', 'Switch to Light Mode');
        } else {
            toggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
            toggleBtn.setAttribute('title', 'Switch to Dark Mode');
        }
    }

    /**
     * Listen to system theme preference changes
     */
    listenToSystemPreference() {
        if (!window.matchMedia) return;
        
        const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
        
        // Handle both old and new API
        if (darkModeQuery.addEventListener) {
            darkModeQuery.addEventListener('change', (e) => {
                // Only apply if user hasn't set a preference
                if (!this.getSavedTheme()) {
                    this.setTheme(e.matches ? this.DARK_MODE : this.LIGHT_MODE);
                }
            });
        } else if (darkModeQuery.addListener) {
            darkModeQuery.addListener((e) => {
                if (!this.getSavedTheme()) {
                    this.setTheme(e.matches ? this.DARK_MODE : this.LIGHT_MODE);
                }
            });
        }
    }

    /**
     * Check if dark mode is active
     */
    isDarkMode() {
        return this.getCurrentTheme() === this.DARK_MODE;
    }

    /**
     * Check if light mode is active
     */
    isLightMode() {
        return this.getCurrentTheme() === this.LIGHT_MODE;
    }

    /**
     * Force light mode
     */
    forceLightMode() {
        return this.setTheme(this.LIGHT_MODE);
    }

    /**
     * Force dark mode
     */
    forceDarkMode() {
        return this.setTheme(this.DARK_MODE);
    }
}

// ===== INITIALIZATION =====

// Initialize theme toggle when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Create global instance
    window.themeToggle = new ThemeToggle();
    
    // Setup toggle button click handler
    setupToggleButton();
    
    // Setup keyboard shortcut (Alt + T)
    setupKeyboardShortcut();
    
    // Log theme for debugging
    console.log('Theme Toggle initialized. Current theme:', window.themeToggle.getCurrentTheme());
});

/**
 * Setup toggle button click handler
 */
function setupToggleButton() {
    const toggleBtn = document.querySelector('.theme-toggle-btn');
    if (!toggleBtn) return;
    
    toggleBtn.addEventListener('click', function(e) {
        e.preventDefault();
        window.themeToggle.toggle();
    });
}

/**
 * Setup keyboard shortcut for theme toggle
 */
function setupKeyboardShortcut() {
    document.addEventListener('keydown', function(e) {
        // Alt + T to toggle theme
        if (e.altKey && e.key === 't') {
            e.preventDefault();
            window.themeToggle.toggle();
            showThemeNotification();
        }
    });
}

/**
 * Show theme change notification
 */
function showThemeNotification() {
    const theme = window.themeToggle.getCurrentTheme();
    const themeName = theme === 'dark' ? 'Dark Mode' : 'Light Mode';
    
    // Create notification
    const notification = document.createElement('div');
    notification.className = 'theme-notification alert alert-info';
    notification.textContent = `Switched to ${themeName}`;
    notification.style.cssText = `
        position: fixed;
        bottom: 80px;
        right: 20px;
        max-width: 300px;
        z-index: 999;
        animation: slideIn 0.3s ease-out;
    `;
    
    document.body.appendChild(notification);
    
    // Remove notification after 2 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}

// ===== EVENT LISTENERS =====

// Listen to theme changes and update any dependent components
window.addEventListener('theme-changed', function(e) {
    const theme = e.detail.theme;
    console.log('Theme changed to:', theme);
    
    // Update any components that depend on theme
    // Example: Update chart colors, icons, etc.
    updateThemeDependentComponents(theme);
});

/**
 * Update components that depend on theme
 */
function updateThemeDependentComponents(theme) {
    // Update chart colors if using Chart.js or similar
    if (window.updateChartTheme) {
        window.updateChartTheme(theme);
    }
    
    // Update code highlight colors if using Prism or similar
    if (window.updateCodeHighlightTheme) {
        window.updateCodeHighlightTheme(theme);
    }
    
    // Add more theme-dependent component updates here
}

// ===== UTILITY FUNCTIONS =====

/**
 * Get theme-aware color
 */
function getThemeColor(lightColor, darkColor) {
    const theme = window.themeToggle ? window.themeToggle.getCurrentTheme() : 'light';
    return theme === 'dark' ? darkColor : lightColor;
}

/**
 * Get CSS variable value
 */
function getThemeVariable(variableName) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(`--${variableName}`);
    return value.trim();
}

/**
 * Apply theme to specific element
 */
function applyThemeToElement(element, theme) {
    if (!element) return;
    element.setAttribute('data-theme', theme);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThemeToggle;
}
