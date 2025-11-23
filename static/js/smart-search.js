/**
 * SmartHire Intelligent Search System
 * Provides smart search with suggestions, quick actions, and recent items
 */

class SmartSearch {
    constructor() {
        this.searchInput = null;
        this.suggestionsPanel = null;
        this.isSearching = false;
        this.searchTimeout = null;
        this.recentSearches = this.loadRecentSearches();
        this.quickActions = this.getQuickActions();
        this.recentItems = this.loadRecentItems();
    }

    // Initialize search system
    init() {
        this.searchInput = document.querySelector('.smart-search-input');
        if (!this.searchInput) return;

        this.createSuggestionsPanel();
        this.bindEvents();
    }

    // Create suggestions dropdown panel
    createSuggestionsPanel() {
        this.suggestionsPanel = document.createElement('div');
        this.suggestionsPanel.className = 'smart-search-suggestions';
        this.suggestionsPanel.innerHTML = `
            <style>
                .smart-search-suggestions {
                    position: absolute;
                    top: 100%;
                    left: 0;
                    right: 0;
                    background: #2d2d2d;
                    border: 1px solid #444;
                    border-top: none;
                    border-radius: 0 0 8px 8px;
                    max-height: 400px;
                    overflow-y: auto;
                    z-index: 1000;
                    display: none;
                    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
                }
                
                .smart-search-suggestions.active {
                    display: block;
                }
                
                .suggestion-section {
                    border-bottom: 1px solid #444;
                }
                
                .suggestion-section:last-child {
                    border-bottom: none;
                }
                
                .suggestion-header {
                    padding: 12px 16px 8px;
                    font-size: 12px;
                    font-weight: 600;
                    color: #7b2cbf;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                .suggestion-item {
                    padding: 10px 16px;
                    cursor: pointer;
                    transition: background-color 0.2s ease;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    color: #f8f9fa;
                    text-decoration: none;
                }
                
                .suggestion-item:hover {
                    background: rgba(123, 44, 191, 0.1);
                }
                
                .suggestion-item.active {
                    background: rgba(123, 44, 191, 0.2);
                }
                
                .suggestion-icon {
                    width: 32px;
                    height: 32px;
                    background: rgba(123, 44, 191, 0.2);
                    border-radius: 6px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #7b2cbf;
                    font-size: 14px;
                }
                
                .suggestion-content {
                    flex: 1;
                }
                
                .suggestion-title {
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 2px;
                }
                
                .suggestion-description {
                    font-size: 12px;
                    color: #adb5bd;
                }
                
                .suggestion-badge {
                    background: rgba(108, 117, 125, 0.2);
                    color: #adb5bd;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 11px;
                    font-weight: 500;
                }
                
                .suggestion-badge.new {
                    background: rgba(23, 162, 184, 0.2);
                    color: #17a2b8;
                }
                
                .suggestion-badge.popular {
                    background: rgba(40, 167, 69, 0.2);
                    color: #28a745;
                }
                
                .suggestion-meta {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    font-size: 11px;
                    color: #6c757d;
                }
                
                .no-results {
                    padding: 20px 16px;
                    text-align: center;
                    color: #6c757d;
                    font-size: 14px;
                }
                
                .no-results i {
                    font-size: 24px;
                    margin-bottom: 8px;
                    opacity: 0.5;
                }
                
                .search-loading {
                    padding: 20px 16px;
                    text-align: center;
                    color: #6c757d;
                }
                
                .search-loading i {
                    animation: spin 1s linear infinite;
                }
                
                @keyframes spin {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }
            </style>
        `;

        // Position the suggestions panel
        const searchContainer = this.searchInput.parentElement;
        searchContainer.style.position = 'relative';
        searchContainer.appendChild(this.suggestionsPanel);
    }

    // Bind event listeners
    bindEvents() {
        // Input events
        this.searchInput.addEventListener('input', (e) => {
            this.handleInput(e.target.value);
        });

        // Focus events
        this.searchInput.addEventListener('focus', () => {
            if (this.searchInput.value.trim() === '') {
                this.showDefaultSuggestions();
            }
        });

        // Blur events
        this.searchInput.addEventListener('blur', () => {
            setTimeout(() => {
                this.hideSuggestions();
            }, 200);
        });

        // Keyboard navigation
        this.searchInput.addEventListener('keydown', (e) => {
            this.handleKeyboardNavigation(e);
        });

        // Click outside to close
        document.addEventListener('click', (e) => {
            if (!this.searchInput.contains(e.target) && !this.suggestionsPanel.contains(e.target)) {
                this.hideSuggestions();
            }
        });
    }

    // Handle input changes
    handleInput(query) {
        clearTimeout(this.searchTimeout);
        
        if (query.trim() === '') {
            this.showDefaultSuggestions();
            return;
        }

        // Show loading state
        this.showLoading();

        // Debounce search
        this.searchTimeout = setTimeout(() => {
            this.performSearch(query);
        }, 300);
    }

    // Show default suggestions (quick actions and recent items)
    showDefaultSuggestions() {
        const suggestions = [
            ...this.quickActions.slice(0, 3),
            ...this.recentItems.slice(0, 3)
        ];

        this.renderSuggestions(suggestions, 'default');
    }

    // Perform actual search
    async performSearch(query) {
        this.isSearching = true;

        try {
            // Simulate API call - replace with actual search endpoint
            const results = await this.searchAPI(query);
            this.renderSuggestions(results, 'search');
        } catch (error) {
            console.error('Search error:', error);
            this.showError();
        } finally {
            this.isSearching = false;
        }
    }

    // Simulated search API - replace with actual implementation
    async searchAPI(query) {
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 500));

        const results = [];

        // Search employees
        if (this.matchesQuery(query, ['employee', 'staff', 'team', 'user'])) {
            results.push({
                type: 'action',
                title: 'Add New Employee',
                description: 'Create a new employee profile',
                icon: 'fas fa-user-plus',
                url: '/hr/add_employee',
                category: 'quick-action',
                badge: 'popular'
            });
        }

        // Search documents
        if (this.matchesQuery(query, ['document', 'template', 'pdf', 'letter'])) {
            results.push({
                type: 'action',
                title: 'Generate Document',
                description: 'Create documents from templates',
                icon: 'fas fa-file-alt',
                url: '/hr/templates',
                category: 'quick-action'
            });
        }

        // Search onboarding
        if (this.matchesQuery(query, ['onboard', 'new hire', 'welcome'])) {
            results.push({
                type: 'action',
                title: 'Start Onboarding',
                description: 'Begin employee onboarding process',
                icon: 'fas fa-user-clock',
                url: '/onboarding',
                category: 'quick-action'
            });
        }

        // Search interviews
        if (this.matchesQuery(query, ['interview', 'hire', 'candidate'])) {
            results.push({
                type: 'action',
                title: 'Conduct Interview',
                description: 'AI-powered interview system',
                icon: 'fas fa-video',
                url: '/interview',
                category: 'quick-action',
                badge: 'new'
            });
        }

        // Add recent searches that match
        this.recentSearches.forEach(search => {
            if (search.toLowerCase().includes(query.toLowerCase())) {
                results.push({
                    type: 'recent-search',
                    title: search,
                    description: 'Recent search',
                    icon: 'fas fa-history',
                    category: 'recent'
                });
            }
        });

        return results;
    }

    // Check if query matches keywords
    matchesQuery(query, keywords) {
        const lowerQuery = query.toLowerCase();
        return keywords.some(keyword => 
            keyword.toLowerCase().includes(lowerQuery) || 
            lowerQuery.includes(keyword.toLowerCase())
        );
    }

    // Render suggestions
    renderSuggestions(suggestions, type) {
        if (suggestions.length === 0) {
            this.showNoResults();
            return;
        }

        // Group suggestions by category
        const grouped = this.groupSuggestions(suggestions);
        let html = '';

        Object.keys(grouped).forEach(category => {
            if (grouped[category].length > 0) {
                html += this.renderSuggestionSection(category, grouped[category]);
            }
        });

        this.suggestionsPanel.innerHTML = html;
        this.suggestionsPanel.classList.add('active');
        this.bindSuggestionEvents();
    }

    // Group suggestions by category
    groupSuggestions(suggestions) {
        const grouped = {};
        
        suggestions.forEach(suggestion => {
            const category = suggestion.category || 'other';
            if (!grouped[category]) {
                grouped[category] = [];
            }
            grouped[category].push(suggestion);
        });

        return grouped;
    }

    // Render suggestion section
    renderSuggestionSection(category, suggestions) {
        const titles = {
            'quick-action': 'Quick Actions',
            'recent': 'Recent',
            'recent-search': 'Recent Searches',
            'employee': 'Employees',
            'document': 'Documents',
            'other': 'Other'
        };

        let html = `
            <div class="suggestion-section">
                <div class="suggestion-header">${titles[category] || category}</div>
        `;

        suggestions.forEach(suggestion => {
            html += this.renderSuggestionItem(suggestion);
        });

        html += '</div>';
        return html;
    }

    // Render individual suggestion item
    renderSuggestionItem(suggestion) {
        const badge = suggestion.badge ? `<span class="suggestion-badge ${suggestion.badge}">${suggestion.badge}</span>` : '';
        const meta = suggestion.meta ? `<div class="suggestion-meta">${suggestion.meta}</div>` : '';

        return `
            <a href="${suggestion.url || '#'}" class="suggestion-item" data-type="${suggestion.type}" data-action="${suggestion.action || ''}">
                <div class="suggestion-icon">
                    <i class="${suggestion.icon}"></i>
                </div>
                <div class="suggestion-content">
                    <div class="suggestion-title">${suggestion.title}</div>
                    <div class="suggestion-description">${suggestion.description}</div>
                    ${meta}
                </div>
                ${badge}
            </a>
        `;
    }

    // Show loading state
    showLoading() {
        this.suggestionsPanel.innerHTML = `
            <div class="search-loading">
                <i class="fas fa-spinner"></i>
                <div>Searching...</div>
            </div>
        `;
        this.suggestionsPanel.classList.add('active');
    }

    // Show no results
    showNoResults() {
        this.suggestionsPanel.innerHTML = `
            <div class="no-results">
                <i class="fas fa-search"></i>
                <div>No results found</div>
                <small>Try different keywords or browse our features</small>
            </div>
        `;
        this.suggestionsPanel.classList.add('active');
    }

    // Show error state
    showError() {
        this.suggestionsPanel.innerHTML = `
            <div class="no-results">
                <i class="fas fa-exclamation-triangle"></i>
                <div>Search error</div>
                <small>Please try again later</small>
            </div>
        `;
        this.suggestionsPanel.classList.add('active');
    }

    // Hide suggestions
    hideSuggestions() {
        this.suggestionsPanel.classList.remove('active');
    }

    // Bind suggestion item events
    bindSuggestionEvents() {
        const items = this.suggestionsPanel.querySelectorAll('.suggestion-item');
        
        items.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleSuggestionClick(item);
            });
        });
    }

    // Handle suggestion click
    handleSuggestionClick(item) {
        const type = item.dataset.type;
        const action = item.dataset.action;
        const url = item.href;
        const title = item.querySelector('.suggestion-title').textContent;

        // Add to recent searches
        this.addToRecentSearches(title);

        // Handle different types of actions
        switch (type) {
            case 'action':
                if (url && url !== '#') {
                    window.location.href = url;
                }
                break;
            case 'recent-search':
                this.searchInput.value = title;
                this.performSearch(title);
                break;
            default:
                if (url && url !== '#') {
                    window.location.href = url;
                }
        }

        this.hideSuggestions();
    }

    // Handle keyboard navigation
    handleKeyboardNavigation(e) {
        const items = this.suggestionsPanel.querySelectorAll('.suggestion-item');
        if (items.length === 0) return;

        let currentIndex = -1;
        items.forEach((item, index) => {
            if (item.classList.contains('active')) {
                currentIndex = index;
            }
        });

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                currentIndex = Math.min(currentIndex + 1, items.length - 1);
                this.highlightItem(items, currentIndex);
                break;
            case 'ArrowUp':
                e.preventDefault();
                currentIndex = Math.max(currentIndex - 1, 0);
                this.highlightItem(items, currentIndex);
                break;
            case 'Enter':
                e.preventDefault();
                if (currentIndex >= 0) {
                    items[currentIndex].click();
                }
                break;
            case 'Escape':
                this.hideSuggestions();
                this.searchInput.blur();
                break;
        }
    }

    // Highlight suggestion item
    highlightItem(items, index) {
        items.forEach(item => item.classList.remove('active'));
        if (items[index]) {
            items[index].classList.add('active');
            items[index].scrollIntoView({ block: 'nearest' });
        }
    }

    // Get quick actions
    getQuickActions() {
        return [
            {
                type: 'action',
                title: 'Add New Employee',
                description: 'Create a new employee profile',
                icon: 'fas fa-user-plus',
                url: '/hr/add_employee',
                category: 'quick-action',
                badge: 'popular'
            },
            {
                type: 'action',
                title: 'Generate Document',
                description: 'Create documents from templates',
                icon: 'fas fa-file-alt',
                url: '/hr/templates',
                category: 'quick-action'
            },
            {
                type: 'action',
                title: 'Start Onboarding',
                description: 'Begin employee onboarding process',
                icon: 'fas fa-user-clock',
                url: '/onboarding',
                category: 'quick-action'
            },
            {
                type: 'action',
                title: 'Conduct Interview',
                description: 'AI-powered interview system',
                icon: 'fas fa-video',
                url: '/interview',
                category: 'quick-action',
                badge: 'new'
            },
            {
                type: 'action',
                title: 'View Analytics',
                description: 'HR analytics and insights',
                icon: 'fas fa-chart-bar',
                url: '/analytics/mood',
                category: 'quick-action'
            }
        ];
    }

    // Load recent searches
    loadRecentSearches() {
        const saved = localStorage.getItem('smarthire_recent_searches');
        return saved ? JSON.parse(saved) : [];
    }

    // Add to recent searches
    addToRecentSearches(query) {
        const searches = this.recentSearches.filter(s => s !== query);
        searches.unshift(query);
        
        // Keep only last 10 searches
        this.recentSearches = searches.slice(0, 10);
        localStorage.setItem('smarthire_recent_searches', JSON.stringify(this.recentSearches));
    }

    // Load recent items
    loadRecentItems() {
        // This would typically come from the server
        return [
            {
                type: 'employee',
                title: 'John Doe',
                description: 'Software Engineer • Engineering',
                icon: 'fas fa-user',
                url: '/hr/view_employee/1',
                category: 'employee',
                meta: 'Updated 2 hours ago'
            },
            {
                type: 'document',
                title: 'Offer Letter Template',
                description: 'Employment offer document',
                icon: 'fas fa-file-alt',
                url: '/hr/templates/1',
                category: 'document',
                meta: 'Used 5 times this week'
            }
        ];
    }
}

// Initialize smart search
document.addEventListener('DOMContentLoaded', () => {
    const smartSearch = new SmartSearch();
    smartSearch.init();
    
    // Make available globally
    window.smartSearch = smartSearch;
});
