document.addEventListener('DOMContentLoaded', function() {
    // Initialize all charts when the page loads
    initAllCharts();
    
    // Set up event listeners for filters and controls
    setupEventListeners();
    
    // Load initial data
    loadInitialData();
});

// Initialize all charts
function initAllCharts() {
    initHiringTrendsChart();
    initCandidateSourcesChart();
    initTimeToHireChart();
    initCandidateStatusChart();
    initTopDepartmentsChart();
    initCandidateExperienceChart();
}

// Set up event listeners for filters and controls
function setupEventListeners() {
    // Date range picker
    const dateRangePicker = document.getElementById('dateRangePicker');
    if (dateRangePicker) {
        dateRangePicker.addEventListener('apply.daterangepicker', function(ev, picker) {
            const startDate = picker.startDate.format('YYYY-MM-DD');
            const endDate = picker.endDate.format('YYYY-MM-DD');
            updateAllCharts(startDate, endDate);
        });
    }
    
    // Department filter
    const departmentFilter = document.getElementById('departmentFilter');
    if (departmentFilter) {
        departmentFilter.addEventListener('change', function() {
            const department = this.value;
            filterChartsByDepartment(department);
        });
    }
    
    // Export buttons
    const exportPdfBtn = document.getElementById('exportPdfBtn');
    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', exportToPdf);
    }
    
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', exportToCsv);
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshDataBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshData);
    }
}

// Load initial data
function loadInitialData() {
    // In a real app, this would be an API call to fetch data
    // For now, we'll use the mock data initialization in each chart function
    updateSummaryCards();
}

// Update all charts with new date range
function updateAllCharts(startDate, endDate) {
    // In a real app, this would make API calls with the date range
    console.log(`Updating charts with date range: ${startDate} to ${endDate}`);
    
    // For now, we'll just reload the charts with the same data
    initAllCharts();
    updateSummaryCards();
    
    // Show a toast notification
    showToast('info', 'Filters Applied', `Showing data from ${startDate} to ${endDate}`);
}

// Filter charts by department
function filterChartsByDepartment(department) {
    if (department === 'all') {
        // Reset all charts to show all departments
        initAllCharts();
    } else {
        // Filter data for the selected department
        // In a real app, this would be an API call to fetch filtered data
        console.log(`Filtering charts for department: ${department}`);
        
        // For now, we'll just show a message
        showToast('info', 'Filter Applied', `Showing data for ${department} department`);
    }
    
    // Update summary cards with filtered data
    updateSummaryCards(department);
}

// Initialize Hiring Trends Chart
function initHiringTrendsChart() {
    const ctx = document.getElementById('hiringTrendsChart').getContext('2d');
    
    // Sample data - in a real app, this would come from an API
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const currentMonth = new Date().getMonth();
    const labels = months.slice(0, currentMonth + 1);
    
    // Generate random data for demonstration
    const hiredData = Array.from({length: labels.length}, () => Math.floor(Math.random() * 50) + 10);
    const interviewedData = hiredData.map(val => val + Math.floor(Math.random() * 20) + 5);
    const appliedData = interviewedData.map(val => val + Math.floor(Math.random() * 30) + 10);
    
    // Create the chart
    window.hiringTrendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Applied',
                    data: appliedData,
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Interviewed',
                    data: interviewedData,
                    borderColor: 'rgba(255, 159, 64, 1)',
                    backgroundColor: 'rgba(255, 159, 64, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Hired',
                    data: hiredData,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.1)',
                    tension: 0.3,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Hiring Trends',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 10
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });
}

// Initialize Candidate Sources Chart
function initCandidateSourcesChart() {
    const ctx = document.getElementById('candidateSourcesChart').getContext('2d');
    
    // Sample data
    const data = {
        labels: ['LinkedIn', 'Company Website', 'Referrals', 'Job Boards', 'Campus', 'Other'],
        datasets: [{
            data: [35, 20, 25, 10, 5, 5],
            backgroundColor: [
                '#0077B5', // LinkedIn blue
                '#4e73df', // Indigo
                '#1cc88a', // Green
                '#f6c23e', // Yellow
                '#e74a3b', // Red
                '#858796'  // Gray
            ],
            borderWidth: 1
        }]
    };
    
    // Create the chart
    window.candidateSourcesChart = new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Candidate Sources',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '70%'
        }
    });
}

// Initialize Time to Hire Chart
function initTimeToHireChart() {
    const ctx = document.getElementById('timeToHireChart').getContext('2d');
    
    // Sample data
    const data = {
        labels: ['Engineering', 'Design', 'Product', 'Marketing', 'Sales', 'Operations'],
        datasets: [{
            label: 'Average Days to Hire',
            data: [45, 30, 38, 28, 22, 35],
            backgroundColor: 'rgba(78, 115, 223, 0.5)',
            borderColor: 'rgba(78, 115, 223, 1)',
            borderWidth: 1,
            borderRadius: 5
        }]
    };
    
    // Create the chart
    window.timeToHireChart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Time to Hire by Department (Days)',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.parsed.y} days`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Days'
                    }
                }
            }
        }
    });
}

// Initialize Candidate Status Chart
function initCandidateStatusChart() {
    const ctx = document.getElementById('candidateStatusChart').getContext('2d');
    
    // Sample data
    const data = {
        labels: ['Hired', 'Interview', 'Screening', 'Applied', 'Rejected', 'Withdrawn'],
        datasets: [{
            data: [15, 25, 30, 50, 20, 10],
            backgroundColor: [
                '#1cc88a', // Green
                '#f6c23e', // Yellow
                '#4e73df', // Blue
                '#858796', // Gray
                '#e74a3b', // Red
                '#6c757d'  // Dark gray
            ],
            borderWidth: 1
        }]
    };
    
    // Create the chart
    window.candidateStatusChart = new Chart(ctx, {
        type: 'pie',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Candidate Pipeline',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Initialize Top Departments Chart
function initTopDepartmentsChart() {
    const ctx = document.getElementById('topDepartmentsChart').getContext('2d');
    
    // Sample data
    const data = {
        labels: ['Engineering', 'Product', 'Design', 'Marketing', 'Sales', 'Operations', 'HR', 'Finance'],
        datasets: [{
            label: 'Number of Open Positions',
            data: [25, 15, 10, 8, 12, 5, 3, 2],
            backgroundColor: 'rgba(28, 200, 138, 0.5)',
            borderColor: 'rgba(28, 200, 138, 1)',
            borderWidth: 1,
            borderRadius: 5
        }]
    };
    
    // Create the chart
    window.topDepartmentsChart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Open Positions by Department',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Initialize Candidate Experience Chart
function initCandidateExperienceChart() {
    const ctx = document.getElementById('candidateExperienceChart').getContext('2d');
    
    // Sample data
    const data = {
        labels: ['0-2 years', '2-5 years', '5-10 years', '10+ years'],
        datasets: [{
            label: 'Number of Candidates',
            data: [15, 35, 30, 20],
            backgroundColor: [
                'rgba(78, 115, 223, 0.5)',
                'rgba(28, 200, 138, 0.5)',
                'rgba(246, 194, 62, 0.5)',
                'rgba(231, 74, 59, 0.5)'
            ],
            borderColor: [
                'rgba(78, 115, 223, 1)',
                'rgba(28, 200, 138, 1)',
                'rgba(246, 194, 62, 1)',
                'rgba(231, 74, 59, 1)'
            ],
            borderWidth: 1
        }]
    };
    
    // Create the chart
    window.candidateExperienceChart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Candidate Experience Distribution',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 5
                    }
                }
            }
        }
    });
}

// Update summary cards with data
function updateSummaryCards(department = 'all') {
    // In a real app, this would fetch data from an API
    // For now, we'll use sample data
    const summaryData = {
        totalCandidates: 245,
        openPositions: 28,
        avgTimeToHire: 32,
        offerAcceptanceRate: 78
    };
    
    // Update the DOM
    document.getElementById('totalCandidates').textContent = summaryData.totalCandidates.toLocaleString();
    document.getElementById('openPositions').textContent = summaryData.openPositions;
    document.getElementById('avgTimeToHire').textContent = `${summaryData.avgTimeToHire} days`;
    document.getElementById('offerAcceptanceRate').textContent = `${summaryData.offerAcceptanceRate}%`;
    
    // Update the trend indicators (up/down arrows)
    updateTrendIndicators();
}

// Update trend indicators (up/down arrows)
function updateTrendIndicators() {
    // In a real app, this would compare with previous period data
    // For now, we'll randomly set trends
    const trends = ['up', 'down', 'neutral'];
    const trendElements = document.querySelectorAll('.trend-indicator');
    
    trendElements.forEach(element => {
        const randomTrend = trends[Math.floor(Math.random() * trends.length)];
        element.className = `trend-indicator ${randomTrend}`;
        
        // Set appropriate icon and color
        const icon = element.querySelector('i');
        if (randomTrend === 'up') {
            icon.className = 'fas fa-arrow-up';
            element.classList.add('text-success');
        } else if (randomTrend === 'down') {
            icon.className = 'fas fa-arrow-down';
            element.classList.add('text-danger');
        } else {
            icon.className = 'fas fa-minus';
            element.classList.add('text-secondary');
        }
    });
}

// Export dashboard to PDF
function exportToPdf() {
    // In a real app, this would use a library like jsPDF or html2pdf
    // For now, we'll just show a message
    showToast('info', 'Export to PDF', 'This would export the dashboard to a PDF file.');
    
    // Example of how it might work with jsPDF:
    /*
    const element = document.getElementById('analyticsDashboard');
    html2pdf()
        .from(element)
        .save('analytics-dashboard.pdf');
    */
}

// Export data to CSV
function exportToCsv() {
    // In a real app, this would generate a CSV file with the data
    // For now, we'll just show a message
    showToast('info', 'Export to CSV', 'This would export the data to a CSV file.');
    
    // Example of how it might work:
    /*
    const csvContent = 'data:text/csv;charset=utf-8,';
    const link = document.createElement('a');
    link.setAttribute('href', encodeURI(csvContent));
    link.setAttribute('download', 'analytics-data.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    */
}

// Refresh data
function refreshData() {
    // Show loading state
    const refreshBtn = document.getElementById('refreshDataBtn');
    const originalHtml = refreshBtn.innerHTML;
    refreshBtn.disabled = true;
    refreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Refreshing...';
    
    // Simulate data refresh
    setTimeout(() => {
        // In a real app, this would fetch fresh data from the server
        initAllCharts();
        updateSummaryCards();
        
        // Reset button
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = originalHtml;
        
        // Show success message
        showToast('success', 'Success', 'Data has been refreshed.');
    }, 1500);
}

// Show toast notification
function showToast(type, title, message) {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;
    
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = 'toast align-items-center text-white bg-' + type + ' border-0';
    toast.role = 'alert';
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong><br>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Remove toast after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}
