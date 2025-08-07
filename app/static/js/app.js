// Main JavaScript for IoT Security Framework

$(document).ready(function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    $('.alert').each(function() {
        var alert = $(this);
        setTimeout(function() {
            alert.fadeOut();
        }, 5000);
    });

    // Confirm delete actions
    $('.btn-delete').click(function(e) {
        if (!confirm('Are you sure you want to delete this item? This action cannot be undone.')) {
            e.preventDefault();
        }
    });

    // Check server status
    checkServerStatus();
    setInterval(checkServerStatus, 60000); // Check every minute
});

// Server status check
function checkServerStatus() {
    $.ajax({
        url: '/health',
        method: 'GET',
        timeout: 5000,
        success: function(data) {
            $('#server-status').removeClass('bg-danger').addClass('bg-success').text('Online');
        },
        error: function() {
            $('#server-status').removeClass('bg-success').addClass('bg-danger').text('Offline');
        }
    });
}

// Dashboard specific functions
function refreshDashboard() {
    // Refresh dashboard statistics
    $.ajax({
        url: '/api/stats',
        method: 'GET',
        success: function(data) {
            updateDashboardStats(data);
        },
        error: function() {
            console.log('Failed to refresh dashboard data');
        }
    });
}

function updateDashboardStats(data) {
    // Update device stats
    if (data.devices) {
        $('#total-devices').text(data.devices.total || 0);
        $('#active-devices').text(data.devices.active || 0);
        $('#high-risk-devices').text(data.devices.high_risk || 0);
    }

    // Update assessment stats
    if (data.assessments) {
        $('#total-assessments').text(data.assessments.total || 0);
        $('#running-assessments').text(data.assessments.running || 0);
        $('#completed-assessments').text(data.assessments.completed || 0);
    }

    // Update vulnerability stats
    if (data.vulnerabilities) {
        $('#total-vulnerabilities').text(data.vulnerabilities.total || 0);
        $('#critical-vulnerabilities').text(data.vulnerabilities.critical || 0);
    }
}

// Chart functions
function createDeviceTypeChart(data) {
    const ctx = document.getElementById('deviceTypeChart').getContext('2d');
    
    const colors = [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', 
        '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
    ];
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: colors.slice(0, Object.keys(data).length),
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

function createVulnerabilityTrendChart(data) {
    const ctx = document.getElementById('vulnerabilityTrendChart').getContext('2d');
    
    const dates = data.map(item => item.date);
    const critical = data.map(item => item.critical || 0);
    const high = data.map(item => item.high || 0);
    const medium = data.map(item => item.medium || 0);
    const low = data.map(item => item.low || 0);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: 'Critical',
                data: critical,
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4
            }, {
                label: 'High',
                data: high,
                borderColor: '#fd7e14',
                backgroundColor: 'rgba(253, 126, 20, 0.1)',
                tension: 0.4
            }, {
                label: 'Medium',
                data: medium,
                borderColor: '#ffc107',
                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                tension: 0.4
            }, {
                label: 'Low',
                data: low,
                borderColor: '#28a745',
                backgroundColor: 'rgba(40, 167, 69, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Date'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Number of Vulnerabilities'
                    },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top'
                }
            }
        }
    });
}

function createRiskDistributionChart(data) {
    const ctx = document.getElementById('riskDistributionChart').getContext('2d');
    
    const riskLevels = ['unknown', 'low', 'medium', 'high', 'critical'];
    const riskColors = {
        'unknown': '#6c757d',
        'low': '#28a745',
        'medium': '#ffc107',
        'high': '#fd7e14',
        'critical': '#dc3545'
    };
    
    const chartData = riskLevels.map(level => data[level] || 0);
    const colors = riskLevels.map(level => riskColors[level]);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: riskLevels.map(level => level.charAt(0).toUpperCase() + level.slice(1)),
            datasets: [{
                label: 'Number of Devices',
                data: chartData,
                backgroundColor: colors,
                borderColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Assessment functions
function startAssessment(assessmentId) {
    if (!confirm('Are you sure you want to start this assessment?')) {
        return;
    }

    const button = $(`#start-btn-${assessmentId}`);
    const originalText = button.html();
    
    button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Starting...');

    $.ajax({
        url: `/api/assessments/${assessmentId}/start`,
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + getAuthToken()
        },
        success: function(data) {
            showAlert('Assessment started successfully!', 'success');
            setTimeout(() => location.reload(), 2000);
        },
        error: function(xhr) {
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Failed to start assessment';
            showAlert(error, 'error');
            button.prop('disabled', false).html(originalText);
        }
    });
}

function stopAssessment(assessmentId) {
    if (!confirm('Are you sure you want to stop this assessment?')) {
        return;
    }

    $.ajax({
        url: `/api/assessments/${assessmentId}/stop`,
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + getAuthToken()
        },
        success: function(data) {
            showAlert('Assessment stopped successfully!', 'success');
            setTimeout(() => location.reload(), 2000);
        },
        error: function(xhr) {
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Failed to stop assessment';
            showAlert(error, 'error');
        }
    });
}

// Device functions
function rescanDevice(deviceId) {
    if (!confirm('Are you sure you want to rescan this device?')) {
        return;
    }

    const button = $(`#rescan-btn-${deviceId}`);
    const originalText = button.html();
    
    button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Scanning...');

    $.ajax({
        url: `/api/devices/${deviceId}/rescan`,
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + getAuthToken()
        },
        success: function(data) {
            showAlert('Device rescanned successfully!', 'success');
            setTimeout(() => location.reload(), 2000);
        },
        error: function(xhr) {
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Failed to rescan device';
            showAlert(error, 'error');
            button.prop('disabled', false).html(originalText);
        }
    });
}

// Utility functions
function getAuthToken() {
    // In a real implementation, this would get the JWT token from localStorage or cookies
    return localStorage.getItem('auth_token') || '';
}

function showAlert(message, type) {
    const alertClass = type === 'error' ? 'alert-danger' : `alert-${type}`;
    const iconClass = type === 'error' ? 'fa-exclamation-circle' : 
                     type === 'success' ? 'fa-check-circle' : 'fa-info-circle';
    
    const alertHtml = `
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <i class="fas ${iconClass} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    $('.container-fluid').first().prepend(alertHtml);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        $('.alert').first().fadeOut();
    }, 5000);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    if (!seconds) return 'N/A';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    return date.toLocaleString();
}

function getRiskBadgeClass(riskLevel) {
    const classes = {
        'unknown': 'bg-secondary',
        'low': 'bg-success',
        'medium': 'bg-warning',
        'high': 'bg-danger',
        'critical': 'bg-danger'
    };
    return classes[riskLevel] || 'bg-secondary';
}

function getStatusBadgeClass(status) {
    const classes = {
        'pending': 'bg-warning',
        'running': 'bg-primary',
        'completed': 'bg-success',
        'failed': 'bg-danger',
        'cancelled': 'bg-secondary'
    };
    return classes[status] || 'bg-secondary';
}

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    let isValid = true;
    const requiredFields = form.querySelectorAll('[required]');
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            isValid = false;
        } else {
            field.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}

// Real-time updates using WebSocket (if implemented)
function initWebSocket() {
    // This would initialize WebSocket connection for real-time updates
    // Implementation would depend on WebSocket server setup
    console.log('WebSocket initialization - not implemented yet');
}

// Export functions for global use
window.IoTSecurity = {
    refreshDashboard,
    startAssessment,
    stopAssessment,
    rescanDevice,
    showAlert,
    formatBytes,
    formatDuration,
    formatDate,
    getRiskBadgeClass,
    getStatusBadgeClass,
    validateForm
};
