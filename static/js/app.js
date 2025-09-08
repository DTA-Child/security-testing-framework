/* Security Testing Framework - JavaScript */

// Global app object
const SecurityFramework = {
    // Configuration
    config: {
        refreshInterval: 5000, // 5 seconds
        apiBase: '/api'
    },

    // Utility functions
    utils: {
        formatDate: (dateString) => {
            const date = new Date(dateString);
            return date.toLocaleString();
        },

        formatUrl: (url, maxLength = 50) => {
            if (url.length <= maxLength) return url;
            return url.substring(0, maxLength) + '...';
        },

        getSeverityClass: (severity) => {
            const classes = {
                'high': 'danger',
                'medium': 'warning', 
                'low': 'info',
                'info': 'secondary'
            };
            return classes[severity] || 'secondary';
        },

        getScannerIcon: (scanner) => {
            const icons = {
                'zap': 'bi-shield-check',
                'nuclei': 'bi-bug',
                'nikto': 'bi-search'
            };
            return icons[scanner] || 'bi-gear';
        },

        showNotification: (message, type = 'info') => {
            // Simple toast notification
            const toast = document.createElement('div');
            toast.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
            toast.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 250px;';
            toast.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(toast);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                toast.remove();
            }, 5000);
        }
    },

    // API functions
    api: {
        async get(endpoint) {
            try {
                const response = await fetch(`${SecurityFramework.config.apiBase}${endpoint}`);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return await response.json();
            } catch (error) {
                console.error('API GET error:', error);
                throw error;
            }
        },

        async post(endpoint, data) {
            try {
                const response = await fetch(`${SecurityFramework.config.apiBase}${endpoint}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return await response.json();
            } catch (error) {
                console.error('API POST error:', error);
                throw error;
            }
        },

        async getScanStatus(scanId) {
            return await this.get(`/scan/${scanId}`);
        },

        async getAllScans() {
            return await this.get('/scans');
        }
    },

    // Scan management
    scans: {
        // Poll scan status
        pollStatus: (scanId, callback, interval = 2000) => {
            const poll = async () => {
                try {
                    const scan = await SecurityFramework.api.getScanStatus(scanId);
                    callback(scan);
                    
                    // Continue polling if scan is still running
                    if (scan.status === 'running') {
                        setTimeout(poll, interval);
                    }
                } catch (error) {
                    console.error('Polling error:', error);
                }
            };
            poll();
        },

        // Format scan results for display
        formatResults: (results) => {
            let totalVulns = 0;
            let highVulns = 0;
            let mediumVulns = 0;

            Object.values(results).forEach(result => {
                if (result.summary) {
                    totalVulns += result.summary.total || 0;
                    highVulns += result.summary.high || 0;
                    mediumVulns += result.summary.medium || 0;
                }
            });

            return { totalVulns, highVulns, mediumVulns };
        }
    },

    // UI helpers
    ui: {
        updateProgressBar: (element, progress) => {
            if (element) {
                element.style.width = `${progress}%`;
                element.setAttribute('aria-valuenow', progress);
                
                // Update text if it has a text element
                const textElement = element.querySelector('span') || element;
                if (textElement) {
                    textElement.textContent = `${progress}%`;
                }
            }
        },

        showLoading: (element) => {
            if (element) {
                element.innerHTML = `
                    <div class="text-center">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                    </div>
                `;
            }
        },

        hideLoading: (element, originalContent = '') => {
            if (element) {
                element.innerHTML = originalContent;
            }
        }
    },

    // Initialize app
    init: () => {
        console.log('Security Testing Framework initialized');
        
        // Add any global event listeners or initialization code here
        document.addEventListener('DOMContentLoaded', () => {
            // Auto-refresh running scans
            const runningElements = document.querySelectorAll('[data-scan-status="running"]');
            runningElements.forEach(element => {
                const scanId = element.getAttribute('data-scan-id');
                if (scanId) {
                    SecurityFramework.scans.pollStatus(scanId, (scan) => {
                        // Update UI based on scan status
                        if (scan.status === 'completed') {
                            location.reload(); // Simple refresh when completed
                        }
                    });
                }
            });
        });
    }
};

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', SecurityFramework.init);
} else {
    SecurityFramework.init();
}

// Form validation helpers
function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function validateScanForm(form) {
    const url = form.querySelector('input[name="target_url"]').value;
    const checkboxes = form.querySelectorAll('input[type="checkbox"]:checked');
    
    if (!validateUrl(url)) {
        SecurityFramework.utils.showNotification('Please enter a valid URL', 'danger');
        return false;
    }
    
    if (checkboxes.length === 0) {
        SecurityFramework.utils.showNotification('Please select at least one scanner', 'warning');
        return false;
    }
    
    return true;
}

// Export for global access
window.SecurityFramework = SecurityFramework;