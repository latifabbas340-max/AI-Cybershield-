// ====================== GLOBAL VARIABLES ======================

const API_BASE_URL = '/api';
let currentSection = 'password';

// ====================== NAVIGATION FUNCTIONS ======================

/**
 * Switch between different sections
 * @param {string} sectionId - The ID of the section to show
 */
function showSection(sectionId) {
    // Hide all sections
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.remove('active');
        section.classList.add('hidden');
    });

    // Remove active class from all nav links
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.classList.remove('active');
    });

    // Show selected section
    const selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
        selectedSection.classList.remove('hidden');
        currentSection = sectionId;

        // Set active nav link
        event.target.classList.add('active');
    }

    // Scroll to top
    window.scrollTo(0, 0);
}

// ====================== PASSWORD CHECKER ======================

/**
 * Check password strength in real-time
 */
async function checkPassword() {
    const password = document.getElementById('passwordInput').value;
    const resultDiv = document.getElementById('passwordResult');

    // Validate input
    if (!password) {
        resultDiv.classList.add('hidden');
        return;
    }

    try {
        // Show loading state
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<div style="text-align: center; color: #667eea;">🔍 Analyzing password...</div>';

        // Send request to API
        const response = await fetch(`${API_BASE_URL}/check-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password: password })
        });

        if (!response.ok) {
            throw new Error('Failed to check password');
        }

        const data = await response.json();

        // Display results
        displayPasswordResult(data);

    } catch (error) {
        console.error('Error:', error);
        resultDiv.innerHTML = '<div style="color: red; padding: 15px;">❌ Error checking password. Please try again.</div>';
    }
}

/**
 * Display password analysis results
 * @param {object} data - Result data from API
 */
function displayPasswordResult(data) {
    const resultDiv = document.getElementById('passwordResult');
    const strengthDiv = document.getElementById('passwordStrength');
    const scoreDiv = document.getElementById('passwordScore');
    const feedbackDiv = document.getElementById('passwordFeedback');

    // Determine color based on strength
    let strengthColor = '';
    if (data.score <= 1) strengthColor = '#f44336'; // Red
    else if (data.score <= 2) strengthColor = '#ff9800'; // Orange
    else if (data.score <= 3) strengthColor = '#ffc107'; // Yellow
    else if (data.score <= 4) strengthColor = '#4caf50'; // Green
    else strengthColor = '#2196F3'; // Blue

    // Display strength indicator
    strengthDiv.innerHTML = `
        <div style="
            background: ${strengthColor};
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-size: 1.2em;
        ">
            ${data.strength}
        </div>
    `;

    // Display score with progress bar
    scoreDiv.innerHTML = `
        <strong>Strength Score: ${data.score}/6</strong>
        <div style="background: #eee; height: 10px; border-radius: 5px; margin-top: 8px; overflow: hidden;">
            <div style="
                background: ${strengthColor};
                height: 100%;
                width: ${data.percentage}%;
                transition: width 0.3s ease;
            "></div>
        </div>
        <p style="margin-top: 8px; font-size: 0.95em; color: #666;">
            ${Math.round(data.percentage)}% Strong
        </p>
    `;

    // Display feedback
    feedbackDiv.innerHTML = '<ul class="feedback-list">' + 
        data.feedback.map(item => `<li>${item}</li>`).join('') + 
        '</ul>';

    resultDiv.classList.remove('hidden');
}

// ====================== PHISHING DETECTOR ======================

/**
 * Check if URL is phishing
 */
async function checkPhishing() {
    const url = document.getElementById('urlInput').value;
    const resultDiv = document.getElementById('phishingResult');

    // Validate input
    if (!url) {
        resultDiv.classList.add('hidden');
        return;
    }

    try {
        // Show loading state
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<div style="text-align: center; color: #667eea;">🔍 Analyzing URL...</div>';

        // Send request to API
        const response = await fetch(`${API_BASE_URL}/check-phishing`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error('Failed to check URL');
        }

        const data = await response.json();

        // Display results
        displayPhishingResult(data);

    } catch (error) {
        console.error('Error:', error);
        resultDiv.innerHTML = '<div style="color: red; padding: 15px;">❌ Error checking URL. Please try again.</div>';
    }
}

/**
 * Display phishing detection results
 * @param {object} data - Result data from API
 */
function displayPhishingResult(data) {
    const resultDiv = document.getElementById('phishingResult');
    const riskDiv = document.getElementById('phishingRisk');
    const indicatorsDiv = document.getElementById('phishingIndicators');
    const recommendationDiv = document.getElementById('phishingRecommendation');

    // Determine color based on risk level
    let riskColor = '';
    if (data.risk_score === 0) riskColor = '#4caf50'; // Green
    else if (data.risk_score <= 2) riskColor = '#ff9800'; // Orange
    else if (data.risk_score <= 4) riskColor = '#f44336'; // Red
    else riskColor = '#c41c3b'; // Dark Red

    // Display risk indicator
    riskDiv.innerHTML = `
        <div style="
            background: ${riskColor};
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-size: 1.2em;
        ">
            Risk Level: ${data.risk_level}
        </div>
        <p style="margin-top: 10px; font-size: 0.95em;">
            <strong>URL:</strong> <code style="background: #f5f5f5; padding: 5px; border-radius: 3px; word-break: break-all;">${data.url}</code>
        </p>
    `;

    // Display indicators
    indicatorsDiv.innerHTML = '<ul class="indicators-list">' + 
        data.indicators.map(indicator => `<li>${indicator}</li>`).join('') + 
        '</ul>';

    // Display recommendation
    recommendationDiv.innerHTML = `
        <strong>⚠️ Recommendation:</strong> ${data.recommendation}
    `;

    resultDiv.classList.remove('hidden');
}

// ====================== FILE SCANNER ======================

/**
 * Scan file for threats
 */
async function scanFile() {
    const filename = document.getElementById('fileInput').value;
    const resultDiv = document.getElementById('fileResult');

    // Validate input
    if (!filename) {
        resultDiv.classList.add('hidden');
        return;
    }

    try {
        // Show loading state
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<div style="text-align: center; color: #667eea;">🔍 Scanning file...</div>';

        // Send request to API
        const response = await fetch(`${API_BASE_URL}/scan-file`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ file: filename })
        });

        if (!response.ok) {
            throw new Error('Failed to scan file');
        }

        const data = await response.json();

        // Display results
        displayFileResult(data);

    } catch (error) {
        console.error('Error:', error);
        resultDiv.innerHTML = '<div style="color: red; padding: 15px;">❌ Error scanning file. Please try again.</div>';
    }
}

/**
 * Display file scanning results
 * @param {object} data - Result data from API
 */
function displayFileResult(data) {
    const resultDiv = document.getElementById('fileResult');
    const threatDiv = document.getElementById('fileThreat');
    const indicatorsDiv = document.getElementById('fileIndicators');
    const recommendationDiv = document.getElementById('fileRecommendation');

    // Determine color based on threat level
    let threatColor = '';
    if (data.threat_level.includes('Safe')) threatColor = '#4caf50'; // Green
    else if (data.threat_level.includes('Caution')) threatColor = '#ff9800'; // Orange
    else if (data.threat_level.includes('Dangerous')) threatColor = '#f44336'; // Red
    else threatColor = '#c41c3b'; // Dark Red

    // Display threat indicator
    threatDiv.innerHTML = `
        <div style="
            background: ${threatColor};
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-size: 1.2em;
        ">
            Threat Level: ${data.threat_level}
        </div>
        <p style="margin-top: 10px; font-size: 0.95em;">
            <strong>File:</strong> ${data.filename}<br>
            <strong>Extension:</strong> ${data.extension || 'None detected'}
        </p>
    `;

    // Display indicators
    indicatorsDiv.innerHTML = '<ul class="indicators-list">' + 
        data.indicators.map(indicator => `<li>${indicator}</li>`).join('') + 
        '</ul>';

    // Display recommendation
    recommendationDiv.innerHTML = `
        <strong>⚠️ Recommendation:</strong> ${data.recommendation}
    `;

    resultDiv.classList.remove('hidden');
}

// ====================== SECURITY TIPS ======================

/**
 * Load and display security tips
 */
async function loadSecurityTips() {
    const resultDiv = document.getElementById('tipsResult');
    const tipsList = document.getElementById('tipsList');

    try {
        // Show loading state
        resultDiv.classList.remove('hidden');
        tipsList.innerHTML = '<div style="text-align: center; color: #667eea;">📚 Loading security tips...</div>';

        // Fetch tips from API
        const response = await fetch(`${API_BASE_URL}/security-tips`);

        if (!response.ok) {
            throw new Error('Failed to load tips');
        }

        const data = await response.json();

        // Display tips
        displaySecurityTips(data);

    } catch (error) {
        console.error('Error:', error);
        tipsList.innerHTML = '<div style="color: red; padding: 15px;">❌ Error loading tips. Please try again.</div>';
    }
}

/**
 * Display security tips in grid layout
 * @param {object} data - Tips data from API
 */
function displaySecurityTips(data) {
    const tipsList = document.getElementById('tipsList');

    const tipsHTML = data.tips.map((tip, index) => `
        <div class="tip-item" style="animation-delay: ${index * 0.1}s;">
            ${tip}
        </div>
    `).join('');

    tipsList.innerHTML = tipsHTML;
}

// ====================== UTILITY FUNCTIONS ======================

/**
 * Format password for display (mask characters)
 * @param {string} password - Password to mask
 * @returns {string} Masked password
 */
function maskPassword(password) {
    return '*'.repeat(password.length);
}

/**
 * Show notification to user
 * @param {string} message - Message to display
 * @param {string} type - Type of notification (success, error, warning)
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 8px;
        background: ${type === 'success' ? '#4caf50' : type === 'error' ? '#f44336' : '#2196F3'};
        color: white;
        z-index: 9999;
        animation: slideInRight 0.3s ease;
    `;
    
    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

/**
 * Validate email address
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Validate URL
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid
 */
function validateURL(url) {
    try {
        new URL(url);
        return true;
    } catch (error) {
        return false;
    }
}

// ====================== EVENT LISTENERS ======================

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('AI CyberShield loaded successfully');
    
    // Set default section to active
    showSection('password');

    // Add keyboard shortcut support
    document.addEventListener('keydown', function(event) {
        if (event.ctrlKey || event.metaKey) {
            if (event.key === '1') showSection('password');
            if (event.key === '2') showSection('phishing');
            if (event.key === '3') showSection('file');
            if (event.key === '4') showSection('tips');
        }
    });
});

// Allow Enter key to submit forms
document.addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        const activeInput = document.activeElement;
        
        if (activeInput.id === 'passwordInput') {
            checkPassword();
        } else if (activeInput.id === 'urlInput') {
            checkPhishing();
        } else if (activeInput.id === 'fileInput') {
            scanFile();
        }
    }
});

// ====================== POLYFILLS & FALLBACKS ======================

// Polyfill for older browsers
if (!String.prototype.repeat) {
    String.prototype.repeat = function(count) {
        if (this == null) throw new TypeError('can\'t convert ' + this + ' to object');
        const str = '' + this;
        count = +count;
        if (count < 0 || count == Infinity) throw new RangeError('repeat count must be non-negative');
        count = Math.floor(count);
        let rpt = '';
        for (let i = 0; i < count; i++) rpt += str;
        return rpt;
    };
          }
