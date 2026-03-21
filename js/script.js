// ========== SCAM MESSAGE DETECTOR LOGIC ==========
// Comprehensive scam keywords and patterns
const SCAM_KEYWORDS = [
    // Prize & money scams
    'won', 'winner', 'winning', 'congratulations', 'prize', 'reward', 'cash prize',
    'million', 'dollars', '$$$', 'money', 'lottery', 'jackpot', 'free money',
    // Urgency tactics
    'urgent', 'immediately', 'immediate', 'act now', 'limited time', 'expires',
    'verify now', 'verify account', 'suspended', 'locked', 'deactivated',
    // Suspicious actions
    'click here', 'http://', 'https://', 'bit.ly', 'tinyurl', 'link', 'transfer',
    'wire money', 'send money', 'payment', 'paypal', 'bank account', 'credit card',
    // Personal info
    'ssn', 'social security', 'password', 'verify identity', 'confirm details',
    'otp', 'one time password', '2fa', 'authentication',
    // Fake offers & threats
    'inheritance', 'investment', 'crypto', 'bitcoin', 'guaranteed return',
    'irs', 'tax refund', 'arrest warrant', 'lawsuit', 'court case'
];

// Additional high-risk patterns (regex)
const SUSPICIOUS_PATTERNS = [
    { pattern: /http[s]?:\/\/[^\s]+/gi, type: 'suspicious_link' },
    { pattern: /\b\d{5,}\b/g, type: 'large_number' },
    { pattern: /!\s*!/g, type: 'multiple_exclamation' },
    { pattern: /[A-Z\s]{10,}/g, type: 'aggressive_caps' }
];

// Function to analyze message and return scam score + details
function analyzeMessage(message) {
    if (!message || message.trim().length === 0) {
        return { isScam: false, score: 0, matchedKeywords: [], patterns: [], reason: 'No message provided' };
    }

    const lowerMsg = message.toLowerCase();
    const matchedKeywords = [];
    
    // Check scam keywords
    for (const keyword of SCAM_KEYWORDS) {
        if (lowerMsg.includes(keyword.toLowerCase())) {
            matchedKeywords.push(keyword);
        }
    }
    
    // Remove duplicates
    const uniqueKeywords = [...new Set(matchedKeywords)];
    
    // Calculate base score (each keyword adds weight)
    let score = uniqueKeywords.length * 12;
    
    // Check suspicious patterns
    const detectedPatterns = [];
    for (const { pattern, type } of SUSPICIOUS_PATTERNS) {
        const matches = message.match(pattern);
        if (matches && matches.length > 0) {
            detectedPatterns.push(type);
            // Add extra points for links and aggressive patterns
            if (type === 'suspicious_link') score += 25;
            if (type === 'multiple_exclamation') score += 8;
            if (type === 'aggressive_caps') score += 10;
            if (type === 'large_number') score += 5;
        }
    }
    
    // Check for phone number patterns (scammers often leave numbers)
    const phonePattern = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
    if (phonePattern.test(message)) {
        detectedPatterns.push('phone_number');
        score += 15;
    }
    
    // Check for email patterns
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    if (emailPattern.test(message)) {
        detectedPatterns.push('email_address');
        score += 8;
    }
    
    // Additional urgency words check
    const urgencyWords = ['urgent', 'immediately', 'asap', 'right now', 'today only'];
    let urgencyCount = 0;
    urgencyWords.forEach(word => {
        if (lowerMsg.includes(word)) urgencyCount++;
    });
    score += urgencyCount * 7;
    
    // Cap score at 100
    score = Math.min(score, 100);
    
    // Determine if scam (threshold 35%)
    const isScam = score >= 35;
    
    // Generate reason
    let reason = '';
    if (isScam) {
        if (uniqueKeywords.length >= 3) reason = `⚠️ Contains ${uniqueKeywords.length} scam indicators including: ${uniqueKeywords.slice(0, 4).join(', ')}...`;
        else if (detectedPatterns.includes('suspicious_link')) reason = '🚨 Suspicious link detected - common phishing tactic';
        else if (score > 60) reason = '🔴 High probability scam - multiple fraud patterns identified';
        else reason = '⚠️ Suspicious patterns detected - proceed with caution';
    } else {
        if (score > 15) reason = 'ℹ️ Low risk but contains some marketing language';
        else reason = '✅ No major scam patterns detected. Message appears legitimate.';
    }
    
    return {
        isScam,
        score: Math.round(score),
        matchedKeywords: uniqueKeywords,
        patterns: detectedPatterns,
        reason
    };
}

// Function to display result in UI with beautiful alert
function displayResult(analysis, originalMessage) {
    const resultArea = document.getElementById('resultArea');
    
    if (!originalMessage || originalMessage.trim() === '') {
        resultArea.innerHTML = `
            <div class="result-placeholder text-center py-4 text-secondary">
                <i class="bi bi-exclamation-triangle fs-1"></i>
                <p class="mt-2 mb-0">Please paste a message to analyze</p>
            </div>
        `;
        return;
    }
    
    const { isScam, score, matchedKeywords, patterns, reason } = analysis;
    
    // Build keywords HTML
    let keywordsHtml = '';
    if (matchedKeywords.length > 0) {
        keywordsHtml = `
            <div class="mt-3">
                <strong><i class="bi bi-tag-fill me-1"></i> Flagged keywords:</strong>
                <div class="scam-keywords-list">
                    ${matchedKeywords.slice(0, 12).map(kw => `<span class="scam-keyword">${escapeHtml(kw)}</span>`).join('')}
                    ${matchedKeywords.length > 12 ? `<span class="scam-keyword">+${matchedKeywords.length - 12} more</span>` : ''}
                </div>
            </div>
        `;
    }
    
    // Patterns info
    let patternsHtml = '';
    if (patterns.length > 0) {
        const patternIcons = {
            suspicious_link: '🔗 Suspicious URL',
            large_number: '💰 Large money amount',
            multiple_exclamation: '❗ Excessive urgency',
            aggressive_caps: '🔊 ALL CAPS text',
            phone_number: '📞 Phone number',
            email_address: '📧 Email address'
        };
        patternsHtml = `
            <div class="mt-2">
                <strong><i class="bi bi-graph-up me-1"></i> Detected patterns:</strong>
                <div class="d-flex flex-wrap gap-2 mt-1">
                    ${patterns.map(p => `<span class="badge bg-secondary bg-opacity-25 text-dark">${patternIcons[p] || p}</span>`).join('')}
                </div>
            </div>
        `;
    }
    
    // Score indicator
    const scoreColor = score >= 60 ? '#dc2626' : (score >= 35 ? '#f97316' : '#10b981');
    
    // Main alert
    const alertClass = isScam ? 'result-danger' : 'result-success';
    const icon = isScam ? '<i class="bi bi-shield-exclamation result-icon"></i>' : '<i class="bi bi-shield-check result-icon"></i>';
    const title = isScam ? '⚠️ SCAM ALERT! High Risk Detected' : '✅ SAFE MESSAGE | Low Risk';
    
    resultArea.innerHTML = `
        <div class="result-alert ${alertClass}">
            <div class="d-flex align-items-start flex-wrap">
                ${icon}
                <div class="flex-grow-1">
                    <h5 class="fw-bold mb-2">${title}</h5>
                    <p class="mb-2"><strong>Risk Score:</strong> <span style="color: ${scoreColor}; font-weight: 800;">${score}%</span> ${score >= 60 ? '(Critical)' : (score >= 35 ? '(Suspicious)' : '(Low Risk)')}</p>
                    <p class="mb-0">${reason}</p>
                    ${keywordsHtml}
                    ${patternsHtml}
                    <div class="mt-3 pt-2 small border-top">
                        <i class="bi bi-info-circle-fill"></i> Always verify suspicious messages with official sources.
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Helper to escape HTML
function escapeHtml(str) {
    return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

// ========== EVENT LISTENERS & UI INTERACTIONS ==========
document.addEventListener('DOMContentLoaded', function() {
    const detectBtn = document.getElementById('detectBtn');
    const clearBtn = document.getElementById('clearBtn');
    const messageInput = document.getElementById('scamMessage');
    const resultArea = document.getElementById('resultArea');
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');

    // THEME: initialize from localStorage or system preference
    function applyTheme(theme) {
        document.documentElement.classList.remove('light-theme', 'dark-theme');
        if (theme === 'light') {
            document.documentElement.classList.add('light-theme');
            themeIcon.className = 'bi bi-sun-fill';
            themeToggle.setAttribute('aria-pressed', 'true');
        } else {
            document.documentElement.classList.add('dark-theme');
            themeIcon.className = 'bi bi-moon-fill';
            themeToggle.setAttribute('aria-pressed', 'false');
        }
    }

    function loadTheme() {
        const saved = localStorage.getItem('shield_theme');
        if (saved === 'light' || saved === 'dark') return saved;
        // Fallback to prefers-color-scheme
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
        return 'dark';
    }

    // initialize theme on load
    const initialTheme = loadTheme();
    applyTheme(initialTheme);

    // toggle handler
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const current = document.documentElement.classList.contains('light-theme') ? 'light' : 'dark';
            const next = current === 'light' ? 'dark' : 'light';
            applyTheme(next);
            localStorage.setItem('shield_theme', next);
        });
    }
    
    // Detect scam button click
    detectBtn.addEventListener('click', function() {
        const message = messageInput.value;
        const analysis = analyzeMessage(message);
        displayResult(analysis, message);
    });
    
    // Clear button functionality
    clearBtn.addEventListener('click', function() {
        messageInput.value = '';
        resultArea.innerHTML = `
            <div class="result-placeholder text-center py-4 text-secondary">
                <i class="bi bi-robot fs-1"></i>
                <p class="mt-2 mb-0">Your scam analysis will appear here</p>
            </div>
        `;
        messageInput.focus();
    });
    
    // Tips toggle functionality (collapsible)
    const tipsToggle = document.getElementById('tipsToggle');
    const tipsContent = document.getElementById('tipsContent');
    const tipsIcon = document.getElementById('tipsIcon');
    
    if (tipsToggle) {
        tipsToggle.addEventListener('click', function() {
            if (tipsContent.style.display === 'none' || tipsContent.style.display === '') {
                tipsContent.style.display = 'block';
                tipsIcon.classList.remove('bi-chevron-down');
                tipsIcon.classList.add('bi-chevron-up');
            } else {
                tipsContent.style.display = 'none';
                tipsIcon.classList.remove('bi-chevron-up');
                tipsIcon.classList.add('bi-chevron-down');
            }
        });
    }
    
    
    messageInput.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            detectBtn.click();
        }
    });
    
    // Demo example prefill for testing (optional but user friendly)
    // You can remove if not needed, but helps showcase functionality
    if (messageInput.value === '') {
        // Not prefilling to keep clean, but if you want demo text uncomment:
        // messageInput.value = "URGENT! Your account has been suspended. Click here to verify immediately: http://fake-link.com or your funds will be lost.";
    }
});