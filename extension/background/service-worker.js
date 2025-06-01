/**
 * PhishGuard AI - Enhanced Background Service Worker
 * File: extension/background/service-worker.js
 * 
 * Advanced background processing, threat intelligence coordination,
 * and real-time protection management for Chrome extension
 */

// Global state management
let extensionState = {
    isInitialized: false,
    aiModelsLoaded: false,
    threatIntelEnabled: true,
    protectionLevel: 'high', // low, medium, high, maximum
    totalThreatsBlocked: 0,
    sessionsProtected: 0,
    lastThreatUpdate: null,
    currentVersion: '1.0.0'
};

// Performance tracking
let performanceMetrics = {
    analysisCount: 0,
    averageAnalysisTime: 0,
    cacheHitRate: 0,
    falsePositiveRate: 0,
    lastPerformanceReset: Date.now()
};

// Threat intelligence cache
let threatCache = new Map();
let domainReputationCache = new Map();

// Active tab monitoring
let activeTabs = new Map();
let protectedSessions = new Set();

// API rate limiting
let apiRateLimits = {
    threatIntel: { requests: 0, resetTime: Date.now() + 3600000 }, // 1 hour
    domainCheck: { requests: 0, resetTime: Date.now() + 3600000 }
};

console.log('🛡️ PhishGuard AI Service Worker initializing...');

/**
 * Extension installation and initialization
 */
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('📦 PhishGuard AI installed:', details.reason);
    
    try {
        await initializeExtension();
        
        if (details.reason === 'install') {
            // First time installation
            await handleFirstInstall();
        } else if (details.reason === 'update') {
            // Extension update
            await handleExtensionUpdate(details.previousVersion);
        }
        
        // Set up default settings
        await chrome.storage.sync.set({
            protectionEnabled: true,
            protectionLevel: 'high',
            realTimeProtection: true,
            threatIntelligence: true,
            blockSuspicious: true,
            showNotifications: true,
            statisticsEnabled: true
        });
        
        console.log('✅ PhishGuard AI initialization complete');
        
    } catch (error) {
        console.error('❌ Extension initialization failed:', error);
        await handleInitializationError(error);
    }
});

/**
 * Initialize core extension functionality
 */
async function initializeExtension() {
    console.log('🔧 Initializing core functionality...');
    
    // Load extension state
    const savedState = await chrome.storage.local.get([
        'totalThreatsBlocked',
        'sessionsProtected',
        'lastThreatUpdate'
    ]);
    
    extensionState = { ...extensionState, ...savedState };
    
    // Initialize threat intelligence
    await initializeThreatIntelligence();
    
    // Set up periodic tasks
    setupPeriodicTasks();
    
    // Initialize performance monitoring
    resetPerformanceMetrics();
    
    // Register context menu items
    await setupContextMenus();
    
    // Initialize alarm for cleanup tasks
    chrome.alarms.create('cleanup', { periodInMinutes: 60 });
    chrome.alarms.create('threatUpdate', { periodInMinutes: 30 });
    chrome.alarms.create('performanceReport', { periodInMinutes: 1440 }); // Daily
    
    extensionState.isInitialized = true;
}

/**
 * Handle first-time installation
 */
async function handleFirstInstall() {
    console.log('🎉 Welcome to PhishGuard AI!');
    
    // Show welcome notification
    await showNotification(
        'PhishGuard AI Active',
        'Your browser is now protected against phishing attacks!',
        'info'
    );
    
    // Open welcome page
    chrome.tabs.create({
        url: chrome.runtime.getURL('welcome.html')
    });
    
    // Initialize statistics
    await chrome.storage.local.set({
        installDate: Date.now(),
        totalThreatsBlocked: 0,
        sessionsProtected: 0
    });
}

/**
 * Handle extension updates
 */
async function handleExtensionUpdate(previousVersion) {
    console.log(`🔄 Updating from version ${previousVersion} to ${extensionState.currentVersion}`);
    
    // Migration logic based on version
    if (compareVersions(previousVersion, '1.0.0') < 0) {
        await migrateToV1();
    }
    
    // Clear old caches
    threatCache.clear();
    domainReputationCache.clear();
    
    // Show update notification
    await showNotification(
        'PhishGuard AI Updated',
        `Updated to version ${extensionState.currentVersion}`,
        'info'
    );
}

/**
 * Initialize threat intelligence systems
 */
async function initializeThreatIntelligence() {
    console.log('🧠 Initializing threat intelligence...');
    
    try {
        // Load threat intelligence data
        const threatData = await chrome.storage.local.get(['threatIntelCache', 'domainReputationCache']);
        
        if (threatData.threatIntelCache) {
            threatCache = new Map(Object.entries(threatData.threatIntelCache));
        }
        
        if (threatData.domainReputationCache) {
            domainReputationCache = new Map(Object.entries(threatData.domainReputationCache));
        }
        
        // Update threat intelligence from external sources
        await updateThreatIntelligence();
        
        console.log(`✅ Loaded ${threatCache.size} threat intelligence entries`);
        
    } catch (error) {
        console.error('❌ Threat intelligence initialization failed:', error);
    }
}

/**
 * Message handling from content scripts and popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('📨 Received message:', message.type, 'from', sender.tab?.url || 'popup');
    
    handleMessage(message, sender, sendResponse);
    return true; // Keep message channel open for async responses
});

/**
 * Handle different types of messages
 */
async function handleMessage(message, sender, sendResponse) {
    try {
        switch (message.type) {
            case 'ANALYZE_URL':
                const analysis = await analyzeUrl(message.url, sender.tab);
                sendResponse({ success: true, analysis });
                break;
                
            case 'ANALYZE_PAGE_CONTENT':
                const pageAnalysis = await analyzePageContent(message.content, message.url, sender.tab);
                sendResponse({ success: true, analysis: pageAnalysis });
                break;
                
            case 'CHECK_DOMAIN_REPUTATION':
                const reputation = await checkDomainReputation(message.domain);
                sendResponse({ success: true, reputation });
                break;
                
            case 'REPORT_PHISHING':
                await reportPhishingUrl(message.url, message.reason, sender.tab);
                sendResponse({ success: true });
                break;
                
            case 'GET_STATISTICS':
                const stats = await getStatistics();
                sendResponse({ success: true, statistics: stats });
                break;
                
            case 'GET_SETTINGS':
                const settings = await chrome.storage.sync.get();
                sendResponse({ success: true, settings });
                break;
                
            case 'UPDATE_SETTINGS':
                await chrome.storage.sync.set(message.settings);
                await applySettingsChanges(message.settings);
                sendResponse({ success: true });
                break;
                
            case 'GET_PROTECTION_STATUS':
                const status = await getProtectionStatus(sender.tab);
                sendResponse({ success: true, status });
                break;
                
            case 'BLOCK_URL':
                await blockUrl(message.url, message.reason, sender.tab);
                sendResponse({ success: true });
                break;
                
            case 'WHITELIST_DOMAIN':
                await whitelistDomain(message.domain);
                sendResponse({ success: true });
                break;
                
            default:
                console.warn('⚠️ Unknown message type:', message.type);
                sendResponse({ success: false, error: 'Unknown message type' });
        }
    } catch (error) {
        console.error('❌ Message handling error:', error);
        sendResponse({ success: false, error: error.message });
    }
}

/**
 * Advanced URL analysis with AI and threat intelligence
 */
async function analyzeUrl(url, tab) {
    const startTime = performance.now();
    
    try {
        console.log(`🔍 Analyzing URL: ${url}`);
        
        // Check cache first
        const cacheKey = generateCacheKey(url);
        if (threatCache.has(cacheKey)) {
            const cached = threatCache.get(cacheKey);
            if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
                performanceMetrics.cacheHitRate++;
                return cached.analysis;
            }
        }
        
        // Parse URL
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        // Multi-layered analysis
        const analyses = await Promise.allSettled([
            analyzeUrlStructure(url),
            checkThreatIntelligence(url),
            checkDomainReputation(domain),
            checkSSLSecurity(url),
            analyzeUrlPatterns(url)
        ]);
        
        // Aggregate results
        const analysis = aggregateAnalyses(analyses, url);
        
        // Cache result
        threatCache.set(cacheKey, {
            analysis,
            timestamp: Date.now()
        });
        
        // Update performance metrics
        const analysisTime = performance.now() - startTime;
        updatePerformanceMetrics(analysisTime);
        
        // Take action based on analysis
        await takeProtectionAction(analysis, tab);
        
        console.log(`✅ Analysis complete: ${analysis.threatLevel} (${analysisTime.toFixed(2)}ms)`);
        
        return analysis;
        
    } catch (error) {
        console.error('❌ URL analysis failed:', error);
        return createErrorAnalysis(url, error);
    }
}

/**
 * Analyze URL structure for suspicious patterns
 */
async function analyzeUrlStructure(url) {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
    const query = urlObj.search;
    
    let suspicionScore = 0;
    const indicators = [];
    
    // Length analysis
    if (url.length > 100) {
        suspicionScore += 15;
        indicators.push('Very long URL');
    }
    
    // Domain analysis
    if (domain.includes('-') && domain.split('-').length > 3) {
        suspicionScore += 20;
        indicators.push('Multiple hyphens in domain');
    }
    
    // IP address instead of domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        suspicionScore += 30;
        indicators.push('IP address used instead of domain');
    }
    
    // Suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        suspicionScore += 25;
        indicators.push('Suspicious top-level domain');
    }
    
    // URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
    if (shorteners.includes(domain)) {
        suspicionScore += 20;
        indicators.push('URL shortener detected');
    }
    
    // Suspicious keywords
    const suspiciousKeywords = ['secure', 'verify', 'update', 'suspended', 'urgent'];
    const hasKeywords = suspiciousKeywords.some(keyword => 
        url.toLowerCase().includes(keyword)
    );
    if (hasKeywords) {
        suspicionScore += 15;
        indicators.push('Contains suspicious keywords');
    }
    
    // HTTPS check
    if (!url.startsWith('https://')) {
        suspicionScore += 10;
        indicators.push('No HTTPS encryption');
    }
    
    return {
        source: 'url_structure',
        suspicionScore: Math.min(suspicionScore, 100),
        indicators,
        confidence: 0.8
    };
}

/**
 * Check against threat intelligence feeds
 */
async function checkThreatIntelligence(url) {
    try {
        // Check rate limits
        if (!checkRateLimit('threatIntel')) {
            return { source: 'threat_intel', error: 'Rate limit exceeded' };
        }
        
        // Simulate threat intelligence lookup
        // In production, this would call external APIs
        const urlHash = await hashString(url);
        const knownThreats = await chrome.storage.local.get(['knownThreats']);
        
        if (knownThreats.knownThreats && knownThreats.knownThreats[urlHash]) {
            return {
                source: 'threat_intel',
                isThreat: true,
                threatType: knownThreats.knownThreats[urlHash].type,
                confidence: 0.95,
                lastSeen: knownThreats.knownThreats[urlHash].lastSeen
            };
        }
        
        return {
            source: 'threat_intel',
            isThreat: false,
            confidence: 0.7
        };
        
    } catch (error) {
        console.error('Threat intelligence check failed:', error);
        return { source: 'threat_intel', error: error.message };
    }
}

/**
 * Check domain reputation
 */
async function checkDomainReputation(domain) {
    try {
        // Check cache
        if (domainReputationCache.has(domain)) {
            const cached = domainReputationCache.get(domain);
            if (Date.now() - cached.timestamp < 86400000) { // 24 hour cache
                return cached.reputation;
            }
        }
        
        // Simulate domain reputation check
        const reputation = await simulateDomainReputationCheck(domain);
        
        // Cache result
        domainReputationCache.set(domain, {
            reputation,
            timestamp: Date.now()
        });
        
        return reputation;
        
    } catch (error) {
        console.error('Domain reputation check failed:', error);
        return { source: 'domain_reputation', error: error.message };
    }
}

/**
 * Simulate domain reputation check
 */
async function simulateDomainReputationCheck(domain) {
    // Known safe domains
    const safeDomains = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'github.com', 'stackoverflow.com', 'youtube.com'
    ];
    
    // Known malicious patterns
    const maliciousPatterns = [
        /g[o0]{2}gle/, /fac[e3]book/, /amazo[n0]/, /micr[o0]s[o0]ft/,
        /payp[a4]l/, /[a4]pple/, /b[a4]nk.*login/, /secure.*verify/
    ];
    
    if (safeDomains.includes(domain)) {
        return {
            source: 'domain_reputation',
            score: 95,
            category: 'trusted',
            confidence: 0.9
        };
    }
    
    if (maliciousPatterns.some(pattern => pattern.test(domain))) {
        return {
            source: 'domain_reputation',
            score: 10,
            category: 'suspicious',
            confidence: 0.85
        };
    }
    
    // Default neutral reputation
    return {
        source: 'domain_reputation',
        score: 50,
        category: 'unknown',
        confidence: 0.5
    };
}

/**
 * Check SSL security
 */
async function checkSSLSecurity(url) {
    try {
        if (!url.startsWith('https://')) {
            return {
                source: 'ssl_check',
                secure: false,
                issue: 'No HTTPS encryption',
                confidence: 1.0
            };
        }
        
        // In a real implementation, you would check certificate validity
        return {
            source: 'ssl_check',
            secure: true,
            confidence: 0.8
        };
        
    } catch (error) {
        return { source: 'ssl_check', error: error.message };
    }
}

/**
 * Analyze URL patterns with regex
 */
async function analyzeUrlPatterns(url) {
    const patterns = [
        { regex: /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./i, score: 20, description: 'Multiple hyphens' },
        { regex: /\d{8,}/i, score: 15, description: 'Long number sequences' },
        { regex: /[a-z]{20,}/i, score: 10, description: 'Very long strings' },
        { regex: /\.tk$|\.ml$|\.ga$|\.cf$/i, score: 25, description: 'Suspicious TLD' },
        { regex: /bit\.ly|tinyurl|t\.co/i, score: 15, description: 'URL shortener' }
    ];
    
    let totalScore = 0;
    const matchedPatterns = [];
    
    for (const pattern of patterns) {
        if (pattern.regex.test(url)) {
            totalScore += pattern.score;
            matchedPatterns.push(pattern.description);
        }
    }
    
    return {
        source: 'pattern_analysis',
        suspicionScore: Math.min(totalScore, 100),
        matchedPatterns,
        confidence: 0.7
    };
}

/**
 * Aggregate analysis results into final assessment
 */
function aggregateAnalyses(analyses, url) {
    const validAnalyses = analyses
        .filter(result => result.status === 'fulfilled')
        .map(result => result.value)
        .filter(analysis => !analysis.error);
    
    if (validAnalyses.length === 0) {
        return createErrorAnalysis(url, 'No valid analyses');
    }
    
    // Calculate weighted threat score
    let totalScore = 0;
    let totalWeight = 0;
    const indicators = [];
    const sources = [];
    
    const weights = {
        'url_structure': 0.3,
        'threat_intel': 0.4,
        'domain_reputation': 0.2,
        'ssl_check': 0.05,
        'pattern_analysis': 0.05
    };
    
    for (const analysis of validAnalyses) {
        const weight = weights[analysis.source] || 0.1;
        const score = analysis.suspicionScore || 
                     (analysis.isThreat ? 100 : 0) ||
                     (100 - (analysis.score || 50));
        
        totalScore += score * weight;
        totalWeight += weight;
        
        if (analysis.indicators) indicators.push(...analysis.indicators);
        if (analysis.matchedPatterns) indicators.push(...analysis.matchedPatterns);
        sources.push(analysis.source);
    }
    
    const finalScore = totalWeight > 0 ? totalScore / totalWeight : 50;
    const threatLevel = classifyThreatLevel(finalScore);
    
    return {
        url,
        threatScore: Math.round(finalScore),
        threatLevel,
        indicators: [...new Set(indicators)],
        sources,
        timestamp: Date.now(),
        analysisVersion: '1.0.0'
    };
}

/**
 * Classify threat level based on score
 */
function classifyThreatLevel(score) {
    if (score >= 80) return 'high';
    if (score >= 60) return 'medium';
    if (score >= 30) return 'low';
    return 'safe';
}

/**
 * Take protective action based on analysis
 */
async function takeProtectionAction(analysis, tab) {
    const settings = await chrome.storage.sync.get([
        'protectionEnabled',
        'protectionLevel',
        'blockSuspicious'
    ]);
    
    if (!settings.protectionEnabled) return;
    
    const shouldBlock = (
        (analysis.threatLevel === 'high') ||
        (analysis.threatLevel === 'medium' && settings.blockSuspicious) ||
        (analysis.threatLevel === 'low' && settings.protectionLevel === 'maximum')
    );
    
    if (shouldBlock) {
        await blockUrl(analysis.url, `Threat detected: ${analysis.threatLevel}`, tab);
        extensionState.totalThreatsBlocked++;
        await chrome.storage.local.set({ 
            totalThreatsBlocked: extensionState.totalThreatsBlocked 
        });
    } else if (analysis.threatLevel !== 'safe') {
        await showWarning(analysis, tab);
    }
}

/**
 * Block a malicious URL
 */
async function blockUrl(url, reason, tab) {
    console.log(`🚫 Blocking URL: ${url} - Reason: ${reason}`);
    
    try {
        // Redirect to warning page
        await chrome.tabs.update(tab.id, {
            url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}`)
        });
        
        // Show notification
        await showNotification(
            'PhishGuard AI - Threat Blocked',
            `Blocked suspicious URL: ${new URL(url).hostname}`,
            'warning'
        );
        
        // Log the block
        await logSecurityEvent('url_blocked', {
            url,
            reason,
            timestamp: Date.now(),
            tabId: tab.id
        });
        
    } catch (error) {
        console.error('❌ Failed to block URL:', error);
    }
}

/**
 * Show warning for suspicious content
 */
async function showWarning(analysis, tab) {
    try {
        // Send warning to content script
        await chrome.tabs.sendMessage(tab.id, {
            type: 'SHOW_WARNING',
            analysis
        });
        
        // Update badge
        chrome.action.setBadgeText({
            text: '⚠️',
            tabId: tab.id
        });
        
        chrome.action.setBadgeBackgroundColor({
            color: '#FFA500',
            tabId: tab.id
        });
        
    } catch (error) {
        console.error('❌ Failed to show warning:', error);
    }
}

/**
 * Show system notification
 */
async function showNotification(title, message, type = 'info') {
    const settings = await chrome.storage.sync.get(['showNotifications']);
    
    if (!settings.showNotifications) return;
    
    try {
        await chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icons/icon128.png'),
            title,
            message
        });
    } catch (error) {
        console.error('❌ Notification failed:', error);
    }
}

/**
 * Get comprehensive statistics
 */
async function getStatistics() {
    const data = await chrome.storage.local.get([
        'totalThreatsBlocked',
        'sessionsProtected',
        'installDate'
    ]);
    
    const daysSinceInstall = data.installDate ? 
        Math.floor((Date.now() - data.installDate) / 86400000) : 0;
    
    return {
        ...data,
        daysSinceInstall,
        performanceMetrics,
        threatCacheSize: threatCache.size,
        domainCacheSize: domainReputationCache.size,
        protectionLevel: extensionState.protectionLevel,
        aiModelsLoaded: extensionState.aiModelsLoaded
    };
}

/**
 * Utility functions
 */
async function hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateCacheKey(url) {
    return `url_${hashString(url)}`;
}

function checkRateLimit(apiType) {
    const limit = apiRateLimits[apiType];
    if (Date.now() > limit.resetTime) {
        limit.requests = 0;
        limit.resetTime = Date.now() + 3600000;
    }
    
    if (limit.requests >= 100) { // Max 100 requests per hour
        return false;
    }
    
    limit.requests++;
    return true;
}

function updatePerformanceMetrics(analysisTime) {
    performanceMetrics.analysisCount++;
    performanceMetrics.averageAnalysisTime = 
        (performanceMetrics.averageAnalysisTime * (performanceMetrics.analysisCount - 1) + analysisTime) / 
        performanceMetrics.analysisCount;
}

function resetPerformanceMetrics() {
    performanceMetrics = {
        analysisCount: 0,
        averageAnalysisTime: 0,
        cacheHitRate: 0,
        falsePositiveRate: 0,
        lastPerformanceReset: Date.now()
    };
}

function createErrorAnalysis(url, error) {
    return {
        url,
        threatScore: 50,
        threatLevel: 'unknown',
        indicators: [`Analysis error: ${error}`],
        sources: ['error'],
        timestamp: Date.now(),
        error: true
    };
}

function compareVersions(a, b) {
    const partsA = a.split('.').map(Number);
    const partsB = b.split('.').map(Number);
    
    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
        const partA = partsA[i] || 0;
        const partB = partsB[i] || 0;
        
        if (partA < partB) return -1;
        if (partA > partB) return 1;
    }
    
    return 0;
}

/**
 * Periodic maintenance tasks
 */
function setupPeriodicTasks() {
    // Update threat intelligence every 30 minutes
    setInterval(updateThreatIntelligence, 30 * 60 * 1000);
    
    // Clean cache every hour
    setInterval(cleanCache, 60 * 60 * 1000);
    
    // Save statistics every 5 minutes
    setInterval(saveStatistics, 5 * 60 * 1000);
}

async function updateThreatIntelligence() {
    console.log('🔄 Updating threat intelligence...');
    // Implementation would fetch from external sources
}

async function cleanCache() {
    console.log('🧹 Cleaning cache...');
    const now = Date.now();
    
    // Clean threat cache (1 hour TTL)
    for (const [key, value] of threatCache.entries()) {
        if (now - value.timestamp > 3600000) {
            threatCache.delete(key);
        }
    }
    
    // Clean domain reputation cache (24 hour TTL)
    for (const [key, value] of domainReputationCache.entries()) {
        if (now - value.timestamp > 86400000) {
            domainReputationCache.delete(key);
        }
    }
}

async function saveStatistics() {
    await chrome.storage.local.set({
        performanceMetrics,
        lastStatsSave: Date.now()
    });
}

/**
 * Alarm handler for scheduled tasks
 */
chrome.alarms.onAlarm.addListener(async (alarm) => {
    console.log(`⏰ Alarm triggered: ${alarm.name}`);
    
    switch (alarm.name) {
        case 'cleanup':
            await cleanCache();
            break;
        case 'threatUpdate':
            await updateThreatIntelligence();
            break;
        case 'performanceReport':
            await generatePerformanceReport();
            break;
    }
});

/**
 * Tab management
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
        await monitorTab(tab);
    }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        await monitorTab(tab);
    }
});

async function monitorTab(tab) {
    activeTabs.set(tab.id, {
        url: tab.url,
        timestamp: Date.now(),
        protected: true
    });
    
    if (!protectedSessions.has(tab.id)) {
        protectedSessions.add(tab.id);
        extensionState.sessionsProtected++;
        await chrome.storage.local.set({
            sessionsProtected: extensionState.sessionsProtected
        });
    }
}

console.log('✅ PhishGuard AI Service Worker loaded successfully');
