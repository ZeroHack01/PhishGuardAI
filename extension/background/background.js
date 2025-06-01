/**
 * PhishGuard AI Background Service Worker
 * Manages extension lifecycle, analysis coordination, and threat intelligence
 * File: extension/background/background.js
 */

class PhishGuardBackgroundService {
    constructor() {
        this.tabAnalyses = new Map();
        this.threatIntelligence = new Map();
        this.settings = {};
        this.statistics = {
            threatsBlocked: 0,
            sitesScanned: 0,
            installDate: Date.now()
        };
        
        // Initialize service
        this.init();
    }
    
    async init() {
        try {
            await this.loadSettings();
            await this.loadStatistics();
            await this.loadThreatIntelligence();
            this.setupEventListeners();
            this.scheduleThreatIntelligenceUpdates();
            
            console.log('PhishGuard AI Background Service initialized');
        } catch (error) {
            console.error('Background service initialization failed:', error);
        }
    }
    
    async loadSettings() {
        return new Promise((resolve) => {
            chrome.storage.sync.get({
                enableRealTime: true,
                enableNotifications: true,
                enableAutoBlock: false,
                protectionLevel: 'medium',
                whitelist: []
            }, (settings) => {
                this.settings = settings;
                resolve();
            });
        });
    }
    
    async loadStatistics() {
        return new Promise((resolve) => {
            chrome.storage.local.get({
                threatsBlocked: 0,
                sitesScanned: 0,
                installDate: Date.now(),
                recentAlerts: [],
                phishingReports: []
            }, (data) => {
                this.statistics = data;
                resolve();
            });
        });
    }
    
    async loadThreatIntelligence() {
        // Load cached threat intelligence
        return new Promise((resolve) => {
            chrome.storage.local.get({
                maliciousDomains: [],
                suspiciousDomains: [],
                lastThreatUpdate: 0
            }, (data) => {
                // Convert arrays to Sets for faster lookup
                this.threatIntelligence.set('malicious', new Set(data.maliciousDomains));
                this.threatIntelligence.set('suspicious', new Set(data.suspiciousDomains));
                this.threatIntelligence.set('lastUpdate', data.lastThreatUpdate);
                
                // Add default threat patterns
                this.addDefaultThreatPatterns();
                resolve();
            });
        });
    }
    
    addDefaultThreatPatterns() {
        // Add known malicious patterns
        const maliciousPatterns = [
            'paypal-security.tk',
            'amazon-verify.ml',
            'microsoft-secure.ga',
            'apple-support.cf',
            'google-account.pw'
        ];
        
        const suspiciousPatterns = [
            'secure-paypal',
            'amazon-customer',
            'microsoft-account',
            'apple-verification',
            'google-security'
        ];
        
        const maliciousSet = this.threatIntelligence.get('malicious');
        const suspiciousSet = this.threatIntelligence.get('suspicious');
        
        maliciousPatterns.forEach(domain => maliciousSet.add(domain));
        suspiciousPatterns.forEach(domain => suspiciousSet.add(domain));
    }
    
    setupEventListeners() {
        // Handle messages from content scripts and popup
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async response
        });
        
        // Handle tab navigation
        chrome.webNavigation.onCompleted.addListener((details) => {
            if (details.frameId === 0) { // Main frame only
                this.handleTabNavigation(details);
            }
        });
        
        // Handle tab updates
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url) {
                this.handleTabUpdate(tabId, tab);
            }
        });
        
        // Handle tab removal
        chrome.tabs.onRemoved.addListener((tabId) => {
            this.tabAnalyses.delete(tabId);
        });
        
        // Handle extension install/update
        chrome.runtime.onInstalled.addListener((details) => {
            this.handleInstall(details);
        });
        
        // Handle commands (keyboard shortcuts)
        chrome.commands.onCommand.addListener((command) => {
            this.handleCommand(command);
        });
        
        // Handle notification clicks
        chrome.notifications.onClicked.addListener((notificationId) => {
            this.handleNotificationClick(notificationId);
        });
    }
    
    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.action) {
                case 'analysisComplete':
                    await this.handleAnalysisComplete(message.data, sender.tab);
                    sendResponse({ success: true });
                    break;
                    
                case 'getTabAnalysis':
                    const analysis = this.tabAnalyses.get(message.tabId);
                    sendResponse({ analysis });
                    break;
                    
                case 'reportPhishing':
                    await this.handlePhishingReport(message.data);
                    sendResponse({ success: true });
                    break;
                    
                case 'settingsUpdated':
                    this.settings = { ...this.settings, ...message.settings };
                    await this.saveSettings();
                    sendResponse({ success: true });
                    break;
                    
                case 'showNotification':
                    if (this.settings.enableNotifications) {
                        await this.showNotification(message.data);
                    }
                    sendResponse({ success: true });
                    break;
                    
                case 'getStatistics':
                    sendResponse({ statistics: this.statistics });
                    break;
                    
                case 'whitelistDomain':
                    await this.whitelistDomain(message.domain);
                    sendResponse({ success: true });
                    break;
                    
                case 'removeFromWhitelist':
                    await this.removeFromWhitelist(message.domain);
                    sendResponse({ success: true });
                    break;
                    
                case 'getThreatIntelligence':
                    sendResponse({
                        maliciousDomains: Array.from(this.threatIntelligence.get('malicious')),
                        suspiciousDomains: Array.from(this.threatIntelligence.get('suspicious')),
                        lastUpdate: this.threatIntelligence.get('lastUpdate')
                    });
                    break;
                    
                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ error: error.message });
        }
    }
    
    async handleAnalysisComplete(analysisData, tab) {
        if (!tab) return;
        
        try {
            // Store analysis results
            this.tabAnalyses.set(tab.id, {
                ...analysisData,
                tabId: tab.id,
                tabTitle: tab.title
            });
            
            // Update statistics
            await this.updateStatistic('sitesScanned');
            
            // Handle threats based on severity
            if (analysisData.threatLevel === 'dangerous') {
                await this.handleDangerousThreat(analysisData, tab);
            } else if (analysisData.threatLevel === 'suspicious') {
                await this.handleSuspiciousThreat(analysisData, tab);
            }
            
            // Update extension badge
            this.updateExtensionBadge(tab.id, analysisData);
            
            // Log analysis for threat intelligence
            await this.logAnalysisResult(analysisData, tab);
            
        } catch (error) {
            console.error('Error handling analysis completion:', error);
        }
    }
    
    async handleDangerousThreat(analysisData, tab) {
        try {
            // Update statistics
            await this.updateStatistic('threatsBlocked');
            
            // Store alert
            await this.storeAlert({
                type: 'dangerous',
                url: analysisData.url,
                description: `Blocked dangerous phishing site: ${new URL(analysisData.url).hostname}`,
                riskScore: analysisData.riskScore,
                threats: analysisData.threats,
                timestamp: Date.now(),
                tabId: tab.id,
                tabTitle: tab.title
            });
            
            // Show high-priority notification
            if (this.settings.enableNotifications) {
                await this.showNotification({
                    type: 'basic',
                    iconUrl: 'icons/icon48.png',
                    title: '🚨 Phishing Threat Blocked',
                    message: `Dangerous website detected: ${new URL(analysisData.url).hostname}`,
                    priority: 2
                });
            }
            
            // Add to threat intelligence
            await this.addToThreatIntelligence(new URL(analysisData.url).hostname, 'malicious');
            
        } catch (error) {
            console.error('Error handling dangerous threat:', error);
        }
    }
    
    async handleSuspiciousThreat(analysisData, tab) {
        try {
            // Store alert for suspicious activity
            await this.storeAlert({
                type: 'suspicious',
                url: analysisData.url,
                description: `Suspicious activity detected: ${new URL(analysisData.url).hostname}`,
                riskScore: analysisData.riskScore,
                threats: analysisData.threats,
                timestamp: Date.now(),
                tabId: tab.id,
                tabTitle: tab.title
            });
            
            // Show notification for high protection level
            if (this.settings.enableNotifications && this.settings.protectionLevel === 'high') {
                await this.showNotification({
                    type: 'basic',
                    iconUrl: 'icons/icon48.png',
                    title: '⚠️ Suspicious Website',
                    message: `Exercise caution: ${new URL(analysisData.url).hostname}`,
                    priority: 1
                });
            }
            
            // Add to suspicious list
            await this.addToThreatIntelligence(new URL(analysisData.url).hostname, 'suspicious');
            
        } catch (error) {
            console.error('Error handling suspicious threat:', error);
        }
    }
    
    async handleTabNavigation(details) {
        if (!this.settings.enableRealTime) return;
        
        try {
            // Clear previous analysis for this tab
            this.tabAnalyses.delete(details.tabId);
            
            // Pre-check URL against threat intelligence
            const preCheck = await this.performPreCheck(details.url);
            
            if (preCheck.isBlocked) {
                // Store immediate threat detection
                this.tabAnalyses.set(details.tabId, {
                    url: details.url,
                    riskScore: 100,
                    threatLevel: 'dangerous',
                    threats: [preCheck.reason],
                    timestamp: Date.now(),
                    preBlocked: true
                });
                
                // Update badge immediately
                this.updateExtensionBadge(details.tabId, {
                    threatLevel: 'dangerous',
                    riskScore: 100
                });
            }
        } catch (error) {
            console.error('Error handling tab navigation:', error);
        }
    }
    
    async handleTabUpdate(tabId, tab) {
        try {
            // Update analysis if URL changed
            const existingAnalysis = this.tabAnalyses.get(tabId);
            if (existingAnalysis && existingAnalysis.url !== tab.url) {
                this.tabAnalyses.delete(tabId);
                // Reset badge
                chrome.action.setBadgeText({ text: '', tabId: tabId });
            }
        } catch (error) {
            console.error('Error handling tab update:', error);
        }
    }
    
    async performPreCheck(url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();
            
            // Check against known malicious domains
            if (this.threatIntelligence.get('malicious').has(hostname)) {
                return { isBlocked: true, reason: 'Known malicious domain' };
            }
            
            // Check against suspicious patterns
            const suspiciousPatterns = Array.from(this.threatIntelligence.get('suspicious'));
            for (const pattern of suspiciousPatterns) {
                if (hostname.includes(pattern)) {
                    return { isBlocked: false, reason: 'Suspicious pattern detected', flag: true };
                }
            }
            
            // Check user whitelist
            if (this.settings.whitelist && this.settings.whitelist.includes(hostname)) {
                return { isBlocked: false, reason: 'User whitelisted' };
            }
            
            return { isBlocked: false };
            
        } catch (error) {
            console.error('Pre-check failed:', error);
            return { isBlocked: false, reason: 'Invalid URL' };
        }
    }
    
    updateExtensionBadge(tabId, analysisData) {
        try {
            let badgeText = '';
            let badgeColor = '#4CAF50'; // Green for safe
            let title = 'PhishGuard AI - Site appears safe';
            
            switch (analysisData.threatLevel) {
                case 'suspicious':
                    badgeText = '!';
                    badgeColor = '#FF9800'; // Orange
                    title = `PhishGuard AI - Suspicious site (${analysisData.riskScore}/100)`;
                    break;
                case 'dangerous':
                    badgeText = '⚠';
                    badgeColor = '#F44336'; // Red
                    title = `PhishGuard AI - Dangerous site blocked (${analysisData.riskScore}/100)`;
                    break;
                default:
                    title = `PhishGuard AI - Site is safe (${analysisData.riskScore}/100)`;
            }
            
            chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
            chrome.action.setTitle({ title: title, tabId: tabId });
            
        } catch (error) {
            console.error('Error updating extension badge:', error);
        }
    }
    
    async storeAlert(alert) {
        return new Promise((resolve) => {
            chrome.storage.local.get({ recentAlerts: [] }, (data) => {
                const alerts = data.recentAlerts;
                alerts.unshift({ ...alert, id: Date.now() }); // Add to beginning with unique ID
                
                // Keep only last 100 alerts
                const trimmedAlerts = alerts.slice(0, 100);
                
                chrome.storage.local.set({ recentAlerts: trimmedAlerts }, () => {
                    resolve();
                });
            });
        });
    }
    
    async showNotification(options) {
        try {
            const notificationId = `phishguard_${Date.now()}`;
            
            await chrome.notifications.create(notificationId, {
                type: options.type || 'basic',
                iconUrl: options.iconUrl || 'icons/icon48.png',
                title: options.title,
                message: options.message,
                priority: options.priority || 1,
                requireInteraction: options.priority === 2
            });
            
            // Auto-clear notification after 10 seconds (except high priority)
            if (options.priority !== 2) {
                setTimeout(() => {
                    chrome.notifications.clear(notificationId);
                }, 10000);
            }
            
        } catch (error) {
            console.error('Error showing notification:', error);
        }
    }
    
    async updateStatistic(statName) {
        return new Promise((resolve) => {
            chrome.storage.local.get({ [statName]: 0 }, (data) => {
                const newValue = data[statName] + 1;
                this.statistics[statName] = newValue;
                chrome.storage.local.set({ [statName]: newValue }, resolve);
            });
        });
    }
    
    async handlePhishingReport(reportData) {
        try {
            // Store report locally
            await this.storePhishingReport(reportData);
            
            // Add to threat intelligence
            const hostname = new URL(reportData.url).hostname;
            await this.addToThreatIntelligence(hostname, 'malicious');
            
            // Show confirmation notification
            if (this.settings.enableNotifications) {
                await this.showNotification({
                    type: 'basic',
                    iconUrl: 'icons/icon48.png',
                    title: 'Report Submitted',
                    message: 'Thank you for reporting this phishing site. It has been added to our threat database.',
                    priority: 0
                });
            }
            
            console.log('Phishing report processed:', reportData);
            
        } catch (error) {
            console.error('Error handling phishing report:', error);
        }
    }
    
    async storePhishingReport(report) {
        return new Promise((resolve) => {
            chrome.storage.local.get({ phishingReports: [] }, (data) => {
                const reports = data.phishingReports;
                reports.push({
                    ...report,
                    id: Date.now(),
                    status: 'submitted',
                    reportedAt: Date.now()
                });
                
                // Keep only last 50 reports
                const trimmedReports = reports.slice(-50);
                
                chrome.storage.local.set({ phishingReports: trimmedReports }, resolve);
            });
        });
    }
    
    async addToThreatIntelligence(hostname, category) {
        try {
            const threatSet = this.threatIntelligence.get(category);
            if (threatSet && !threatSet.has(hostname)) {
                threatSet.add(hostname);
                
                // Save to storage
                const storageKey = category === 'malicious' ? 'maliciousDomains' : 'suspiciousDomains';
                const storageData = { [storageKey]: Array.from(threatSet) };
                
                chrome.storage.local.set(storageData);
                console.log(`Added ${hostname} to ${category} threat intelligence`);
            }
        } catch (error) {
            console.error('Error adding to threat intelligence:', error);
        }
    }
    
    async logAnalysisResult(analysisData, tab) {
        try {
            // Log analysis for machine learning improvement
            const logEntry = {
                url: analysisData.url,
                hostname: new URL(analysisData.url).hostname,
                riskScore: analysisData.riskScore,
                threatLevel: analysisData.threatLevel,
                threats: analysisData.threats,
                features: analysisData.features,
                timestamp: Date.now(),
                tabId: tab.id,
                userAgent: navigator.userAgent
            };
            
            // Store in local analysis log (for potential ML training)
            chrome.storage.local.get({ analysisLog: [] }, (data) => {
                const log = data.analysisLog;
                log.push(logEntry);
                
                // Keep only last 1000 entries
                const trimmedLog = log.slice(-1000);
                chrome.storage.local.set({ analysisLog: trimmedLog });
            });
            
        } catch (error) {
            console.error('Error logging analysis result:', error);
        }
    }
    
    async whitelistDomain(domain) {
        try {
            if (!this.settings.whitelist.includes(domain)) {
                this.settings.whitelist.push(domain);
                await this.saveSettings();
                console.log(`Domain ${domain} added to whitelist`);
            }
        } catch (error) {
            console.error('Error whitelisting domain:', error);
        }
    }
    
    async removeFromWhitelist(domain) {
        try {
            const index = this.settings.whitelist.indexOf(domain);
            if (index > -1) {
                this.settings.whitelist.splice(index, 1);
                await this.saveSettings();
                console.log(`Domain ${domain} removed from whitelist`);
            }
        } catch (error) {
            console.error('Error removing from whitelist:', error);
        }
    }
    
    async saveSettings() {
        return new Promise((resolve) => {
            chrome.storage.sync.set(this.settings, resolve);
        });
    }
    
    scheduleThreatIntelligenceUpdates() {
        // Update threat intelligence every 6 hours
        const updateInterval = 6 * 60 * 60 * 1000; // 6 hours in milliseconds
        
        setInterval(() => {
            this.updateThreatIntelligence();
        }, updateInterval);
        
        // Run initial update if data is old
        const lastUpdate = this.threatIntelligence.get('lastUpdate') || 0;
        if (Date.now() - lastUpdate > updateInterval) {
            this.updateThreatIntelligence();
        }
    }
    
    async updateThreatIntelligence() {
        try {
            console.log('Updating threat intelligence...');
            
            // In a production environment, this would fetch from external APIs
            // For now, we'll simulate with predefined updates
            const newThreats = [
                'phishing-bank-update.tk',
                'secure-paypal-verify.ml',
                'amazon-security-check.ga'
            ];
            
            const maliciousSet = this.threatIntelligence.get('malicious');
            newThreats.forEach(threat => maliciousSet.add(threat));
            
            // Update timestamp
            this.threatIntelligence.set('lastUpdate', Date.now());
            
            // Save to storage
            chrome.storage.local.set({
                maliciousDomains: Array.from(maliciousSet),
                lastThreatUpdate: Date.now()
            });
            
            console.log('Threat intelligence updated with', newThreats.length, 'new threats');
            
        } catch (error) {
            console.error('Failed to update threat intelligence:', error);
        }
    }
    
    async handleInstall(details) {
        try {
            if (details.reason === 'install') {
                // First-time installation
                await this.initializeForFirstTime();
                
                // Show welcome notification
                await this.showNotification({
                    type: 'basic',
                    iconUrl: 'icons/icon48.png',
                    title: '🛡️ PhishGuard AI Installed',
                    message: 'Your browser is now protected against phishing attacks!',
                    priority: 1
                });
                
                // Open demo page
                chrome.tabs.create({
                    url: chrome.runtime.getURL('web-demo/index.html')
                });
                
            } else if (details.reason === 'update') {
                // Extension updated
                console.log('PhishGuard AI updated to version', chrome.runtime.getManifest().version);
                
                // Migrate settings if needed
                await this.migrateSettings(details.previousVersion);
            }
        } catch (error) {
            console.error('Error handling install:', error);
        }
    }
    
    async initializeForFirstTime() {
        const defaultData = {
            threatsBlocked: 0,
            sitesScanned: 0,
            installDate: Date.now(),
            recentAlerts: [],
            phishingReports: [],
            analysisLog: []
        };
        
        chrome.storage.local.set(defaultData);
        this.statistics = defaultData;
    }
    
    async migrateSettings(previousVersion) {
        // Handle settings migration for updates
        console.log(`Migrating from version ${previousVersion}`);
        
        // Add any new default settings
        const newDefaults = {
            enableAutoBlock: false,
            protectionLevel: 'medium'
        };
        
        chrome.storage.sync.get(null, (currentSettings) => {
            const updatedSettings = { ...newDefaults, ...currentSettings };
            chrome.storage.sync.set(updatedSettings);
        });
    }
    
    async handleCommand(command) {
        try {
            switch (command) {
                case 'toggle-protection':
                    this.settings.enableRealTime = !this.settings.enableRealTime;
                    await this.saveSettings();
                    
                    await this.showNotification({
                        type: 'basic',
                        iconUrl: 'icons/icon48.png',
                        title: 'PhishGuard AI',
                        message: `Protection ${this.settings.enableRealTime ? 'enabled' : 'disabled'}`,
                        priority: 0
                    });
                    break;
                    
                case 'quick-scan':
                    // Trigger immediate scan of current tab
                    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    if (activeTab) {
                        chrome.tabs.sendMessage(activeTab.id, { action: 'forceScan' });
                    }
                    break;
            }
        } catch (error) {
            console.error('Error handling command:', error);
        }
    }
    
    handleNotificationClick(notificationId) {
        try {
            // Open extension popup or relevant page
            chrome.tabs.create({
                url: chrome.runtime.getURL('popup/popup.html')
            });
            
            // Clear the notification
            chrome.notifications.clear(notificationId);
        } catch (error) {
            console.error('Error handling notification click:', error);
        }
    }
}

// Initialize the background service
const phishGuardService = new PhishGuardBackgroundService();
