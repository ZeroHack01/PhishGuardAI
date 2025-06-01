/**
 * PhishGuard AI - Cyber Interface Controller
 * File: extension/popup/popup.js
 * Controls the cyberpunk-themed popup interface
 */

class CyberPopupController {
    constructor() {
        this.currentTabData = null;
        this.settings = {};
        this.statistics = {};
        this.matrixCanvas = null;
        this.matrixCtx = null;
        this.matrixAnimation = null;
        this.isInitialized = false;
        
        // Matrix animation properties
        this.matrixChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()";
        this.matrixColumns = [];
        this.matrixDrops = [];
        
        this.init();
    }
    
    async init() {
        try {
            await this.loadSettings();
            await this.getCurrentTabData();
            await this.loadStatistics();
            
            this.setupMatrixBackground();
            this.setupEventListeners();
            this.updateInterface();
            this.startPeriodicUpdates();
            
            this.isInitialized = true;
            this.showSystemMessage("PHISHGUARD_AI_NEURAL_MATRIX_ONLINE");
            
        } catch (error) {
            console.error('CyberPopup initialization failed:', error);
            this.showSystemMessage("INITIALIZATION_ERROR", "error");
        }
    }
    
    async loadSettings() {
        return new Promise((resolve) => {
            if (typeof chrome !== 'undefined' && chrome.storage) {
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
            } else {
                // Fallback for testing
                this.settings = {
                    enableRealTime: true,
                    enableNotifications: true,
                    enableAutoBlock: false,
                    protectionLevel: 'medium',
                    whitelist: []
                };
                resolve();
            }
        });
    }
    
    async getCurrentTabData() {
        return new Promise((resolve) => {
            if (typeof chrome !== 'undefined' && chrome.tabs) {
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        this.currentTabData = {
                            url: tabs[0].url,
                            title: tabs[0].title,
                            id: tabs[0].id
                        };
                        
                        // Request analysis data from background script
                        chrome.runtime.sendMessage({
                            action: 'getTabAnalysis',
                            tabId: tabs[0].id
                        }, (response) => {
                            if (response && response.analysis) {
                                this.currentTabData.analysis = response.analysis;
                            }
                            resolve();
                        });
                    } else {
                        resolve();
                    }
                });
            } else {
                // Fallback for testing
                this.currentTabData = {
                    url: 'https://example.com',
                    title: 'Example Site',
                    id: 1,
                    analysis: {
                        riskScore: 25,
                        threatLevel: 'safe',
                        threats: [],
                        timestamp: Date.now()
                    }
                };
                resolve();
            }
        });
    }
    
    async loadStatistics() {
        return new Promise((resolve) => {
            if (typeof chrome !== 'undefined' && chrome.storage) {
                chrome.storage.local.get({
                    threatsBlocked: 0,
                    sitesScanned: 0,
                    installDate: Date.now(),
                    recentAlerts: []
                }, (data) => {
                    this.statistics = data;
                    resolve();
                });
            } else {
                // Fallback for testing
                this.statistics = {
                    threatsBlocked: 42,
                    sitesScanned: 1337,
                    installDate: Date.now() - (7 * 24 * 60 * 60 * 1000),
                    recentAlerts: []
                };
                resolve();
            }
        });
    }
    
    setupMatrixBackground() {
        this.matrixCanvas = document.getElementById('matrixCanvas');
        if (!this.matrixCanvas) return;
        
        this.matrixCtx = this.matrixCanvas.getContext('2d');
        
        // Set canvas size
        this.resizeMatrixCanvas();
        window.addEventListener('resize', () => this.resizeMatrixCanvas());
        
        // Initialize matrix drops
        this.initializeMatrixDrops();
        
        // Start matrix animation
        this.startMatrixAnimation();
    }
    
    resizeMatrixCanvas() {
        const rect = this.matrixCanvas.parentElement.getBoundingClientRect();
        this.matrixCanvas.width = rect.width;
        this.matrixCanvas.height = rect.height;
        
        // Recalculate columns
        const columnWidth = 10;
        this.matrixColumns = Math.floor(this.matrixCanvas.width / columnWidth);
        
        // Reset drops array
        this.matrixDrops = [];
        for (let i = 0; i < this.matrixColumns; i++) {
            this.matrixDrops[i] = Math.random() * this.matrixCanvas.height;
        }
    }
    
    initializeMatrixDrops() {
        const columnWidth = 10;
        this.matrixColumns = Math.floor(this.matrixCanvas.width / columnWidth);
        
        this.matrixDrops = [];
        for (let i = 0; i < this.matrixColumns; i++) {
            this.matrixDrops[i] = Math.random() * this.matrixCanvas.height;
        }
    }
    
    startMatrixAnimation() {
        const drawMatrix = () => {
            // Semi-transparent black background for trailing effect
            this.matrixCtx.fillStyle = 'rgba(0, 0, 0, 0.04)';
            this.matrixCtx.fillRect(0, 0, this.matrixCanvas.width, this.matrixCanvas.height);
            
            // Green text color
            this.matrixCtx.fillStyle = '#00ff41';
            this.matrixCtx.font = '10px JetBrains Mono, monospace';
            
            // Draw characters
            for (let i = 0; i < this.matrixDrops.length; i++) {
                const char = this.matrixChars[Math.floor(Math.random() * this.matrixChars.length)];
                this.matrixCtx.fillText(char, i * 10, this.matrixDrops[i]);
                
                // Reset drop to top randomly
                if (this.matrixDrops[i] > this.matrixCanvas.height && Math.random() > 0.975) {
                    this.matrixDrops[i] = 0;
                }
                
                // Move drop down
                this.matrixDrops[i]++;
            }
        };
        
        this.matrixAnimation = setInterval(drawMatrix, 35);
    }
    
    setupEventListeners() {
        // Refresh analysis button
        const refreshBtn = document.getElementById('refreshAnalysis');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshAnalysis());
        }
        
        // Action buttons
        const reportBtn = document.getElementById('reportThreatBtn');
        if (reportBtn) {
            reportBtn.addEventListener('click', () => this.reportThreat());
        }
        
        const whitelistBtn = document.getElementById('whitelistBtn');
        if (whitelistBtn) {
            whitelistBtn.addEventListener('click', () => this.whitelistSite());
        }
        
        // Footer controls
        const configBtn = document.getElementById('configBtn');
        if (configBtn) {
            configBtn.addEventListener('click', () => this.showConfigModal());
        }
        
        const helpBtn = document.getElementById('helpBtn');
        if (helpBtn) {
            helpBtn.addEventListener('click', () => this.showHelp());
        }
        
        const aboutBtn = document.getElementById('aboutBtn');
        if (aboutBtn) {
            aboutBtn.addEventListener('click', () => this.showAboutModal());
        }
        
        // Modal controls
        this.setupModalEventListeners();
        
        // Log controls
        const clearLogBtn = document.getElementById('clearLogBtn');
        if (clearLogBtn) {
            clearLogBtn.addEventListener('click', () => this.clearThreatLog());
        }
    }
    
    setupModalEventListeners() {
        // Settings modal
        const settingsModal = document.getElementById('settingsModal');
        const closeSettingsBtn = document.getElementById('closeSettingsBtn');
        const saveConfigBtn = document.getElementById('saveConfigBtn');
        const resetConfigBtn = document.getElementById('resetConfigBtn');
        
        if (closeSettingsBtn) {
            closeSettingsBtn.addEventListener('click', () => this.hideConfigModal());
        }
        
        if (saveConfigBtn) {
            saveConfigBtn.addEventListener('click', () => this.saveConfiguration());
        }
        
        if (resetConfigBtn) {
            resetConfigBtn.addEventListener('click', () => this.resetConfiguration());
        }
        
        // About modal
        const aboutModal = document.getElementById('aboutModal');
        const closeAboutBtn = document.getElementById('closeAboutBtn');
        const visitMatrixBtn = document.getElementById('visitMatrixBtn');
        const viewCodeBtn = document.getElementById('viewCodeBtn');
        
        if (closeAboutBtn) {
            closeAboutBtn.addEventListener('click', () => this.hideAboutModal());
        }
        
        if (visitMatrixBtn) {
            visitMatrixBtn.addEventListener('click', () => this.visitWebsite());
        }
        
        if (viewCodeBtn) {
            viewCodeBtn.addEventListener('click', () => this.viewSourceCode());
        }
        
        // Whitelist management
        const addWhitelistBtn = document.getElementById('addWhitelistBtn');
        const whitelistInput = document.getElementById('whitelistInput');
        
        if (addWhitelistBtn) {
            addWhitelistBtn.addEventListener('click', () => this.addToWhitelist());
        }
        
        if (whitelistInput) {
            whitelistInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.addToWhitelist();
                }
            });
        }
        
        // Modal backdrop clicks
        if (settingsModal) {
            settingsModal.addEventListener('click', (e) => {
                if (e.target === settingsModal) {
                    this.hideConfigModal();
                }
            });
        }
        
        if (aboutModal) {
            aboutModal.addEventListener('click', (e) => {
                if (e.target === aboutModal) {
                    this.hideAboutModal();
                }
            });
        }
    }
    
    updateInterface() {
        this.updateTargetInfo();
        this.updateThreatAnalysis();
        this.updateStatistics();
        this.updateSystemStatus();
    }
    
    updateTargetInfo() {
        if (!this.currentTabData) return;
        
        try {
            const url = new URL(this.currentTabData.url);
            
            // Update URL display
            const protocolEl = document.getElementById('urlProtocol');
            const domainEl = document.getElementById('urlDomain');
            
            if (protocolEl) {
                protocolEl.textContent = url.protocol + '//';
            }
            
            if (domainEl) {
                domainEl.textContent = url.hostname;
            }
            
            // Update target status
            const statusEl = document.getElementById('targetStatus');
            if (statusEl && this.currentTabData.analysis) {
                const analysis = this.currentTabData.analysis;
                let statusText = 'NEURAL_ANALYSIS_COMPLETE';
                
                switch (analysis.threatLevel) {
                    case 'safe':
                        statusText = 'SECURE_CONNECTION_VERIFIED';
                        break;
                    case 'suspicious':
                        statusText = 'SUSPICIOUS_PATTERNS_DETECTED';
                        break;
                    case 'dangerous':
                        statusText = 'CRITICAL_THREAT_IDENTIFIED';
                        break;
                }
                
                statusEl.textContent = statusText;
            }
            
        } catch (error) {
            console.error('Error updating target info:', error);
        }
    }
    
    updateThreatAnalysis() {
        if (!this.currentTabData || !this.currentTabData.analysis) {
            this.showAnalyzing();
            return;
        }
        
        const analysis = this.currentTabData.analysis;
        
        // Update risk score
        this.updateRiskGauge(analysis.riskScore, analysis.threatLevel);
        
        // Update threat matrix
        this.updateThreatMatrix(analysis);
        
        // Update vulnerabilities if any
        if (analysis.threats && analysis.threats.length > 0) {
            this.showVulnerabilities(analysis.threats);
        }
    }
    
    updateRiskGauge(riskScore, threatLevel) {
        const riskScoreEl = document.getElementById('riskScore');
        const gaugeFill = document.getElementById('riskGaugeFill');
        
        if (riskScoreEl) {
            riskScoreEl.textContent = riskScore || '--';
            
            // Remove existing classes
            riskScoreEl.classList.remove('safe', 'warning', 'danger');
            
            // Add appropriate class
            if (threatLevel) {
                riskScoreEl.classList.add(threatLevel === 'suspicious' ? 'warning' : threatLevel);
            }
        }
        
        if (gaugeFill) {
            // Remove existing classes
            gaugeFill.classList.remove('safe', 'warning', 'danger');
            
            // Calculate gauge rotation based on risk score
            const rotation = (riskScore / 100) * 180;
            gaugeFill.style.transform = `rotate(${rotation - 90}deg)`;
            
            // Add appropriate class
            if (threatLevel) {
                gaugeFill.classList.add(threatLevel === 'suspicious' ? 'warning' : threatLevel);
            }
        }
    }
    
    updateThreatMatrix(analysis) {
        const matrixTitle = document.getElementById('threatLevel');
        const matrixContent = document.getElementById('threatContent');
        
        if (matrixTitle) {
            let title = 'THREAT_ASSESSMENT';
            let icon = '🛡️';
            
            switch (analysis.threatLevel) {
                case 'safe':
                    title = 'SECURE_STATUS';
                    icon = '✅';
                    break;
                case 'suspicious':
                    title = 'SUSPICIOUS_ACTIVITY';
                    icon = '⚠️';
                    break;
                case 'dangerous':
                    title = 'CRITICAL_THREAT';
                    icon = '🚨';
                    break;
            }
            
            matrixTitle.innerHTML = `<span class="matrix-icon">${icon}</span><span class="matrix-title">${title}</span>`;
        }
        
        if (matrixContent) {
            let content = '';
            
            switch (analysis.threatLevel) {
                case 'safe':
                    content = `
                        <div class="threat-status safe">
                            <div class="status-text">NEURAL_NETWORK_VERIFICATION_COMPLETE</div>
                            <div class="status-detail">All security parameters within acceptable ranges</div>
                        </div>
                    `;
                    break;
                case 'suspicious':
                    content = `
                        <div class="threat-status warning">
                            <div class="status-text">ANOMALOUS_PATTERNS_IDENTIFIED</div>
                            <div class="status-detail">Recommend enhanced security protocols</div>
                        </div>
                    `;
                    break;
                case 'dangerous':
                    content = `
                        <div class="threat-status danger">
                            <div class="status-text">IMMINENT_THREAT_DETECTED</div>
                            <div class="status-detail">Initiating defensive countermeasures</div>
                        </div>
                    `;
                    break;
            }
            
            matrixContent.innerHTML = content;
        }
    }
    
    showVulnerabilities(threats) {
        const vulnerabilitiesEl = document.getElementById('vulnerabilities');
        const vulnList = document.getElementById('vulnList');
        
        if (vulnerabilitiesEl && vulnList) {
            vulnerabilitiesEl.style.display = 'block';
            
            let html = '';
            threats.slice(0, 5).forEach((threat, index) => {
                html += `
                    <div class="vuln-item" style="animation-delay: ${index * 0.1}s">
                        <span class="vuln-id">[VUL_${String(index + 1).padStart(3, '0')}]</span>
                        <span class="vuln-desc">${threat.description || threat}</span>
                    </div>
                `;
            });
            
            if (threats.length > 5) {
                html += `
                    <div class="vuln-item">
                        <span class="vuln-id">[...]</span>
                        <span class="vuln-desc">+${threats.length - 5} additional threats detected</span>
                    </div>
                `;
            }
            
            vulnList.innerHTML = html;
        }
    }
    
    showAnalyzing() {
        const riskScoreEl = document.getElementById('riskScore');
        const matrixContent = document.getElementById('threatContent');
        
        if (riskScoreEl) {
            riskScoreEl.textContent = '--';
        }
        
        if (matrixContent) {
            matrixContent.innerHTML = `
                <div class="scanning-animation">
                    <div class="scan-bar"></div>
                    <div class="scan-text">NEURAL_NETWORK_PROCESSING...</div>
                </div>
            `;
        }
    }
    
    updateStatistics() {
        const threatsEl = document.getElementById('threatsNeutralized');
        const scannedEl = document.getElementById('nodesScanned');
        const uptimeEl = document.getElementById('uptime');
        
        if (threatsEl) {
            this.animateCounter(threatsEl, this.statistics.threatsBlocked || 0);
        }
        
        if (scannedEl) {
            this.animateCounter(scannedEl, this.statistics.sitesScanned || 0);
        }
        
        if (uptimeEl) {
            const installDate = this.statistics.installDate || Date.now();
            const days = Math.floor((Date.now() - installDate) / (1000 * 60 * 60 * 24));
            this.animateCounter(uptimeEl, days);
        }
    }
    
    animateCounter(element, targetValue) {
        const currentValue = parseInt(element.textContent) || 0;
        const increment = Math.ceil((targetValue - currentValue) / 20);
        
        if (currentValue < targetValue) {
            element.textContent = Math.min(currentValue + increment, targetValue);
            setTimeout(() => this.animateCounter(element, targetValue), 50);
        }
    }
    
    updateSystemStatus() {
        const statusDot = document.getElementById('statusText');
        
        if (statusDot && this.currentTabData && this.currentTabData.analysis) {
            const analysis = this.currentTabData.analysis;
            
            let statusText = 'SYSTEM_OPERATIONAL';
            
            if (analysis.threatLevel === 'dangerous') {
                statusText = 'THREAT_DETECTED';
            } else if (analysis.threatLevel === 'suspicious') {
                statusText = 'MONITORING_ENHANCED';
            }
            
            statusDot.textContent = statusText;
        }
    }
    
    async refreshAnalysis() {
        this.showSystemMessage("INITIATING_RESCAN", "info");
        this.showAnalyzing();
        
        if (typeof chrome !== 'undefined' && chrome.tabs && this.currentTabData) {
            // Send message to content script to re-analyze
            chrome.tabs.sendMessage(this.currentTabData.id, { action: 'forceScan' });
            
            // Wait for analysis to complete
            setTimeout(async () => {
                await this.getCurrentTabData();
                this.updateInterface();
                this.showSystemMessage("RESCAN_COMPLETE", "success");
            }, 2000);
        } else {
            // Simulate analysis for testing
            setTimeout(() => {
                if (this.currentTabData && this.currentTabData.analysis) {
                    // Slightly randomize the risk score for demo
                    this.currentTabData.analysis.riskScore = Math.max(0, 
                        this.currentTabData.analysis.riskScore + (Math.random() - 0.5) * 10
                    );
                }
                this.updateInterface();
                this.showSystemMessage("RESCAN_COMPLETE", "success");
            }, 2000);
        }
    }
    
    async reportThreat() {
        if (!this.currentTabData) return;
        
        this.showSystemMessage("SUBMITTING_THREAT_REPORT", "warning");
        
        const reportData = {
            url: this.currentTabData.url,
            title: this.currentTabData.title,
            timestamp: Date.now(),
            userAgent: navigator.userAgent
        };
        
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                action: 'reportPhishing',
                data: reportData
            });
        }
        
        // Add to threat log
        this.addThreatLogEntry('THREAT_REPORTED', `Manual report: ${new URL(this.currentTabData.url).hostname}`, 'warning');
        
        // Show confirmation
        setTimeout(() => {
            this.showSystemMessage("THREAT_REPORT_SUBMITTED", "success");
            this.showToast('Report Submitted', 'Threat data uploaded to neural network', 'success');
        }, 1000);
    }
    
    async whitelistSite() {
        if (!this.currentTabData) return;
        
        try {
            const url = new URL(this.currentTabData.url);
            const hostname = url.hostname;
            
            this.showSystemMessage("ADDING_TO_TRUSTED_MATRIX", "info");
            
            if (typeof chrome !== 'undefined' && chrome.runtime) {
                chrome.runtime.sendMessage({
                    action: 'whitelistDomain',
                    domain: hostname
                });
            }
            
            // Update local settings
            if (!this.settings.whitelist.includes(hostname)) {
                this.settings.whitelist.push(hostname);
                await this.saveSettings();
            }
            
            // Add to threat log
            this.addThreatLogEntry('WHITELIST_ADDED', `Trusted node: ${hostname}`, 'success');
            
            // Show confirmation and refresh analysis
            setTimeout(async () => {
                this.showSystemMessage("NODE_ADDED_TO_TRUSTED_MATRIX", "success");
                this.showToast('Site Whitelisted', `${hostname} added to trusted matrix`, 'success');
                await this.refreshAnalysis();
            }, 1000);
            
        } catch (error) {
            this.showSystemMessage("WHITELIST_ERROR", "error");
            this.showToast('Error', 'Unable to whitelist site', 'error');
        }
    }
    
    showConfigModal() {
        const modal = document.getElementById('settingsModal');
        if (modal) {
            modal.classList.add('show');
            this.loadConfigurationToModal();
        }
    }
    
    hideConfigModal() {
        const modal = document.getElementById('settingsModal');
        if (modal) {
            modal.classList.remove('show');
        }
    }
    
    loadConfigurationToModal() {
        // Load current settings into modal
        const realtimeToggle = document.getElementById('enableRealTime');
        const notificationsToggle = document.getElementById('enableNotifications');
        const autoBlockToggle = document.getElementById('enableAutoBlock');
        const protectionLevel = document.getElementById('protectionLevel');
        
        if (realtimeToggle) realtimeToggle.checked = this.settings.enableRealTime;
        if (notificationsToggle) notificationsToggle.checked = this.settings.enableNotifications;
        if (autoBlockToggle) autoBlockToggle.checked = this.settings.enableAutoBlock;
        if (protectionLevel) protectionLevel.value = this.settings.protectionLevel;
        
        // Load whitelist
        this.updateWhitelistDisplay();
    }
    
    updateWhitelistDisplay() {
        const trustedNodes = document.getElementById('trustedNodes');
        if (!trustedNodes) return;
        
        if (!this.settings.whitelist || this.settings.whitelist.length === 0) {
            trustedNodes.innerHTML = '<div class="nodes-empty">NO_TRUSTED_NODES_CONFIGURED</div>';
            return;
        }
        
        let html = '';
        this.settings.whitelist.forEach(domain => {
            html += `
                <div class="node-item">
                    <span class="node-domain">${domain}</span>
                    <button class="node-remove" onclick="cyberPopup.removeFromWhitelist('${domain}')">✕</button>
                </div>
            `;
        });
        
        trustedNodes.innerHTML = html;
    }
    
    async saveConfiguration() {
        const realtimeToggle = document.getElementById('enableRealTime');
        const notificationsToggle = document.getElementById('enableNotifications');
        const autoBlockToggle = document.getElementById('enableAutoBlock');
        const protectionLevel = document.getElementById('protectionLevel');
        
        const newSettings = {
            enableRealTime: realtimeToggle ? realtimeToggle.checked : this.settings.enableRealTime,
            enableNotifications: notificationsToggle ? notificationsToggle.checked : this.settings.enableNotifications,
            enableAutoBlock: autoBlockToggle ? autoBlockToggle.checked : this.settings.enableAutoBlock,
            protectionLevel: protectionLevel ? protectionLevel.value : this.settings.protectionLevel,
            whitelist: this.settings.whitelist
        };
        
        this.settings = newSettings;
        await this.saveSettings();
        
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                action: 'settingsUpdated',
                settings: newSettings
            });
        }
        
        this.hideConfigModal();
        this.showSystemMessage("CONFIGURATION_SAVED", "success");
        this.showToast('Settings Saved', 'Neural matrix configuration updated', 'success');
    }
    
    async resetConfiguration() {
        const defaultSettings = {
            enableRealTime: true,
            enableNotifications: true,
            enableAutoBlock: false,
            protectionLevel: 'medium',
            whitelist: []
        };
        
        this.settings = defaultSettings;
        await this.saveSettings();
        
        this.loadConfigurationToModal();
        this.showSystemMessage("CONFIGURATION_RESET", "info");
        this.showToast('Settings Reset', 'Configuration restored to defaults', 'success');
    }
    
    async addToWhitelist() {
        const input = document.getElementById('whitelistInput');
        if (!input || !input.value.trim()) return;
        
        const domain = input.value.trim().toLowerCase();
        
        // Basic domain validation
        if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(domain)) {
            this.showToast('Invalid Domain', 'Please enter a valid domain name', 'error');
            return;
        }
        
        if (this.settings.whitelist.includes(domain)) {
            this.showToast('Domain Exists', 'Domain already in trusted matrix', 'warning');
            return;
        }
        
        this.settings.whitelist.push(domain);
        await this.saveSettings();
        
        input.value = '';
        this.updateWhitelistDisplay();
        this.showToast('Node Added', `${domain} added to trusted matrix`, 'success');
    }
    
    async removeFromWhitelist(domain) {
        const index = this.settings.whitelist.indexOf(domain);
        if (index > -1) {
            this.settings.whitelist.splice(index, 1);
            await this.saveSettings();
            this.updateWhitelistDisplay();
            this.showToast('Node Removed', `${domain} removed from trusted matrix`, 'success');
        }
    }
    
    showAboutModal() {
        const modal = document.getElementById('aboutModal');
        if (modal) {
            modal.classList.add('show');
        }
    }
    
    hideAboutModal() {
        const modal = document.getElementById('aboutModal');
        if (modal) {
            modal.classList.remove('show');
        }
    }
    
    visitWebsite() {
        if (typeof chrome !== 'undefined' && chrome.tabs) {
            chrome.tabs.create({ url: 'https://phishguard-ai.com' });
        } else {
            window.open('https://phishguard-ai.com', '_blank');
        }
    }
    
    viewSourceCode() {
        if (typeof chrome !== 'undefined' && chrome.tabs) {
            chrome.tabs.create({ url: 'https://github.com/phishguard-ai/extension' });
        } else {
            window.open('https://github.com/phishguard-ai/extension', '_blank');
        }
    }
    
    showHelp() {
        if (typeof chrome !== 'undefined' && chrome.tabs) {
            chrome.tabs.create({ url: 'https://phishguard-ai.com/help' });
        } else {
            window.open('https://phishguard-ai.com/help', '_blank');
        }
    }
    
    clearThreatLog() {
        const logContent = document.getElementById('threatLogContent');
        if (logContent) {
            logContent.innerHTML = `
                <div class="log-entry system-entry">
                    <span class="log-time">[${this.getCurrentTime()}]</span>
                    <span class="log-level success">INFO</span>
                    <span class="log-message">THREAT_LOG_PURGED</span>
                </div>
            `;
        }
        this.showSystemMessage("THREAT_LOG_CLEARED", "info");
    }
    
    addThreatLogEntry(level, message, type = 'info') {
        const logContent = document.getElementById('threatLogContent');
        if (!logContent) return;
        
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `
            <span class="log-time">[${this.getCurrentTime()}]</span>
            <span class="log-level ${type}">${level}</span>
            <span class="log-message">${message}</span>
        `;
        
        logContent.appendChild(entry);
        
        // Keep only last 20 entries
        const entries = logContent.querySelectorAll('.log-entry');
        if (entries.length > 20) {
            entries[0].remove();
        }
        
        // Scroll to bottom
        logContent.scrollTop = logContent.scrollHeight;
    }
    
    showSystemMessage(message, type = 'info') {
        this.addThreatLogEntry(type.toUpperCase(), message, type);
    }
    
    showToast(title, message, type = 'info') {
        const toastContainer = document.getElementById('toastMatrix');
        if (!toastContainer) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const iconMap = {
            success: '✅',
            warning: '⚠️',
            error: '🚨',
            info: 'ℹ️'
        };
        
        toast.innerHTML = `
            <div class="toast-content">
                <div class="toast-icon">${iconMap[type] || iconMap.info}</div>
                <div class="toast-text">
                    <div class="toast-title">${title}</div>
                    <div class="toast-message">${message}</div>
                </div>
                <button class="toast-close" onclick="this.parentElement.parentElement.remove()">✕</button>
            </div>
        `;
        
        toastContainer.appendChild(toast);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    }
    
    getCurrentTime() {
        const now = new Date();
        return now.toTimeString().split(' ')[0];
    }
    
    async saveSettings() {
        return new Promise((resolve) => {
            if (typeof chrome !== 'undefined' && chrome.storage) {
                chrome.storage.sync.set(this.settings, resolve);
            } else {
                resolve();
            }
        });
    }
    
    startPeriodicUpdates() {
        // Update interface every 30 seconds
        setInterval(() => {
            if (this.isInitialized) {
                this.updateInterface();
            }
        }, 30000);
        
        // Update system time every second
        setInterval(() => {
            this.updateSystemTime();
        }, 1000);
    }
    
    updateSystemTime() {
        // Update any time displays
        const timeElements = document.querySelectorAll('.system-time');
        timeElements.forEach(el => {
            el.textContent = this.getCurrentTime();
        });
    }
    
    // Utility function to simulate typing effect
    typeText(element, text, speed = 50) {
        if (!element) return;
        
        element.textContent = '';
        let i = 0;
        
        const typeInterval = setInterval(() => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(typeInterval);
            }
        }, speed);
    }
    
    // Simulate glitch effect on elements
    glitchElement(element, duration = 1000) {
        if (!element) return;
        
        element.classList.add('glitch-effect');
        
        setTimeout(() => {
            element.classList.remove('glitch-effect');
        }, duration);
    }
    
    // Add pulsing effect to elements
    pulseElement(element, color = '#00ff41') {
        if (!element) return;
        
        const originalBoxShadow = element.style.boxShadow;
        
        element.style.transition = 'box-shadow 0.3s ease';
        element.style.boxShadow = `0 0 20px ${color}`;
        
        setTimeout(() => {
            element.style.boxShadow = originalBoxShadow;
        }, 300);
    }
    
    // Handle keyboard shortcuts
    handleKeyboardShortcuts(event) {
        // Ctrl/Cmd + R: Refresh analysis
        if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
            event.preventDefault();
            this.refreshAnalysis();
        }
        
        // Ctrl/Cmd + W: Whitelist current site
        if ((event.ctrlKey || event.metaKey) && event.key === 'w') {
            event.preventDefault();
            this.whitelistSite();
        }
        
        // Ctrl/Cmd + S: Open settings
        if ((event.ctrlKey || event.metaKey) && event.key === 's') {
            event.preventDefault();
            this.showConfigModal();
        }
        
        // Escape: Close modals
        if (event.key === 'Escape') {
            this.hideConfigModal();
            this.hideAboutModal();
        }
    }
    
    // Initialize drag and drop for whitelist
    initializeDragAndDrop() {
        const whitelistInput = document.getElementById('whitelistInput');
        if (!whitelistInput) return;
        
        whitelistInput.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        });
        
        whitelistInput.addEventListener('drop', (e) => {
            e.preventDefault();
            const data = e.dataTransfer.getData('text/plain');
            
            try {
                const url = new URL(data);
                whitelistInput.value = url.hostname;
            } catch {
                // If not a valid URL, use as-is
                whitelistInput.value = data;
            }
        });
    }
    
    // Handle window focus/blur events
    handleVisibilityChange() {
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                // Pause matrix animation when hidden
                if (this.matrixAnimation) {
                    clearInterval(this.matrixAnimation);
                }
            } else {
                // Resume matrix animation when visible
                this.startMatrixAnimation();
                // Refresh data when popup becomes visible again
                this.updateInterface();
            }
        });
    }
    
    // Clean up resources
    destroy() {
        if (this.matrixAnimation) {
            clearInterval(this.matrixAnimation);
        }
        
        // Remove event listeners
        document.removeEventListener('keydown', this.handleKeyboardShortcuts);
        window.removeEventListener('resize', this.resizeMatrixCanvas);
    }
}

// Additional CSS for dynamic effects (injected via JavaScript)
const additionalStyles = `
    .glitch-effect {
        animation: glitchShake 0.5s ease-in-out infinite !important;
    }
    
    @keyframes glitchShake {
        0%, 100% { transform: translate(0); }
        10% { transform: translate(-2px, 1px); }
        20% { transform: translate(2px, -1px); }
        30% { transform: translate(-1px, 2px); }
        40% { transform: translate(1px, -2px); }
        50% { transform: translate(-2px, -1px); }
        60% { transform: translate(2px, 1px); }
        70% { transform: translate(-1px, -2px); }
        80% { transform: translate(1px, 2px); }
        90% { transform: translate(-2px, -1px); }
    }
    
    .threat-status {
        padding: 8px 12px;
        border-radius: 4px;
        text-align: center;
        background: rgba(0, 20, 0, 0.6);
        border: 1px solid rgba(0, 255, 65, 0.3);
    }
    
    .threat-status.safe {
        background: rgba(0, 40, 0, 0.6);
        border-color: #00ff41;
    }
    
    .threat-status.warning {
        background: rgba(40, 40, 0, 0.6);
        border-color: #ffff00;
    }
    
    .threat-status.danger {
        background: rgba(40, 0, 0, 0.6);
        border-color: #ff0040;
        animation: dangerBlink 1s ease-in-out infinite;
    }
    
    @keyframes dangerBlink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }
    
    .status-text {
        font-family: 'Orbitron', monospace;
        font-size: 10px;
        font-weight: 600;
        color: #00ff41;
        text-shadow: 0 0 5px #00ff41;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 4px;
    }
    
    .status-detail {
        font-size: 8px;
        color: #00d4ff;
        text-shadow: 0 0 3px #00d4ff;
    }
    
    .threat-status.warning .status-text {
        color: #ffff00;
        text-shadow: 0 0 5px #ffff00;
    }
    
    .threat-status.danger .status-text {
        color: #ff0040;
        text-shadow: 0 0 5px #ff0040;
    }
    
    .vuln-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 4px 8px;
        margin-bottom: 4px;
        background: rgba(255, 255, 0, 0.1);
        border: 1px solid rgba(255, 255, 0, 0.3);
        border-radius: 3px;
        font-size: 8px;
        animation: vulnAppear 0.5s ease-in-out forwards;
        opacity: 0;
        transform: translateX(-20px);
    }
    
    @keyframes vulnAppear {
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    .vuln-id {
        color: #ff0040;
        text-shadow: 0 0 3px #ff0040;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        min-width: 60px;
    }
    
    .vuln-desc {
        color: #ffff00;
        text-shadow: 0 0 3px #ffff00;
        flex: 1;
    }
`;

// Inject additional styles
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);

// Initialize the cyber popup controller
let cyberPopup;

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        cyberPopup = new CyberPopupController();
        
        // Add keyboard shortcuts
        document.addEventListener('keydown', (e) => cyberPopup.handleKeyboardShortcuts(e));
        
        // Handle visibility changes
        cyberPopup.handleVisibilityChange();
        
        // Initialize drag and drop
        cyberPopup.initializeDragAndDrop();
    });
} else {
    cyberPopup = new CyberPopupController();
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => cyberPopup.handleKeyboardShortcuts(e));
    
    // Handle visibility changes
    cyberPopup.handleVisibilityChange();
    
    // Initialize drag and drop
    cyberPopup.initializeDragAndDrop();
}

// Global cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (cyberPopup) {
        cyberPopup.destroy();
    }
});

// Expose for debugging in development
if (typeof window !== 'undefined') {
    window.cyberPopup = cyberPopup;
}
