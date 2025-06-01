/**
 * PhishGuard AI Content Script - Core Detection Engine
 * Analyzes web pages in real-time for phishing indicators
 * File: extension/content/content.js
 */

class PhishGuardDetector {
    constructor() {
        this.isInitialized = false;
        this.currentUrl = window.location.href;
        this.riskScore = 0;
        this.detectedThreats = [];
        this.analysisStartTime = Date.now();
        this.settings = {
            enableRealTime: true,
            protectionLevel: 'medium',
            enableAutoBlock: false
        };
        
        // Feature weights for scoring
        this.featureWeights = {
            hasIPAddress: 30,
            suspiciousTLD: 25,
            noHTTPS: 20,
            hasPhishingKeywords: 15,
            brandImpersonation: 35,
            externalForms: 40,
            suspiciousLength: 10,
            newDomain: 25,
            hiddenContent: 15
        };
        
        this.init();
    }
    
    async init() {
        try {
            // Skip analysis for chrome:// pages and extensions
            if (this.shouldSkipAnalysis()) {
                return;
            }
            
            await this.loadSettings();
            
            if (this.settings.enableRealTime) {
                await this.analyzePage();
            }
            
            this.isInitialized = true;
            console.log('PhishGuard AI: Analysis complete in', Date.now() - this.analysisStartTime, 'ms');
            
        } catch (error) {
            console.error('PhishGuard AI initialization failed:', error);
        }
    }
    
    shouldSkipAnalysis() {
        const url = window.location.href;
        const skipPatterns = [
            /^chrome:/,
            /^chrome-extension:/,
            /^moz-extension:/,
            /^about:/,
            /^file:/,
            /^data:/
        ];
        
        return skipPatterns.some(pattern => pattern.test(url));
    }
    
    async loadSettings() {
        return new Promise((resolve) => {
            if (typeof chrome !== 'undefined' && chrome.storage) {
                chrome.storage.sync.get({
                    enableRealTime: true,
                    protectionLevel: 'medium',
                    enableAutoBlock: false,
                    whitelist: []
                }, (settings) => {
                    this.settings = settings;
                    resolve();
                });
            } else {
                resolve();
            }
        });
    }
    
    async analyzePage() {
        try {
            // Check if site is whitelisted
            if (this.isWhitelisted()) {
                this.sendAnalysisResult({
                    url: this.currentUrl,
                    riskScore: 0,
                    threatLevel: 'safe',
                    threats: [],
                    reason: 'Whitelisted domain',
                    timestamp: Date.now()
                });
                return;
            }
            
            // Extract features and calculate risk
            const features = this.extractAllFeatures();
            this.riskScore = this.calculateRiskScore(features);
            
            // Determine threat level
            const threatLevel = this.determineThreatLevel(this.riskScore);
            
            // Send results to background script
            const analysisResult = {
                url: this.currentUrl,
                riskScore: this.riskScore,
                threatLevel: threatLevel,
                threats: this.detectedThreats,
                features: features,
                timestamp: Date.now()
            };
            
            this.sendAnalysisResult(analysisResult);
            
            // Take protective action if needed
            if (threatLevel === 'dangerous') {
                this.handleDangerousThreat();
            } else if (threatLevel === 'suspicious') {
                this.handleSuspiciousThreat();
            }
            
        } catch (error) {
            console.error('PhishGuard AI: Analysis failed', error);
        }
    }
    
    isWhitelisted() {
        if (!this.settings.whitelist) return false;
        
        try {
            const hostname = new URL(this.currentUrl).hostname.toLowerCase();
            return this.settings.whitelist.some(domain => 
                hostname === domain || hostname.endsWith('.' + domain)
            );
        } catch {
            return false;
        }
    }
    
    extractAllFeatures() {
        const features = {};
        
        // URL-based features
        Object.assign(features, this.extractUrlFeatures());
        
        // Domain-based features
        Object.assign(features, this.extractDomainFeatures());
        
        // Content-based features
        Object.assign(features, this.extractContentFeatures());
        
        // Form-based features
        Object.assign(features, this.extractFormFeatures());
        
        // Technical features
        Object.assign(features, this.extractTechnicalFeatures());
        
        return features;
    }
    
    extractUrlFeatures() {
        const features = {};
        
        try {
            const url = new URL(this.currentUrl);
            const fullUrl = this.currentUrl.toLowerCase();
            
            // Basic URL metrics
            features.urlLength = this.currentUrl.length;
            features.domainLength = url.hostname.length;
            features.pathLength = url.pathname.length;
            features.queryLength = url.search.length;
            
            // IP address detection
            features.hasIPAddress = this.isIPAddress(url.hostname);
            if (features.hasIPAddress) {
                this.addThreat('URL uses IP address instead of domain name', 'high');
            }
            
            // HTTPS check
            features.usesHTTPS = url.protocol === 'https:';
            if (!features.usesHTTPS) {
                this.addThreat('Website does not use secure HTTPS connection', 'medium');
            }
            
            // Suspicious TLD check
            features.suspiciousTLD = this.hasSuspiciousTLD(url.hostname);
            if (features.suspiciousTLD) {
                this.addThreat('Uses suspicious top-level domain (.tk, .ml, .ga, etc.)', 'high');
            }
            
            // URL length analysis
            features.unusuallyLong = this.currentUrl.length > 100;
            if (features.unusuallyLong) {
                this.addThreat('Unusually long URL designed to hide suspicious elements', 'low');
            }
            
            // Subdomain analysis
            const subdomains = url.hostname.split('.').length - 2;
            features.excessiveSubdomains = subdomains > 2;
            if (features.excessiveSubdomains) {
                this.addThreat('Excessive subdomains used to appear legitimate', 'medium');
            }
            
            // Phishing keywords in URL
            features.hasPhishingKeywords = this.containsPhishingKeywords(fullUrl);
            if (features.hasPhishingKeywords) {
                this.addThreat('URL contains phishing-related keywords', 'medium');
            }
            
            // Brand impersonation
            features.brandImpersonation = this.checkBrandImpersonation(fullUrl, url.hostname);
            if (features.brandImpersonation) {
                this.addThreat('Potential brand impersonation detected', 'high');
            }
            
            // URL obfuscation
            features.urlEncoded = (this.currentUrl.match(/%[0-9a-f]{2}/gi) || []).length > 3;
            if (features.urlEncoded) {
                this.addThreat('URL contains excessive encoding (potential obfuscation)', 'medium');
            }
            
            // Suspicious characters
            features.hasAtSymbol = this.currentUrl.includes('@');
            if (features.hasAtSymbol) {
                this.addThreat('URL contains @ symbol (potential redirect)', 'medium');
            }
            
        } catch (error) {
            console.error('URL feature extraction failed:', error);
        }
        
        return features;
    }
    
    extractDomainFeatures() {
        const features = {};
        
        try {
            const url = new URL(this.currentUrl);
            const hostname = url.hostname.toLowerCase();
            
            // Domain characteristics
            features.domainHasNumbers = /\d/.test(hostname);
            features.domainHasHyphens = hostname.includes('-');
            features.domainMixtureAlphaNum = /\d/.test(hostname) && /[a-z]/.test(hostname);
            
            // Port analysis
            features.hasNonStandardPort = url.port && !['80', '443', ''].includes(url.port);
            if (features.hasNonStandardPort) {
                this.addThreat('Uses non-standard port number', 'low');
            }
            
            // Known malicious patterns
            features.knownMaliciousPattern = this.checkMaliciousPatterns(hostname);
            if (features.knownMaliciousPattern) {
                this.addThreat('Domain matches known malicious patterns', 'high');
            }
            
        } catch (error) {
            console.error('Domain feature extraction failed:', error);
        }
        
        return features;
    }
    
    extractContentFeatures() {
        const features = {};
        
        try {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                return features;
            }
            
            const pageText = document.body ? document.body.innerText.toLowerCase() : '';
            const pageHTML = document.documentElement.outerHTML.toLowerCase();
            
            // Content analysis
            features.textLength = pageText.length;
            features.htmlLength = pageHTML.length;
            
            // Title analysis
            const title = document.title || '';
            features.titleLength = title.length;
            features.titleHasPhishingKeywords = this.containsPhishingKeywords(title.toLowerCase());
            
            // Phishing keywords in content
            const phishingKeywordCount = this.countPhishingKeywords(pageText);
            features.phishingKeywordDensity = phishingKeywordCount / Math.max(pageText.split(' ').length, 1);
            
            if (phishingKeywordCount > 3) {
                this.addThreat(`High concentration of phishing keywords (${phishingKeywordCount} found)`, 'medium');
            }
            
            // Urgency indicators
            const urgencyWords = ['urgent', 'immediate', 'expires', 'suspended', 'verify now', 'act now', 'limited time'];
            features.urgencyWordCount = urgencyWords.filter(word => pageText.includes(word)).length;
            
            if (features.urgencyWordCount > 2) {
                this.addThreat('Contains urgent language designed to pressure users', 'medium');
            }
            
            // Brand mentions
            features.brandMentions = this.countBrandMentions(pageText);
            if (features.brandMentions > 0 && !this.isLegitimateService()) {
                this.addThreat('Mentions major brands but hosted on suspicious domain', 'high');
            }
            
            // Copyright and legal text
            features.hasCopyright = pageText.includes('copyright') || pageText.includes('©');
            features.hasPrivacyPolicy = pageText.includes('privacy policy');
            features.hasTermsOfService = pageText.includes('terms of service');
            
            // Language quality indicators
            features.hasTypos = this.detectCommonTypos(pageText);
            if (features.hasTypos) {
                this.addThreat('Poor spelling/grammar indicating fake content', 'low');
            }
            
        } catch (error) {
            console.error('Content feature extraction failed:', error);
        }
        
        return features;
    }
    
    extractFormFeatures() {
        const features = {};
        
        try {
            const forms = document.querySelectorAll('form');
            const inputs = document.querySelectorAll('input');
            
            features.formCount = forms.length;
            features.inputCount = inputs.length;
            
            // Password field detection
            features.hasPasswordField = document.querySelector('input[type="password"]') !== null;
            
            // Email/username fields
            features.hasEmailField = Array.from(inputs).some(input => 
                input.type === 'email' || 
                input.name.toLowerCase().includes('email') ||
                input.name.toLowerCase().includes('username')
            );
            
            // Credit card fields
            features.hasCreditCardField = Array.from(inputs).some(input =>
                input.name.toLowerCase().includes('card') ||
                input.name.toLowerCase().includes('credit') ||
                input.placeholder.toLowerCase().includes('card number')
            );
            
            // Hidden fields
            features.hiddenFieldCount = document.querySelectorAll('input[type="hidden"]').length;
            
            // External form actions
            features.externalFormCount = 0;
            const currentDomain = window.location.hostname;
            
            forms.forEach(form => {
                const action = form.getAttribute('action');
                if (action && action.startsWith('http') && !action.includes(currentDomain)) {
                    features.externalFormCount++;
                }
            });
            
            if (features.externalFormCount > 0) {
                this.addThreat('Forms submit data to external domains', 'high');
            }
            
            // Login form on non-HTTPS
            if (features.hasPasswordField && !window.location.href.startsWith('https://')) {
                this.addThreat('Password field on non-secure HTTP page', 'high');
            }
            
            // Suspicious form combinations
            if (features.hasPasswordField && features.hasCreditCardField) {
                this.addThreat('Both login and payment forms present (unusual combination)', 'medium');
            }
            
        } catch (error) {
            console.error('Form feature extraction failed:', error);
        }
        
        return features;
    }
    
    extractTechnicalFeatures() {
        const features = {};
        
        try {
            // Iframe analysis
            const iframes = document.querySelectorAll('iframe');
            features.iframeCount = iframes.length;
            features.hiddenIframeCount = Array.from(iframes).filter(iframe => 
                iframe.style.display === 'none' || 
                iframe.style.visibility === 'hidden' ||
                iframe.width === '0' || 
                iframe.height === '0'
            ).length;
            
            if (features.hiddenIframeCount > 0) {
                this.addThreat('Hidden iframes detected (potential malicious content)', 'medium');
            }
            
            // External resources
            const scripts = document.querySelectorAll('script[src]');
            const links = document.querySelectorAll('link[href]');
            const images = document.querySelectorAll('img[src]');
            
            const currentDomain = window.location.hostname;
            features.externalScriptCount = Array.from(scripts).filter(script => 
                script.src && !script.src.includes(currentDomain)
            ).length;
            
            features.externalLinkCount = Array.from(links).filter(link => 
                link.href && !link.href.includes(currentDomain)
            ).length;
            
            // Meta refresh
            const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
            features.hasMetaRefresh = metaRefresh !== null;
            if (features.hasMetaRefresh) {
                this.addThreat('Page uses meta refresh (potential redirect)', 'low');
            }
            
            // Favicon analysis
            features.hasFavicon = document.querySelector('link[rel*="icon"]') !== null;
            
            // Right-click disable attempt
            features.rightClickDisabled = document.oncontextmenu === null || 
                                        typeof document.oncontextmenu === 'function';
            
            // Status bar text manipulation
            features.statusBarManipulation = Array.from(document.querySelectorAll('a')).some(link => 
                link.onmouseover || link.onmouseout
            );
            
        } catch (error) {
            console.error('Technical feature extraction failed:', error);
        }
        
        return features;
    }
    
    calculateRiskScore(features) {
        let score = 0;
        
        // URL-based scoring
        if (features.hasIPAddress) score += this.featureWeights.hasIPAddress;
        if (features.suspiciousTLD) score += this.featureWeights.suspiciousTLD;
        if (!features.usesHTTPS) score += this.featureWeights.noHTTPS;
        if (features.hasPhishingKeywords) score += this.featureWeights.hasPhishingKeywords;
        if (features.brandImpersonation) score += this.featureWeights.brandImpersonation;
        if (features.externalFormCount > 0) score += this.featureWeights.externalForms;
        if (features.unusuallyLong) score += this.featureWeights.suspiciousLength;
        
        // Content-based scoring
        if (features.urgencyWordCount > 2) score += 15;
        if (features.phishingKeywordDensity > 0.01) score += 10;
        if (features.brandMentions > 0 && !this.isLegitimateService()) score += 20;
        
        // Technical scoring
        if (features.hiddenIframeCount > 0) score += 15;
        if (features.externalFormCount > 0) score += 25;
        if (features.hasPasswordField && !features.usesHTTPS) score += 30;
        
        // Form-based scoring
        if (features.hasPasswordField && features.hasCreditCardField) score += 15;
        
        // Apply protection level multiplier
        const multipliers = {
            'low': 0.7,
            'medium': 1.0,
            'high': 1.3
        };
        
        score *= multipliers[this.settings.protectionLevel] || 1.0;
        
        return Math.min(Math.round(score), 100);
    }
    
    determineThreatLevel(riskScore) {
        if (riskScore >= 70) return 'dangerous';
        if (riskScore >= 40) return 'suspicious';
        return 'safe';
    }
    
    // Helper methods
    isIPAddress(hostname) {
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        return ipPattern.test(hostname);
    }
    
    hasSuspiciousTLD(hostname) {
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.work'];
        return suspiciousTLDs.some(tld => hostname.endsWith(tld));
    }
    
    containsPhishingKeywords(text) {
        const keywords = [
            'verify', 'suspend', 'security', 'alert', 'confirm', 'update',
            'action', 'required', 'immediate', 'expires', 'limited', 'urgent'
        ];
        return keywords.some(keyword => text.includes(keyword));
    }
    
    countPhishingKeywords(text) {
        const keywords = [
            'verify account', 'suspended', 'security alert', 'confirm identity',
            'unusual activity', 'immediate action', 'expires soon', 'limited time'
        ];
        return keywords.filter(keyword => text.includes(keyword)).length;
    }
    
    checkBrandImpersonation(url, hostname) {
        const majorBrands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'twitter'];
        
        for (const brand of majorBrands) {
            if (url.includes(brand) && !this.isLegitimateService(brand)) {
                return true;
            }
        }
        return false;
    }
    
    isLegitimateService(brand = null) {
        const hostname = window.location.hostname.toLowerCase();
        const legitDomains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'facebook.com', 'twitter.com', 'github.com'
        ];
        
        if (brand) {
            return hostname.endsWith(`${brand}.com`);
        }
        
        return legitDomains.some(domain => hostname.endsWith(domain));
    }
    
    countBrandMentions(text) {
        const brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook'];
        return brands.filter(brand => text.includes(brand)).length;
    }
    
    detectCommonTypos(text) {
        const typos = ['recieve', 'seperate', 'occured', 'necesary', 'accomodate'];
        return typos.some(typo => text.includes(typo));
    }
    
    checkMaliciousPatterns(hostname) {
        const patterns = [
            /.*-security\..*/, /.*-verify\..*/, /.*-update\..*/, /.*-alert\..*/
        ];
        return patterns.some(pattern => pattern.test(hostname));
    }
    
    addThreat(description, severity = 'medium') {
        this.detectedThreats.push({
            description,
            severity,
            timestamp: Date.now()
        });
    }
    
    sendAnalysisResult(result) {
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                action: 'analysisComplete',
                data: result
            });
        }
    }
    
    handleDangerousThreat() {
        if (this.settings.enableAutoBlock) {
            this.blockPage();
        } else {
            this.showWarning();
        }
    }
    
    handleSuspiciousThreat() {
        this.showCaution();
    }
    
    showWarning() {
        // Create full-page warning overlay
        const overlay = this.createWarningOverlay();
        document.body.appendChild(overlay);
        
        // Send notification
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                action: 'showNotification',
                data: {
                    type: 'danger',
                    title: 'Phishing Threat Detected',
                    message: `Dangerous website blocked: ${window.location.hostname}`
                }
            });
        }
    }
    
    showCaution() {
        // Create warning banner
        const banner = this.createCautionBanner();
        document.body.insertBefore(banner, document.body.firstChild);
        document.body.style.paddingTop = '60px';
    }
    
    createWarningOverlay() {
        const overlay = document.createElement('div');
        overlay.id = 'phishguard-warning-overlay';
        overlay.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(244, 67, 54, 0.95);
                z-index: 999999;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            ">
                <div style="
                    background: white;
                    padding: 40px;
                    border-radius: 12px;
                    max-width: 500px;
                    text-align: center;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                ">
                    <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
                    <h2 style="color: #d32f2f; margin-bottom: 16px; font-size: 24px;">Phishing Threat Detected</h2>
                    <p style="margin-bottom: 20px; line-height: 1.6; color: #333;">
                        PhishGuard AI has detected this website as potentially dangerous. 
                        It may be attempting to steal your personal information or login credentials.
                    </p>
                    <div style="margin-bottom: 24px; padding: 16px; background: #ffebee; border-radius: 8px;">
                        <strong style="color: #d32f2f;">Risk Score: ${this.riskScore}/100</strong><br>
                        <small style="color: #666;">Threats detected: ${this.detectedThreats.length}</small>
                    </div>
                    <div style="margin-bottom: 24px;">
                        <strong>Detected Threats:</strong>
                        <ul style="text-align: left; margin-top: 8px; color: #666;">
                            ${this.detectedThreats.slice(0, 5).map(threat => 
                                `<li style="margin-bottom: 4px;">${threat.description}</li>`
                            ).join('')}
                        </ul>
                    </div>
                    <button onclick="window.history.back()" style="
                        background: #d32f2f;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 6px;
                        cursor: pointer;
                        margin-right: 12px;
                        font-size: 16px;
                        font-weight: 500;
                    ">Go Back to Safety</button>
                    <button onclick="document.getElementById('phishguard-warning-overlay').remove()" style="
                        background: #666;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 16px;
                    ">Proceed Anyway (Not Recommended)</button>
                </div>
            </div>
        `;
        
        return overlay;
    }
    
    createCautionBanner() {
        const banner = document.createElement('div');
        banner.id = 'phishguard-caution-banner';
        banner.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                background: linear-gradient(135deg, #ff9800, #f57c00);
                color: white;
                padding: 16px;
                text-align: center;
                z-index: 999998;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                font-size: 14px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            ">
                <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: center; gap: 16px;">
                    <span style="font-size: 20px;">⚠️</span>
                    <span>
                        <strong>PhishGuard AI Warning:</strong> This website shows suspicious characteristics (Risk: ${this.riskScore}/100). 
                        Exercise caution when entering personal information.
                    </span>
                    <button onclick="document.getElementById('phishguard-caution-banner').remove(); document.body.style.paddingTop = '0'" style="
                        background: rgba(255,255,255,0.2);
                        border: 1px solid rgba(255,255,255,0.3);
                        color: white;
                        padding: 6px 12px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 12px;
                    ">Dismiss</button>
                </div>
            </div>
        `;
        
        return banner;
    }
    
    blockPage() {
        // Prevent page from loading further
        if (document.readyState === 'loading') {
            window.stop();
        }
        
        // Clear page content
        document.documentElement.innerHTML = `
            <html><head><title>Site Blocked by PhishGuard AI</title></head>
            <body style="margin:0;padding:40px;font-family:Arial,sans-serif;background:#f44336;color:white;text-align:center;">
                <h1>🛡️ Site Blocked</h1>
                <p>This website has been automatically blocked by PhishGuard AI due to high phishing risk.</p>
                <button onclick="history.back()" style="background:white;color:#f44336;border:none;padding:12px 24px;border-radius:6px;cursor:pointer;">Go Back</button>
            </body></html>
        `;
    }
}

// Initialize detector when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishGuardDetector();
    });
} else {
    new PhishGuardDetector();
}

// Handle navigation changes (for SPAs)
let lastUrl = location.href;
new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrl) {
        lastUrl = url;
        setTimeout(() => new PhishGuardDetector(), 1000);
    }
}).observe(document, { subtree: true, childList: true });
