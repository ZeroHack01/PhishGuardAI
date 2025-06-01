/**
 * PhishGuard AI - Advanced DOM Inspector
 * File: extension/content/dom-inspector.js
 * 
 * Real-time DOM analysis for phishing detection
 * Monitors page content, forms, and behavioral patterns
 */

class DOMInspector {
    constructor() {
        this.observers = [];
        this.analysisResults = {};
        this.securityMetrics = {
            suspiciousElements: 0,
            hiddenForms: 0,
            externalResources: 0,
            jsObfuscation: 0,
            socialEngineering: 0
        };
        
        // Configuration
        this.config = {
            enableRealTimeMonitoring: true,
            deepContentAnalysis: true,
            behavioralAnalysis: true,
            performanceMode: 'balanced' // fast, balanced, thorough
        };
        
        // Phishing indicators database
        this.phishingIndicators = {
            suspiciousText: [
                'verify your account', 'suspended account', 'unusual activity',
                'click here immediately', 'confirm your identity', 'update payment',
                'security alert', 'account locked', 'act now', 'limited time',
                'winner selected', 'congratulations', 'free gift', 'no cost'
            ],
            urgencyWords: [
                'urgent', 'immediate', 'expires', 'deadline', 'hurry', 'quick',
                'fast', 'now', 'today', 'asap', 'emergency', 'critical'
            ],
            authoritativeTerms: [
                'bank', 'government', 'irs', 'fbi', 'police', 'legal',
                'court', 'official', 'security team', 'support team'
            ],
            brandNames: [
                'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
                'twitter', 'instagram', 'netflix', 'spotify', 'adobe'
            ]
        };
        
        console.log('🔍 DOM Inspector initialized');
        this.initializeInspection();
    }

    /**
     * Initialize DOM inspection and monitoring
     */
    async initializeInspection() {
        try {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.startInspection());
            } else {
                this.startInspection();
            }
            
            // Monitor dynamic content changes
            this.setupMutationObserver();
            
            // Monitor user interactions
            this.setupBehavioralMonitoring();
            
            // Periodic security checks
            this.setupPeriodicChecks();
            
        } catch (error) {
            console.error('❌ DOM Inspector initialization failed:', error);
        }
    }

    /**
     * Start comprehensive DOM inspection
     */
    async startInspection() {
        console.log('🔍 Starting DOM inspection...');
        
        const startTime = performance.now();
        
        try {
            // Comprehensive analysis
            const analysisPromises = [
                this.analyzePageStructure(),
                this.analyzeForms(),
                this.analyzeLinks(),
                this.analyzeImages(),
                this.analyzeScripts(),
                this.analyzeTextContent(),
                this.analyzeMetadata(),
                this.analyzeStyles()
            ];
            
            const results = await Promise.allSettled(analysisPromises);
            
            // Aggregate results
            this.analysisResults = this.aggregateAnalysis(results);
            
            // Calculate overall risk score
            const riskScore = this.calculateRiskScore();
            
            // Send results to background script
            await this.reportAnalysis({
                ...this.analysisResults,
                riskScore,
                analysisTime: performance.now() - startTime,
                url: window.location.href,
                timestamp: Date.now()
            });
            
            console.log(`✅ DOM inspection complete - Risk: ${riskScore}/100`);
            
        } catch (error) {
            console.error('❌ DOM inspection failed:', error);
        }
    }

    /**
     * Analyze overall page structure
     */
    async analyzePageStructure() {
        const analysis = {
            title: document.title,
            domain: window.location.hostname,
            protocol: window.location.protocol,
            hasSSL: window.location.protocol === 'https:',
            elementCount: document.querySelectorAll('*').length,
            textContent: document.body ? document.body.innerText.length : 0,
            suspiciousStructure: false
        };
        
        // Check for suspicious page structure
        const suspiciousIndicators = [];
        
        // Very minimal content
        if (analysis.textContent < 100) {
            suspiciousIndicators.push('Minimal content');
            analysis.suspiciousStructure = true;
        }
        
        // Missing standard elements
        if (!document.querySelector('footer') && !document.querySelector('nav')) {
            suspiciousIndicators.push('Missing standard navigation elements');
        }
        
        // Excessive redirects or meta refreshes
        const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
        if (metaRefresh) {
            suspiciousIndicators.push('Auto-redirect detected');
            analysis.suspiciousStructure = true;
        }
        
        // Hidden iframes
        const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"]');
        if (hiddenIframes.length > 0) {
            suspiciousIndicators.push(`${hiddenIframes.length} hidden iframes detected`);
            analysis.suspiciousStructure = true;
        }
        
        analysis.suspiciousIndicators = suspiciousIndicators;
        
        return { source: 'page_structure', ...analysis };
    }

    /**
     * Analyze forms for credential harvesting
     */
    async analyzeForms() {
        const forms = document.querySelectorAll('form');
        const analysis = {
            formCount: forms.length,
            suspiciousForms: [],
            credentialForms: 0,
            externalForms: 0,
            hiddenForms: 0
        };
        
        forms.forEach((form, index) => {
            const formAnalysis = {
                index,
                action: form.action,
                method: form.method,
                isExternal: false,
                isHidden: false,
                hasPassword: false,
                hasEmail: false,
                hasCredit: false,
                suspiciousFields: []
            };
            
            // Check if form submits to external domain
            if (form.action && !form.action.includes(window.location.hostname)) {
                formAnalysis.isExternal = true;
                analysis.externalForms++;
            }
            
            // Check if form is hidden
            const style = window.getComputedStyle(form);
            if (style.display === 'none' || style.visibility === 'hidden') {
                formAnalysis.isHidden = true;
                analysis.hiddenForms++;
            }
            
            // Analyze form fields
            const inputs = form.querySelectorAll('input, select, textarea');
            inputs.forEach(input => {
                const type = input.type?.toLowerCase();
                const name = input.name?.toLowerCase() || '';
                const id = input.id?.toLowerCase() || '';
                const placeholder = input.placeholder?.toLowerCase() || '';
                
                // Password fields
                if (type === 'password') {
                    formAnalysis.hasPassword = true;
                    analysis.credentialForms++;
                }
                
                // Email fields
                if (type === 'email' || name.includes('email') || id.includes('email')) {
                    formAnalysis.hasEmail = true;
                }
                
                // Credit card fields
                if (name.includes('card') || name.includes('cvv') || name.includes('expir') ||
                    placeholder.includes('card') || placeholder.includes('cvv')) {
                    formAnalysis.hasCredit = true;
                    formAnalysis.suspiciousFields.push('Credit card information');
                }
                
                // Social security or sensitive data
                if (name.includes('ssn') || name.includes('social') || 
                    placeholder.includes('social security')) {
                    formAnalysis.suspiciousFields.push('Social security number');
                }
            });
            
            // Flag suspicious forms
            if (formAnalysis.isExternal || formAnalysis.isHidden || 
                (formAnalysis.hasPassword && formAnalysis.hasEmail)) {
                analysis.suspiciousForms.push(formAnalysis);
            }
        });
        
        return { source: 'forms', ...analysis };
    }

    /**
     * Analyze links for suspicious destinations
     */
    async analyzeLinks() {
        const links = document.querySelectorAll('a[href]');
        const analysis = {
            linkCount: links.length,
            externalLinks: 0,
            suspiciousLinks: [],
            shortenerLinks: 0,
            javascriptLinks: 0
        };
        
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'tiny.cc'];
        
        links.forEach((link, index) => {
            const href = link.href;
            const text = link.textContent.trim();
            
            try {
                const url = new URL(href);
                
                // External links
                if (url.hostname !== window.location.hostname) {
                    analysis.externalLinks++;
                    
                    // URL shorteners
                    if (shorteners.includes(url.hostname)) {
                        analysis.shortenerLinks++;
                        analysis.suspiciousLinks.push({
                            index,
                            href,
                            text,
                            reason: 'URL shortener'
                        });
                    }
                }
                
                // JavaScript links
                if (href.startsWith('javascript:')) {
                    analysis.javascriptLinks++;
                    analysis.suspiciousLinks.push({
                        index,
                        href,
                        text,
                        reason: 'JavaScript execution'
                    });
                }
                
                // Mismatched text and URL
                if (text && text.includes('http') && !href.includes(text)) {
                    analysis.suspiciousLinks.push({
                        index,
                        href,
                        text,
                        reason: 'Mismatched link text and destination'
                    });
                }
                
            } catch (error) {
                // Invalid URL
                analysis.suspiciousLinks.push({
                    index,
                    href,
                    text,
                    reason: 'Invalid URL format'
                });
            }
        });
        
        return { source: 'links', ...analysis };
    }

    /**
     * Analyze images for logo spoofing
     */
    async analyzeImages() {
        const images = document.querySelectorAll('img');
        const analysis = {
            imageCount: images.length,
            externalImages: 0,
            suspiciousImages: [],
            logoSpoof: false
        };
        
        images.forEach((img, index) => {
            const src = img.src;
            const alt = img.alt?.toLowerCase() || '';
            
            if (src) {
                try {
                    const url = new URL(src);
                    
                    // External images
                    if (url.hostname !== window.location.hostname) {
                        analysis.externalImages++;
                    }
                    
                    // Potential logo spoofing
                    this.phishingIndicators.brandNames.forEach(brand => {
                        if (alt.includes(brand) || src.toLowerCase().includes(brand)) {
                            analysis.suspiciousImages.push({
                                index,
                                src,
                                alt,
                                reason: `Potential ${brand} logo spoofing`
                            });
                            analysis.logoSpoof = true;
                        }
                    });
                    
                } catch (error) {
                    // Invalid image URL
                    analysis.suspiciousImages.push({
                        index,
                        src,
                        reason: 'Invalid image URL'
                    });
                }
            }
        });
        
        return { source: 'images', ...analysis };
    }

    /**
     * Analyze JavaScript for obfuscation and malicious patterns
     */
    async analyzeScripts() {
        const scripts = document.querySelectorAll('script');
        const analysis = {
            scriptCount: scripts.length,
            inlineScripts: 0,
            externalScripts: 0,
            obfuscatedScripts: 0,
            suspiciousPatterns: []
        };
        
        const obfuscationPatterns = [
            /eval\s*\(/i,
            /document\.write\s*\(/i,
            /fromCharCode/i,
            /\\x[0-9a-f]{2}/i,
            /\\u[0-9a-f]{4}/i
        ];
        
        scripts.forEach((script, index) => {
            if (script.src) {
                analysis.externalScripts++;
                
                // Check external script domains
                try {
                    const url = new URL(script.src);
                    if (url.hostname !== window.location.hostname) {
                        analysis.suspiciousPatterns.push(`External script from ${url.hostname}`);
                    }
                } catch (error) {
                    analysis.suspiciousPatterns.push('Invalid script URL');
                }
            } else if (script.textContent) {
                analysis.inlineScripts++;
                
                const content = script.textContent;
                
                // Check for obfuscation patterns
                obfuscationPatterns.forEach(pattern => {
                    if (pattern.test(content)) {
                        analysis.obfuscatedScripts++;
                        analysis.suspiciousPatterns.push('Code obfuscation detected');
                    }
                });
                
                // Check for suspicious functions
                if (content.includes('btoa') || content.includes('atob')) {
                    analysis.suspiciousPatterns.push('Base64 encoding/decoding');
                }
                
                if (content.includes('XMLHttpRequest') || content.includes('fetch')) {
                    analysis.suspiciousPatterns.push('Network requests in script');
                }
            }
        });
        
        return { source: 'scripts', ...analysis };
    }

    /**
     * Analyze text content for social engineering
     */
    async analyzeTextContent() {
        const textContent = document.body ? document.body.innerText.toLowerCase() : '';
        const analysis = {
            textLength: textContent.length,
            suspiciousPhrasesFound: [],
            urgencyIndicators: 0,
            authorityAppeals: 0,
            brandMentions: [],
            socialEngineering: false
        };
        
        // Check for suspicious phrases
        this.phishingIndicators.suspiciousText.forEach(phrase => {
            if (textContent.includes(phrase.toLowerCase())) {
                analysis.suspiciousPhrasesFound.push(phrase);
                analysis.socialEngineering = true;
            }
        });
        
        // Count urgency words
        this.phishingIndicators.urgencyWords.forEach(word => {
            const regex = new RegExp(`\\b${word}\\b`, 'gi');
            const matches = textContent.match(regex);
            if (matches) {
                analysis.urgencyIndicators += matches.length;
            }
        });
        
        // Count authority appeals
        this.phishingIndicators.authoritativeTerms.forEach(term => {
            if (textContent.includes(term)) {
                analysis.authorityAppeals++;
            }
        });
        
        // Check for brand mentions
        this.phishingIndicators.brandNames.forEach(brand => {
            if (textContent.includes(brand)) {
                analysis.brandMentions.push(brand);
            }
        });
        
        return { source: 'text_content', ...analysis };
    }

    /**
     * Analyze page metadata
     */
    async analyzeMetadata() {
        const analysis = {
            title: document.title,
            description: '',
            keywords: '',
            author: '',
            suspiciousMetadata: []
        };
        
        // Get meta tags
        const metaTags = document.querySelectorAll('meta');
        metaTags.forEach(meta => {
            const name = meta.getAttribute('name')?.toLowerCase();
            const property = meta.getAttribute('property')?.toLowerCase();
            const content = meta.getAttribute('content') || '';
            
            if (name === 'description' || property === 'og:description') {
                analysis.description = content;
            } else if (name === 'keywords') {
                analysis.keywords = content;
            } else if (name === 'author') {
                analysis.author = content;
            }
        });
        
        // Check for suspicious metadata
        if (!analysis.description) {
            analysis.suspiciousMetadata.push('Missing description');
        }
        
        if (analysis.title.length < 10) {
            analysis.suspiciousMetadata.push('Very short title');
        }
        
        return { source: 'metadata', ...analysis };
    }

    /**
     * Analyze CSS styles for cloaking techniques
     */
    async analyzeStyles() {
        const analysis = {
            hiddenElements: 0,
            transparentElements: 0,
            overlayElements: 0,
            suspiciousStyles: []
        };
        
        const allElements = document.querySelectorAll('*');
        
        allElements.forEach((element, index) => {
            const style = window.getComputedStyle(element);
            
            // Hidden elements
            if (style.display === 'none' || style.visibility === 'hidden') {
                analysis.hiddenElements++;
            }
            
            // Transparent elements
            if (parseFloat(style.opacity) < 0.1) {
                analysis.transparentElements++;
            }
            
            // Overlay elements (potential clickjacking)
            if (style.position === 'absolute' || style.position === 'fixed') {
                const zIndex = parseInt(style.zIndex);
                if (zIndex > 1000) {
                    analysis.overlayElements++;
                    analysis.suspiciousStyles.push('High z-index overlay element');
                }
            }
        });
        
        return { source: 'styles', ...analysis };
    }

    /**
     * Setup mutation observer for dynamic content monitoring
     */
    setupMutationObserver() {
        if (!this.config.enableRealTimeMonitoring) return;
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            this.analyzeNewElement(node);
                        }
                    });
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        
        this.observers.push(observer);
    }

    /**
     * Analyze newly added DOM elements
     */
    analyzeNewElement(element) {
        // Check for suspicious forms
        if (element.tagName === 'FORM') {
            this.checkSuspiciousForm(element);
        }
        
        // Check for hidden iframes
        if (element.tagName === 'IFRAME') {
            const style = window.getComputedStyle(element);
            if (style.display === 'none' || style.visibility === 'hidden') {
                this.reportSuspiciousActivity('Hidden iframe added dynamically');
            }
        }
        
        // Check for suspicious scripts
        if (element.tagName === 'SCRIPT') {
            this.checkSuspiciousScript(element);
        }
    }

    /**
     * Setup behavioral monitoring
     */
    setupBehavioralMonitoring() {
        if (!this.config.behavioralAnalysis) return;
        
        // Monitor right-click blocking
        document.addEventListener('contextmenu', (e) => {
            if (e.defaultPrevented) {
                this.reportSuspiciousActivity('Right-click disabled');
            }
        });
        
        // Monitor F12 key blocking
        document.addEventListener('keydown', (e) => {
            if (e.key === 'F12' && e.defaultPrevented) {
                this.reportSuspiciousActivity('Developer tools access blocked');
            }
        });
        
        // Monitor popup attempts
        const originalOpen = window.open;
        window.open = function(...args) {
            this.reportSuspiciousActivity('Popup window attempt');
            return originalOpen.apply(window, args);
        }.bind(this);
    }

    /**
     * Setup periodic security checks
     */
    setupPeriodicChecks() {
        // Check every 30 seconds for dynamic changes
        setInterval(() => {
            this.performQuickSecurityCheck();
        }, 30000);
    }

    /**
     * Perform quick security check
     */
    async performQuickSecurityCheck() {
        const newFormCount = document.querySelectorAll('form').length;
        const newScriptCount = document.querySelectorAll('script').length;
        
        if (newFormCount > this.analysisResults.forms?.formCount || 0) {
            await this.analyzeForms();
        }
        
        if (newScriptCount > this.analysisResults.scripts?.scriptCount || 0) {
            await this.analyzeScripts();
        }
    }

    /**
     * Aggregate all analysis results
     */
    aggregateAnalysis(results) {
        const aggregated = {};
        
        results.forEach((result) => {
            if (result.status === 'fulfilled' && result.value) {
                const analysis = result.value;
                aggregated[analysis.source] = analysis;
            }
        });
        
        return aggregated;
    }

    /**
     * Calculate overall risk score
     */
    calculateRiskScore() {
        let riskScore = 0;
        const weights = {
            page_structure: 0.15,
            forms: 0.25,
            links: 0.15,
            images: 0.10,
            scripts: 0.20,
            text_content: 0.10,
            metadata: 0.05
        };
        
        Object.keys(weights).forEach(source => {
            const analysis = this.analysisResults[source];
            if (analysis) {
                riskScore += this.calculateSourceRisk(source, analysis) * weights[source];
            }
        });
        
        return Math.round(riskScore);
    }

    /**
     * Calculate risk score for specific analysis source
     */
    calculateSourceRisk(source, analysis) {
        let risk = 0;
        
        switch (source) {
            case 'page_structure':
                if (analysis.suspiciousStructure) risk += 60;
                if (!analysis.hasSSL) risk += 20;
                if (analysis.suspiciousIndicators.length > 0) risk += 30;
                break;
                
            case 'forms':
                risk += analysis.suspiciousForms.length * 30;
                risk += analysis.externalForms * 25;
                risk += analysis.hiddenForms * 40;
                break;
                
            case 'links':
                risk += analysis.suspiciousLinks.length * 15;
                risk += analysis.shortenerLinks * 20;
                risk += analysis.javascriptLinks * 25;
                break;
                
            case 'images':
                if (analysis.logoSpoof) risk += 50;
                risk += analysis.suspiciousImages.length * 20;
                break;
                
            case 'scripts':
                risk += analysis.obfuscatedScripts * 40;
                risk += analysis.suspiciousPatterns.length * 15;
                break;
                
            case 'text_content':
                if (analysis.socialEngineering) risk += 40;
                risk += analysis.urgencyIndicators * 10;
                risk += analysis.authorityAppeals * 15;
                break;
                
            case 'metadata':
                risk += analysis.suspiciousMetadata.length * 10;
                break;
        }
        
        return Math.min(risk, 100);
    }

    /**
     * Report analysis results to background script
     */
    async reportAnalysis(analysis) {
        try {
            chrome.runtime.sendMessage({
                type: 'DOM_ANALYSIS_COMPLETE',
                analysis
            });
        } catch (error) {
            console.error('❌ Failed to report analysis:', error);
        }
    }

    /**
     * Report suspicious activity
     */
    reportSuspiciousActivity(activity) {
        console.warn(`⚠️ Suspicious activity: ${activity}`);
        
        chrome.runtime.sendMessage({
            type: 'SUSPICIOUS_ACTIVITY',
            activity,
            url: window.location.href,
            timestamp: Date.now()
        });
    }

    /**
     * Check for suspicious form
     */
    checkSuspiciousForm(form) {
        const inputs = form.querySelectorAll('input[type="password"], input[type="email"]');
        if (inputs.length > 0 && form.action && !form.action.includes(window.location.hostname)) {
            this.reportSuspiciousActivity('External credential form detected');
        }
    }

    /**
     * Check for suspicious script
     */
    checkSuspiciousScript(script) {
        if (script.textContent && script.textContent.includes('eval(')) {
            this.reportSuspiciousActivity('Script with eval() function detected');
        }
    }

    /**
     * Cleanup observers and listeners
     */
    cleanup() {
        this.observers.forEach(observer => observer.disconnect());
        this.observers = [];
        console.log('🧹 DOM Inspector cleaned up');
    }
}

// Initialize DOM Inspector when script loads
const domInspector = new DOMInspector();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    domInspector.cleanup();
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DOMInspector;
}
