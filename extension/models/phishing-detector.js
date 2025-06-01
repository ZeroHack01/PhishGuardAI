/**
 * PhishGuard AI - TensorFlow.js Phishing Detection Model
 * File: extension/models/phishing-detector.js
 * 
 * Main AI model loader and inference engine for real-time phishing detection
 * Handles model loading, feature extraction, and threat prediction
 */

class PhishingDetector {
    constructor() {
        this.model = null;
        this.urlModel = null;
        this.contentModel = null;
        this.isLoaded = false;
        this.featureExtractor = new FeatureExtractor();
        this.threatThresholds = {
            safe: 0.3,
            suspicious: 0.7,
            dangerous: 0.9
        };
    }

    /**
     * Initialize and load all AI models
     */
    async initialize() {
        try {
            console.log('🧠 Loading PhishGuard AI models...');
            
            // Load main ensemble model
            this.model = await tf.loadLayersModel(chrome.runtime.getURL('models/phishing-ensemble.json'));
            
            // Load specialized URL analysis model
            this.urlModel = await tf.loadLayersModel(chrome.runtime.getURL('models/url-classifier.json'));
            
            // Load content analysis model
            this.contentModel = await tf.loadLayersModel(chrome.runtime.getURL('models/content-analyzer.json'));
            
            // Warm up models with dummy data
            await this.warmUpModels();
            
            this.isLoaded = true;
            console.log('✅ PhishGuard AI models loaded successfully');
            
            // Send initialization complete message
            chrome.runtime.sendMessage({
                type: 'MODEL_LOADED',
                timestamp: Date.now()
            });
            
        } catch (error) {
            console.error('❌ Error loading PhishGuard models:', error);
            this.handleModelLoadError(error);
        }
    }

    /**
     * Warm up models with dummy predictions to improve first-run performance
     */
    async warmUpModels() {
        const dummyUrlFeatures = tf.zeros([1, 15]);
        const dummyContentFeatures = tf.zeros([1, 25]);
        const dummyEnsembleFeatures = tf.zeros([1, 40]);

        await this.urlModel.predict(dummyUrlFeatures).data();
        await this.contentModel.predict(dummyContentFeatures).data();
        await this.model.predict(dummyEnsembleFeatures).data();

        // Clean up tensors
        dummyUrlFeatures.dispose();
        dummyContentFeatures.dispose();
        dummyEnsembleFeatures.dispose();
    }

    /**
     * Main prediction function - analyzes URL and content for phishing indicators
     */
    async predictPhishing(url, content = null, pageData = {}) {
        if (!this.isLoaded) {
            throw new Error('Models not yet loaded. Call initialize() first.');
        }

        const startTime = performance.now();

        try {
            // Extract features from URL
            const urlFeatures = this.featureExtractor.extractUrlFeatures(url);
            
            // Extract features from page content if available
            const contentFeatures = content ? 
                this.featureExtractor.extractContentFeatures(content, pageData) :
                new Array(25).fill(0);

            // Get predictions from specialized models
            const urlPrediction = await this.predictUrl(urlFeatures);
            const contentPrediction = content ? await this.predictContent(contentFeatures) : 0.5;

            // Combine features for ensemble prediction
            const ensembleFeatures = [...urlFeatures, ...contentFeatures];
            const ensemblePrediction = await this.predictEnsemble(ensembleFeatures);

            // Calculate final risk score with weighted ensemble
            const finalScore = this.calculateFinalScore(urlPrediction, contentPrediction, ensemblePrediction);

            // Determine threat level
            const threatLevel = this.classifyThreat(finalScore);

            const analysisTime = performance.now() - startTime;

            return {
                riskScore: Math.round(finalScore * 100),
                threatLevel: threatLevel,
                confidence: this.calculateConfidence(finalScore),
                analysisTime: Math.round(analysisTime),
                predictions: {
                    url: urlPrediction,
                    content: contentPrediction,
                    ensemble: ensemblePrediction
                },
                features: {
                    url: urlFeatures,
                    content: contentFeatures
                },
                timestamp: Date.now()
            };

        } catch (error) {
            console.error('❌ Error during phishing prediction:', error);
            return this.getErrorPrediction(error);
        }
    }

    /**
     * URL-specific phishing detection
     */
    async predictUrl(urlFeatures) {
        const tensor = tf.tensor2d([urlFeatures]);
        const prediction = await this.urlModel.predict(tensor).data();
        tensor.dispose();
        return prediction[0];
    }

    /**
     * Content-specific phishing detection
     */
    async predictContent(contentFeatures) {
        const tensor = tf.tensor2d([contentFeatures]);
        const prediction = await this.contentModel.predict(tensor).data();
        tensor.dispose();
        return prediction[0];
    }

    /**
     * Ensemble model prediction combining all features
     */
    async predictEnsemble(features) {
        const tensor = tf.tensor2d([features]);
        const prediction = await this.model.predict(tensor).data();
        tensor.dispose();
        return prediction[0];
    }

    /**
     * Calculate weighted final score from multiple model predictions
     */
    calculateFinalScore(urlScore, contentScore, ensembleScore) {
        // Weighted ensemble: URL (30%), Content (25%), Ensemble (45%)
        return (urlScore * 0.3) + (contentScore * 0.25) + (ensembleScore * 0.45);
    }

    /**
     * Classify threat level based on risk score
     */
    classifyThreat(score) {
        if (score < this.threatThresholds.safe) return 'safe';
        if (score < this.threatThresholds.suspicious) return 'suspicious';
        if (score < this.threatThresholds.dangerous) return 'suspicious';
        return 'dangerous';
    }

    /**
     * Calculate prediction confidence
     */
    calculateConfidence(score) {
        // Higher confidence for scores near 0 or 1, lower for middle values
        const distance = Math.abs(score - 0.5);
        return Math.round((distance * 2) * 100);
    }

    /**
     * Handle model loading errors gracefully
     */
    handleModelLoadError(error) {
        // Fallback to rule-based detection
        console.warn('⚠️ Falling back to rule-based detection');
        this.isLoaded = false;
        
        chrome.runtime.sendMessage({
            type: 'MODEL_LOAD_ERROR',
            error: error.message,
            fallback: true
        });
    }

    /**
     * Return error prediction when inference fails
     */
    getErrorPrediction(error) {
        return {
            riskScore: 50,
            threatLevel: 'unknown',
            confidence: 0,
            analysisTime: 0,
            error: error.message,
            fallback: true,
            timestamp: Date.now()
        };
    }

    /**
     * Get model performance metrics
     */
    getModelInfo() {
        return {
            loaded: this.isLoaded,
            models: {
                ensemble: this.model ? 'loaded' : 'not loaded',
                url: this.urlModel ? 'loaded' : 'not loaded',
                content: this.contentModel ? 'loaded' : 'not loaded'
            },
            thresholds: this.threatThresholds,
            version: '1.0.0'
        };
    }

    /**
     * Update threat thresholds dynamically
     */
    updateThresholds(newThresholds) {
        this.threatThresholds = { ...this.threatThresholds, ...newThresholds };
        console.log('🔧 Updated threat thresholds:', this.threatThresholds);
    }

    /**
     * Dispose of models and free memory
     */
    dispose() {
        if (this.model) this.model.dispose();
        if (this.urlModel) this.urlModel.dispose();
        if (this.contentModel) this.contentModel.dispose();
        
        this.isLoaded = false;
        console.log('🧹 PhishGuard models disposed');
    }
}

/**
 * Feature extraction utilities for phishing detection
 */
class FeatureExtractor {
    constructor() {
        this.suspiciousKeywords = [
            'verify', 'secure', 'update', 'suspend', 'urgent', 'confirm',
            'login', 'signin', 'account', 'bank', 'paypal', 'amazon',
            'microsoft', 'google', 'apple', 'facebook', 'twitter'
        ];
        
        this.phishingPatterns = [
            /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP addresses
            /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./,              // Multiple hyphens
            /[0-9]{8,}/,                                       // Long numbers
            /[a-z]{20,}/                                       // Long strings
        ];
    }

    /**
     * Extract features from URL for ML model
     */
    extractUrlFeatures(url) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            const path = urlObj.pathname;
            const query = urlObj.search;

            return [
                // Length-based features
                url.length / 100,                              // 0: Normalized URL length
                domain.length / 50,                            // 1: Normalized domain length
                path.length / 50,                              // 2: Normalized path length
                
                // Character composition
                (url.match(/[0-9]/g) || []).length / url.length,  // 3: Digit ratio
                (url.match(/[-]/g) || []).length,                 // 4: Hyphen count
                (url.match(/[.]/g) || []).length,                 // 5: Dot count
                
                // Suspicious patterns
                this.phishingPatterns.some(p => p.test(url)) ? 1 : 0,  // 6: Phishing patterns
                this.hasSuspiciousKeywords(url) ? 1 : 0,                // 7: Suspicious keywords
                
                // Domain analysis
                this.isIPAddress(domain) ? 1 : 0,              // 8: IP address as domain
                this.getSubdomainCount(domain),                // 9: Subdomain count
                this.hasSuspiciousTLD(domain) ? 1 : 0,         // 10: Suspicious TLD
                
                // Protocol and security
                url.startsWith('https://') ? 1 : 0,            // 11: HTTPS usage
                query.length > 0 ? 1 : 0,                      // 12: Has query parameters
                
                // URL shortening services
                this.isUrlShortener(domain) ? 1 : 0,           // 13: URL shortener
                
                // Homograph/typosquatting detection
                this.hasHomographs(domain) ? 1 : 0             // 14: Homograph characters
            ];
        } catch (error) {
            console.warn('Error extracting URL features:', error);
            return new Array(15).fill(0);
        }
    }

    /**
     * Extract features from page content
     */
    extractContentFeatures(content, pageData = {}) {
        const text = content.toLowerCase();
        const forms = pageData.forms || [];
        const links = pageData.links || [];
        const images = pageData.images || [];

        return [
            // Content length and structure
            Math.min(content.length / 10000, 1),               // 0: Normalized content length
            (text.match(/\n/g) || []).length / 100,            // 1: Line break density
            
            // Suspicious phrases
            this.countSuspiciousPhrases(text),                 // 2: Suspicious phrase count
            this.hasUrgencyWords(text) ? 1 : 0,                // 3: Urgency indicators
            this.hasCredentialRequests(text) ? 1 : 0,          // 4: Credential requests
            
            // Form analysis
            forms.length,                                      // 5: Number of forms
            forms.filter(f => f.hasPasswordField).length,      // 6: Password forms
            forms.filter(f => f.action && !f.action.includes(window.location.hostname)).length, // 7: External forms
            
            // Link analysis
            Math.min(links.length / 50, 1),                    // 8: Link density
            links.filter(l => this.isExternalLink(l)).length / Math.max(links.length, 1), // 9: External link ratio
            links.filter(l => this.isSuspiciousLink(l)).length, // 10: Suspicious links
            
            // Image analysis
            images.length,                                     // 11: Image count
            images.filter(i => this.isExternalImage(i)).length, // 12: External images
            
            // Text analysis
            this.calculateReadability(text),                   // 13: Readability score
            this.hasGrammarErrors(text) ? 1 : 0,               // 14: Grammar issues
            
            // Social engineering indicators
            this.hasSocialEngineering(text) ? 1 : 0,           // 15: Social engineering
            this.hasScarcityTactics(text) ? 1 : 0,             // 16: Scarcity tactics
            this.hasAuthorityAppeals(text) ? 1 : 0,            // 17: Authority appeals
            
            // Technical indicators
            pageData.hasPopups ? 1 : 0,                        // 18: Popup presence
            pageData.disablesRightClick ? 1 : 0,               // 19: Right-click disabled
            pageData.hasObfuscatedCode ? 1 : 0,                // 20: Code obfuscation
            
            // Brand impersonation
            this.detectBrandImpersonation(text),               // 21: Brand impersonation score
            this.hasOfficialAppearance(text) ? 1 : 0,          // 22: Official appearance
            
            // Contact information
            this.hasContactInfo(text) ? 1 : 0,                 // 23: Contact information
            this.hasLegalInfo(text) ? 1 : 0                    // 24: Legal information
        ];
    }

    // Helper methods for feature extraction
    hasSuspiciousKeywords(text) {
        return this.suspiciousKeywords.some(keyword => 
            text.toLowerCase().includes(keyword)
        );
    }

    isIPAddress(domain) {
        return /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(domain);
    }

    getSubdomainCount(domain) {
        return Math.max(0, domain.split('.').length - 2);
    }

    hasSuspiciousTLD(domain) {
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top'];
        return suspiciousTLDs.some(tld => domain.endsWith(tld));
    }

    isUrlShortener(domain) {
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
        return shorteners.includes(domain);
    }

    hasHomographs(domain) {
        // Check for common homograph characters
        const homographs = /[а-я]|[αβγδε]|[⁰¹²³⁴⁵⁶⁷⁸⁹]/;
        return homographs.test(domain);
    }

    countSuspiciousPhrases(text) {
        const phrases = [
            'click here', 'act now', 'limited time', 'expires today',
            'verify account', 'suspended account', 'unusual activity'
        ];
        return phrases.filter(phrase => text.includes(phrase)).length;
    }

    hasUrgencyWords(text) {
        const urgencyWords = ['urgent', 'immediate', 'expires', 'deadline', 'hurry'];
        return urgencyWords.some(word => text.includes(word));
    }

    hasCredentialRequests(text) {
        return text.includes('password') || text.includes('username') || 
               text.includes('login') || text.includes('sign in');
    }

    isExternalLink(link) {
        try {
            const linkUrl = new URL(link.href);
            return linkUrl.hostname !== window.location.hostname;
        } catch {
            return false;
        }
    }

    isSuspiciousLink(link) {
        return this.isUrlShortener(link.hostname) || 
               this.hasSuspiciousKeywords(link.href);
    }

    isExternalImage(img) {
        try {
            const imgUrl = new URL(img.src);
            return imgUrl.hostname !== window.location.hostname;
        } catch {
            return false;
        }
    }

    calculateReadability(text) {
        // Simple readability score based on sentence and word length
        const sentences = text.split(/[.!?]+/).length;
        const words = text.split(/\s+/).length;
        return Math.min(words / Math.max(sentences, 1) / 20, 1);
    }

    hasGrammarErrors(text) {
        // Simple grammar error detection
        const errors = [
            /\s{2,}/, // Multiple spaces
            /[a-z]\.[A-Z]/, // Missing space after period
            /\s,/, // Space before comma
        ];
        return errors.some(pattern => pattern.test(text));
    }

    hasSocialEngineering(text) {
        const phrases = [
            'you have won', 'congratulations', 'selected winner',
            'free gift', 'no cost', 'risk free'
        ];
        return phrases.some(phrase => text.includes(phrase));
    }

    hasScarcityTactics(text) {
        const tactics = ['limited', 'only', 'last chance', 'few remaining'];
        return tactics.some(tactic => text.includes(tactic));
    }

    hasAuthorityAppeals(text) {
        const authorities = ['bank', 'government', 'irs', 'fbi', 'police'];
        return authorities.some(auth => text.includes(auth));
    }

    detectBrandImpersonation(text) {
        const brands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook'];
        return brands.filter(brand => text.includes(brand)).length / brands.length;
    }

    hasOfficialAppearance(text) {
        const official = ['official', 'secure', 'verified', 'authentic'];
        return official.some(word => text.includes(word));
    }

    hasContactInfo(text) {
        return /\b[\w._%+-]+@[\w.-]+\.[A-Z|a-z]{2,}\b/.test(text) || // Email
               /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(text); // Phone
    }

    hasLegalInfo(text) {
        const legal = ['privacy policy', 'terms of service', 'copyright', 'trademark'];
        return legal.some(term => text.includes(term));
    }
}

// Global instance
let phishingDetector = null;

// Initialize detector when script loads
(async function initializeDetector() {
    try {
        phishingDetector = new PhishingDetector();
        await phishingDetector.initialize();
    } catch (error) {
        console.error('Failed to initialize PhishGuard detector:', error);
    }
})();

// Export for use in other extension scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PhishingDetector, FeatureExtractor };
}
