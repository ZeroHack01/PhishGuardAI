/**
 * PhishGuard AI - Unit Tests for Phishing Detector
 * File: testing/unit-tests/test-detector.js
 * 
 * Comprehensive test suite for AI model functionality
 * Tests feature extraction, model inference, and edge cases
 */

// Test framework setup
const assert = require('assert');
const sinon = require('sinon');

// Import modules to test
const { PhishingDetector, FeatureExtractor } = require('../../extension/models/phishing-detector.js');

// Mock TensorFlow.js for testing
const tf = {
    loadLayersModel: sinon.stub(),
    tensor2d: sinon.stub(),
    zeros: sinon.stub()
};

// Mock Chrome runtime
const chrome = {
    runtime: {
        getURL: sinon.stub().returns('mock://model.json'),
        sendMessage: sinon.stub()
    }
};

// Test data
const testUrls = {
    safe: [
        'https://google.com',
        'https://github.com/user/repo',
        'https://stackoverflow.com/questions/123',
        'https://amazon.com/product/123',
        'https://microsoft.com'
    ],
    suspicious: [
        'https://g00gle-security.net',
        'https://payp4l-verify.com', 
        'https://amazon-update.tk',
        'https://secure-bank-login.com',
        'https://microsoft-security-alert.ml'
    ],
    dangerous: [
        'https://192.168.1.1/phishing',
        'https://bit.ly/malicious',
        'https://urgent-account-suspended.cf',
        'https://winner-selected-congratulations.pw',
        'https://verify-your-paypal-account-now.ga'
    ]
};

const testContent = {
    safe: `
        Welcome to our secure banking platform. 
        Please log in to access your account.
        Contact us at support@bank.com for assistance.
        Privacy Policy | Terms of Service
    `,
    suspicious: `
        URGENT: Your account has been suspended due to unusual activity.
        Click here to verify your identity immediately.
        Failure to act within 24 hours will result in permanent closure.
    `,
    dangerous: `
        CONGRATULATIONS! You have been selected as our winner!
        Claim your $1000 prize now by entering your bank details.
        This offer expires today - ACT NOW!
        Enter your social security number to verify eligibility.
    `
};

describe('PhishGuard AI - Phishing Detector Tests', function() {
    let detector;
    let featureExtractor;
    
    // Mock model responses
    const mockModels = {
        ensemble: {
            predict: sinon.stub().returns({
                data: sinon.stub().resolves([0.15]) // Safe prediction
            }),
            dispose: sinon.stub()
        },
        url: {
            predict: sinon.stub().returns({
                data: sinon.stub().resolves([0.1])
            }),
            dispose: sinon.stub()
        },
        content: {
            predict: sinon.stub().returns({
                data: sinon.stub().resolves([0.2])
            }),
            dispose: sinon.stub()
        }
    };
    
    beforeEach(async function() {
        // Reset all stubs
        sinon.resetHistory();
        
        // Setup TensorFlow mocks
        tf.loadLayersModel.resolves(mockModels.ensemble);
        tf.tensor2d.returns({
            dispose: sinon.stub()
        });
        tf.zeros.returns({
            dispose: sinon.stub()
        });
        
        // Initialize detector
        detector = new PhishingDetector();
        featureExtractor = new FeatureExtractor();
        
        // Mock successful model loading
        detector.model = mockModels.ensemble;
        detector.urlModel = mockModels.url;
        detector.contentModel = mockModels.content;
        detector.isLoaded = true;
    });
    
    afterEach(function() {
        sinon.restore();
    });

    describe('PhishingDetector Initialization', function() {
        it('should initialize with correct default values', function() {
            const newDetector = new PhishingDetector();
            
            assert.strictEqual(newDetector.isLoaded, false);
            assert.strictEqual(newDetector.model, null);
            assert.deepStrictEqual(newDetector.threatThresholds, {
                safe: 0.3,
                suspicious: 0.7,
                dangerous: 0.9
            });
        });
        
        it('should load models successfully', async function() {
            const newDetector = new PhishingDetector();
            
            // Mock successful model loading
            tf.loadLayersModel.onFirstCall().resolves(mockModels.ensemble);
            tf.loadLayersModel.onSecondCall().resolves(mockModels.url);
            tf.loadLayersModel.onThirdCall().resolves(mockModels.content);
            
            await newDetector.initialize();
            
            assert.strictEqual(newDetector.isLoaded, true);
            assert.strictEqual(tf.loadLayersModel.callCount, 3);
        });
        
        it('should handle model loading errors gracefully', async function() {
            const newDetector = new PhishingDetector();
            
            // Mock model loading failure
            tf.loadLayersModel.rejects(new Error('Model load failed'));
            
            await newDetector.initialize();
            
            assert.strictEqual(newDetector.isLoaded, false);
            assert.strictEqual(chrome.runtime.sendMessage.callCount, 1);
        });
    });

    describe('URL Prediction Tests', function() {
        it('should predict safe URLs correctly', async function() {
            for (const url of testUrls.safe) {
                mockModels.ensemble.predict().data.resolves([0.1]); // Low threat
                mockModels.url.predict().data.resolves([0.05]);
                mockModels.content.predict().data.resolves([0.15]);
                
                const result = await detector.predictPhishing(url);
                
                assert.strictEqual(result.threatLevel, 'safe');
                assert(result.riskScore < 30, `Risk score ${result.riskScore} should be < 30 for safe URL: ${url}`);
                assert(result.confidence > 0, 'Confidence should be greater than 0');
            }
        });
        
        it('should predict suspicious URLs correctly', async function() {
            for (const url of testUrls.suspicious) {
                mockModels.ensemble.predict().data.resolves([0.65]); // Medium threat
                mockModels.url.predict().data.resolves([0.7]);
                mockModels.content.predict().data.resolves([0.6]);
                
                const result = await detector.predictPhishing(url);
                
                assert(result.threatLevel === 'suspicious' || result.threatLevel === 'dangerous');
                assert(result.riskScore >= 30, `Risk score ${result.riskScore} should be >= 30 for suspicious URL: ${url}`);
            }
        });
        
        it('should predict dangerous URLs correctly', async function() {
            for (const url of testUrls.dangerous) {
                mockModels.ensemble.predict().data.resolves([0.95]); // High threat
                mockModels.url.predict().data.resolves([0.9]);
                mockModels.content.predict().data.resolves([0.85]);
                
                const result = await detector.predictPhishing(url);
                
                assert.strictEqual(result.threatLevel, 'dangerous');
                assert(result.riskScore >= 70, `Risk score ${result.riskScore} should be >= 70 for dangerous URL: ${url}`);
            }
        });
        
        it('should handle invalid URLs gracefully', async function() {
            const invalidUrls = ['not-a-url', 'http://', 'ftp://invalid', ''];
            
            for (const url of invalidUrls) {
                const result = await detector.predictPhishing(url);
                
                assert(result.riskScore >= 0 && result.riskScore <= 100);
                assert(['safe', 'suspicious', 'dangerous', 'unknown'].includes(result.threatLevel));
            }
        });
    });

    describe('Content Analysis Tests', function() {
        it('should analyze safe content correctly', async function() {
            mockModels.ensemble.predict().data.resolves([0.1]);
            mockModels.url.predict().data.resolves([0.05]);
            mockModels.content.predict().data.resolves([0.15]);
            
            const result = await detector.predictPhishing('https://safe-bank.com', testContent.safe);
            
            assert.strictEqual(result.threatLevel, 'safe');
            assert(result.riskScore < 40);
        });
        
        it('should detect suspicious content patterns', async function() {
            mockModels.ensemble.predict().data.resolves([0.7]);
            mockModels.url.predict().data.resolves([0.6]);
            mockModels.content.predict().data.resolves([0.8]);
            
            const result = await detector.predictPhishing('https://test.com', testContent.suspicious);
            
            assert(result.threatLevel === 'suspicious' || result.threatLevel === 'dangerous');
            assert(result.riskScore >= 50);
        });
        
        it('should detect dangerous social engineering', async function() {
            mockModels.ensemble.predict().data.resolves([0.95]);
            mockModels.url.predict().data.resolves([0.9]);
            mockModels.content.predict().data.resolves([0.92]);
            
            const result = await detector.predictPhishing('https://scam.com', testContent.dangerous);
            
            assert.strictEqual(result.threatLevel, 'dangerous');
            assert(result.riskScore >= 80);
        });
    });

    describe('Performance Tests', function() {
        it('should complete analysis within reasonable time', async function() {
            this.timeout(5000); // 5 second timeout
            
            const startTime = performance.now();
            await detector.predictPhishing('https://example.com', testContent.safe);
            const analysisTime = performance.now() - startTime;
            
            assert(analysisTime < 1000, `Analysis took ${analysisTime}ms, should be < 1000ms`);
        });
        
        it('should handle concurrent predictions', async function() {
            const urls = testUrls.safe.concat(testUrls.suspicious);
            const promises = urls.map(url => detector.predictPhishing(url));
            
            const results = await Promise.all(promises);
            
            assert.strictEqual(results.length, urls.length);
            results.forEach(result => {
                assert(result.riskScore >= 0 && result.riskScore <= 100);
                assert(['safe', 'suspicious', 'dangerous'].includes(result.threatLevel));
            });
        });
        
        it('should properly dispose of tensors', async function() {
            await detector.predictPhishing('https://test.com', testContent.safe);
            
            // Verify tensor disposal was called
            assert(tf.tensor2d().dispose.called);
        });
    });

    describe('Edge Cases and Error Handling', function() {
        it('should handle model not loaded error', async function() {
            detector.isLoaded = false;
            
            try {
                await detector.predictPhishing('https://test.com');
                assert.fail('Should have thrown error');
            } catch (error) {
                assert(error.message.includes('Models not yet loaded'));
            }
        });
        
        it('should handle model prediction errors', async function() {
            mockModels.ensemble.predict.throws(new Error('Model prediction failed'));
            
            const result = await detector.predictPhishing('https://test.com');
            
            assert.strictEqual(result.error, 'Model prediction failed');
            assert.strictEqual(result.fallback, true);
        });
        
        it('should handle empty content gracefully', async function() {
            const result = await detector.predictPhishing('https://test.com', '');
            
            assert(result.riskScore >= 0 && result.riskScore <= 100);
            assert(['safe', 'suspicious', 'dangerous'].includes(result.threatLevel));
        });
        
        it('should handle very long URLs', async function() {
            const longUrl = 'https://example.com/' + 'a'.repeat(10000);
            
            const result = await detector.predictPhishing(longUrl);
            
            assert(result.riskScore >= 0 && result.riskScore <= 100);
        });
    });

    describe('Configuration and Settings', function() {
        it('should update threat thresholds correctly', function() {
            const newThresholds = {
                safe: 0.2,
                suspicious: 0.6,
                dangerous: 0.8
            };
            
            detector.updateThresholds(newThresholds);
            
            assert.deepStrictEqual(detector.threatThresholds, newThresholds);
        });
        
        it('should return correct model info', function() {
            const info = detector.getModelInfo();
            
            assert.strictEqual(info.loaded, true);
            assert.strictEqual(info.models.ensemble, 'loaded');
            assert.strictEqual(info.models.url, 'loaded');
            assert.strictEqual(info.models.content, 'loaded');
        });
        
        it('should dispose models correctly', function() {
            detector.dispose();
            
            assert.strictEqual(detector.isLoaded, false);
            assert(mockModels.ensemble.dispose.called);
            assert(mockModels.url.dispose.called);
            assert(mockModels.content.dispose.called);
        });
    });
});

describe('FeatureExtractor Tests', function() {
    let extractor;
    
    beforeEach(function() {
        extractor = new FeatureExtractor();
    });

    describe('URL Feature Extraction', function() {
        it('should extract features from safe URLs', function() {
            const url = 'https://google.com/search?q=test';
            const features = extractor.extractUrlFeatures(url);
            
            assert.strictEqual(features.length, 15);
            assert(features.every(f => typeof f === 'number'));
            assert.strictEqual(features[11], 1); // HTTPS usage should be 1
            assert.strictEqual(features[8], 0);  // Not an IP address
        });
        
        it('should detect suspicious URL patterns', function() {
            const suspiciousUrl = 'http://192.168.1.1/secure-bank-login-verify.php';
            const features = extractor.extractUrlFeatures(suspiciousUrl);
            
            assert.strictEqual(features[11], 0); // No HTTPS
            assert.strictEqual(features[8], 1);  // IP address detected
            assert.strictEqual(features[7], 1);  // Suspicious keywords
        });
        
        it('should handle URL shorteners', function() {
            const shortUrl = 'https://bit.ly/abc123';
            const features = extractor.extractUrlFeatures(shortUrl);
            
            assert.strictEqual(features[13], 1); // URL shortener detected
        });
        
        it('should detect homograph attacks', function() {
            const homographUrl = 'https://gοοgle.com'; // Using Greek omicron
            const features = extractor.extractUrlFeatures(homographUrl);
            
            assert.strictEqual(features[14], 1); // Homograph detected
        });
    });

    describe('Content Feature Extraction', function() {
        it('should extract features from safe content', function() {
            const features = extractor.extractContentFeatures(testContent.safe);
            
            assert.strictEqual(features.length, 25);
            assert(features.every(f => typeof f === 'number'));
            assert.strictEqual(features[3], 0); // No urgency words
            assert.strictEqual(features[15], 0); // No social engineering
        });
        
        it('should detect social engineering content', function() {
            const features = extractor.extractContentFeatures(testContent.dangerous);
            
            assert.strictEqual(features[15], 1); // Social engineering detected
            assert.strictEqual(features[16], 1); // Scarcity tactics
            assert(features[3] > 0); // Urgency words present
        });
        
        it('should analyze form data correctly', function() {
            const pageData = {
                forms: [
                    {
                        hasPasswordField: true,
                        action: 'https://external-site.com/login'
                    }
                ]
            };
            
            const features = extractor.extractContentFeatures(testContent.safe, pageData);
            
            assert.strictEqual(features[5], 1); // Form count
            assert.strictEqual(features[6], 1); // Password form
            assert.strictEqual(features[7], 1); // External form
        });
    });

    describe('Helper Methods', function() {
        it('should detect suspicious keywords correctly', function() {
            assert.strictEqual(extractor.hasSuspiciousKeywords('verify your account'), true);
            assert.strictEqual(extractor.hasSuspiciousKeywords('hello world'), false);
        });
        
        it('should identify IP addresses', function() {
            assert.strictEqual(extractor.isIPAddress('192.168.1.1'), true);
            assert.strictEqual(extractor.isIPAddress('google.com'), false);
        });
        
        it('should count subdomains correctly', function() {
            assert.strictEqual(extractor.getSubdomainCount('www.google.com'), 1);
            assert.strictEqual(extractor.getSubdomainCount('mail.google.com'), 1);
            assert.strictEqual(extractor.getSubdomainCount('a.b.c.google.com'), 3);
        });
        
        it('should detect URL shorteners', function() {
            assert.strictEqual(extractor.isUrlShortener('bit.ly'), true);
            assert.strictEqual(extractor.isUrlShortener('google.com'), false);
        });
        
        it('should calculate readability scores', function() {
            const simpleText = 'This is simple. Easy to read.';
            const complexText = 'This is an extraordinarily complex sentence with multiple clauses that would be very difficult for the average reader to comprehend without significant effort and concentration.';
            
            const simpleScore = extractor.calculateReadability(simpleText);
            const complexScore = extractor.calculateReadability(complexText);
            
            assert(simpleScore < complexScore);
        });
    });

    describe('Error Handling', function() {
        it('should handle invalid URLs gracefully', function() {
            const features = extractor.extractUrlFeatures('invalid-url');
            
            assert.strictEqual(features.length, 15);
            assert(features.every(f => f === 0)); // Should return zeros
        });
        
        it('should handle empty content', function() {
            const features = extractor.extractContentFeatures('');
            
            assert.strictEqual(features.length, 25);
            assert(features.every(f => typeof f === 'number'));
        });
        
        it('should handle malformed page data', function() {
            const badPageData = {
                forms: null,
                links: undefined,
                images: 'not-an-array'
            };
            
            const features = extractor.extractContentFeatures(testContent.safe, badPageData);
            
            assert.strictEqual(features.length, 25);
            assert(features.every(f => typeof f === 'number'));
        });
    });
});

describe('Integration Tests', function() {
    let detector;
    
    beforeEach(async function() {
        detector = new PhishingDetector();
        
        // Mock successful model loading
        detector.model = mockModels.ensemble;
        detector.urlModel = mockModels.url;
        detector.contentModel = mockModels.content;
        detector.isLoaded = true;
    });

    it('should integrate URL and content analysis', async function() {
        // Test with known phishing pattern
        const phishingUrl = 'https://secure-bank-verify.tk/login';
        const phishingContent = 'URGENT: Verify your account now or it will be suspended!';
        
        mockModels.ensemble.predict().data.resolves([0.85]);
        mockModels.url.predict().data.resolves([0.8]);
        mockModels.content.predict().data.resolves([0.9]);
        
        const result = await detector.predictPhishing(phishingUrl, phishingContent);
        
        assert.strictEqual(result.threatLevel, 'dangerous');
        assert(result.riskScore >= 70);
        assert(result.sources.length > 0);
        assert(result.analysisTime > 0);
    });
    
    it('should provide consistent results for same input', async function() {
        const url = 'https://test-site.com';
        const content = 'Test content for consistency check';
        
        mockModels.ensemble.predict().data.resolves([0.4]);
        mockModels.url.predict().data.resolves([0.3]);
        mockModels.content.predict().data.resolves([0.5]);
        
        const result1 = await detector.predictPhishing(url, content);
        const result2 = await detector.predictPhishing(url, content);
        
        assert.strictEqual(result1.threatLevel, result2.threatLevel);
        assert.strictEqual(result1.riskScore, result2.riskScore);
    });
});

// Test runner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        testUrls,
        testContent,
        mockModels
    };
}

// Run tests if this file is executed directly
if (require.main === module) {
    console.log('🧪 Running PhishGuard AI unit tests...');
    
    // Simple test runner for Node.js environment
    const Mocha = require('mocha');
    const mocha = new Mocha({
        timeout: 10000,
        reporter: 'spec'
    });
    
    mocha.addFile(__filename);
    
    mocha.run((failures) => {
        if (failures) {
            console.error(`❌ ${failures} test(s) failed`);
            process.exit(1);
        } else {
            console.log('✅ All tests passed!');
            process.exit(0);
        }
    });
}
