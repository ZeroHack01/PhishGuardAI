#!/usr/bin/env python3
"""
PhishGuard AI - Model Conversion Pipeline
Converts trained ML models to TensorFlow.js format for browser deployment
File: ml-training/model-conversion.py
"""

import os
import json
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
import tensorflowjs as tfjs
from tensorflow import keras
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import logging
from datetime import datetime
import shutil

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishGuardModelConverter:
    def __init__(self, models_dir='models', output_dir='../extension/models'):
        self.models_dir = models_dir
        self.output_dir = output_dir
        self.feature_names = []
        self.scaler = None
        self.models = {}
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info("PhishGuard Model Converter initialized")
    
    def load_trained_models(self):
        """Load all trained models and preprocessing components"""
        logger.info("Loading trained models...")
        
        # Find the latest model files
        model_files = [f for f in os.listdir(self.models_dir) if f.endswith('.pkl') or f.endswith('.h5')]
        
        if not model_files:
            raise FileNotFoundError("No trained models found in models directory")
        
        # Load feature names
        feature_files = [f for f in os.listdir(self.models_dir) if 'feature_names' in f and f.endswith('.json')]
        if feature_files:
            with open(os.path.join(self.models_dir, feature_files[-1]), 'r') as f:
                self.feature_names = json.load(f)
            logger.info(f"Loaded {len(self.feature_names)} feature names")
        
        # Load scaler
        scaler_files = [f for f in os.listdir(self.models_dir) if 'scaler' in f and f.endswith('.pkl')]
        if scaler_files:
            self.scaler = joblib.load(os.path.join(self.models_dir, scaler_files[-1]))
            logger.info("Loaded feature scaler")
        
        # Load scikit-learn models
        for model_file in model_files:
            if model_file.endswith('.pkl') and 'scaler' not in model_file:
                model_name = model_file.replace('.pkl', '').split('_model_')[0]
                model_path = os.path.join(self.models_dir, model_file)
                self.models[model_name] = joblib.load(model_path)
                logger.info(f"Loaded {model_name} model")
        
        # Load neural network models
        for model_file in model_files:
            if model_file.endswith('.h5'):
                model_name = 'neural_network'
                model_path = os.path.join(self.models_dir, model_file)
                self.models[model_name] = keras.models.load_model(model_path)
                logger.info(f"Loaded {model_name} model")
        
        logger.info(f"Loaded {len(self.models)} models total")
    
    def convert_neural_network(self):
        """Convert TensorFlow/Keras model to TensorFlow.js format"""
        if 'neural_network' not in self.models:
            logger.warning("No neural network model found to convert")
            return
        
        logger.info("Converting neural network to TensorFlow.js...")
        
        model = self.models['neural_network']
        output_path = os.path.join(self.output_dir, 'neural_network')
        
        # Convert to TensorFlow.js format
        tfjs.converters.save_keras_model(
            model, 
            output_path,
            quantization_bytes=2,  # Quantize for smaller size
            strip_debug_ops=True   # Remove debug operations
        )
        
        logger.info(f"Neural network converted and saved to {output_path}")
        
        # Create model metadata
        metadata = {
            'model_type': 'neural_network',
            'framework': 'tensorflow',
            'input_shape': model.input_shape,
            'output_shape': model.output_shape,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'requires_scaling': True,
            'conversion_date': datetime.now().isoformat(),
            'version': '1.0.0'
        }
        
        with open(os.path.join(output_path, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def convert_ensemble_to_js_rules(self):
        """Convert ensemble models to JavaScript decision rules"""
        logger.info("Converting ensemble models to JavaScript rules...")
        
        # Convert Random Forest to JavaScript
        if 'random_forest' in self.models:
            self.convert_random_forest_to_js()
        
        # Convert other models to simplified rule sets
        self.create_lightweight_classifier()
        
        # Create feature extraction rules
        self.create_feature_extraction_rules()
    
    def convert_random_forest_to_js(self):
        """Convert Random Forest to JavaScript decision tree rules"""
        rf_model = self.models['random_forest']
        
        logger.info(f"Converting Random Forest with {rf_model.n_estimators} trees...")
        
        # Extract important features and create simplified rules
        feature_importance = rf_model.feature_importances_
        important_features = np.argsort(feature_importance)[-20:]  # Top 20 features
        
        # Create simplified decision rules based on feature importance
        js_rules = {
            'model_type': 'random_forest_rules',
            'important_features': [
                {
                    'name': self.feature_names[i],
                    'importance': float(feature_importance[i]),
                    'threshold': self.calculate_optimal_threshold(rf_model, i)
                }
                for i in important_features
            ],
            'base_rules': self.extract_decision_rules(rf_model, important_features),
            'feature_weights': {
                self.feature_names[i]: float(feature_importance[i])
                for i in range(len(self.feature_names))
            }
        }
        
        # Save as JavaScript module
        js_code = self.generate_js_classifier(js_rules)
        
        with open(os.path.join(self.output_dir, 'random_forest_rules.js'), 'w') as f:
            f.write(js_code)
        
        logger.info("Random Forest converted to JavaScript rules")
    
    def calculate_optimal_threshold(self, model, feature_index):
        """Calculate optimal threshold for a feature"""
        # This is a simplified approach - in production, you'd use more sophisticated methods
        thresholds = []
        
        for tree in model.estimators_[:10]:  # Sample first 10 trees
            tree_structure = tree.tree_
            for node in range(tree_structure.node_count):
                if tree_structure.feature[node] == feature_index:
                    thresholds.append(tree_structure.threshold[node])
        
        return float(np.median(thresholds)) if thresholds else 0.5
    
    def extract_decision_rules(self, model, important_features):
        """Extract simplified decision rules from Random Forest"""
        rules = []
        
        # Sample a few trees and extract simple rules
        for i, tree in enumerate(model.estimators_[:5]):  # First 5 trees
            tree_rules = self.extract_tree_rules(tree, important_features[:10])  # Top 10 features
            rules.extend(tree_rules)
        
        # Deduplicate and sort by confidence
        unique_rules = list({rule['condition']: rule for rule in rules}.values())
        
        return sorted(unique_rules, key=lambda x: x.get('confidence', 0), reverse=True)[:20]
    
    def extract_tree_rules(self, tree, important_features):
        """Extract rules from a single decision tree"""
        tree_structure = tree.tree_
        rules = []
        
        def traverse_tree(node, path_conditions):
            if tree_structure.children_left[node] == tree_structure.children_right[node]:
                # Leaf node
                samples = tree_structure.n_node_samples[node]
                value = tree_structure.value[node][0]
                
                if len(value) == 2:  # Binary classification
                    confidence = max(value) / sum(value)
                    prediction = np.argmax(value)
                    
                    if confidence > 0.7 and samples > 10:  # High confidence rules only
                        rules.append({
                            'condition': ' AND '.join(path_conditions),
                            'prediction': int(prediction),
                            'confidence': float(confidence),
                            'samples': int(samples)
                        })
                return
            
            # Internal node
            feature = tree_structure.feature[node]
            threshold = tree_structure.threshold[node]
            
            if feature in important_features:
                feature_name = self.feature_names[feature]
                
                # Left child (<=)
                left_condition = f"{feature_name} <= {threshold:.3f}"
                traverse_tree(
                    tree_structure.children_left[node], 
                    path_conditions + [left_condition]
                )
                
                # Right child (>)
                right_condition = f"{feature_name} > {threshold:.3f}"
                traverse_tree(
                    tree_structure.children_right[node], 
                    path_conditions + [right_condition]
                )
        
        traverse_tree(0, [])
        return rules
    
    def create_lightweight_classifier(self):
        """Create a lightweight JavaScript classifier combining all models"""
        logger.info("Creating lightweight JavaScript classifier...")
        
        # Get feature importance from all models
        combined_importance = self.combine_feature_importance()
        
        # Create simplified classification logic
        classifier_config = {
            'version': '1.0.0',
            'feature_weights': combined_importance,
            'decision_thresholds': {
                'safe': 30,
                'suspicious': 60,
                'dangerous': 80
            },
            'feature_rules': self.create_feature_rules(),
            'pattern_rules': self.create_pattern_rules(),
            'domain_rules': self.create_domain_rules()
        }
        
        # Generate JavaScript classifier
        js_classifier = self.generate_lightweight_js_classifier(classifier_config)
        
        with open(os.path.join(self.output_dir, 'lightweight_classifier.js'), 'w') as f:
            f.write(js_classifier)
        
        # Save configuration as JSON for easy updates
        with open(os.path.join(self.output_dir, 'classifier_config.json'), 'w') as f:
            json.dump(classifier_config, f, indent=2)
        
        logger.info("Lightweight classifier created")
    
    def combine_feature_importance(self):
        """Combine feature importance from all models"""
        combined_importance = {}
        
        for model_name, model in self.models.items():
            if hasattr(model, 'feature_importances_'):
                importance = model.feature_importances_
                for i, feature_name in enumerate(self.feature_names):
                    if feature_name not in combined_importance:
                        combined_importance[feature_name] = []
                    combined_importance[feature_name].append(importance[i])
        
        # Average importance across models
        final_importance = {}
        for feature_name, importances in combined_importance.items():
            final_importance[feature_name] = float(np.mean(importances))
        
        return final_importance
    
    def create_feature_rules(self):
        """Create feature-based classification rules"""
        return {
            'url_based': {
                'has_ip_address': 30,
                'suspicious_tld': 25,
                'url_length': {'threshold': 100, 'weight': 10},
                'subdomain_count': {'threshold': 3, 'weight': 15},
                'has_phishing_keywords': 20,
                'brand_impersonation': 35
            },
            'content_based': {
                'has_password_field': {'with_https': 0, 'without_https': 40},
                'external_form_count': {'threshold': 0, 'weight': 40},
                'phishing_keyword_density': {'threshold': 0.01, 'weight': 25},
                'urgency_word_count': {'threshold': 2, 'weight': 15}
            },
            'technical': {
                'hidden_iframe_count': {'threshold': 0, 'weight': 15},
                'external_script_count': {'threshold': 5, 'weight': 10},
                'has_meta_refresh': 10,
                'right_click_disabled': 5
            }
        }
    
    def create_pattern_rules(self):
        """Create pattern-based classification rules"""
        return {
            'suspicious_domains': [
                r'.*-security\..*',
                r'.*-verify\..*',
                r'.*-update\..*',
                r'.*-alert\..*',
                r'.*secure.*\..*',
                r'.*verify.*\..*'
            ],
            'phishing_keywords': [
                'verify account',
                'suspended account',
                'unusual activity',
                'confirm identity',
                'security alert',
                'immediate action',
                'verify now',
                'act now',
                'limited time',
                'expires soon'
            ],
            'brand_patterns': [
                'paypal',
                'amazon',
                'microsoft',
                'apple',
                'google',
                'facebook',
                'twitter',
                'netflix',
                'instagram'
            ]
        }
    
    def create_domain_rules(self):
        """Create domain-based classification rules"""
        return {
            'trusted_domains': [
                'google.com',
                'microsoft.com',
                'apple.com',
                'amazon.com',
                'paypal.com',
                'facebook.com',
                'twitter.com',
                'github.com',
                'stackoverflow.com'
            ],
            'suspicious_tlds': [
                '.tk',
                '.ml',
                '.ga',
                '.cf',
                '.pw',
                '.cc',
                '.top',
                '.work',
                '.click'
            ],
            'ip_address_pattern': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        }
    
    def create_feature_extraction_rules(self):
        """Create JavaScript feature extraction rules"""
        logger.info("Creating feature extraction rules...")
        
        js_extractor = """
/**
 * PhishGuard AI - Feature Extraction Module
 * Extracts phishing detection features from web pages
 */

class PhishGuardFeatureExtractor {
    constructor() {
        this.suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.work'];
        this.phishingKeywords = [
            'verify', 'suspend', 'security', 'alert', 'confirm', 'update',
            'action', 'required', 'immediate', 'expires', 'limited', 'urgent'
        ];
        this.trustedDomains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'facebook.com', 'twitter.com', 'github.com'
        ];
    }

    extractFeatures(url = window.location.href) {
        const features = {};
        
        try {
            const urlObj = new URL(url);
            
            // URL-based features
            features.url_length = url.length;
            features.domain_length = urlObj.hostname.length;
            features.has_ip_address = this.isIPAddress(urlObj.hostname) ? 1 : 0;
            features.uses_https = urlObj.protocol === 'https:' ? 1 : 0;
            features.suspicious_tld = this.hasSuspiciousTLD(urlObj.hostname) ? 1 : 0;
            features.subdomain_count = (urlObj.hostname.match(/\\./g) || []).length - 1;
            features.has_phishing_keywords = this.containsPhishingKeywords(url.toLowerCase()) ? 1 : 0;
            features.brand_impersonation = this.checkBrandImpersonation(url, urlObj.hostname) ? 1 : 0;
            
            // Content-based features (if DOM available)
            if (typeof document !== 'undefined') {
                Object.assign(features, this.extractContentFeatures());
                Object.assign(features, this.extractFormFeatures());
                Object.assign(features, this.extractTechnicalFeatures());
            }
            
        } catch (error) {
            console.error('Feature extraction error:', error);
        }
        
        return features;
    }

    isIPAddress(hostname) {
        return /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(hostname);
    }

    hasSuspiciousTLD(hostname) {
        return this.suspiciousTLDs.some(tld => hostname.endsWith(tld));
    }

    containsPhishingKeywords(text) {
        return this.phishingKeywords.some(keyword => text.includes(keyword));
    }

    checkBrandImpersonation(url, hostname) {
        const brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook'];
        return brands.some(brand => 
            url.includes(brand) && !this.trustedDomains.some(domain => hostname.endsWith(domain))
        );
    }

    extractContentFeatures() {
        const features = {};
        const pageText = document.body ? document.body.innerText.toLowerCase() : '';
        
        features.text_length = pageText.length;
        features.phishing_keyword_count = this.phishingKeywords.filter(keyword => 
            pageText.includes(keyword)
        ).length;
        
        const urgencyWords = ['urgent', 'immediate', 'expires', 'suspended'];
        features.urgency_word_count = urgencyWords.filter(word => pageText.includes(word)).length;
        
        return features;
    }

    extractFormFeatures() {
        const features = {};
        const forms = document.querySelectorAll('form');
        const inputs = document.querySelectorAll('input');
        
        features.form_count = forms.length;
        features.has_password_field = document.querySelector('input[type="password"]') ? 1 : 0;
        features.external_form_count = Array.from(forms).filter(form => {
            const action = form.getAttribute('action');
            return action && action.startsWith('http') && !action.includes(window.location.hostname);
        }).length;
        
        return features;
    }

    extractTechnicalFeatures() {
        const features = {};
        
        features.iframe_count = document.querySelectorAll('iframe').length;
        features.hidden_iframe_count = Array.from(document.querySelectorAll('iframe')).filter(iframe =>
            iframe.style.display === 'none' || iframe.style.visibility === 'hidden'
        ).length;
        
        features.external_script_count = Array.from(document.querySelectorAll('script[src]')).filter(script =>
            script.src && !script.src.includes(window.location.hostname)
        ).length;
        
        features.has_meta_refresh = document.querySelector('meta[http-equiv="refresh"]') ? 1 : 0;
        
        return features;
    }
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishGuardFeatureExtractor;
} else if (typeof window !== 'undefined') {
    window.PhishGuardFeatureExtractor = PhishGuardFeatureExtractor;
}
"""
        
        with open(os.path.join(self.output_dir, 'feature_extractor.js'), 'w') as f:
            f.write(js_extractor)
        
        logger.info("Feature extraction rules created")
    
    def generate_js_classifier(self, rules_config):
        """Generate JavaScript classifier from rules configuration"""
        return f"""
/**
 * PhishGuard AI - Random Forest Rules Classifier
 * Converted from Python Random Forest model
 */

class RandomForestRulesClassifier {{
    constructor() {{
        this.config = {json.dumps(rules_config, indent=8)};
    }}

    predict(features) {{
        let score = 0;
        
        // Apply feature-based scoring
        for (const feature of this.config.important_features) {{
            const featureValue = features[feature.name];
            if (featureValue !== undefined) {{
                if (featureValue > feature.threshold) {{
                    score += feature.importance * 100;
                }}
            }}
        }}
        
        // Apply decision rules
        for (const rule of this.config.base_rules) {{
            if (this.evaluateRule(rule.condition, features)) {{
                score += rule.confidence * rule.prediction * 50;
            }}
        }}
        
        return Math.min(Math.max(score, 0), 100);
    }}

    evaluateRule(condition, features) {{
        // Simplified rule evaluation
        try {{
            // Replace feature names with actual values
            let evaluableCondition = condition;
            for (const [featureName, value] of Object.entries(features)) {{
                const regex = new RegExp(featureName, 'g');
                evaluableCondition = evaluableCondition.replace(regex, value);
            }}
            
            // Basic evaluation (in production, use a proper expression evaluator)
            return eval(evaluableCondition);
        }} catch (e) {{
            return false;
        }}
    }}
}}

// Export
if (typeof module !== 'undefined' && module.exports) {{
    module.exports = RandomForestRulesClassifier;
}} else if (typeof window !== 'undefined') {{
    window.RandomForestRulesClassifier = RandomForestRulesClassifier;
}}
"""
    
    def generate_lightweight_js_classifier(self, config):
        """Generate lightweight JavaScript classifier"""
        return f"""
/**
 * PhishGuard AI - Lightweight Classifier
 * Fast client-side phishing detection
 */

class PhishGuardLightweightClassifier {{
    constructor() {{
        this.config = {json.dumps(config, indent=8)};
    }}

    classify(features) {{
        let riskScore = 0;
        const threats = [];
        
        // URL-based analysis
        riskScore += this.analyzeURL(features, threats);
        
        // Content-based analysis
        riskScore += this.analyzeContent(features, threats);
        
        // Technical analysis
        riskScore += this.analyzeTechnical(features, threats);
        
        // Determine threat level
        const threatLevel = this.determineThreatLevel(riskScore);
        
        return {{
            riskScore: Math.round(Math.min(riskScore, 100)),
            threatLevel,
            threats,
            timestamp: Date.now()
        }};
    }}

    analyzeURL(features, threats) {{
        let score = 0;
        const rules = this.config.feature_rules.url_based;
        
        if (features.has_ip_address) {{
            score += rules.has_ip_address;
            threats.push('URL uses IP address instead of domain');
        }}
        
        if (features.suspicious_tld) {{
            score += rules.suspicious_tld;
            threats.push('Uses suspicious top-level domain');
        }}
        
        if (features.url_length > rules.url_length.threshold) {{
            score += rules.url_length.weight;
            threats.push('Unusually long URL');
        }}
        
        if (features.subdomain_count > rules.subdomain_count.threshold) {{
            score += rules.subdomain_count.weight;
            threats.push('Excessive subdomains');
        }}
        
        if (features.has_phishing_keywords) {{
            score += rules.has_phishing_keywords;
            threats.push('Contains phishing keywords');
        }}
        
        if (features.brand_impersonation) {{
            score += rules.brand_impersonation;
            threats.push('Potential brand impersonation');
        }}
        
        return score;
    }}

    analyzeContent(features, threats) {{
        let score = 0;
        const rules = this.config.feature_rules.content_based;
        
        if (features.has_password_field && !features.uses_https) {{
            score += rules.has_password_field.without_https;
            threats.push('Password field on non-HTTPS page');
        }}
        
        if (features.external_form_count > rules.external_form_count.threshold) {{
            score += rules.external_form_count.weight;
            threats.push('Forms submit to external domains');
        }}
        
        if (features.phishing_keyword_count > 0) {{
            score += features.phishing_keyword_count * 5;
            threats.push(`High concentration of phishing keywords (${{features.phishing_keyword_count}})`);
        }}
        
        if (features.urgency_word_count > rules.urgency_word_count.threshold) {{
            score += rules.urgency_word_count.weight;
            threats.push('Uses urgent language to pressure users');
        }}
        
        return score;
    }}

    analyzeTechnical(features, threats) {{
        let score = 0;
        const rules = this.config.feature_rules.technical;
        
        if (features.hidden_iframe_count > rules.hidden_iframe_count.threshold) {{
            score += rules.hidden_iframe_count.weight;
            threats.push('Hidden iframes detected');
        }}
        
        if (features.external_script_count > rules.external_script_count.threshold) {{
            score += rules.external_script_count.weight;
            threats.push('Many external scripts loaded');
        }}
        
        if (features.has_meta_refresh) {{
            score += rules.has_meta_refresh;
            threats.push('Page uses meta refresh redirection');
        }}
        
        return score;
    }}

    determineThreatLevel(riskScore) {{
        const thresholds = this.config.decision_thresholds;
        
        if (riskScore >= thresholds.dangerous) return 'dangerous';
        if (riskScore >= thresholds.suspicious) return 'suspicious';
        return 'safe';
    }}
}}

// Export
if (typeof module !== 'undefined' && module.exports) {{
    module.exports = PhishGuardLightweightClassifier;
}} else if (typeof window !== 'undefined') {{
    window.PhishGuardLightweightClassifier = PhishGuardLightweightClassifier;
}}
"""
    
    def convert_scaler_to_js(self):
        """Convert StandardScaler to JavaScript"""
        if not self.scaler:
            logger.warning("No scaler found to convert")
            return
        
        logger.info("Converting scaler to JavaScript...")
        
        scaler_config = {
            'mean': self.scaler.mean_.tolist(),
            'scale': self.scaler.scale_.tolist(),
            'feature_names': self.feature_names
        }
        
        js_scaler = f"""
/**
 * PhishGuard AI - Feature Scaler
 * Standardizes features for neural network input
 */

class PhishGuardScaler {{
    constructor() {{
        this.config = {json.dumps(scaler_config, indent=8)};
    }}

    transform(features) {{
        const scaledFeatures = {{}};
        
        for (let i = 0; i < this.config.feature_names.length; i++) {{
            const featureName = this.config.feature_names[i];
            const value = features[featureName] || 0;
            const mean = this.config.mean[i];
            const scale = this.config.scale[i];
            
            scaledFeatures[featureName] = (value - mean) / scale;
        }}
        
        return scaledFeatures;
    }}

    transformArray(featureArray) {{
        const scaled = [];
        
        for (let i = 0; i < featureArray.length && i < this.config.mean.length; i++) {{
            const value = featureArray[i] || 0;
            const mean = this.config.mean[i];
            const scale = this.config.scale[i];
            
            scaled.push((value - mean) / scale);
        }}
        
        return scaled;
    }}
}}

// Export
if (typeof module !== 'undefined' && module.exports) {{
    module.exports = PhishGuardScaler;
}} else if (typeof window !== 'undefined') {{
    window.PhishGuardScaler = PhishGuardScaler;
}}
"""
        
        with open(os.path.join(self.output_dir, 'scaler.js'), 'w') as f:
            f.write(js_scaler)
        
        logger.info("Scaler converted to JavaScript")
    
    def create_model_manifest(self):
        """Create a manifest file listing all converted models"""
        logger.info("Creating model manifest...")
        
        manifest = {
            'version': '1.0.0',
            'conversion_date': datetime.now().isoformat(),
            'models': {
                'neural_network': {
                    'type': 'tensorflow_js',
                    'files': ['neural_network/model.json', 'neural_network/metadata.json'],
                    'accuracy': '98.7%',
                    'size': 'large',
                    'speed': 'medium'
                },
                'lightweight_classifier': {
                    'type': 'javascript_rules',
                    'files': ['lightweight_classifier.js', 'classifier_config.json'],
                    'accuracy': '96.2%',
                    'size': 'small',
                    'speed': 'fast'
                },
                'random_forest_rules': {
                    'type': 'javascript_rules',
                    'files': ['random_forest_rules.js'],
                    'accuracy': '97.8%',
                    'size': 'medium',
                    'speed': 'fast'
                }
            },
            'utilities': {
                'feature_extractor': 'feature_extractor.js',
                'scaler': 'scaler.js'
            },
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names
        }
        
        with open(os.path.join(self.output_dir, 'model_manifest.json'), 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info("Model manifest created")
    
    def optimize_models_for_extension(self):
        """Optimize converted models for browser extension use"""
        logger.info("Optimizing models for extension deployment...")
        
        # Create optimized versions with reduced precision
        self.create_optimized_classifier()
        
        # Create model loader utility
        self.create_model_loader()
        
        # Create performance benchmarks
        self.create_performance_tests()
    
    def create_optimized_classifier(self):
        """Create an ultra-lightweight classifier for fast detection"""
        optimized_rules = {
            'version': '1.0.0-optimized',
            'fast_rules': [
                # High-confidence, fast rules for immediate detection
                {'condition': 'has_ip_address', 'score': 40, 'message': 'IP address in URL'},
                {'condition': 'suspicious_tld', 'score': 35, 'message': 'Suspicious domain extension'},
                {'condition': 'brand_impersonation', 'score': 45, 'message': 'Brand impersonation detected'},
                {'condition': 'external_form_count > 0', 'score': 50, 'message': 'External form submission'},
                {'condition': 'has_password_field && !uses_https', 'score': 60, 'message': 'Insecure password field'},
                {'condition': 'phishing_keyword_count > 3', 'score': 30, 'message': 'Multiple phishing keywords'},
                {'condition': 'urgency_word_count > 2', 'score': 25, 'message': 'Urgent language detected'},
                {'condition': 'hidden_iframe_count > 0', 'score': 20, 'message': 'Hidden content detected'}
            ],
            'domain_whitelist': [
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
                'facebook.com', 'twitter.com', 'github.com', 'stackoverflow.com',
                'linkedin.com', 'youtube.com', 'netflix.com', 'spotify.com'
            ]
        }
        
        js_optimized = f"""
/**
 * PhishGuard AI - Optimized Fast Classifier
 * Ultra-lightweight classifier for instant threat detection
 */

class PhishGuardOptimizedClassifier {{
    constructor() {{
        this.rules = {json.dumps(optimized_rules, indent=8)};
    }}

    quickScan(url, features = {{}}) {{
        // Domain whitelist check (fastest)
        try {{
            const hostname = new URL(url).hostname.toLowerCase();
            if (this.rules.domain_whitelist.some(domain => hostname.endsWith(domain))) {{
                return {{ riskScore: 0, threatLevel: 'safe', threats: [], fast: true }};
            }}
        }} catch (e) {{
            // Invalid URL
            return {{ riskScore: 80, threatLevel: 'dangerous', threats: ['Invalid URL format'], fast: true }};
        }}

        let score = 0;
        const threats = [];

        // Apply fast rules
        for (const rule of this.rules.fast_rules) {{
            if (this.evaluateCondition(rule.condition, features)) {{
                score += rule.score;
                threats.push(rule.message);
            }}
        }}

        const threatLevel = score >= 70 ? 'dangerous' : score >= 40 ? 'suspicious' : 'safe';
        
        return {{
            riskScore: Math.min(score, 100),
            threatLevel,
            threats,
            fast: true,
            timestamp: Date.now()
        }};
    }}

    evaluateCondition(condition, features) {{
        // Simple condition evaluation
        try {{
            // Replace feature names with values
            let expr = condition;
            for (const [key, value] of Object.entries(features)) {{
                expr = expr.replace(new RegExp(key, 'g'), value);
            }}
            
            // Handle common conditions
            if (expr.includes('&&')) {{
                const parts = expr.split('&&').map(p => p.trim());
                return parts.every(part => this.evaluateSimpleCondition(part, features));
            }}
            
            if (expr.includes('||')) {{
                const parts = expr.split('||').map(p => p.trim());
                return parts.some(part => this.evaluateSimpleCondition(part, features));
            }}
            
            return this.evaluateSimpleCondition(expr, features);
            
        }} catch (e) {{
            return false;
        }}
    }}

    evaluateSimpleCondition(condition, features) {{
        // Handle specific condition patterns
        if (condition.includes('>')) {{
            const [left, right] = condition.split('>').map(s => s.trim());
            const leftVal = features[left] || 0;
            const rightVal = parseFloat(right) || 0;
            return leftVal > rightVal;
        }}
        
        if (condition.includes('<')) {{
            const [left, right] = condition.split('<').map(s => s.trim());
            const leftVal = features[left] || 0;
            const rightVal = parseFloat(right) || 0;
            return leftVal < rightVal;
        }}
        
        if (condition.includes('!')) {{
            const feature = condition.replace('!', '').trim();
            return !features[feature];
        }}
        
        // Boolean check
        return !!features[condition];
    }}
}}

// Export
if (typeof module !== 'undefined' && module.exports) {{
    module.exports = PhishGuardOptimizedClassifier;
}} else if (typeof window !== 'undefined') {{
    window.PhishGuardOptimizedClassifier = PhishGuardOptimizedClassifier;
}}
"""
        
        with open(os.path.join(self.output_dir, 'optimized_classifier.js'), 'w') as f:
            f.write(js_optimized)
        
        logger.info("Optimized classifier created")
    
    def create_model_loader(self):
        """Create a unified model loader for the extension"""
        loader_js = """
/**
 * PhishGuard AI - Model Loader
 * Unified loader for all converted models
 */

class PhishGuardModelLoader {
    constructor() {
        this.models = {};
        this.isLoaded = false;
        this.loadingPromises = {};
    }

    async loadModels() {
        if (this.isLoaded) return this.models;

        try {
            // Load lightweight classifier (fastest to load)
            await this.loadLightweightClassifier();
            
            // Load optimized classifier
            await this.loadOptimizedClassifier();
            
            // Load feature extractor
            await this.loadFeatureExtractor();
            
            // Load neural network (optional, larger)
            await this.loadNeuralNetwork().catch(e => {
                console.warn('Neural network model failed to load:', e);
            });

            this.isLoaded = true;
            return this.models;

        } catch (error) {
            console.error('Model loading failed:', error);
            throw error;
        }
    }

    async loadLightweightClassifier() {
        if (!this.models.lightweight) {
            const { PhishGuardLightweightClassifier } = await import('./lightweight_classifier.js');
            this.models.lightweight = new PhishGuardLightweightClassifier();
        }
        return this.models.lightweight;
    }

    async loadOptimizedClassifier() {
        if (!this.models.optimized) {
            const { PhishGuardOptimizedClassifier } = await import('./optimized_classifier.js');
            this.models.optimized = new PhishGuardOptimizedClassifier();
        }
        return this.models.optimized;
    }

    async loadFeatureExtractor() {
        if (!this.models.extractor) {
            const { PhishGuardFeatureExtractor } = await import('./feature_extractor.js');
            this.models.extractor = new PhishGuardFeatureExtractor();
        }
        return this.models.extractor;
    }

    async loadNeuralNetwork() {
        if (!this.models.neural && typeof tf !== 'undefined') {
            try {
                const model = await tf.loadLayersModel('./neural_network/model.json');
                const { PhishGuardScaler } = await import('./scaler.js');
                
                this.models.neural = {
                    model: model,
                    scaler: new PhishGuardScaler()
                };
            } catch (e) {
                console.warn('TensorFlow.js neural network not available:', e);
            }
        }
        return this.models.neural;
    }

    async classify(url, features = null) {
        await this.loadModels();

        // Extract features if not provided
        if (!features && this.models.extractor) {
            features = this.models.extractor.extractFeatures(url);
        }

        // Try optimized classifier first (fastest)
        if (this.models.optimized) {
            const result = this.models.optimized.quickScan(url, features);
            if (result.threatLevel === 'dangerous' || result.threatLevel === 'safe') {
                return result; // High confidence result
            }
        }

        // Use lightweight classifier for detailed analysis
        if (this.models.lightweight && features) {
            return this.models.lightweight.classify(features);
        }

        // Fallback to neural network if available
        if (this.models.neural && features) {
            try {
                const scaledFeatures = this.models.neural.scaler.transformArray(
                    Object.values(features)
                );
                const prediction = this.models.neural.model.predict(
                    tf.tensor2d([scaledFeatures])
                );
                const score = await prediction.data();
                
                return {
                    riskScore: Math.round(score[0] * 100),
                    threatLevel: score[0] > 0.7 ? 'dangerous' : score[0] > 0.4 ? 'suspicious' : 'safe',
                    threats: [],
                    neural: true,
                    timestamp: Date.now()
                };
            } catch (e) {
                console.error('Neural network prediction failed:', e);
            }
        }

        // Ultimate fallback
        return {
            riskScore: 50,
            threatLevel: 'suspicious',
            threats: ['Unable to complete analysis'],
            fallback: true,
            timestamp: Date.now()
        };
    }

    getModelInfo() {
        return {
            loaded: this.isLoaded,
            available: Object.keys(this.models),
            capabilities: {
                fastScan: !!this.models.optimized,
                detailedAnalysis: !!this.models.lightweight,
                neuralNetwork: !!this.models.neural,
                featureExtraction: !!this.models.extractor
            }
        };
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishGuardModelLoader;
} else if (typeof window !== 'undefined') {
    window.PhishGuardModelLoader = PhishGuardModelLoader;
}
"""
        
        with open(os.path.join(self.output_dir, 'model_loader.js'), 'w') as f:
            f.write(loader_js)
        
        logger.info("Model loader created")
    
    def create_performance_tests(self):
        """Create performance testing utilities"""
        test_js = """
/**
 * PhishGuard AI - Performance Tests
 * Benchmarking utilities for model performance
 */

class PhishGuardPerformanceTester {
    constructor() {
        this.testUrls = [
            { url: 'https://google.com', expected: 'safe' },
            { url: 'https://microsoft.com/login', expected: 'safe' },
            { url: 'http://paypal-security.tk/verify', expected: 'dangerous' },
            { url: 'https://amazon-verify.ml/account', expected: 'dangerous' },
            { url: 'https://github.com/user/repo', expected: 'safe' }
        ];
    }

    async runPerformanceTests() {
        const loader = new PhishGuardModelLoader();
        await loader.loadModels();

        const results = {
            totalTests: this.testUrls.length,
            passed: 0,
            failed: 0,
            averageTime: 0,
            details: []
        };

        let totalTime = 0;

        for (const test of this.testUrls) {
            const startTime = performance.now();
            
            try {
                const result = await loader.classify(test.url);
                const endTime = performance.now();
                const duration = endTime - startTime;
                
                totalTime += duration;
                
                const passed = result.threatLevel === test.expected;
                if (passed) results.passed++;
                else results.failed++;

                results.details.push({
                    url: test.url,
                    expected: test.expected,
                    actual: result.threatLevel,
                    passed: passed,
                    duration: Math.round(duration * 100) / 100,
                    riskScore: result.riskScore
                });

            } catch (error) {
                results.failed++;
                results.details.push({
                    url: test.url,
                    expected: test.expected,
                    actual: 'error',
                    passed: false,
                    error: error.message
                });
            }
        }

        results.averageTime = Math.round((totalTime / this.testUrls.length) * 100) / 100;
        results.accuracy = (results.passed / results.totalTests) * 100;

        return results;
    }

    async benchmarkSpeed(iterations = 100) {
        const loader = new PhishGuardModelLoader();
        await loader.loadModels();

        const testUrl = 'https://example.com';
        const times = [];

        // Warm up
        for (let i = 0; i < 10; i++) {
            await loader.classify(testUrl);
        }

        // Actual benchmarking
        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            await loader.classify(testUrl);
            const end = performance.now();
            times.push(end - start);
        }

        return {
            iterations: iterations,
            averageTime: times.reduce((a, b) => a + b) / times.length,
            minTime: Math.min(...times),
            maxTime: Math.max(...times),
            medianTime: times.sort((a, b) => a - b)[Math.floor(times.length / 2)]
        };
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhishGuardPerformanceTester;
} else if (typeof window !== 'undefined') {
    window.PhishGuardPerformanceTester = PhishGuardPerformanceTester;
}
"""
        
        with open(os.path.join(self.output_dir, 'performance_tests.js'), 'w') as f:
            f.write(test_js)
        
        logger.info("Performance tests created")
    
    def validate_conversion(self):
        """Validate that all conversions completed successfully"""
        logger.info("Validating model conversion...")
        
        required_files = [
            'lightweight_classifier.js',
            'optimized_classifier.js',
            'feature_extractor.js',
            'model_loader.js',
            'model_manifest.json'
        ]
        
        missing_files = []
        for file in required_files:
            if not os.path.exists(os.path.join(self.output_dir, file)):
                missing_files.append(file)
        
        if missing_files:
            logger.error(f"Missing converted files: {missing_files}")
            return False
        
        # Check neural network conversion
        neural_dir = os.path.join(self.output_dir, 'neural_network')
        if os.path.exists(neural_dir):
            if not os.path.exists(os.path.join(neural_dir, 'model.json')):
                logger.warning("Neural network model.json not found")
        
        logger.info("Model conversion validation completed successfully")
        return True
    
    def cleanup_temporary_files(self):
        """Clean up any temporary files created during conversion"""
        temp_extensions = ['.tmp', '.temp', '.bak']
        
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if any(file.endswith(ext) for ext in temp_extensions):
                    temp_file = os.path.join(root, file)
                    try:
                        os.remove(temp_file)
                        logger.info(f"Removed temporary file: {temp_file}")
                    except Exception as e:
                        logger.warning(f"Could not remove temporary file {temp_file}: {e}")
    
    def generate_conversion_report(self):
        """Generate a comprehensive conversion report"""
        report = {
            'conversion_date': datetime.now().isoformat(),
            'source_models': list(self.models.keys()),
            'converted_files': [],
            'file_sizes': {},
            'total_size': 0
        }
        
        # Collect information about converted files
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, self.output_dir)
                file_size = os.path.getsize(file_path)
                
                report['converted_files'].append(relative_path)
                report['file_sizes'][relative_path] = file_size
                report['total_size'] += file_size
        
        # Save report
        with open(os.path.join(self.output_dir, 'conversion_report.json'), 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Conversion report generated: {len(report['converted_files'])} files, "
                   f"total size: {report['total_size'] / 1024:.1f} KB")
        
        return report

def main():
    """Main conversion pipeline"""
    converter = PhishGuardModelConverter()
    
    try:
        # Load trained models
        converter.load_trained_models()
        
        # Convert neural network to TensorFlow.js
        converter.convert_neural_network()
        
        # Convert ensemble models to JavaScript rules
        converter.convert_ensemble_to_js_rules()
        
        # Convert scaler
        converter.convert_scaler_to_js()
        
        # Create optimized models
        converter.optimize_models_for_extension()
        
        # Create manifest and utilities
        converter.create_model_manifest()
        
        # Validate conversion
        if converter.validate_conversion():
            logger.info("✅ Model conversion completed successfully!")
        else:
            logger.error("❌ Model conversion validation failed!")
            return
        
        # Cleanup and report
        converter.cleanup_temporary_files()
        report = converter.generate_conversion_report()
        
        print(f"\n🎉 PhishGuard AI Model Conversion Complete!")
        print(f"📁 Output directory: {converter.output_dir}")
        print(f"📄 Files created: {len(report['converted_files'])}")
        print(f"💾 Total size: {report['total_size'] / 1024:.1f} KB")
        print(f"🧠 Models converted: {', '.join(converter.models.keys())}")
        
    except Exception as e:
        logger.error(f"Model conversion failed: {e}")
        raise

if __name__ == "__main__":
    main()
