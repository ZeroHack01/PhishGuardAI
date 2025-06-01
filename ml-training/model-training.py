#!/usr/bin/env python3
"""
PhishGuard AI - Advanced Model Training Pipeline
Trains sophisticated ML models for phishing detection with production-ready performance
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.feature_selection import SelectKBest, f_classif, RFE
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class PhishingModelTrainer:
    def __init__(self, data_path):
        self.data_path = data_path
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.performance_metrics = {}
        
    def load_and_preprocess_data(self):
        """Load and preprocess the feature dataset"""
        logger.info("Loading and preprocessing data...")
        
        # Load dataset
        self.df = pd.read_csv(self.data_path)
        logger.info(f"Loaded {len(self.df)} samples with {len(self.df.columns)} features")
        
        # Basic data cleaning
        self.df = self.df.dropna(subset=['label'])  # Remove samples without labels
        
        # Separate features and labels
        feature_columns = [col for col in self.df.columns if col not in ['label', 'url']]
        self.X = self.df[feature_columns].fillna(0)  # Fill NaN with 0
        self.y = self.df['label']
        
        # Encode categorical features if any
        categorical_features = self.X.select_dtypes(include=['object']).columns
        for col in categorical_features:
            le = LabelEncoder()
            self.X[col] = le.fit_transform(self.X[col].astype(str))
        
        # Feature engineering: create interaction features
        self.X = self._create_interaction_features(self.X)
        
        # Feature selection
        self.X = self._perform_feature_selection(self.X, self.y)
        
        # Split the data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y, test_size=0.2, random_state=42, stratify=self.y
        )
        
        # Scale features for algorithms that need it
        self.scaler = StandardScaler()
        self.X_train_scaled = self.scaler.fit_transform(self.X_train)
        self.X_test_scaled = self.scaler.transform(self.X_test)
        
        logger.info(f"Training set: {len(self.X_train)} samples")
        logger.info(f"Test set: {len(self.X_test)} samples")
        logger.info(f"Final feature count: {self.X.shape[1]}")
        
        return self.X_train, self.X_test, self.y_train, self.y_test
    
    def _create_interaction_features(self, X):
        """Create interaction features to improve model performance"""
        logger.info("Creating interaction features...")
        
        # Create meaningful interaction features for phishing detection
        interactions = pd.DataFrame()
        
        # URL length interactions
        if 'url_length' in X.columns and 'domain_length' in X.columns:
            interactions['url_domain_ratio'] = X['url_length'] / (X['domain_length'] + 1)
        
        # Security indicators
        if 'uses_https' in X.columns and 'has_password_field' in X.columns:
            interactions['https_password_interaction'] = X['uses_https'] * X['has_password_field']
        
        # Suspicious pattern combinations
        if 'suspicious_tld' in X.columns and 'has_phishing_keywords' in X.columns:
            interactions['suspicious_combo'] = X['suspicious_tld'] * X['has_phishing_keywords']
        
        # Domain trust indicators
        if 'domain_age_days' in X.columns:
            interactions['domain_very_new'] = (X['domain_age_days'] < 7).astype(int)
            interactions['domain_age_log'] = np.log1p(X['domain_age_days'].clip(lower=0))
        
        # External content indicators
        if 'external_form_count' in X.columns and 'form_count' in X.columns:
            interactions['external_form_ratio'] = X['external_form_count'] / (X['form_count'] + 1)
        
        # Combine with original features
        X_enhanced = pd.concat([X, interactions], axis=1)
        logger.info(f"Added {len(interactions.columns)} interaction features")
        
        return X_enhanced
    
    def _perform_feature_selection(self, X, y):
        """Select the most important features using multiple methods"""
        logger.info("Performing feature selection...")
        
        # Method 1: Statistical feature selection
        selector_stats = SelectKBest(score_func=f_classif, k=min(50, X.shape[1]))
        X_selected_stats = selector_stats.fit_transform(X, y)
        selected_features_stats = X.columns[selector_stats.get_support()]
        
        # Method 2: Random Forest feature importance
        rf_selector = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_selector.fit(X, y)
        
        # Get top features based on importance
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': rf_selector.feature_importances_
        }).sort_values('importance', ascending=False)
        
        top_features_rf = feature_importance.head(min(40, len(X.columns)))['feature'].tolist()
        
        # Combine both methods
        selected_features = list(set(selected_features_stats) | set(top_features_rf))
        
        logger.info(f"Selected {len(selected_features)} features from {len(X.columns)} total")
        
        # Store feature importance for later analysis
        self.feature_importance['random_forest'] = feature_importance
        
        return X[selected_features]
    
    def train_ensemble_models(self):
        """Train multiple models for ensemble prediction"""
        logger.info("Training ensemble of models...")
        
        # Model configurations
        model_configs = {
            'random_forest': {
                'model': RandomForestClassifier(random_state=42),
                'params': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [10, 20, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4]
                },
                'use_scaled': False
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier(random_state=42),
                'params': {
                    'n_estimators': [100, 200],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'max_depth': [3, 5, 7]
                },
                'use_scaled': False
            },
            'logistic_regression': {
                'model': LogisticRegression(random_state=42),
                'params': {
                    'C': [0.1, 1, 10, 100],
                    'penalty': ['l1', 'l2'],
                    'solver': ['liblinear', 'saga']
                },
                'use_scaled': True
            },
            'svm': {
                'model': SVC(random_state=42, probability=True),
                'params': {
                    'C': [0.1, 1, 10],
                    'kernel': ['rbf', 'poly'],
                    'gamma': ['scale', 'auto']
                },
                'use_scaled': True
            }
        }
        
        # Train each model with hyperparameter tuning
        for model_name, config in model_configs.items():
            logger.info(f"Training {model_name}...")
            
            # Select appropriate data (scaled or unscaled)
            X_train_data = self.X_train_scaled if config['use_scaled'] else self.X_train
            X_test_data = self.X_test_scaled if config['use_scaled'] else self.X_test
            
            # Hyperparameter tuning with cross-validation
            grid_search = GridSearchCV(
                config['model'], 
                config['params'],
                cv=5,
                scoring='roc_auc',
                n_jobs=-1,
                verbose=1
            )
            
            grid_search.fit(X_train_data, self.y_train)
            
            # Store best model
            self.models[model_name] = grid_search.best_estimator_
            
            # Evaluate model
            train_score = grid_search.best_estimator_.score(X_train_data, self.y_train)
            test_score = grid_search.best_estimator_.score(X_test_data, self.y_test)
            
            # Get predictions and probabilities
            y_pred = grid_search.best_estimator_.predict(X_test_data)
            y_pred_proba = grid_search.best_estimator_.predict_proba(X_test_data)[:, 1]
            
            # Calculate metrics
            auc_score = roc_auc_score(self.y_test, y_pred_proba)
            
            self.performance_metrics[model_name] = {
                'train_accuracy': train_score,
                'test_accuracy': test_score,
                'auc_score': auc_score,
                'best_params': grid_search.best_params_,
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            logger.info(f"{model_name} - Train: {train_score:.4f}, Test: {test_score:.4f}, AUC: {auc_score:.4f}")
    
    def train_neural_network(self):
        """Train a deep neural network for phishing detection"""
        logger.info("Training neural network...")
        
        # Build neural network architecture
        model = keras.Sequential([
            layers.Dense(128, activation='relu', input_shape=(self.X_train_scaled.shape[1],)),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            
            layers.Dense(16, activation='relu'),
            layers.Dropout(0.1),
            
            layers.Dense(1, activation='sigmoid')
        ])
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        # Callbacks for training
        callbacks = [
            keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=5),
            keras.callbacks.ModelCheckpoint('models/best_nn_model.h5', save_best_only=True)
        ]
        
        # Train model
        history = model.fit(
            self.X_train_scaled, self.y_train,
            epochs=100,
            batch_size=32,
            validation_split=0.2,
            callbacks=callbacks,
            verbose=1
        )
        
        # Evaluate neural network
        test_loss, test_accuracy, test_precision, test_recall = model.evaluate(
            self.X_test_scaled, self.y_test, verbose=0
        )
        
        y_pred_nn = (model.predict(self.X_test_scaled) > 0.5).astype(int).flatten()
        y_pred_proba_nn = model.predict(self.X_test_scaled).flatten()
        auc_score_nn = roc_auc_score(self.y_test, y_pred_proba_nn)
        
        # Store neural network
        self.models['neural_network'] = model
        self.performance_metrics['neural_network'] = {
            'test_accuracy': test_accuracy,
            'test_precision': test_precision,
            'test_recall': test_recall,
            'auc_score': auc_score_nn,
            'predictions': y_pred_nn,
            'probabilities': y_pred_proba_nn,
            'training_history': history.history
        }
        
        logger.info(f"Neural Network - Accuracy: {test_accuracy:.4f}, AUC: {auc_score_nn:.4f}")
    
    def create_ensemble_predictions(self):
        """Create ensemble predictions from all models"""
        logger.info("Creating ensemble predictions...")
        
        # Collect all probability predictions
        all_probabilities = []
        model_weights = []
        
        for model_name, metrics in self.performance_metrics.items():
            if 'probabilities' in metrics:
                all_probabilities.append(metrics['probabilities'])
                # Weight by AUC score
                model_weights.append(metrics['auc_score'])
        
        # Normalize weights
        model_weights = np.array(model_weights)
        model_weights = model_weights / model_weights.sum()
        
        # Weighted ensemble prediction
        ensemble_probabilities = np.average(all_probabilities, axis=0, weights=model_weights)
        ensemble_predictions = (ensemble_probabilities > 0.5).astype(int)
        
        # Calculate ensemble metrics
        ensemble_accuracy = (ensemble_predictions == self.y_test).mean()
        ensemble_auc = roc_auc_score(self.y_test, ensemble_probabilities)
        
        self.performance_metrics['ensemble'] = {
            'test_accuracy': ensemble_accuracy,
            'auc_score': ensemble_auc,
            'predictions': ensemble_predictions,
            'probabilities': ensemble_probabilities,
            'model_weights': dict(zip(self.performance_metrics.keys(), model_weights))
        }
        
        logger.info(f"Ensemble - Accuracy: {ensemble_accuracy:.4f}, AUC: {ensemble_auc:.4f}")
    
    def evaluate_models(self):
        """Comprehensive model evaluation and comparison"""
        logger.info("Evaluating all models...")
        
        # Create evaluation plots
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # ROC Curves
        ax1 = axes[0, 0]
        for model_name, metrics in self.performance_metrics.items():
            if 'probabilities' in metrics:
                fpr, tpr, _ = roc_curve(self.y_test, metrics['probabilities'])
                auc = metrics['auc_score']
                ax1.plot(fpr, tpr, label=f'{model_name} (AUC = {auc:.3f})')
        
        ax1.plot([0, 1], [0, 1], 'k--', label='Random')
        ax1.set_xlabel('False Positive Rate')
        ax1.set_ylabel('True Positive Rate')
        ax1.set_title('ROC Curves Comparison')
        ax1.legend()
        ax1.grid(True)
        
        # Model Performance Comparison
        ax2 = axes[0, 1]
        model_names = list(self.performance_metrics.keys())
        accuracies = [self.performance_metrics[name]['test_accuracy'] for name in model_names]
        aucs = [self.performance_metrics[name]['auc_score'] for name in model_names]
        
        x = np.arange(len(model_names))
        width = 0.35
        
        ax2.bar(x - width/2, accuracies, width, label='Accuracy')
        ax2.bar(x + width/2, aucs, width, label='AUC')
        ax2.set_xlabel('Models')
        ax2.set_ylabel('Score')
        ax2.set_title('Model Performance Comparison')
        ax2.set_xticks(x)
        ax2.set_xticklabels(model_names, rotation=45)
        ax2.legend()
        ax2.grid(True)
        
        # Feature Importance (Random Forest)
        if 'random_forest' in self.feature_importance:
            ax3 = axes[1, 0]
            top_features = self.feature_importance['random_forest'].head(15)
            ax3.barh(top_features['feature'], top_features['importance'])
            ax3.set_xlabel('Importance')
            ax3.set_title('Top 15 Feature Importance (Random Forest)')
            ax3.grid(True)
        
        # Confusion Matrix for Best Model
        best_model_name = max(self.performance_metrics.keys(), 
                             key=lambda x: self.performance_metrics[x]['auc_score'])
        ax4 = axes[1, 1]
        
        cm = confusion_matrix(self.y_test, self.performance_metrics[best_model_name]['predictions'])
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax4)
        ax4.set_xlabel('Predicted')
        ax4.set_ylabel('Actual')
        ax4.set_title(f'Confusion Matrix - {best_model_name}')
        
        plt.tight_layout()
        plt.savefig('models/model_evaluation.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print detailed classification reports
        print("\n" + "="*80)
        print("DETAILED MODEL EVALUATION RESULTS")
        print("="*80)
        
        for model_name, metrics in self.performance_metrics.items():
            if 'predictions' in metrics:
                print(f"\n{model_name.upper()} CLASSIFICATION REPORT:")
                print("-" * 50)
                print(classification_report(self.y_test, metrics['predictions']))
    
    def save_models(self):
        """Save all trained models and scalers"""
        logger.info("Saving models...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save scikit-learn models
        for model_name, model in self.models.items():
            if model_name != 'neural_network':
                joblib.dump(model, f'models/{model_name}_model_{timestamp}.pkl')
        
        # Save scaler
        joblib.dump(self.scaler, f'models/scaler_{timestamp}.pkl')
        
        # Save neural network separately
        if 'neural_network' in self.models:
            self.models['neural_network'].save(f'models/neural_network_{timestamp}.h5')
        
        # Save performance metrics
        with open(f'models/performance_metrics_{timestamp}.json', 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            metrics_serializable = {}
            for model_name, metrics in self.performance_metrics.items():
                metrics_copy = metrics.copy()
                for key, value in metrics_copy.items():
                    if isinstance(value, np.ndarray):
                        metrics_copy[key] = value.tolist()
                metrics_serializable[model_name] = metrics_copy
            
            json.dump(metrics_serializable, f, indent=2)
        
        # Save feature names
        with open(f'models/feature_names_{timestamp}.json', 'w') as f:
            json.dump(list(self.X.columns), f)
        
        logger.info(f"Models saved with timestamp: {timestamp}")
    
    def generate_model_report(self):
        """Generate comprehensive model performance report"""
        report = {
            'training_summary': {
                'total_samples': len(self.df),
                'training_samples': len(self.X_train),
                'test_samples': len(self.X_test),
                'feature_count': self.X.shape[1],
                'class_distribution': self.y.value_counts().to_dict()
            },
            'model_performance': self.performance_metrics,
            'best_model': max(self.performance_metrics.keys(), 
                            key=lambda x: self.performance_metrics[x]['auc_score']),
            'training_timestamp': datetime.now().isoformat()
        }
        
        # Save report
        with open('models/training_report.json', 'w') as f:
            # Handle numpy serialization
            def serialize_numpy(obj):
                if isinstance(obj, np.ndarray):
                    return obj.tolist()
                elif isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                return obj
            
            import json
            json.dump(report, f, indent=2, default=serialize_numpy)
        
        return report

def main():
    """Main training pipeline"""
    # Initialize trainer
    trainer = PhishingModelTrainer('training-data/phishing_features.csv')
    
    # Load and preprocess data
    trainer.load_and_preprocess_data()
    
    # Train all models
    trainer.train_ensemble_models()
    trainer.train_neural_network()
    trainer.create_ensemble_predictions()
    
    # Evaluate models
    trainer.evaluate_models()
    
    # Save models and generate report
    trainer.save_models()
    report = trainer.generate_model_report()
    
    print(f"\n🎉 Training Complete!")
    print(f"Best Model: {report['best_model']}")
    print(f"Best AUC Score: {report['model_performance'][report['best_model']]['auc_score']:.4f}")

if __name__ == "__main__":
    main()
