import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from typing import Dict, Any, Tuple, List
import logging
import joblib
import os
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Trusted domains whitelist - major legitimate websites
TRUSTED_DOMAINS = {
    'google.com', 'www.google.com', 'gmail.com', 'youtube.com',
    'microsoft.com', 'www.microsoft.com', 'office.com', 'outlook.com',
    'amazon.com', 'www.amazon.com', 'aws.amazon.com',
    'facebook.com', 'www.facebook.com', 'instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com',
    'stackoverflow.com', 'www.stackoverflow.com', 'stackexchange.com',
    'wikipedia.org', 'www.wikipedia.org',
    'twitter.com', 'x.com',
    'apple.com', 'www.apple.com', 'icloud.com',
    'yahoo.com', 'www.yahoo.com',
    'reddit.com', 'www.reddit.com',
    'netflix.com', 'www.netflix.com',
    'paypal.com', 'www.paypal.com',
    'ebay.com', 'www.ebay.com',
    'dropbox.com', 'www.dropbox.com',
    'adobe.com', 'www.adobe.com'
}


class HybridClassifier:
    def __init__(self):
        # Use ensemble of models for better precision
        self.models = {
            'rf': RandomForestClassifier(
                n_estimators=100, 
                random_state=42, 
                class_weight='balanced',
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2
            ),
            'gb': GradientBoostingClassifier(
                n_estimators=50,
                random_state=42,
                learning_rate=0.1,
                max_depth=6
            ),
            'lr': LogisticRegression(
                random_state=42, 
                max_iter=1000, 
                class_weight='balanced',
                C=0.1
            )
        }
        
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_fitted = False
        self.feature_importance = {}
        
        # Enhanced classification thresholds
        self.thresholds = {
            'phishing': 0.7,      # Higher threshold for phishing (more precision)
            'suspicious': 0.4,    # Medium threshold for suspicious
        }
        
        self._initialize_with_synthetic_data()
    
    def _initialize_with_synthetic_data(self):
        """Bootstrap the models with enhanced synthetic training data"""
        synthetic_data = self._generate_enhanced_synthetic_data()
        
        if len(synthetic_data) > 0:
            X, y = self._prepare_training_data(synthetic_data)
            self._train_models(X, y)
            logger.info(f"Initialized models with {len(synthetic_data)} synthetic samples")
    
    def _generate_enhanced_synthetic_data(self) -> List[Dict[str, Any]]:
        """Generate more comprehensive synthetic training examples"""
        synthetic_samples = []
        
        # High-confidence phishing examples
        phishing_samples = [
            {
                # URL features
                'url_length': 95, 'hostname_length': 32, 'subdomain_count': 4,
                'has_ip_address': False, 'has_suspicious_tld': True, 'dash_count': 5,
                'digit_count': 8, 'phishing_keyword_count': 3, 'url_entropy': 4.5,
                'hostname_entropy': 4.2, 'randomness_score': 0.8, 'brand_impersonation_score': 0.9,
                
                # Content features
                'has_forms': True, 'form_count': 2, 'has_password_input': True,
                'password_input_count': 2, 'phishing_keyword_density': 0.15,
                'urgent_keyword_count': 3, 'security_keyword_count': 4,
                'suspicious_title': 0.8, 'external_links_count': 12,
                'external_link_ratio': 0.9, 'suspicious_link_count': 6,
                
                # Advanced features
                'has_homograph_chars': True, 'certificate_warnings': True,
                'countdown_timer_present': True, 'obfuscated_content': True,
                'spelling_error_indicators': 0.3, 'domain_age_days': 3,
                'label': 'phishing'
            },
            {
                # Another phishing variant
                'url_length': 120, 'hostname_length': 45, 'subdomain_count': 5,
                'has_ip_address': True, 'has_suspicious_tld': False, 'dash_count': 3,
                'digit_count': 12, 'phishing_keyword_count': 4, 'url_entropy': 4.8,
                'hostname_entropy': 4.5, 'randomness_score': 0.9, 'brand_impersonation_score': 0.85,
                
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.12,
                'urgent_keyword_count': 2, 'security_keyword_count': 5,
                'suspicious_title': 0.9, 'external_links_count': 8,
                'external_link_ratio': 0.8, 'suspicious_link_count': 4,
                
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': True,
                'spelling_error_indicators': 0.2, 'domain_age_days': 1,
                'label': 'phishing'
            }
        ]
        
        # Suspicious examples (medium confidence)
        suspicious_samples = [
            {
                'url_length': 65, 'hostname_length': 25, 'subdomain_count': 2,
                'has_ip_address': False, 'has_suspicious_tld': True, 'dash_count': 2,
                'digit_count': 4, 'phishing_keyword_count': 1, 'url_entropy': 3.8,
                'hostname_entropy': 3.5, 'randomness_score': 0.4, 'brand_impersonation_score': 0.6,
                
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.05,
                'urgent_keyword_count': 1, 'security_keyword_count': 2,
                'suspicious_title': 0.4, 'external_links_count': 5,
                'external_link_ratio': 0.5, 'suspicious_link_count': 1,
                
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.1, 'domain_age_days': 30,
                'label': 'suspicious'
            }
        ]
        
        # Benign examples
        benign_samples = [
            {
                'url_length': 35, 'hostname_length': 15, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 0,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 2.8,
                'hostname_entropy': 2.5, 'randomness_score': 0.1, 'brand_impersonation_score': 0.0,
                
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.01,
                'urgent_keyword_count': 0, 'security_keyword_count': 1,
                'suspicious_title': 0.0, 'external_links_count': 2,
                'external_link_ratio': 0.2, 'suspicious_link_count': 0,
                
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 1095,
                'label': 'benign'
            },
            {
                'url_length': 28, 'hostname_length': 12, 'subdomain_count': 0,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 0,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 2.5,
                'hostname_entropy': 2.2, 'randomness_score': 0.05, 'brand_impersonation_score': 0.0,
                
                'has_forms': False, 'form_count': 0, 'has_password_input': False,
                'password_input_count': 0, 'phishing_keyword_density': 0.0,
                'urgent_keyword_count': 0, 'security_keyword_count': 0,
                'suspicious_title': 0.0, 'external_links_count': 3,
                'external_link_ratio': 0.3, 'suspicious_link_count': 0,
                
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 2190,
                'label': 'benign'
            }
        ]
        
        # Replicate samples to create more training data
        synthetic_samples.extend(phishing_samples * 3)
        synthetic_samples.extend(suspicious_samples * 2)
        synthetic_samples.extend(benign_samples * 4)
        
        return synthetic_samples
    
    def _prepare_training_data(self, samples: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Convert samples to feature matrix and labels"""
        X_list = []
        y_list = []
        
        for sample in samples:
            label = sample.pop('label')
            
            # Convert features to numeric values
            feature_vector = []
            for key, value in sample.items():
                if isinstance(value, bool):
                    feature_vector.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            X_list.append(feature_vector)
            
            # Convert labels to numeric
            if label == 'phishing':
                y_list.append(2)
            elif label == 'suspicious':
                y_list.append(1)
            else:  # benign
                y_list.append(0)
                
            # Re-add label for consistency
            sample['label'] = label
        
        # Store feature names from first sample
        if self.feature_names == [] and len(samples) > 0:
            sample_copy = samples[0].copy()
            sample_copy.pop('label', None)
            self.feature_names = list(sample_copy.keys())
        
        return np.array(X_list), np.array(y_list)
    
    def _train_models(self, X: np.ndarray, y: np.ndarray):
        """Train all models in the ensemble"""
        try:
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train each model
            for name, model in self.models.items():
                model.fit(X_scaled, y)
                logger.info(f"Trained {name} model with {len(X)} samples")
            
            # Calculate feature importance from Random Forest
            if 'rf' in self.models and self.feature_names:
                importance = self.models['rf'].feature_importances_
                self.feature_importance = dict(zip(self.feature_names, importance))
            
            self.is_fitted = True
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            raise
    
    def _ensemble_predict(self, X: np.ndarray) -> Tuple[np.ndarray, Dict[str, float]]:
        """Make predictions using ensemble of models"""
        if not self.is_fitted:
            raise ValueError("Models not fitted yet")
        
        X_scaled = self.scaler.transform(X)
        predictions = {}
        probabilities = {}
        
        # Get predictions from each model
        for name, model in self.models.items():
            pred = model.predict(X_scaled)
            pred_proba = model.predict_proba(X_scaled)
            predictions[name] = pred
            probabilities[name] = pred_proba
        
        # Ensemble voting with weighted average
        weights = {'rf': 0.4, 'gb': 0.4, 'lr': 0.2}  # RF and GB are more reliable
        
        final_probabilities = np.zeros((X.shape[0], 3))  # 3 classes: benign, suspicious, phishing
        
        for name, weight in weights.items():
            if name in probabilities:
                final_probabilities += weight * probabilities[name]
        
        # Get final predictions based on enhanced thresholds
        final_predictions = []
        confidence_scores = {}
        
        for i in range(X.shape[0]):
            proba = final_probabilities[i]
            phishing_prob = proba[2]  # Class 2 = phishing
            suspicious_prob = proba[1]  # Class 1 = suspicious
            benign_prob = proba[0]     # Class 0 = benign
            
            # Enhanced classification logic
            if phishing_prob >= self.thresholds['phishing']:
                final_predictions.append(2)
                risk_level = 'high'
            elif suspicious_prob >= self.thresholds['suspicious'] or phishing_prob >= 0.3:
                final_predictions.append(1)
                risk_level = 'medium'
            else:
                final_predictions.append(0)
                risk_level = 'low'
            
            confidence_scores[f'sample_{i}'] = {
                'phishing_probability': float(phishing_prob),
                'suspicious_probability': float(suspicious_prob),
                'benign_probability': float(benign_prob),
                'risk_level': risk_level,
                'confidence': float(max(proba))
            }
        
        return np.array(final_predictions), confidence_scores
    
    def _is_trusted_domain(self, url: str) -> bool:
        """Check if domain is in trusted whitelist"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            return domain in TRUSTED_DOMAINS
        except Exception:
            return False

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Make prediction for a single URL"""
        try:
            # Check if domain is trusted first
            url = features.get('url', '')
            if url and self._is_trusted_domain(url):
                logger.info(f"Domain recognized as trusted: {url}")
                return {
                    'prediction': 'benign',
                    'confidence': 0.99,
                    'confidence_score': 0.99,
                    'threat_level': 'LOW',
                    'phishing_probability': 0.01,
                    'suspicious_probability': 0.01,
                    'benign_probability': 0.99,
                    'risk_factors': [],
                    'explanation': 'This domain is recognized as a trusted, legitimate website.',
                    'model_explanation': 'Domain whitelist: Recognized as trusted legitimate website'
                }
            
            if not self.is_fitted:
                # Try to load saved model or use default
                self._initialize_with_synthetic_data()
            
            # Convert features to array
            feature_vector = []
            for feature_name in self.feature_names:
                value = features.get(feature_name, 0)
                if isinstance(value, bool):
                    feature_vector.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            X = np.array([feature_vector])
            predictions, confidence_scores = self._ensemble_predict(X)
            
            prediction = predictions[0]
            sample_confidence = confidence_scores.get('sample_0', {})
            
            # Map prediction to label
            if prediction == 2:
                prediction_label = 'phishing'
                threat_level = 'HIGH'
            elif prediction == 1:
                prediction_label = 'suspicious'
                threat_level = 'MEDIUM'
            else:
                prediction_label = 'benign'
                threat_level = 'LOW'
            
            # Get risk factors
            risk_factors = self._identify_risk_factors(features)
            
            # AGGRESSIVE PHISHING DETECTION - Check for obvious phishing patterns first
            obvious_phishing_indicators = []
            
            # Brand impersonation with suspicious subdomains (major red flag)
            if (features.get('subdomain_count', 0) >= 2 and 
                any(brand in features.get('hostname_length', 0) for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'twitter', 'instagram', 'allegro', 'ebay', 'netflix']) if isinstance(features.get('hostname_length'), str) else False):
                obvious_phishing_indicators.append('Brand impersonation with suspicious subdomains')
            
            # Multiple suspicious subdomains (often used in phishing)
            if features.get('subdomain_count', 0) >= 3:
                obvious_phishing_indicators.append('Multiple suspicious subdomains')
            
            # Very long domain names with numbers (common phishing pattern)
            if features.get('hostname_length', 0) > 30 and features.get('digit_count', 0) >= 8:
                obvious_phishing_indicators.append('Very long domain with many numbers')
            
            # Domain age less than 7 days (fresh phishing domains)
            if features.get('domain_age_days', 365) < 7 and features.get('domain_age_days', 365) != -1:
                obvious_phishing_indicators.append('Extremely new domain (less than 7 days)')
            
            # No HTTPS on suspicious domain
            if not features.get('uses_https', True) and features.get('subdomain_count', 0) >= 2:
                obvious_phishing_indicators.append('No HTTPS with suspicious subdomains')
            
            # If we have obvious phishing indicators, upgrade aggressively
            if len(obvious_phishing_indicators) >= 2:
                prediction_label = 'phishing'
                threat_level = 'HIGH'
                risk_factors.extend(obvious_phishing_indicators)
            elif len(obvious_phishing_indicators) >= 1:
                prediction_label = 'suspicious'
                threat_level = 'MEDIUM'
                risk_factors.extend(obvious_phishing_indicators)
            
            # Standard threat level upgrading based on risk factors
            elif threat_level == 'LOW' and len(risk_factors) >= 2:
                # Multiple risk factors should elevate to suspicious
                prediction_label = 'suspicious'
                threat_level = 'MEDIUM'
            elif threat_level == 'MEDIUM' and len(risk_factors) >= 3:
                # Many risk factors should elevate to high threat
                prediction_label = 'phishing'
                threat_level = 'HIGH'
            
            # Additional special cases for highly suspicious patterns
            suspicious_patterns = [
                features.get('has_ip_address', False),
                features.get('has_homograph_chars', False),
                features.get('brand_impersonation_score', 0) > 0.5,
                features.get('phishing_keyword_count', 0) > 2,
                features.get('url_length', 0) > 100,
                features.get('subdomain_count', 0) > 3,
                not features.get('uses_https', True),
                features.get('domain_age_days', 365) < 7,
                # Enhanced: Hosted infrastructure patterns
                features.get('is_hosted_infrastructure', False) and features.get('hosted_service_type') in ['ngrok', 'tunnel_service', 'free_hosting'],
                features.get('has_suspicious_tld', False),
                features.get('randomness_score', 0) > 0.8
            ]
            
            if sum(suspicious_patterns) >= 2 and threat_level == 'LOW':
                prediction_label = 'suspicious' 
                threat_level = 'MEDIUM'
            elif sum(suspicious_patterns) >= 3:
                prediction_label = 'phishing'
                threat_level = 'HIGH'
            
            result = {
                'prediction': prediction_label,
                'threat_level': threat_level,
                'confidence_score': sample_confidence.get('confidence', 0.5),
                'phishing_probability': sample_confidence.get('phishing_probability', 0.0),
                'risk_factors': risk_factors,
                'model_explanation': self._explain_prediction(features, {
                    'risk_level': threat_level.lower(),
                    'confidence': sample_confidence.get('confidence', 0.5),
                    'prediction': prediction_label,
                    'threat_level': threat_level
                })
            }
            
            logger.info(f"Prediction: {prediction_label} (confidence: {result['confidence_score']:.3f})")
            return result
            
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            # Return conservative prediction
            return {
                'prediction': 'suspicious',
                'threat_level': 'MEDIUM',
                'confidence_score': 0.5,
                'phishing_probability': 0.5,
                'risk_factors': ['Error in prediction model'],
                'model_explanation': f'Model error: {str(e)}'
            }
    
    def _identify_risk_factors(self, features: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors based on feature values"""
        risk_factors = []
        
        # AGGRESSIVE BRAND IMPERSONATION DETECTION
        hostname = features.get('hostname', '').lower()
        known_brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 
                       'twitter', 'instagram', 'allegro', 'ebay', 'netflix', 'linkedin',
                       'github', 'dropbox', 'wordpress', 'shopify', 'stripe', 'visa',
                       'mastercard', 'americanexpress', 'discover']
        
        # Check for brand impersonation patterns in hostname
        for brand in known_brands:
            if brand in hostname and not hostname.startswith(brand + '.'):
                # Brand name appears but not as the main domain (likely impersonation)
                if features.get('subdomain_count', 0) >= 1:
                    risk_factors.append(f'Potential {brand.title()} brand impersonation with subdomains')
        
        # URL-based risks
        if features.get('has_ip_address', False):
            risk_factors.append('URL contains IP address instead of domain name')
        
        if features.get('url_length', 0) > 80:
            risk_factors.append('Unusually long URL')
        
        if features.get('subdomain_count', 0) > 2:
            risk_factors.append('Multiple suspicious subdomains')
        
        # Aggressive detection of suspicious domain patterns
        if features.get('hostname_length', 0) > 30 and features.get('digit_count', 0) >= 5:
            risk_factors.append('Very long domain name with many numbers')
        
        if features.get('has_suspicious_tld', False):
            risk_factors.append('Suspicious top-level domain')
        
        if features.get('dash_count', 0) > 3:
            risk_factors.append('Excessive dashes in URL (typosquatting)')
        
        if features.get('brand_impersonation_score', 0) > 0.7:
            risk_factors.append('Potential brand impersonation detected')
        
        if features.get('has_homograph_chars', False):
            risk_factors.append('Homograph/Unicode spoofing characters detected')
        
        # Content-based risks
        if features.get('has_password_input', False) and features.get('certificate_warnings', False):
            risk_factors.append('Password input on insecure connection')
        
        if features.get('phishing_keyword_density', 0) > 0.1:
            risk_factors.append('High density of phishing-related keywords')
        
        if features.get('urgent_keyword_count', 0) > 2:
            risk_factors.append('Urgent language designed to create pressure')
        
        if features.get('countdown_timer_present', False):
            risk_factors.append('Countdown timer creating false urgency')
        
        if features.get('obfuscated_content', False):
            risk_factors.append('Content obfuscation detected')
        
        if features.get('spelling_error_indicators', 0) > 0.2:
            risk_factors.append('High number of spelling errors')
        
        # Domain-based risks  
        if features.get('domain_age_days', 365) < 30:
            risk_factors.append('Very new domain (less than 30 days old)')
        
        # Hosted infrastructure risks
        if features.get('is_hosted_infrastructure', False):
            service_type = features.get('hosted_service_type', 'unknown')
            if service_type == 'ngrok':
                risk_factors.append('Using ngrok tunneling service (high risk)')
            elif service_type == 'cloudflare_tunnel':
                risk_factors.append('Using Cloudflare tunnel (medium risk)')
            elif service_type == 'tunnel_service':
                risk_factors.append('Using tunneling service (suspicious)')
            elif service_type == 'dev_platform':
                risk_factors.append('Hosted on development platform')
            elif service_type == 'free_hosting':
                risk_factors.append('Using free hosting service (suspicious)')
            elif service_type == 'dynamic_dns':
                risk_factors.append('Using dynamic DNS service')
            else:
                risk_factors.append('Using hosted infrastructure service')
        
        return risk_factors
    
    def _explain_prediction(self, features: Dict[str, Any], confidence_info: Dict[str, Any]) -> str:
        """Generate human-readable explanation of the prediction"""
        threat_level = confidence_info.get('risk_level', 'unknown')
        confidence = confidence_info.get('confidence', 0.5)
        prediction = confidence_info.get('prediction', 'unknown')
        
        if threat_level == 'high' or prediction == 'phishing':
            explanation = f"🚨 PHISHING DETECTED: This URL shows strong indicators of phishing (confidence: {confidence:.1%}). "
        elif threat_level == 'medium' or prediction == 'suspicious':
            explanation = f"⚠️ SUSPICIOUS: This URL has concerning characteristics (confidence: {confidence:.1%}). "
        else:
            explanation = f"✅ SAFE: This URL appears legitimate (confidence: {confidence:.1%}). "
        
        # Add key contributing factors
        key_factors = []
        if features.get('brand_impersonation_score', 0) > 0.7:
            key_factors.append("brand impersonation")
        if features.get('has_homograph_chars', False):
            key_factors.append("character spoofing")
        if features.get('phishing_keyword_density', 0) > 0.1:
            key_factors.append("phishing keywords")
        if features.get('urgent_keyword_count', 0) > 2:
            key_factors.append("urgency tactics")
        if features.get('has_ip_address', False):
            key_factors.append("IP address in URL")
        if features.get('is_hosted_infrastructure', False):
            key_factors.append("hosted infrastructure")
        
        if key_factors:
            explanation += f"Key concerns: {', '.join(key_factors)}."
        
        return explanation
    
    def retrain(self, new_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Retrain the model with new samples"""
        try:
            logger.info(f"Retraining with {len(new_samples)} new samples")
            
            if len(new_samples) == 0:
                return {'status': 'error', 'message': 'No samples provided for retraining'}
            
            X, y = self._prepare_training_data(new_samples)
            
            # If we have existing model, combine with new data
            if self.is_fitted:
                # For now, just retrain on new data
                # In production, you might want to combine old and new data
                pass
            
            self._train_models(X, y)
            
            return {
                'status': 'success',
                'message': f'Model retrained with {len(new_samples)} samples',
                'feature_count': len(self.feature_names),
                'model_types': list(self.models.keys())
            }
            
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
            return {'status': 'error', 'message': f'Retraining failed: {str(e)}'}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            'is_fitted': self.is_fitted,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'model_types': list(self.models.keys()) if self.models else [],
            'thresholds': self.thresholds,
            'top_features': dict(sorted(
                self.feature_importance.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]) if self.feature_importance else {}
        }
