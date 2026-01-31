"""
Machine Learning Phishing Detector
Integrates with existing security scanner to provide AI-powered classification
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import re
import logging

logger = logging.getLogger(__name__)


class MLPhishingDetector:
    """
    Machine Learning-based phishing detection using Random Forest
    """
    
    def __init__(self, model_path: str = "models/phishing_model.pkl"):
        """
        Initialize the ML detector
        
        Args:
            model_path: Path to save/load the trained model
        """
        self.model_path = model_path
        self.model = None
        self.feature_names = None
        self.is_trained = False
        
        # Try to load existing model
        if os.path.exists(model_path):
            self.load_model(model_path)
    
    def extract_features(self, url: str, scan_report=None) -> Dict[str, Any]:
        """
        Extract ML features from URL and scan report
        
        Args:
            url: The URL to analyze
            scan_report: Optional ScanReport object from scanner
            
        Returns:
            Dictionary of features for ML model
        """
        features = {}
        
        # ===== URL-BASED FEATURES =====
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['has_ip_address'] = 1 if self._has_ip_in_domain(domain) else 0
        features['num_dots'] = domain.count('.')
        features['num_hyphens'] = domain.count('-')
        features['num_underscores'] = domain.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_ampersands'] = url.count('&')
        features['num_equals'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        
        # Protocol features
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_port'] = 1 if ':' in domain and not domain.startswith('[') else 0
        
        # Suspicious patterns in URL
        features['has_double_slash_in_path'] = 1 if '//' in path else 0
        features['has_suspicious_tld'] = self._check_suspicious_tld(domain)
        
        # Character distribution
        features['digit_ratio'] = self._calculate_digit_ratio(url)
        features['special_char_ratio'] = self._calculate_special_char_ratio(url)
        
        # ===== DOMAIN-BASED FEATURES (from scan report) =====
        if scan_report:
            # Domain age
            if scan_report.domain_age and scan_report.domain_age.get('available'):
                features['domain_age_days'] = scan_report.domain_age.get('days_old', 0)
                features['is_new_domain'] = 1 if scan_report.domain_age.get('is_new', False) else 0
                features['is_very_new_domain'] = 1 if scan_report.domain_age.get('is_very_new', False) else 0
            else:
                features['domain_age_days'] = -1  # Unknown
                features['is_new_domain'] = 0
                features['is_very_new_domain'] = 0
            
            # HTTPS/SSL
            if scan_report.https:
                features['https_enforced'] = 1 if scan_report.https.get('https_enforced') else 0
                features['redirected_to_https'] = 1 if scan_report.https.get('redirected_to_https') else 0
            else:
                features['https_enforced'] = 0
                features['redirected_to_https'] = 0
            
            if scan_report.ssl:
                features['ssl_valid'] = 1 if scan_report.ssl.get('valid') else 0
            else:
                features['ssl_valid'] = 0
            
            # Blacklist
            if scan_report.blacklist:
                features['is_blacklisted'] = 1 if scan_report.blacklist.get('is_blacklisted') else 0
            else:
                features['is_blacklisted'] = 0
            
            # Homograph attack
            if scan_report.homograph:
                features['homograph_suspicious'] = 1 if scan_report.homograph.get('is_suspicious') else 0
                features['homograph_patterns_count'] = len(scan_report.homograph.get('patterns_found', []))
            else:
                features['homograph_suspicious'] = 0
                features['homograph_patterns_count'] = 0
            
            # Domain in title
            if scan_report.domain_in_title:
                features['domain_in_title'] = 1 if scan_report.domain_in_title.get('domain_in_title') else 0
            else:
                features['domain_in_title'] = 0
            
            # Security headers
            if scan_report.headers:
                features['num_missing_headers'] = len(scan_report.headers.get('missing', []))
                features['num_present_headers'] = len(scan_report.headers.get('present', []))
            else:
                features['num_missing_headers'] = 5  # Assume all missing
                features['num_present_headers'] = 0
            
            # Forms
            features['num_insecure_forms'] = len(scan_report.forms) if scan_report.forms else 0
            features['num_external_form_redirects'] = len(scan_report.form_redirects) if scan_report.form_redirects else 0
            
            # Domain length
            if scan_report.domain_length:
                features['domain_length_suspicious'] = 1 if scan_report.domain_length.get('is_suspicious') else 0
            else:
                features['domain_length_suspicious'] = 0
            
            # TLD
            if scan_report.suspicious_tld:
                features['tld_suspicious'] = 1 if scan_report.suspicious_tld.get('is_suspicious') else 0
            else:
                features['tld_suspicious'] = 0
            
            # Subdomain depth
            if scan_report.subdomain_depth:
                features['subdomain_depth'] = scan_report.subdomain_depth.get('depth', 0)
                features['subdomain_suspicious'] = 1 if scan_report.subdomain_depth.get('is_suspicious') else 0
            else:
                features['subdomain_depth'] = 0
                features['subdomain_suspicious'] = 0
            
            # Brand impersonation
            if scan_report.brand_impersonation:
                features['brand_impersonation'] = 1 if scan_report.brand_impersonation.get('potential_impersonation') else 0
                features['num_suspicious_keywords'] = len(scan_report.brand_impersonation.get('suspicious_keywords', []))
            else:
                features['brand_impersonation'] = 0
                features['num_suspicious_keywords'] = 0
        else:
            # If no scan report, set defaults for all scan-based features
            default_features = {
                'domain_age_days': -1,
                'is_new_domain': 0,
                'is_very_new_domain': 0,
                'https_enforced': 0,
                'redirected_to_https': 0,
                'ssl_valid': 0,
                'is_blacklisted': 0,
                'homograph_suspicious': 0,
                'homograph_patterns_count': 0,
                'domain_in_title': 0,
                'num_missing_headers': 5,
                'num_present_headers': 0,
                'num_insecure_forms': 0,
                'num_external_form_redirects': 0,
                'domain_length_suspicious': 0,
                'tld_suspicious': 0,
                'subdomain_depth': 0,
                'subdomain_suspicious': 0,
                'brand_impersonation': 0,
                'num_suspicious_keywords': 0
            }
            features.update(default_features)
        
        return features
    
    def _has_ip_in_domain(self, domain: str) -> bool:
        """Check if domain contains IP address"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, domain))
    
    def _check_suspicious_tld(self, domain: str) -> int:
        """Check for commonly abused TLDs"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov']
        return 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
    
    def _calculate_digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits in text"""
        if not text:
            return 0.0
        digit_count = sum(c.isdigit() for c in text)
        return digit_count / len(text)
    
    def _calculate_special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters"""
        if not text:
            return 0.0
        special_count = sum(not c.isalnum() for c in text)
        return special_count / len(text)
    
    def train(self, 
              good_websites_csv: str, 
              bad_websites_csv: str,
              test_size: float = 0.2,
              random_state: int = 42) -> Dict[str, Any]:
        """
        Train the ML model on labeled data
        
        Args:
            good_websites_csv: Path to CSV with legitimate websites
            bad_websites_csv: Path to CSV with phishing websites
            test_size: Proportion of data for testing
            random_state: Random seed for reproducibility
            
        Returns:
            Dictionary with training results and metrics
        """
        logger.info("Loading training data...")
        
        # Load datasets
        good_df = pd.read_csv(good_websites_csv)
        bad_df = pd.read_csv(bad_websites_csv)
        
        # Assuming CSV has a 'url' column (adjust if different)
        url_column = self._detect_url_column(good_df)
        
        logger.info(f"Loaded {len(good_df)} good websites and {len(bad_df)} bad websites")
        
        # Extract features for all URLs
        logger.info("Extracting features...")
        good_features = []
        for url in good_df[url_column]:
            try:
                features = self.extract_features(str(url))
                good_features.append(features)
            except Exception as e:
                logger.warning(f"Error extracting features from {url}: {e}")
        
        bad_features = []
        for url in bad_df[url_column]:
            try:
                features = self.extract_features(str(url))
                bad_features.append(features)
            except Exception as e:
                logger.warning(f"Error extracting features from {url}: {e}")
        
        # Create DataFrame
        good_features_df = pd.DataFrame(good_features)
        bad_features_df = pd.DataFrame(bad_features)
        
        # Add labels
        good_features_df['label'] = 0  # Legitimate
        bad_features_df['label'] = 1  # Phishing
        
        # Combine
        df = pd.concat([good_features_df, bad_features_df], ignore_index=True)
        
        # Handle missing values
        df = df.fillna(-1)
        
        # Split features and labels
        X = df.drop('label', axis=1)
        y = df['label']
        
        self.feature_names = list(X.columns)
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        logger.info(f"Training set: {len(X_train)}, Test set: {len(X_test)}")
        
        # Train Random Forest
        logger.info("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        y_pred_train = self.model.predict(X_train)
        
        train_accuracy = accuracy_score(y_train, y_pred_train)
        test_accuracy = accuracy_score(y_test, y_pred)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=5)
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        self.is_trained = True
        
        logger.info(f"Training complete! Test Accuracy: {test_accuracy:.4f}")
        
        results = {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'cv_mean_accuracy': cv_scores.mean(),
            'cv_std_accuracy': cv_scores.std(),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, 
                                                          target_names=['Legitimate', 'Phishing'],
                                                          output_dict=True),
            'top_features': feature_importance.head(10).to_dict('records'),
            'num_features': len(self.feature_names),
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        return results
    
    def _detect_url_column(self, df: pd.DataFrame) -> str:
        """Detect which column contains URLs"""
        possible_names = ['url', 'URL', 'website', 'Website', 'domain', 'Domain', 'link', 'Link']
        
        for name in possible_names:
            if name in df.columns:
                return name
        
        # If not found, assume first column
        return df.columns[0]
    
    def predict(self, url: str, scan_report=None) -> Dict[str, Any]:
        """
        Predict if URL is phishing
        
        Args:
            url: URL to analyze
            scan_report: Optional ScanReport object
            
        Returns:
            Dictionary with prediction results
        """
        if not self.is_trained:
            return {
                'error': 'Model not trained yet',
                'prediction': None,
                'confidence': 0.0
            }
        
        # Extract features
        features = self.extract_features(url, scan_report)
        
        # Convert to DataFrame with correct column order
        features_df = pd.DataFrame([features])
        features_df = features_df.reindex(columns=self.feature_names, fill_value=-1)
        
        # Predict
        prediction = self.model.predict(features_df)[0]
        probabilities = self.model.predict_proba(features_df)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(probabilities[prediction]),
            'phishing_probability': float(probabilities[1]),
            'legitimate_probability': float(probabilities[0]),
            'ml_verdict': 'PHISHING' if prediction == 1 else 'LEGITIMATE'
        }
    
    def save_model(self, path: Optional[str] = None):
        """Save trained model to disk"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        save_path = path or self.model_path
        
        # Create directory if needed
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # Save model and feature names
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names
        }
        
        joblib.dump(model_data, save_path)
        logger.info(f"Model saved to {save_path}")
    
    def load_model(self, path: Optional[str] = None):
        """Load trained model from disk"""
        load_path = path or self.model_path
        
        if not os.path.exists(load_path):
            logger.warning(f"Model file not found: {load_path}")
            return False
        
        model_data = joblib.load(load_path)
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        self.is_trained = True
        
        logger.info(f"Model loaded from {load_path}")
        return True
    
    def get_feature_importance(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """Get feature importance rankings"""
        if not self.is_trained:
            return []
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False).head(top_n)
        
        return importance_df.to_dict('records')


# Convenience function for integration
def get_ml_detector() -> MLPhishingDetector:
    """Get or create ML detector instance"""
    detector = MLPhishingDetector()
    return detector