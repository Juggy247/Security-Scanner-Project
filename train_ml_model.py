"""
Advanced Training Script - Uses Full Security Scan Data
This version runs actual security scans on training URLs to get MongoDB data
"""

import sys
import os
from pathlib import Path
import json
from datetime import datetime
import pandas as pd
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.ml_detector import MLPhishingDetector
from scanner.core import SecurityScanner
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def train_with_full_scans(csv_path: str, model_output: str = "models/phishing_model_enhanced.pkl", 
                          max_samples: int = None):
    """
    Train ML model using FULL security scans (includes MongoDB data)
    
    WARNING: This is SLOW because it scans every URL!
    Use max_samples to limit for testing.
    
    Args:
        csv_path: Path to combined CSV
        model_output: Where to save model
        max_samples: Limit number of URLs to scan (None = all)
    """
    
    logger.info("=" * 60)
    logger.info("ADVANCED ML TRAINING - WITH FULL SECURITY SCANS")
    logger.info("=" * 60)
    logger.info("⚠️  This will take longer as it performs full security scans")
    logger.info("")
    
    # Load data
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return
    
    logger.info(f"Loading data from: {csv_path}")
    df = pd.read_csv(csv_path)
    
    # Separate by label
    safe_labels = ['safe', 'legitimate', 'benign', 'good']
    phishing_labels = ['phishing', 'malicious', 'bad', 'unsafe', 'dangerous']
    
    safe_df = df[df['label'].str.lower().isin(safe_labels)]
    phishing_df = df[df['label'].str.lower().isin(phishing_labels)]
    
    logger.info(f"Safe URLs: {len(safe_df)}")
    logger.info(f"Phishing URLs: {len(phishing_df)}")
    
    # Limit samples if specified
    if max_samples:
        logger.info(f"⚠️  Limiting to {max_samples} URLs per class for testing")
        safe_df = safe_df.head(max_samples)
        phishing_df = phishing_df.head(max_samples)
    
    logger.info("")
    logger.info("🔍 Scanning URLs to extract features...")
    logger.info("This will take a while - performing full security scans...")
    logger.info("")
    
    # Initialize scanner and detector
    scanner = SecurityScanner(bypass_robots=True)
    detector = MLPhishingDetector(model_path=model_output)
    
    # Scan safe URLs
    logger.info("Scanning SAFE URLs...")
    safe_features = []
    safe_failed = 0
    
    for i, url in enumerate(tqdm(safe_df['url'], desc="Safe URLs")):
        try:
            # Full security scan
            report = scanner.scan(str(url))
            
            # Extract features WITH scan data
            features = detector.extract_features(str(url), scan_report=report)
            safe_features.append(features)
            
        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            break
        except Exception as e:
            logger.debug(f"Error scanning {url}: {e}")
            safe_failed += 1
            # Still extract URL-only features
            try:
                features = detector.extract_features(str(url))
                safe_features.append(features)
            except:
                pass
    
    logger.info(f"Successfully scanned: {len(safe_features)}/{len(safe_df)} safe URLs")
    if safe_failed > 0:
        logger.warning(f"Failed to scan: {safe_failed} URLs")
    logger.info("")
    
    # Scan phishing URLs
    logger.info("Scanning PHISHING URLs...")
    phishing_features = []
    phishing_failed = 0
    
    for i, url in enumerate(tqdm(phishing_df['url'], desc="Phishing URLs")):
        try:
            # Full security scan
            report = scanner.scan(str(url))
            
            # Extract features WITH scan data
            features = detector.extract_features(str(url), scan_report=report)
            phishing_features.append(features)
            
        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            break
        except Exception as e:
            logger.debug(f"Error scanning {url}: {e}")
            phishing_failed += 1
            # Still extract URL-only features
            try:
                features = detector.extract_features(str(url))
                phishing_features.append(features)
            except:
                pass
    
    logger.info(f"Successfully scanned: {len(phishing_features)}/{len(phishing_df)} phishing URLs")
    if phishing_failed > 0:
        logger.warning(f"Failed to scan: {phishing_failed} URLs")
    logger.info("")
    
    if len(safe_features) == 0 or len(phishing_features) == 0:
        logger.error("Not enough data to train!")
        return
    
    # Create DataFrames
    safe_features_df = pd.DataFrame(safe_features)
    phishing_features_df = pd.DataFrame(phishing_features)
    
    safe_features_df['label'] = 0
    phishing_features_df['label'] = 1
    
    combined_df = pd.concat([safe_features_df, phishing_features_df], ignore_index=True)
    combined_df = combined_df.fillna(-1)
    
    # Train model (same as before)
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    from sklearn.ensemble import RandomForestClassifier
    
    X = combined_df.drop('label', axis=1)
    y = combined_df['label']
    
    detector.feature_names = list(X.columns)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info("Training Random Forest with enhanced features...")
    detector.model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    detector.model.fit(X_train, y_train)
    
    y_pred = detector.model.predict(X_test)
    y_pred_train = detector.model.predict(X_train)
    
    train_accuracy = accuracy_score(y_train, y_pred_train)
    test_accuracy = accuracy_score(y_test, y_pred)
    cv_scores = cross_val_score(detector.model, X_train, y_train, cv=5)
    
    feature_importance = pd.DataFrame({
        'feature': detector.feature_names,
        'importance': detector.model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    detector.is_trained = True
    
    # Display results
    logger.info("")
    logger.info("=" * 60)
    logger.info("TRAINING RESULTS (WITH MONGODB DATA)")
    logger.info("=" * 60)
    logger.info(f"Training Accuracy: {train_accuracy:.4f} ({train_accuracy*100:.2f}%)")
    logger.info(f"Test Accuracy: {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
    logger.info(f"Cross-Validation: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
    logger.info(f"Features: {len(detector.feature_names)}")
    logger.info("")
    
    cm = confusion_matrix(y_test, y_pred)
    logger.info("Confusion Matrix:")
    logger.info(f"  True Negatives:  {cm[0][0]}")
    logger.info(f"  False Positives: {cm[0][1]}")
    logger.info(f"  False Negatives: {cm[1][0]}")
    logger.info(f"  True Positives:  {cm[1][1]}")
    logger.info("")
    
    logger.info("Top 20 Most Important Features:")
    for i, row in feature_importance.head(20).iterrows():
        bar = "█" * int(row['importance'] * 50)
        logger.info(f"  {i+1:2d}. {row['feature']:30s} {bar} {row['importance']:.4f}")
    logger.info("")
    
    # Check if MongoDB features are important
    mongodb_features = ['tld_suspicious', 'brand_impersonation', 'is_blacklisted', 
                        'num_suspicious_keywords', 'domain_age_days']
    logger.info("MongoDB-Enhanced Features Importance:")
    for feat in mongodb_features:
        if feat in feature_importance['feature'].values:
            imp = feature_importance[feature_importance['feature'] == feat]['importance'].values[0]
            logger.info(f"  {feat:30s} - {imp:.4f}")
    logger.info("")
    
    # Save
    detector.save_model()
    logger.info(f"✅ Enhanced model saved to: {model_output}")
    
    # Save results
    tn, fp, fn, tp = cm.ravel()
    results = {
        'train_accuracy': train_accuracy,
        'test_accuracy': test_accuracy,
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
        'confusion_matrix': cm.tolist(),
        'precision': tp / (tp + fp) if (tp + fp) > 0 else 0,
        'recall': tp / (tp + fn) if (tp + fn) > 0 else 0,
        'top_features': feature_importance.head(30).to_dict('records'),
        'training_method': 'full_security_scan',
        'mongodb_enhanced': True,
        'trained_date': datetime.now().isoformat()
    }
    
    results_file = model_output.replace('.pkl', '_results.json')
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"✅ Results saved to: {results_file}")
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("ENHANCED TRAINING COMPLETE!")
    logger.info("=" * 60)


def main():
    if len(sys.argv) < 2:
        logger.info("Usage: python train_ml_advanced.py <csv_path> [max_samples]")
        logger.info("")
        logger.info("Example:")
        logger.info("  python train_ml_advanced.py DataCollections/training_urls.csv")
        logger.info("  python train_ml_advanced.py DataCollections/training_urls.csv 50")
        logger.info("")
        logger.info("⚠️  WARNING: This performs FULL security scans on every URL")
        logger.info("    With 400 URLs, this could take 30-60 minutes!")
        logger.info("    Consider using max_samples=50 for testing")
        return
    
    csv_path = sys.argv[1]
    max_samples = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    if max_samples:
        logger.info(f"Testing mode: Will scan only {max_samples} URLs per class")
    else:
        logger.info("⚠️  Will scan ALL URLs - this may take a while!")
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Cancelled")
            return
    
    train_with_full_scans(csv_path, max_samples=max_samples)


if __name__ == "__main__":
    main()