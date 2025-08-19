import asyncio
import json
import os
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from typing import Optional
import logging

from config import settings

# MongoDB imports
from mongo_models import URLRecord, Detection, Label
from bson import ObjectId

from feature_extractor import FeatureExtractor
from classifier import HybridClassifier

logger = logging.getLogger(__name__)


class MongoMonitoringService:
    """MongoDB-compatible monitoring service"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.feature_extractor = FeatureExtractor()
        self.classifier = HybridClassifier()
        self.is_running = False
        
        # Enhanced classifier initializes automatically with synthetic data
        # self.classifier.load_model("phishguard_model.joblib")
    
    def start(self):
        """Start the monitoring scheduler"""
        if not self.is_running:
            self.scheduler.add_job(
                self._scan_known_urls,
                IntervalTrigger(seconds=settings.schedule_seconds),
                id='url_scanner',
                replace_existing=True
            )
            self.scheduler.start()
            self.is_running = True
            logger.info(f"MongoDB Monitoring service started with {settings.schedule_seconds}s interval")
    
    def stop(self):
        """Stop the monitoring scheduler"""
        if self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("MongoDB Monitoring service stopped")
    
    async def _scan_known_urls(self):
        """Periodically scan known URLs for changes"""
        try:
            # Get URLs that haven't been scanned recently
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            urls_to_scan = await URLRecord.find(
                {"last_scanned": {"$lt": cutoff_time}}
            ).limit(10).to_list()
            
            for url_record in urls_to_scan:
                try:
                    await self._scan_single_url(url_record)
                except Exception as e:
                    logger.error(f"Error scanning {url_record.url}: {e}")
            
        except Exception as e:
            logger.error(f"Error in scheduled scan: {e}")
    
    async def _scan_single_url(self, url_record: URLRecord):
        """Scan a single URL and create detection record"""
        # Extract features
        features = self.feature_extractor.extract_features(
            url_record.url, 
            url_record.cse_hint
        )
        
        # Classify
        prediction_result = self.classifier.predict(features)
        classification = prediction_result['prediction']
        confidence = prediction_result['confidence_score']
        
        # Save HTML evidence if fetch was successful
        evidence_path = None
        if features.get('fetch_success', False):
            evidence_path = self._save_html_evidence(url_record.url, str(url_record.id))
        
        # Create detection record
        detection = Detection(
            url_id=url_record.id,
            classification=classification,
            confidence_score=confidence,
            features=features,  # Store as dict directly
            evidence_path=evidence_path
        )
        
        await detection.insert()
        
        # Update URL record
        url_record.last_scanned = datetime.utcnow()
        url_record.scan_count += 1
        await url_record.save()
        
        logger.info(f"Scanned {url_record.url}: {classification} ({confidence:.2f})")
    
    def _save_html_evidence(self, url: str, url_id: str) -> Optional[str]:
        """Save HTML snapshot for evidence"""
        try:
            # Create evidence directory if it doesn't exist
            evidence_dir = "evidence"
            os.makedirs(evidence_dir, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"url_{url_id}_{timestamp}.html"
            filepath = os.path.join(evidence_dir, filename)
            
            # Fetch and save HTML content
            response = self.feature_extractor.session.get(url, timeout=10)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            return filepath
            
        except Exception as e:
            logger.warning(f"Failed to save HTML evidence for {url}: {e}")
            return None
    
    async def submit_url_for_scanning(self, url: str, cse_hint: Optional[str] = None) -> dict:
        """Submit a URL for enhanced precision scanning"""
        try:
            # Check if URL already exists
            existing_url = await URLRecord.find_one({"url": url})
            
            if existing_url:
                url_record = existing_url
                url_record.last_scanned = datetime.utcnow()
                url_record.scan_count += 1
                if cse_hint:
                    url_record.cse_hint = cse_hint
                await url_record.save()
            else:
                # Create new URL record
                url_record = URLRecord(
                    url=url,
                    cse_hint=cse_hint
                )
                await url_record.insert()
            
            # Extract enhanced features with improved precision
            features = self.feature_extractor.extract_features(url, cse_hint)
            
            # Get enhanced prediction with detailed analysis
            try:
                prediction_result = self.classifier.predict(features)
                logger.info(f"Classifier returned: {type(prediction_result)}: {prediction_result}")
            except Exception as e:
                logger.error(f"Classifier predict() failed: {e}")
                prediction_result = None
            
            # Handle case where prediction fails
            if prediction_result is None:
                logger.warning(f"Prediction failed for {url}, using fallback")
                prediction_result = {
                    'prediction': 'suspicious',
                    'confidence_score': 0.5,
                    'threat_level': 'MEDIUM',
                    'phishing_probability': 0.5,
                    'risk_factors': ['Model prediction failed'],
                    'model_explanation': 'Fallback prediction due to model error'
                }
            
            # Save HTML evidence if fetch was successful
            evidence_path = None
            screenshot_data_dict = None
            html_evidence = None
            
            if features.get('fetch_success', False):
                # Store HTML evidence in database
                try:
                    from screenshot_capture import get_screenshot_capturer
                    screenshot_capturer = get_screenshot_capturer()
                    html_result = screenshot_capturer.capture_html_snapshot(url, str(url_record.id), return_content=True)
                    if html_result and 'html_content' in html_result:
                        html_evidence = html_result['html_content']
                        logger.info(f"HTML evidence captured: {html_result['size']} bytes")
                except Exception as e:
                    logger.warning(f"HTML evidence capture failed: {e}")
            
            # Capture screenshot for high-risk URLs or if enabled
            threat_level = prediction_result.get('threat_level', 'LOW')
            if settings.enable_screenshot and (threat_level in ['HIGH', 'MEDIUM'] or features.get('fetch_success', False)):
                try:
                    from screenshot_capture import get_screenshot_capturer
                    screenshot_capturer = get_screenshot_capturer()
                    
                    if hasattr(screenshot_capturer, 'capture_screenshot_async'):
                        screenshot_data_dict = await screenshot_capturer.capture_screenshot_async(
                            url, str(url_record.id), save_to_db=True
                        )
                    else:
                        # Fallback to HTML snapshot for lightweight capturer
                        if not html_evidence:  # Only if we haven't captured HTML already
                            html_result = screenshot_capturer.capture_html_snapshot(
                                url, str(url_record.id), return_content=True
                            )
                            if html_result and 'html_content' in html_result:
                                html_evidence = html_result['html_content']
                        
                    if screenshot_data_dict and 'data' in screenshot_data_dict:
                        logger.info(f"Screenshot captured to database: {screenshot_data_dict['size']} bytes")
                            
                except Exception as e:
                    logger.warning(f"Screenshot capture failed for {url}: {e}")
            
            # Create enhanced detection record with database evidence storage
            detection_data = {
                'url_id': url_record.id,
                'classification': prediction_result['prediction'],
                'confidence_score': prediction_result['confidence_score'],
                'features': features,
                'evidence_path': evidence_path,  # Keep for backward compatibility
                'threat_level': prediction_result.get('threat_level', 'UNKNOWN'),
                'phishing_probability': prediction_result.get('phishing_probability', 0.0),
                'risk_factors': prediction_result.get('risk_factors', []) or [],  # Handle None case
                'html_evidence': html_evidence
            }
            
            # Add screenshot data if captured
            if screenshot_data_dict and 'data' in screenshot_data_dict:
                detection_data.update({
                    'screenshot_data': screenshot_data_dict['data'],
                    'screenshot_filename': screenshot_data_dict['filename'],
                    'screenshot_content_type': screenshot_data_dict['content_type'],
                    'screenshot_size': screenshot_data_dict['size']
                })
            
            detection = Detection(**detection_data)
            
            await detection.insert()
            
            # Validate prediction_result before returning
            if prediction_result is None or not isinstance(prediction_result, dict):
                logger.error(f"Invalid prediction_result: {type(prediction_result)}: {prediction_result}")
                return {
                    'prediction': 'suspicious',
                    'threat_level': 'MEDIUM',
                    'confidence_score': 0.5,
                    'phishing_probability': 0.5,
                    'risk_factors': ['Prediction validation failed'],
                    'features': features,
                    'evidence_path': evidence_path,
                    'scan_id': str(detection.id),
                    'explanation': 'Fallback response due to prediction error'
                }
            
            # Safely handle risk_factors which might be None
            risk_factors = prediction_result.get('risk_factors', [])
            if risk_factors is None:
                risk_factors = []
                
            return {
                'prediction': prediction_result.get('prediction', 'suspicious'),
                'threat_level': prediction_result.get('threat_level', 'MEDIUM'),
                'confidence_score': prediction_result.get('confidence_score', 0.5),
                'phishing_probability': prediction_result.get('phishing_probability', 0.5),
                'risk_factors': risk_factors[:5],  # Top 5 for response
                'features': features,
                'evidence_path': evidence_path,
                'scan_id': str(detection.id),
                'explanation': prediction_result.get('model_explanation', 'Analysis complete')
            }
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            raise
    
    async def retrain_model(self):
        """Retrain the model with new labeled data"""
        try:
            # Get all labeled data
            labels = await Label.find().to_list()
            
            if not labels:
                logger.warning("No labeled data available for retraining")
                return
            
            # Prepare training data
            training_data = []
            for label in labels:
                # Get the latest detection for this URL
                detection = await Detection.find_one(
                    {"url_id": label.url_id},
                    sort=[("detection_time", -1)]
                )
                
                if detection and detection.features:
                    features = detection.features.copy()
                    features['label'] = label.true_label
                    training_data.append(features)
            
            if training_data:
                # Retrain model
                self.classifier.retrain(training_data)
                
                # Save updated model
                self.classifier.save_model("phishguard_model.joblib")
                
                logger.info(f"Model retrained with {len(training_data)} labeled samples")
            
        except Exception as e:
            logger.error(f"Error retraining model: {e}")


class SQLiteMonitoringService:
    """SQLite fallback monitoring service (original implementation)"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.feature_extractor = FeatureExtractor()
        self.classifier = HybridClassifier()
        self.is_running = False
        
        # Enhanced classifier initializes automatically with synthetic data
        # self.classifier.load_model("phishguard_model.joblib")
    
    def start(self):
        """Start the monitoring scheduler"""
        if not self.is_running:
            # For SQLite, we'll use a simplified sync version
            self.is_running = True
            logger.info(f"SQLite Monitoring service started (simplified mode)")
    
    def stop(self):
        """Stop the monitoring scheduler"""
        if self.is_running:
            self.is_running = False
            logger.info("SQLite Monitoring service stopped")
    
    def submit_url_for_scanning(self, url: str, cse_hint: Optional[str] = None) -> dict:
        """Submit a URL for immediate scanning (sync version for SQLite)"""
        # Simplified implementation for demonstration
        features = self.feature_extractor.extract_features(url, cse_hint)
        classification, confidence = self.classifier.predict(features)
        
        return {
            'classification': classification,
            'confidence_score': confidence,
            'features': features,
            'evidence_path': None
        }
    
    def retrain_model(self):
        """Retrain model (simplified for SQLite)"""
        logger.info("SQLite model retraining (simplified)")


# Create the appropriate monitoring service based on configuration
if settings.use_mongodb:
    monitoring_service = MongoMonitoringService()
else:
    monitoring_service = SQLiteMonitoringService()
