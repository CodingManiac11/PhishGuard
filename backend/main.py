from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from typing import List, Optional
import json
import logging
import os
import warnings
from datetime import datetime

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
warnings.filterwarnings('ignore', category=RuntimeWarning)

from config import settings

# JSON Storage - replaces MongoDB
from json_storage import storage

from schemas import (
    URLSubmission, DetectionResponse, LabelSubmission, 
    LabelResponse, AlertResponse, ScanResult,
    VirusTotalScanRequest, VirusTotalScanResult,
    SSLAnalysisRequest, SSLAnalysisResult,
    EmailAnalysisRequest, EmailAnalysisResult
)

# Import classifier and feature extractor
from classifier import HybridClassifier
from feature_extractor import FeatureExtractor

# Security services
from virustotal import virustotal_service
from ssl_analyzer import ssl_analyzer
from email_analyzer import email_analyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize ML components
feature_extractor = FeatureExtractor()
classifier = HybridClassifier()

# Create FastAPI app
app = FastAPI(
    title="PhishGuard MVP",
    description="Hybrid AI/ML phishing detection system with JSON storage",
    version="3.0.0"
)

# Mount static files (frontend) - use absolute path
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

# Startup/Shutdown events
@app.on_event("startup")
async def startup_event():
    await storage.connect()
    logger.info("🚀 PhishGuard started with JSON storage")

@app.on_event("shutdown")
async def shutdown_event():
    await storage.disconnect()
    logger.info("👋 PhishGuard shutdown complete")


@app.get("/", response_class=HTMLResponse)
async def read_index():
    """Serve the main dashboard"""
    try:
        index_path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
        
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(f.read())
        return HTMLResponse("<html><body><h1>PhishGuard API</h1><p>Visit <a href='/docs'>/docs</a> for API documentation.</p></body></html>")
    except Exception as e:
        logger.error(f"Error serving index: {e}")
        return HTMLResponse(f"<html><body><h1>PhishGuard API</h1><p>Error: {e}</p></body></html>")


@app.post("/submit", response_model=ScanResult)
async def submit_url(url_submission: URLSubmission):
    """Submit a URL for phishing detection"""
    try:
        url = url_submission.url
        cse_hint = url_submission.cse_hint
        
        logger.info(f"🔍 Scanning URL: {url}")
        
        # Extract features (not async)
        features = feature_extractor.extract_features(url, cse_hint)
        
        # Add URL to features so classifier can check trusted domains
        features['url'] = url
        
        # Classify
        prediction = classifier.predict(features)
        
        # Log prediction details for debugging
        logger.info(f"Classifier prediction: {prediction.get('prediction', 'N/A')}, threat: {prediction.get('threat_level', 'N/A')}")
        
        # Build result - classifier uses 'prediction' key not 'classification'
        # Also determine classification from threat_level if prediction is missing
        classification = prediction.get("prediction", prediction.get("classification", "unknown"))
        threat_level = prediction.get("threat_level", "MEDIUM")
        
        # If classification is still unknown, derive from threat level
        if classification == "unknown":
            if threat_level == "HIGH":
                classification = "phishing"
            elif threat_level == "MEDIUM":
                classification = "suspicious"
            else:
                classification = "benign"
        
        result = {
            "scan_id": None,
            "classification": classification,
            "confidence_score": prediction.get("confidence_score", prediction.get("confidence", 0.5)),
            "threat_level": threat_level,
            "phishing_probability": prediction.get("phishing_probability", 0.5),
            "risk_factors": prediction.get("risk_factors", []),
            "explanation": prediction.get("explanation", "") or prediction.get("model_explanation", ""),
            "features": features,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Save to JSON storage
        scan_id = storage.save_scan(url, result)
        result["scan_id"] = scan_id
        
        # Save alert if high threat
        if result["threat_level"] in ["HIGH", "MEDIUM"]:
            storage.save_alert(
                url=url,
                classification=result["classification"],
                confidence=result["confidence_score"],
                threat_level=result["threat_level"],
                explanation=result["explanation"]
            )
        
        logger.info(f"✅ Scan complete: {result['classification']} ({result['confidence_score']:.2f})")
        
        return ScanResult(**result)
        
    except Exception as e:
        logger.error(f"Error processing URL submission: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts", response_model=AlertResponse)
async def get_alerts(
    limit: int = Query(50, ge=1, le=100),
    classification: Optional[str] = Query(None)
):
    """Get recent phishing alerts"""
    try:
        alerts = storage.get_alerts(limit=limit)
        
        if classification:
            alerts = [a for a in alerts if a.get("classification") == classification]
        
        detection_responses = [
            DetectionResponse(
                id=alert.get("id", ""),
                url=alert.get("url", ""),
                classification=alert.get("classification", "unknown"),
                confidence_score=alert.get("confidence_score", 0),
                detection_time=datetime.fromisoformat(alert.get("timestamp", datetime.utcnow().isoformat())),
                evidence_path=None,
                features={},
                cse_hint=None
            )
            for alert in alerts
        ]
        
        return AlertResponse(
            detections=detection_responses,
            total_count=len(detection_responses)
        )
            
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/labels", response_model=LabelResponse)
async def add_label(label_submission: LabelSubmission):
    """Add a truth label for model training"""
    try:
        label_id = storage.save_label(
            url=label_submission.url_id,  # Using url_id as URL for simplicity
            label=label_submission.true_label,
            notes=label_submission.notes or ""
        )
        
        return LabelResponse(
            id=label_id,
            url_id=label_submission.url_id,
            true_label=label_submission.true_label,
            labeled_at=datetime.utcnow(),
            notes=label_submission.notes
        )
            
    except Exception as e:
        logger.error(f"Error adding label: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/labels", response_model=List[LabelResponse])
async def get_labels():
    """Get all truth labels"""
    try:
        labels = storage.get_labels()
        
        return [
            LabelResponse(
                id=label.get("id", ""),
                url_id=label.get("url", ""),
                true_label=label.get("label", "unknown"),
                labeled_at=datetime.fromisoformat(label.get("timestamp", datetime.utcnow().isoformat())),
                notes=label.get("notes")
            )
            for label in labels
        ]
            
    except Exception as e:
        logger.error(f"Error retrieving labels: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/urls")
async def get_urls():
    """Get all scanned URLs"""
    try:
        scans = storage.get_scans(limit=100)
        
        return [
            {
                "id": scan.get("id", ""),
                "url": scan.get("url", ""),
                "classification": scan.get("classification", "unknown"),
                "confidence_score": scan.get("confidence_score", 0),
                "timestamp": scan.get("timestamp", "")
            }
            for scan in scans
        ]
            
    except Exception as e:
        logger.error(f"Error retrieving URLs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get system statistics"""
    try:
        stats = storage.get_stats()
        
        return {
            "total_urls": stats.get("total_urls", 0),
            "phishing_count": stats.get("phishing_count", 0),
            "suspicious_count": stats.get("suspicious_count", 0),
            "benign_count": stats.get("benign_count", 0),
            "model_accuracy": classifier.get_accuracy() if hasattr(classifier, 'get_accuracy') else None,
            "last_retrained": None,
            "storage_type": "JSON"
        }
            
    except Exception as e:
        logger.error(f"Error retrieving stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/retrain")
async def retrain_model():
    """Manually trigger model retraining"""
    try:
        # Get labeled data for training
        labels = storage.get_labels()
        if len(labels) > 0:
            classifier.retrain(labels)
            return {"message": "Model retraining initiated", "samples": len(labels)}
        return {"message": "No labeled data available for training"}
    except Exception as e:
        logger.error(f"Error retraining model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== SECURITY SCAN ENDPOINTS ====================

@app.post("/scan/virustotal", response_model=VirusTotalScanResult)
async def scan_virustotal(request: VirusTotalScanRequest):
    """Scan URL using VirusTotal (70+ antivirus engines)"""
    try:
        if not virustotal_service.is_configured():
            return VirusTotalScanResult(
                success=False,
                is_threat=False,
                error="VirusTotal API key not configured"
            )
        
        result = await virustotal_service.scan_url(request.url)
        summary = virustotal_service.get_threat_summary(result)
        
        return VirusTotalScanResult(
            success=result.get("success", False),
            is_threat=result.get("is_threat", False),
            threat_level=result.get("threat_level"),
            stats=result.get("stats"),
            detection_rate=result.get("detection_rate"),
            categories=result.get("categories"),
            summary=summary,
            error=result.get("error")
        )
    except Exception as e:
        logger.error(f"VirusTotal scan error: {e}")
        return VirusTotalScanResult(
            success=False,
            is_threat=False,
            error=str(e)
        )


@app.post("/scan/ssl", response_model=SSLAnalysisResult)
async def analyze_ssl(request: SSLAnalysisRequest):
    """Analyze SSL certificate for security issues"""
    try:
        result = await ssl_analyzer.analyze_url(request.url)
        
        return SSLAnalysisResult(
            success=result.get("success", False),
            is_secure=result.get("is_secure", False),
            risk_level=result.get("risk_level"),
            hostname=result.get("hostname"),
            certificate=result.get("certificate"),
            issues=result.get("issues"),
            warnings=result.get("warnings"),
            summary=result.get("summary"),
            error=result.get("error")
        )
    except Exception as e:
        logger.error(f"SSL analysis error: {e}")
        return SSLAnalysisResult(
            success=False,
            is_secure=False,
            error=str(e)
        )


@app.post("/scan/email", response_model=EmailAnalysisResult)
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email headers for spoofing and phishing"""
    try:
        result = await email_analyzer.analyze_headers(request.headers)
        
        return EmailAnalysisResult(
            success=result.get("success", False),
            is_suspicious=result.get("is_suspicious", False),
            risk_level=result.get("risk_level"),
            sender=result.get("sender"),
            authentication=result.get("authentication"),
            issues=result.get("issues"),
            warnings=result.get("warnings"),
            summary=result.get("summary"),
            error=result.get("error")
        )
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        return EmailAnalysisResult(
            success=False,
            is_suspicious=True,
            error=str(e)
        )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": "JSON File Storage",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
