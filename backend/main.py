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

# MongoDB imports only
from mongo_database import connect_to_mongo, close_mongo_connection
from mongo_models import URLRecord, Detection, Label
from bson import ObjectId

from schemas import (
    URLSubmission, DetectionResponse, LabelSubmission, 
    LabelResponse, AlertResponse, ScanResult
)
from mongo_monitor import monitoring_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="PhishGuard MVP",
    description="Hybrid AI/ML phishing detection system with MongoDB Atlas support",
    version="2.0.0"
)

# Mount static files (frontend) - use absolute path
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

# Database initialization - MongoDB only
@app.on_event("startup")
async def startup_event():
    success = await connect_to_mongo()
    if success:
        logger.info("🚀 Starting with MongoDB Atlas")
        monitoring_service.start()
    else:
        logger.error("❌ Failed to connect to MongoDB Atlas")

@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()
    monitoring_service.stop()


@app.get("/", response_class=HTMLResponse)
async def read_index():
    """Serve the main dashboard"""
    try:
        index_path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
        logger.info(f"Looking for index.html at: {index_path}")
        logger.info(f"File exists: {os.path.exists(index_path)}")
        logger.info(f"Directory contents: {os.listdir(os.path.dirname(__file__))}")
        
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(f.read())
        return HTMLResponse(f"<html><body><h1>PhishGuard API</h1><p>Frontend not found at: {index_path}</p><p>Visit <a href='/docs'>/docs</a> for API documentation.</p></body></html>")
    except Exception as e:
        logger.error(f"Error serving index: {e}")
        return HTMLResponse(f"<html><body><h1>PhishGuard API</h1><p>Error: {e}</p><p>Visit <a href='/docs'>/docs</a> for API documentation.</p></body></html>")


@app.post("/submit", response_model=ScanResult)
async def submit_url(url_submission: URLSubmission):
    """Submit a URL for phishing detection"""
    try:
        logger.info(f"Processing URL submission: {url_submission.url}")
        result = await monitoring_service.submit_url_for_scanning(
            url_submission.url, 
            url_submission.cse_hint
        )
        
        logger.info(f"Monitoring service returned: {type(result)} with keys: {result.keys() if isinstance(result, dict) else 'Not a dict'}")
        
        # Debug log the result structure
        if isinstance(result, dict):
            for key, value in result.items():
                logger.info(f"  {key}: {type(value)} = {value}")
        
        return ScanResult(**result)
        
    except Exception as e:
        logger.error(f"Error processing URL submission: {e}")
        logger.error(f"Result that caused error: {result if 'result' in locals() else 'result not available'}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts", response_model=AlertResponse)
async def get_alerts(
    limit: int = Query(50, ge=1, le=100),
    classification: Optional[str] = Query(None)
):
    """Get recent phishing alerts"""
    try:
        return await get_alerts_mongodb(limit, classification)
            
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_alerts_mongodb(limit: int, classification: Optional[str]) -> AlertResponse:
    """Get alerts from MongoDB"""
    query = {}
    if classification:
        query["classification"] = classification
    
    detections = await Detection.find(query).sort([("detection_time", -1)]).limit(limit).to_list()
    
    detection_responses = []
    for detection in detections:
        # Fetch URL record
        url_record = await URLRecord.get(detection.url_id)
        
        detection_response = DetectionResponse(
            id=str(detection.id),
            url=url_record.url if url_record else "Unknown",
            classification=detection.classification,
            confidence_score=detection.confidence_score,
            detection_time=detection.detection_time,
            evidence_path=detection.evidence_path,
            features=detection.features,
            cse_hint=url_record.cse_hint if url_record else None
        )
        detection_responses.append(detection_response)
    
    total_count = await Detection.count()
    
    return AlertResponse(
        detections=detection_responses,
        total_count=total_count
    )



@app.post("/labels", response_model=LabelResponse)
async def add_label(label_submission: LabelSubmission):
    """Add a truth label for model training"""
    try:
        return await add_label_mongodb(label_submission)
            
    except Exception as e:
        logger.error(f"Error adding label: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def add_label_mongodb(label_submission: LabelSubmission) -> LabelResponse:
    """Add label to MongoDB"""
    # Convert string ID to ObjectId
    try:
        url_object_id = ObjectId(label_submission.url_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid URL ID format")
    
    # Verify URL exists
    url_record = await URLRecord.get(url_object_id)
    if not url_record:
        raise HTTPException(status_code=404, detail="URL not found")
    
    # Create label
    label = Label(
        url_id=url_object_id,
        true_label=label_submission.true_label,
        notes=label_submission.notes
    )
    
    await label.insert()
    
    # Trigger model retraining (async)
    try:
        monitoring_service.retrain_model()
    except Exception as e:
        logger.warning(f"Model retraining failed: {e}")
    
    return LabelResponse(
        id=str(label.id),
        url_id=str(label.url_id),
        true_label=label.true_label,
        labeled_at=label.labeled_at,
        notes=label.notes
    )



@app.get("/labels", response_model=List[LabelResponse])
async def get_labels():
    """Get all truth labels"""
    try:
        return await get_labels_mongodb()
            
    except Exception as e:
        logger.error(f"Error retrieving labels: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_labels_mongodb() -> List[LabelResponse]:
    """Get labels from MongoDB"""
    labels = await Label.find().sort([("labeled_at", -1)]).to_list()
    
    return [
        LabelResponse(
            id=str(label.id),
            url_id=str(label.url_id),
            true_label=label.true_label,
            labeled_at=label.labeled_at,
            notes=label.notes
        )
        for label in labels
    ]



@app.get("/urls")
async def get_urls():
    """Get all monitored URLs"""
    try:
        urls = await URLRecord.find().sort([("last_scanned", -1)]).to_list()
        
        return [
            {
                "id": str(url.id),
                "url": url.url,
                "cse_hint": url.cse_hint,
                "first_seen": url.first_seen,
                "last_scanned": url.last_scanned,
                "scan_count": url.scan_count
            }
            for url in urls
        ]
            
    except Exception as e:
        logger.error(f"Error retrieving URLs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get system statistics"""
    try:
        total_urls = await URLRecord.count()
        total_detections = await Detection.count()
        total_labels = await Label.count()
        
        # Get unique URL counts by getting the latest detection for each URL
        detections = await Detection.find().to_list()
        
        # Group detections by URL and get the latest one for each
        url_latest_detections = {}
        for detection in detections:
            url_id = detection.url_id
            if url_id not in url_latest_detections:
                url_latest_detections[url_id] = detection
            elif detection.detection_time > url_latest_detections[url_id].detection_time:
                url_latest_detections[url_id] = detection
        
        # Count unique classifications
        phishing_count = sum(1 for d in url_latest_detections.values() if d.classification == "phishing")
        suspected_count = sum(1 for d in url_latest_detections.values() if d.classification == "suspicious")
        benign_count = sum(1 for d in url_latest_detections.values() if d.classification == "benign")
        
        return {
            "total_urls": total_urls,
            "total_detections": total_detections,
            "total_labels": total_labels,
            "phishing_count": phishing_count,
            "suspicious_count": suspected_count,
            "benign_count": benign_count,
            "monitoring_active": monitoring_service.is_running,
            "database_type": "MongoDB Atlas"
        }
        
    except Exception as e:
        logger.error(f"Error retrieving stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/retrain")
async def retrain_model():
    """Manually trigger model retraining"""
    try:
        monitoring_service.retrain_model()
        return {"message": "Model retraining initiated"}
    except Exception as e:
        logger.error(f"Error retraining model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": "MongoDB Atlas",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
