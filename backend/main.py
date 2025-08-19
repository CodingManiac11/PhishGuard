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

# Import both database systems
if settings.use_mongodb:
    from mongo_database import connect_to_mongo, close_mongo_connection
    from mongo_models import URLRecord, Detection, Label
    from bson import ObjectId
else:
    from database import get_db, engine, Base
    from models import URLRecord, Detection, Label

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

# Mount static files (frontend)
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Database initialization
if settings.use_mongodb:
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
else:
    # Create SQLite tables for fallback
    Base.metadata.create_all(bind=engine)
    
    @app.on_event("startup")
    async def startup_event():
        logger.info("🚀 Starting with SQLite fallback")
        monitoring_service.start()

    @app.on_event("shutdown")
    async def shutdown_event():
        monitoring_service.stop()


@app.get("/", response_class=HTMLResponse)
async def read_index():
    """Serve the main dashboard"""
    try:
        with open("frontend/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


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
        if settings.use_mongodb:
            return await get_alerts_mongodb(limit, classification)
        else:
            return await get_alerts_sqlite(limit, classification)
            
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


async def get_alerts_sqlite(limit: int, classification: Optional[str]) -> AlertResponse:
    """Get alerts from SQLite (fallback)"""
    # This would use the original SQLAlchemy code
    # For now, return empty response
    return AlertResponse(detections=[], total_count=0)


@app.post("/labels", response_model=LabelResponse)
async def add_label(label_submission: LabelSubmission):
    """Add a truth label for model training"""
    try:
        if settings.use_mongodb:
            return await add_label_mongodb(label_submission)
        else:
            return await add_label_sqlite(label_submission)
            
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


async def add_label_sqlite(label_submission: LabelSubmission) -> LabelResponse:
    """Add label to SQLite (fallback)"""
    # Original SQLAlchemy implementation would go here
    raise HTTPException(status_code=501, detail="SQLite labeling not implemented in this version")


@app.get("/labels", response_model=List[LabelResponse])
async def get_labels():
    """Get all truth labels"""
    try:
        if settings.use_mongodb:
            return await get_labels_mongodb()
        else:
            return await get_labels_sqlite()
            
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


async def get_labels_sqlite() -> List[LabelResponse]:
    """Get labels from SQLite (fallback)"""
    return []


@app.get("/urls")
async def get_urls():
    """Get all monitored URLs"""
    try:
        if settings.use_mongodb:
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
        else:
            return []
            
    except Exception as e:
        logger.error(f"Error retrieving URLs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get system statistics"""
    try:
        if settings.use_mongodb:
            total_urls = await URLRecord.count()
            total_detections = await Detection.count()
            total_labels = await Label.count()
            
            phishing_count = await Detection.find({"classification": "phishing"}).count()
            suspected_count = await Detection.find({"classification": "suspected"}).count()
            benign_count = await Detection.find({"classification": "benign"}).count()
        else:
            # SQLite fallback
            total_urls = 0
            total_detections = 0
            total_labels = 0
            phishing_count = 0
            suspected_count = 0
            benign_count = 0
        
        return {
            "total_urls": total_urls,
            "total_detections": total_detections,
            "total_labels": total_labels,
            "phishing_count": phishing_count,
            "suspected_count": suspected_count,
            "benign_count": benign_count,
            "monitoring_active": monitoring_service.is_running,
            "database_type": "MongoDB Atlas" if settings.use_mongodb else "SQLite"
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
        "database": "MongoDB Atlas" if settings.use_mongodb else "SQLite",
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
