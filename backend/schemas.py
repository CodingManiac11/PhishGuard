from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class URLSubmission(BaseModel):
    url: str
    cse_hint: Optional[str] = None


class DetectionResponse(BaseModel):
    id: str  # Changed from int to str for MongoDB ObjectId compatibility
    url: str
    classification: str
    confidence_score: float
    detection_time: datetime
    evidence_path: Optional[str]
    features: Dict[str, Any]
    cse_hint: Optional[str]
    # Enhanced fields
    threat_level: Optional[str] = None
    cse_similarity_score: Optional[float] = None
    hosted_infrastructure: Optional[bool] = None
    infrastructure_type: Optional[str] = None
    screenshot_path: Optional[str] = None
    risk_factors: Optional[List[str]] = None

    class Config:
        from_attributes = True


class LabelSubmission(BaseModel):
    url_id: int
    true_label: str
    notes: Optional[str] = None


class LabelResponse(BaseModel):
    id: int
    url_id: int
    true_label: str
    labeled_at: datetime
    notes: Optional[str]

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    detections: List[DetectionResponse]
    total_count: int


class ScanResult(BaseModel):
    scan_id: Optional[str] = None
    classification: str
    confidence_score: float
    threat_level: Optional[str] = None
    phishing_probability: Optional[float] = None
    risk_factors: Optional[List[str]] = None
    explanation: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    evidence_path: Optional[str] = None
    timestamp: Optional[str] = None
    # Enhanced fields
    cse_similarity_score: Optional[float] = None
    hosted_infrastructure: Optional[bool] = None
    infrastructure_type: Optional[str] = None
    screenshot_path: Optional[str] = None
