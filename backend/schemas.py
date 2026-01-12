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


# New Security Scan Schemas
class VirusTotalScanRequest(BaseModel):
    url: str


class VirusTotalScanResult(BaseModel):
    success: bool
    is_threat: bool
    threat_level: Optional[str] = None
    stats: Optional[Dict[str, int]] = None
    detection_rate: Optional[str] = None
    categories: Optional[Dict[str, str]] = None
    summary: Optional[str] = None
    error: Optional[str] = None


class SSLAnalysisRequest(BaseModel):
    url: str


class SSLAnalysisResult(BaseModel):
    success: bool
    is_secure: bool
    risk_level: Optional[str] = None
    hostname: Optional[str] = None
    certificate: Optional[Dict[str, Any]] = None
    issues: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    summary: Optional[str] = None
    error: Optional[str] = None


class QRScanRequest(BaseModel):
    image_base64: str


class QRScanResult(BaseModel):
    success: bool
    found: Optional[bool] = None
    count: Optional[int] = None
    urls: Optional[List[str]] = None
    data: Optional[List[Dict[str, Any]]] = None
    message: Optional[str] = None
    error: Optional[str] = None


class EmailAnalysisRequest(BaseModel):
    headers: str


class EmailAnalysisResult(BaseModel):
    success: bool
    is_suspicious: bool
    risk_level: Optional[str] = None
    sender: Optional[Dict[str, str]] = None
    authentication: Optional[Dict[str, Any]] = None
    issues: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    summary: Optional[str] = None
    error: Optional[str] = None

