from beanie import Document, Indexed
from pydantic import Field, ConfigDict
from typing import Optional, List, Annotated
from datetime import datetime
from bson import ObjectId


class URLRecord(Document):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    url: Annotated[str, Indexed(unique=True)]
    cse_hint: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_scanned: datetime = Field(default_factory=datetime.utcnow)
    scan_count: int = 1
    
    class Settings:
        name = "url_records"


class Detection(Document):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    url_id: ObjectId
    url_record: Optional[URLRecord] = None  # Will be populated when needed
    detection_time: datetime = Field(default_factory=datetime.utcnow)
    classification: str  # phishing, suspicious, benign
    confidence_score: float
    features: dict  # Store features directly as dict instead of JSON string
    evidence_path: Optional[str] = None
    
    # Enhanced precision fields
    threat_level: Optional[str] = None  # HIGH, MEDIUM, LOW
    phishing_probability: Optional[float] = None  # Specific phishing probability
    risk_factors: Optional[List[str]] = None  # List of identified risk factors
    model_explanation: Optional[str] = None  # Human-readable explanation
    
    # Enhanced evidence storage
    screenshot_data: Optional[bytes] = None  # Store screenshot as binary data
    screenshot_filename: Optional[str] = None  # Original filename
    screenshot_content_type: Optional[str] = None  # MIME type (image/png)
    screenshot_size: Optional[int] = None  # File size in bytes
    html_evidence: Optional[str] = None  # Store HTML content directly
    
    class Settings:
        name = "detections"


class Label(Document):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    url_id: ObjectId
    url_record: Optional[URLRecord] = None  # Will be populated when needed
    true_label: str  # phishing, benign
    labeled_at: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None
    
    class Settings:
        name = "labels"
