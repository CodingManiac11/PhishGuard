"""
JSON File Storage for PhishGuard
Simple local file-based storage to replace MongoDB
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from threading import Lock

logger = logging.getLogger(__name__)

# Storage directory
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "data")


class JSONStorage:
    """Simple JSON file-based storage"""
    
    def __init__(self):
        self._lock = Lock()
        self._ensure_storage_dir()
        self._data = {
            "scans": [],
            "alerts": [],
            "labels": [],
            "stats": {
                "total_urls": 0,
                "phishing_count": 0,
                "suspicious_count": 0,
                "benign_count": 0
            }
        }
        self._load_data()
        logger.info("✅ JSON Storage initialized")
    
    def _ensure_storage_dir(self):
        """Create storage directory if it doesn't exist"""
        if not os.path.exists(STORAGE_DIR):
            os.makedirs(STORAGE_DIR)
            logger.info(f"📁 Created storage directory: {STORAGE_DIR}")
    
    def _get_file_path(self) -> str:
        """Get path to main data file"""
        return os.path.join(STORAGE_DIR, "phishguard_data.json")
    
    def _load_data(self):
        """Load data from JSON file"""
        file_path = self._get_file_path()
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self._data = json.load(f)
                logger.info(f"📂 Loaded {len(self._data.get('scans', []))} scans from storage")
            except Exception as e:
                logger.error(f"Error loading data: {e}")
    
    def _save_data(self):
        """Save data to JSON file"""
        file_path = self._get_file_path()
        try:
            with self._lock:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self._data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving data: {e}")
    
    # ================= SCAN OPERATIONS =================
    
    def save_scan(self, url: str, result: Dict[str, Any]) -> str:
        """Save a scan result and return its ID"""
        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        
        scan_record = {
            "id": scan_id,
            "url": url,
            "classification": result.get("classification", "unknown"),
            "confidence_score": result.get("confidence_score", 0),
            "threat_level": result.get("threat_level", "UNKNOWN"),
            "phishing_probability": result.get("phishing_probability", 0),
            "risk_factors": result.get("risk_factors", []),
            "explanation": result.get("explanation", ""),
            "timestamp": datetime.utcnow().isoformat(),
            "features": result.get("features", {})
        }
        
        with self._lock:
            self._data["scans"].append(scan_record)
            
            # Update stats
            self._data["stats"]["total_urls"] += 1
            if result.get("classification") == "phishing":
                self._data["stats"]["phishing_count"] += 1
            elif result.get("classification") == "suspicious":
                self._data["stats"]["suspicious_count"] += 1
            else:
                self._data["stats"]["benign_count"] += 1
        
        self._save_data()
        return scan_id
    
    def get_scans(self, limit: int = 100, classification: Optional[str] = None) -> List[Dict]:
        """Get scan records, optionally filtered by classification"""
        scans = self._data.get("scans", [])
        
        if classification:
            scans = [s for s in scans if s.get("classification") == classification]
        
        # Return most recent first
        return sorted(scans, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
    
    def get_scan_by_url(self, url: str) -> Optional[Dict]:
        """Find a scan by URL"""
        for scan in reversed(self._data.get("scans", [])):
            if scan.get("url") == url:
                return scan
        return None
    
    # ================= ALERT OPERATIONS =================
    
    def save_alert(self, url: str, classification: str, confidence: float, 
                   threat_level: str, explanation: str = "") -> str:
        """Save an alert"""
        alert_id = f"alert_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        
        alert = {
            "id": alert_id,
            "url": url,
            "classification": classification,
            "confidence_score": confidence,
            "threat_level": threat_level,
            "explanation": explanation,
            "timestamp": datetime.utcnow().isoformat(),
            "acknowledged": False
        }
        
        with self._lock:
            self._data["alerts"].append(alert)
        
        self._save_data()
        return alert_id
    
    def get_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts"""
        alerts = self._data.get("alerts", [])
        return sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged"""
        for alert in self._data.get("alerts", []):
            if alert.get("id") == alert_id:
                alert["acknowledged"] = True
                self._save_data()
                return True
        return False
    
    # ================= LABEL OPERATIONS =================
    
    def save_label(self, url: str, label: str, notes: str = "") -> str:
        """Save a label for a URL"""
        label_id = f"label_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        
        label_record = {
            "id": label_id,
            "url": url,
            "label": label,
            "notes": notes,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        with self._lock:
            self._data["labels"].append(label_record)
        
        self._save_data()
        return label_id
    
    def get_labels(self, limit: int = 100) -> List[Dict]:
        """Get labels"""
        labels = self._data.get("labels", [])
        return sorted(labels, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
    
    def get_label_for_url(self, url: str) -> Optional[Dict]:
        """Get the most recent label for a URL"""
        for label in reversed(self._data.get("labels", [])):
            if label.get("url") == url:
                return label
        return None
    
    # ================= STATS OPERATIONS =================
    
    def get_stats(self) -> Dict[str, int]:
        """Get current statistics"""
        return self._data.get("stats", {
            "total_urls": 0,
            "phishing_count": 0,
            "suspicious_count": 0,
            "benign_count": 0
        })
    
    def recalculate_stats(self):
        """Recalculate stats from scan data"""
        scans = self._data.get("scans", [])
        
        stats = {
            "total_urls": len(scans),
            "phishing_count": sum(1 for s in scans if s.get("classification") == "phishing"),
            "suspicious_count": sum(1 for s in scans if s.get("classification") == "suspicious"),
            "benign_count": sum(1 for s in scans if s.get("classification") == "benign")
        }
        
        self._data["stats"] = stats
        self._save_data()
        return stats
    
    # ================= URL HISTORY =================
    
    def get_urls(self, limit: int = 100, classification: Optional[str] = None) -> List[Dict]:
        """Get URL scan history"""
        return self.get_scans(limit=limit, classification=classification)
    
    # ================= CONNECTION METHODS (for compatibility) =================
    
    async def connect(self):
        """Compatibility method - JSON storage doesn't need connection"""
        logger.info("✅ JSON Storage ready (no connection needed)")
    
    async def disconnect(self):
        """Compatibility method - save data on shutdown"""
        self._save_data()
        logger.info("✅ JSON Storage saved and closed")


# Singleton instance
storage = JSONStorage()
