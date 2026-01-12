"""
VirusTotal API Integration for PhishGuard
Checks URLs against 70+ antivirus engines
"""

import requests
import hashlib
import base64
import logging
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
from config import settings

logger = logging.getLogger(__name__)

class VirusTotalService:
    """Service for checking URLs against VirusTotal"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        if self.api_key:
            logger.info("✅ VirusTotal API initialized")
        else:
            logger.warning("⚠️ VirusTotal API key not configured")
    
    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)
    
    def _get_url_id(self, url: str) -> str:
        """Get VirusTotal URL identifier (base64 encoded URL)"""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning and get results
        Returns scan results with detection stats
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "VirusTotal API key not configured",
                "is_threat": False,
                "stats": {}
            }
        
        try:
            # First, try to get existing analysis
            url_id = self._get_url_id(url)
            result = await self._get_url_report(url_id)
            
            if result.get("success"):
                return result
            
            # If no existing report, submit for scanning
            scan_result = await self._submit_url(url)
            if not scan_result.get("success"):
                return scan_result
            
            # Wait briefly and try to get results
            await asyncio.sleep(2)
            return await self._get_url_report(url_id)
            
        except Exception as e:
            logger.error(f"VirusTotal scan error: {e}")
            return {
                "success": False,
                "error": str(e),
                "is_threat": False,
                "stats": {}
            }
    
    async def _submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            response = requests.post(
                f"{self.BASE_URL}/urls",
                headers=self.headers,
                data=f"url={url}",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "analysis_id": data.get("data", {}).get("id"),
                    "status": "queued"
                }
            elif response.status_code == 429:
                return {
                    "success": False,
                    "error": "Rate limit exceeded. Free tier: 4 requests/minute",
                    "is_threat": False
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "is_threat": False
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "is_threat": False
            }
    
    async def _get_url_report(self, url_id: str) -> Dict[str, Any]:
        """Get URL analysis report"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                
                is_threat = (malicious + suspicious) > 0
                threat_level = "LOW"
                if malicious >= 5:
                    threat_level = "HIGH"
                elif malicious >= 1 or suspicious >= 3:
                    threat_level = "MEDIUM"
                
                return {
                    "success": True,
                    "is_threat": is_threat,
                    "threat_level": threat_level,
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "total_engines": total
                    },
                    "detection_rate": f"{malicious}/{total}" if total > 0 else "0/0",
                    "categories": attributes.get("categories", {}),
                    "reputation": attributes.get("reputation", 0),
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "source": "virustotal"
                }
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "URL not found in VirusTotal database",
                    "is_threat": False,
                    "stats": {}
                }
            else:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code}",
                    "is_threat": False,
                    "stats": {}
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "is_threat": False,
                "stats": {}
            }
    
    def get_threat_summary(self, result: Dict[str, Any]) -> str:
        """Generate human-readable threat summary"""
        if not result.get("success"):
            return result.get("error", "Analysis failed")
        
        stats = result.get("stats", {})
        malicious = stats.get("malicious", 0)
        total = stats.get("total_engines", 0)
        
        if malicious == 0:
            return f"✅ Clean - No threats detected ({total} engines checked)"
        elif malicious < 3:
            return f"⚠️ Suspicious - {malicious}/{total} engines flagged this URL"
        else:
            return f"🚨 MALICIOUS - {malicious}/{total} engines detected threats!"


# Singleton instance
virustotal_service = VirusTotalService()
