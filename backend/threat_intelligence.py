"""
Google Safe Browsing API Integration
Provides real-time URL threat checking using Google's Safe Browsing service.

To use this service, you need a Google Safe Browsing API key:
1. Go to: https://console.cloud.google.com/
2. Create a new project or select existing
3. Enable "Safe Browsing API"
4. Create credentials (API Key)
5. Add to .env: PHISHGUARD_GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
"""

import requests
import logging
from typing import Dict, Any, Optional, List
from config import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """
    Integrates with external threat intelligence APIs for enhanced detection.
    Primary: Google Safe Browsing API
    """
    
    def __init__(self):
        self.google_api_key = getattr(settings, 'google_safe_browsing_api_key', None)
        self.google_api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        
        # Threat types to check
        self.threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",  # Phishing
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
        
        # Platform types
        self.platform_types = ["ANY_PLATFORM"]
        
        # Threat entry types
        self.threat_entry_types = ["URL"]
        
        if self.google_api_key:
            logger.info("✅ Google Safe Browsing API initialized")
        else:
            logger.warning("⚠️ Google Safe Browsing API key not configured. External threat checking disabled.")
    
    def is_configured(self) -> bool:
        """Check if the threat intelligence service is properly configured"""
        return bool(self.google_api_key)
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against Google Safe Browsing API.
        
        Returns:
            Dict with:
            - is_threat: bool - True if URL is flagged as malicious
            - threat_types: List[str] - Types of threats detected
            - confidence: float - Confidence score (1.0 if threat found)
            - source: str - "google_safe_browsing"
            - error: str - Error message if API call failed
        """
        if not self.google_api_key:
            return {
                'is_threat': False,
                'threat_types': [],
                'confidence': 0.0,
                'source': 'google_safe_browsing',
                'error': 'API key not configured'
            }
        
        try:
            # Build the request payload
            payload = {
                "client": {
                    "clientId": "phishguard",
                    "clientVersion": "2.0.0"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": self.platform_types,
                    "threatEntryTypes": self.threat_entry_types,
                    "threatEntries": [
                        {"url": url}
                    ]
                }
            }
            
            # Make the API request
            response = requests.post(
                f"{self.google_api_url}?key={self.google_api_key}",
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if any matches were found
                if 'matches' in data and len(data['matches']) > 0:
                    threat_types = list(set(
                        match.get('threatType', 'UNKNOWN') 
                        for match in data['matches']
                    ))
                    
                    logger.warning(f"🚨 THREAT DETECTED by Google Safe Browsing: {url} - {threat_types}")
                    
                    return {
                        'is_threat': True,
                        'threat_types': threat_types,
                        'confidence': 1.0,  # Google's detection is authoritative
                        'source': 'google_safe_browsing',
                        'details': data['matches']
                    }
                else:
                    # No threats found
                    return {
                        'is_threat': False,
                        'threat_types': [],
                        'confidence': 0.0,
                        'source': 'google_safe_browsing'
                    }
            
            elif response.status_code == 400:
                logger.error(f"Google Safe Browsing API bad request: {response.text}")
                return {
                    'is_threat': False,
                    'threat_types': [],
                    'confidence': 0.0,
                    'source': 'google_safe_browsing',
                    'error': 'Bad request to API'
                }
            
            elif response.status_code == 403:
                logger.error("Google Safe Browsing API key invalid or quota exceeded")
                return {
                    'is_threat': False,
                    'threat_types': [],
                    'confidence': 0.0,
                    'source': 'google_safe_browsing',
                    'error': 'API key invalid or quota exceeded'
                }
            
            else:
                logger.error(f"Google Safe Browsing API error: {response.status_code}")
                return {
                    'is_threat': False,
                    'threat_types': [],
                    'confidence': 0.0,
                    'source': 'google_safe_browsing',
                    'error': f'API returned status {response.status_code}'
                }
                
        except requests.Timeout:
            logger.warning("Google Safe Browsing API timeout")
            return {
                'is_threat': False,
                'threat_types': [],
                'confidence': 0.0,
                'source': 'google_safe_browsing',
                'error': 'API timeout'
            }
        except Exception as e:
            logger.error(f"Google Safe Browsing API error: {e}")
            return {
                'is_threat': False,
                'threat_types': [],
                'confidence': 0.0,
                'source': 'google_safe_browsing',
                'error': str(e)
            }
    
    def check_url_sync(self, url: str) -> Dict[str, Any]:
        """Synchronous version of check_url for non-async contexts"""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're in an async context, create a new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.check_url(url))
                    return future.result()
            else:
                return loop.run_until_complete(self.check_url(url))
        except RuntimeError:
            return asyncio.run(self.check_url(url))
    
    def get_threat_description(self, threat_type: str) -> str:
        """Get human-readable description of threat type"""
        descriptions = {
            'MALWARE': 'Malware distribution site',
            'SOCIAL_ENGINEERING': 'Phishing/deceptive site',
            'UNWANTED_SOFTWARE': 'Unwanted software distribution',
            'POTENTIALLY_HARMFUL_APPLICATION': 'Potentially harmful application',
            'THREAT_TYPE_UNSPECIFIED': 'Unknown threat'
        }
        return descriptions.get(threat_type, f'Threat: {threat_type}')


# Global instance
threat_intelligence = ThreatIntelligenceService()
