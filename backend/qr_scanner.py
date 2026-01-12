"""
QR Code Scanner for PhishGuard
Extracts and analyzes URLs embedded in QR codes
"""

import logging
import base64
import io
from typing import Dict, Any, Optional, List
from PIL import Image

logger = logging.getLogger(__name__)

# Try to import pyzbar, but make it optional
try:
    from pyzbar.pyzbar import decode as decode_qr
    from pyzbar.pyzbar import ZBarSymbol
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False
    logger.warning("⚠️ pyzbar not available - QR scanning disabled")


class QRScanner:
    """Scan QR codes and extract URLs for analysis"""
    
    def __init__(self):
        if PYZBAR_AVAILABLE:
            logger.info("✅ QR Scanner initialized")
        else:
            logger.warning("⚠️ QR Scanner disabled - install pyzbar and zbar")
    
    def is_available(self) -> bool:
        """Check if QR scanning is available"""
        return PYZBAR_AVAILABLE
    
    async def scan_image(self, image_data: bytes) -> Dict[str, Any]:
        """
        Scan QR code from image bytes
        Returns extracted data and URLs
        """
        if not PYZBAR_AVAILABLE:
            return {
                "success": False,
                "error": "QR scanning not available - pyzbar not installed",
                "urls": []
            }
        
        try:
            # Load image
            image = Image.open(io.BytesIO(image_data))
            
            # Decode QR codes
            decoded_objects = decode_qr(image, symbols=[ZBarSymbol.QRCODE])
            
            if not decoded_objects:
                return {
                    "success": True,
                    "found": False,
                    "message": "No QR code found in image",
                    "urls": [],
                    "data": []
                }
            
            # Extract data from all QR codes
            results = []
            urls = []
            
            for obj in decoded_objects:
                data = obj.data.decode("utf-8", errors="ignore")
                result = {
                    "type": obj.type,
                    "data": data,
                    "rect": {
                        "left": obj.rect.left,
                        "top": obj.rect.top,
                        "width": obj.rect.width,
                        "height": obj.rect.height
                    }
                }
                
                # Check if data is a URL
                if self._is_url(data):
                    result["is_url"] = True
                    urls.append(data)
                else:
                    result["is_url"] = False
                
                results.append(result)
            
            return {
                "success": True,
                "found": True,
                "count": len(decoded_objects),
                "urls": urls,
                "data": results,
                "message": f"Found {len(decoded_objects)} QR code(s), {len(urls)} URL(s)"
            }
            
        except Exception as e:
            logger.error(f"QR scan error: {e}")
            return {
                "success": False,
                "error": str(e),
                "urls": []
            }
    
    async def scan_base64(self, base64_data: str) -> Dict[str, Any]:
        """Scan QR code from base64 encoded image"""
        try:
            # Remove data URL prefix if present
            if "," in base64_data:
                base64_data = base64_data.split(",")[1]
            
            image_bytes = base64.b64decode(base64_data)
            return await self.scan_image(image_bytes)
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Invalid base64 data: {e}",
                "urls": []
            }
    
    def _is_url(self, text: str) -> bool:
        """Check if text is a URL"""
        text = text.lower().strip()
        return (
            text.startswith("http://") or 
            text.startswith("https://") or
            text.startswith("www.") or
            text.startswith("ftp://")
        )


# Singleton instance
qr_scanner = QRScanner()
