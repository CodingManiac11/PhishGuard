"""
Screenshot capture module for PhishGuard
Captures screenshots of phishing websites as evidence
"""

import asyncio
import os
import logging
from typing import Optional
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import requests
from config import settings

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """Screenshot capture using Selenium WebDriver"""
    
    def __init__(self):
        self.driver = None
        self.screenshot_dir = "screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    def _get_driver(self):
        """Initialize Chrome WebDriver with headless options"""
        if self.driver is None:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-plugins")
            chrome_options.add_argument("--disable-images")  # Faster loading
            chrome_options.add_argument(f"--user-agent={settings.ua}")
            
            try:
                # Use webdriver-manager to automatically handle ChromeDriver
                service = Service(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
                self.driver.set_page_load_timeout(30)  # 30 second timeout
            except Exception as e:
                logger.error(f"Failed to initialize Chrome driver: {e}")
                raise
        
        return self.driver
    
    def capture_screenshot(self, url: str, scan_id: str, save_to_db: bool = True) -> Optional[dict]:
        """
        Capture screenshot of the URL
        
        Args:
            url: URL to capture
            scan_id: Unique scan identifier
            save_to_db: Whether to return data for database storage
            
        Returns:
            Dict with screenshot data or file path, or None if failed
        """
        if not settings.enable_screenshot:
            logger.info("Screenshot capture disabled in settings")
            return None
            
        try:
            driver = self._get_driver()
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{scan_id}_{timestamp}.png"
            
            logger.info(f"Capturing screenshot of {url}")
            
            # Navigate to URL
            driver.get(url)
            
            # Wait for page to load (or timeout after 10 seconds)
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except:
                logger.warning(f"Page body not found for {url}, capturing anyway")
            
            # Additional wait for dynamic content
            import time
            time.sleep(2)
            
            if save_to_db:
                # Capture screenshot to memory for database storage
                screenshot_data = driver.get_screenshot_as_png()
                
                if screenshot_data and len(screenshot_data) > 0:
                    logger.info(f"Screenshot captured to memory: {len(screenshot_data)} bytes")
                    return {
                        'data': screenshot_data,
                        'filename': filename,
                        'content_type': 'image/png',
                        'size': len(screenshot_data)
                    }
                else:
                    logger.error("Screenshot data is empty")
                    return None
            else:
                # Capture full page screenshot to file (legacy mode)
                filepath = os.path.join(self.screenshot_dir, filename)
                driver.save_screenshot(filepath)
                
                # Verify screenshot was created
                if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                    logger.info(f"Screenshot saved to file: {filepath}")
                    return {'file_path': filepath}
                else:
                    logger.error(f"Screenshot file not created or empty: {filepath}")
                    return None
                
        except Exception as e:
            logger.error(f"Failed to capture screenshot for {url}: {e}")
            return None
    
    async def capture_screenshot_async(self, url: str, scan_id: str, save_to_db: bool = True) -> Optional[dict]:
        """Async wrapper for screenshot capture"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.capture_screenshot, url, scan_id, save_to_db)
    
    def close(self):
        """Close the WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
                self.driver = None
            except Exception as e:
                logger.error(f"Error closing WebDriver: {e}")
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        self.close()


class LightweightScreenshot:
    """Lightweight screenshot alternative using requests + HTML2Image (fallback)"""
    
    def __init__(self):
        self.screenshot_dir = "screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    def capture_html_snapshot(self, url: str, scan_id: str, return_content: bool = True) -> Optional[dict]:
        """
        Capture HTML content as evidence
        
        Args:
            url: URL to capture
            scan_id: Unique scan identifier  
            return_content: Whether to return HTML content for database storage
            
        Returns:
            Dict with HTML content or file path, or None if failed
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"html_snapshot_{scan_id}_{timestamp}.html"
            
            # Fetch page content
            response = requests.get(url, timeout=30, headers={'User-Agent': settings.ua})
            
            if response.status_code == 200:
                html_content = response.text
                
                if return_content:
                    # Return content for database storage
                    logger.info(f"HTML content captured: {len(html_content)} characters")
                    return {
                        'html_content': html_content,
                        'filename': filename,
                        'size': len(html_content.encode('utf-8'))
                    }
                else:
                    # Save to file (legacy mode)
                    filepath = os.path.join(self.screenshot_dir, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    
                    logger.info(f"HTML snapshot saved: {filepath}")
                    return {'file_path': filepath}
            else:
                logger.warning(f"Failed to fetch {url}: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to capture HTML snapshot for {url}: {e}")
            return None


# Database Screenshot Storage Functions
async def store_screenshot_in_db(screenshot_data: dict) -> str:
    """
    Store screenshot data in MongoDB database
    
    Args:
        screenshot_data: Dictionary containing screenshot binary data and metadata
        
    Returns:
        str: Screenshot ID for database retrieval
    """
    try:
        from mongo_models import Detection
        import base64
        from datetime import datetime
        from bson import ObjectId
        
        # Generate unique ID
        screenshot_id = str(ObjectId())
        
        # Encode binary data to base64 for storage
        screenshot_b64 = base64.b64encode(screenshot_data['data']).decode('utf-8')
        
        # Store in database - using a simple approach for now
        # In production, you might want a dedicated Screenshot collection
        screenshot_doc = {
            '_id': ObjectId(screenshot_id),
            'screenshot_data': screenshot_b64,
            'content_type': screenshot_data.get('content_type', 'image/png'),
            'filename': screenshot_data.get('filename', f'screenshot_{screenshot_id}.png'),
            'size': screenshot_data.get('size', len(screenshot_data['data'])),
            'stored_at': datetime.utcnow()
        }
        
        # Store using motor client directly
        from mongo_database import database
        if database is not None:
            result = await database.screenshots.insert_one(screenshot_doc)
            logger.info(f"Screenshot stored in database with ID: {screenshot_id}")
            return screenshot_id
        else:
            logger.error("Database not available for screenshot storage")
            return None
            
    except Exception as e:
        logger.error(f"Failed to store screenshot in database: {e}")
        return None


async def get_screenshot_from_db(screenshot_id: str) -> dict:
    """
    Retrieve screenshot data from MongoDB database
    
    Args:
        screenshot_id: Screenshot ID from database
        
    Returns:
        dict: Screenshot data dictionary with binary data and metadata
    """
    try:
        from bson import ObjectId
        import base64
        from mongo_database import database
        
        if database is None:
            logger.error("Database not available for screenshot retrieval")
            return None
            
        # Retrieve from database
        screenshot_doc = await database.screenshots.find_one({'_id': ObjectId(screenshot_id)})
        
        if not screenshot_doc:
            logger.warning(f"Screenshot not found in database: {screenshot_id}")
            return None
            
        # Decode base64 data back to binary
        screenshot_data = base64.b64decode(screenshot_doc['screenshot_data'])
        
        return {
            'data': screenshot_data,
            'content_type': screenshot_doc.get('content_type', 'image/png'),
            'filename': screenshot_doc.get('filename'),
            'size': screenshot_doc.get('size', len(screenshot_data))
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve screenshot from database: {e}")
        return None


# Global screenshot capture instance
screenshot_capturer = None

def get_screenshot_capturer():
    """Get or create screenshot capturer instance"""
    global screenshot_capturer
    if screenshot_capturer is None:
        try:
            screenshot_capturer = ScreenshotCapture()
        except Exception as e:
            logger.warning(f"Failed to initialize screenshot capturer, using lightweight version: {e}")
            screenshot_capturer = LightweightScreenshot()
    return screenshot_capturer
