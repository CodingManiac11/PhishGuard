#!/usr/bin/env python3
"""
Screenshot Viewer Tool for PhishGuard Database Screenshots
"""
import asyncio
import requests
import base64
import os
import webbrowser
from datetime import datetime
import sys

# Add the current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mongo_database import connect_to_mongo, close_mongo_connection
from mongo_models import Detection


async def list_screenshots():
    """List all available screenshots in database"""
    print("🖼️  Available Screenshots in Database:")
    print("=" * 50)
    
    try:
        await connect_to_mongo()
        
        # Get all detections with screenshots
        detections = await Detection.find(
            Detection.screenshot_data != None
        ).sort([("detection_time", -1)]).to_list()
        
        if not detections:
            print("❌ No screenshots found in database")
            return []
            
        for i, detection in enumerate(detections, 1):
            url_record = None
            if detection.url_id:
                from mongo_models import URLRecord
                try:
                    url_record = await URLRecord.get(detection.url_id)
                except:
                    pass
            
            url = url_record.url if url_record else "Unknown URL"
            size = detection.screenshot_size or (len(detection.screenshot_data) if detection.screenshot_data else 0)
            
            print(f"{i:2}. ID: {detection.id}")
            print(f"    URL: {url[:80]}{'...' if len(url) > 80 else ''}")
            print(f"    Classification: {detection.classification}")
            print(f"    Threat Level: {detection.threat_level}")
            print(f"    Screenshot Size: {size:,} bytes")
            print(f"    Detection Time: {detection.detection_time}")
            print(f"    API URL: http://localhost:8000/screenshot/{detection.id}")
            print()
        
        return detections
        
    except Exception as e:
        print(f"❌ Error listing screenshots: {e}")
        return []


def view_screenshot_in_browser(detection_id):
    """Open screenshot in web browser"""
    screenshot_url = f"http://localhost:8000/screenshot/{detection_id}"
    print(f"🌐 Opening screenshot in browser: {screenshot_url}")
    webbrowser.open(screenshot_url)


def download_screenshot(detection_id, filename=None):
    """Download screenshot to local file"""
    try:
        screenshot_url = f"http://localhost:8000/screenshot/{detection_id}"
        info_url = f"http://localhost:8000/screenshot/{detection_id}/info"
        
        # Get screenshot info first
        info_response = requests.get(info_url)
        if info_response.status_code == 200:
            info = info_response.json()
            if not filename:
                filename = info.get('filename', f'screenshot_{detection_id}.png')
        else:
            filename = filename or f'screenshot_{detection_id}.png'
        
        # Download screenshot
        response = requests.get(screenshot_url)
        if response.status_code == 200:
            with open(filename, 'wb') as f:
                f.write(response.content)
            print(f"✅ Screenshot downloaded: {filename}")
            print(f"📁 Size: {len(response.content):,} bytes")
            return filename
        else:
            print(f"❌ Failed to download screenshot: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Error downloading screenshot: {e}")
        return None


async def create_screenshot_gallery():
    """Create an HTML gallery of all screenshots"""
    print("🎨 Creating Screenshot Gallery...")
    
    try:
        await connect_to_mongo()
        
        detections = await Detection.find(
            Detection.screenshot_data != None
        ).sort([("detection_time", -1)]).to_list()
        
        if not detections:
            print("❌ No screenshots found for gallery")
            return
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PhishGuard Screenshot Gallery</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .gallery {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }}
        .screenshot-card {{ 
            background: white; 
            border-radius: 10px; 
            padding: 20px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .screenshot-img {{ 
            width: 100%; 
            height: 250px; 
            object-fit: cover; 
            border-radius: 8px;
            cursor: pointer;
        }}
        .screenshot-info {{ margin-top: 15px; }}
        .url {{ font-weight: bold; color: #333; word-break: break-all; }}
        .classification {{ 
            display: inline-block; 
            padding: 5px 10px; 
            border-radius: 5px; 
            color: white;
            font-size: 12px;
            margin: 5px 0;
        }}
        .benign {{ background: #28a745; }}
        .suspicious {{ background: #ffc107; color: #000; }}
        .malicious {{ background: #dc3545; }}
        .phishing {{ background: #dc3545; }}
        .threat-level {{ font-size: 12px; color: #666; }}
        .timestamp {{ font-size: 12px; color: #999; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🖼️ PhishGuard Screenshot Gallery</h1>
        <p>Database Screenshots - Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Screenshots: {len(detections)}</p>
    </div>
    <div class="gallery">
"""
        
        for detection in detections:
            url_record = None
            if detection.url_id:
                from mongo_models import URLRecord
                try:
                    url_record = await URLRecord.get(detection.url_id)
                except:
                    pass
            
            url = url_record.url if url_record else "Unknown URL"
            screenshot_url = f"http://localhost:8000/screenshot/{detection.id}"
            size = detection.screenshot_size or (len(detection.screenshot_data) if detection.screenshot_data else 0)
            
            html += f"""
        <div class="screenshot-card">
            <img src="{screenshot_url}" alt="Screenshot" class="screenshot-img" 
                 onclick="window.open('{screenshot_url}', '_blank')">
            <div class="screenshot-info">
                <div class="url">{url[:100]}{'...' if len(url) > 100 else ''}</div>
                <div class="classification {detection.classification}">{detection.classification.upper()}</div>
                <div class="threat-level">Threat Level: {detection.threat_level}</div>
                <div class="threat-level">Confidence: {detection.confidence_score:.2f}</div>
                <div class="threat-level">Size: {size:,} bytes</div>
                <div class="timestamp">{detection.detection_time}</div>
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        # Save gallery
        gallery_file = "screenshot_gallery.html"
        with open(gallery_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ Gallery created: {gallery_file}")
        print(f"🌐 Opening gallery in browser...")
        webbrowser.open(os.path.abspath(gallery_file))
        
    except Exception as e:
        print(f"❌ Error creating gallery: {e}")


async def main():
    """Main screenshot viewer interface"""
    print("🖼️  PhishGuard Screenshot Viewer")
    print("=" * 40)
    
    try:
        while True:
            print("\nOptions:")
            print("1. List all screenshots")
            print("2. View screenshot in browser")
            print("3. Download screenshot")
            print("4. Create HTML gallery")
            print("5. Exit")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                detections = await list_screenshots()
                
            elif choice == '2':
                detections = await list_screenshots()
                if detections:
                    try:
                        index = int(input("Enter screenshot number: ")) - 1
                        if 0 <= index < len(detections):
                            view_screenshot_in_browser(detections[index].id)
                        else:
                            print("❌ Invalid screenshot number")
                    except ValueError:
                        print("❌ Please enter a valid number")
                        
            elif choice == '3':
                detections = await list_screenshots()
                if detections:
                    try:
                        index = int(input("Enter screenshot number: ")) - 1
                        if 0 <= index < len(detections):
                            filename = input("Enter filename (press Enter for auto): ").strip()
                            download_screenshot(detections[index].id, filename or None)
                        else:
                            print("❌ Invalid screenshot number")
                    except ValueError:
                        print("❌ Please enter a valid number")
                        
            elif choice == '4':
                await create_screenshot_gallery()
                
            elif choice == '5':
                break
                
            else:
                print("❌ Invalid option")
                
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await close_mongo_connection()


if __name__ == "__main__":
    asyncio.run(main())
