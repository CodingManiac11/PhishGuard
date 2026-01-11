from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any
import re
from urllib.parse import urlparse

app = FastAPI(title="PhishGuard MVP")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLSubmission(BaseModel):
    url: str

class ScanResult(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    risk_factors: List[str]
    safe_to_visit: bool

# Simple phishing detection
def classify_url(url: str) -> Dict[str, Any]:
    risk_score = 0.0
    risk_factors = []
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    trusted_domains = {'google.com', 'microsoft.com', 'amazon.com', 'github.com'}
    
    if domain in trusted_domains:
        return {
            'is_phishing': False,
            'confidence': 0.95,
            'risk_factors': [],
            'safe_to_visit': True
        }
    
    if len(url) > 100:
        risk_score += 0.2
        risk_factors.append('Long URL')
    
    if len(domain.split('.')) > 3:
        risk_score += 0.3
        risk_factors.append('Multiple subdomains')
    
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
        risk_score += 0.4
        risk_factors.append('IP address')
    
    is_phishing = risk_score >= 0.7
    confidence = min(risk_score, 0.95) if is_phishing else max(0.5, 1.0 - risk_score)
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'risk_factors': risk_factors,
        'safe_to_visit': not is_phishing
    }

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishGuard - URL Security Scanner</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { background: #f5f5f5; padding: 30px; border-radius: 10px; }
            h1 { text-align: center; color: #333; }
            input { width: 70%; padding: 10px; margin: 10px; border: 1px solid #ccc; border-radius: 5px; }
            button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
            .safe { background: #d4edda; color: #155724; }
            .danger { background: #f8d7da; color: #721c24; }
            .warning { background: #fff3cd; color: #856404; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ PhishGuard</h1>
            <p style="text-align: center;">Enter a URL to check for phishing indicators</p>
            
            <div style="text-align: center;">
                <input type="url" id="urlInput" placeholder="https://example.com" />
                <button onclick="scanUrl()">Scan URL</button>
            </div>
            
            <div id="result"></div>
        </div>
        
        <script>
            async function scanUrl() {
                const url = document.getElementById('urlInput').value;
                if (!url) return;
                
                try {
                    const response = await fetch('/api/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    
                    const data = await response.json();
                    displayResult(data);
                } catch (error) {
                    document.getElementById('result').innerHTML = 
                        '<div class="result danger">Error: ' + error.message + '</div>';
                }
            }
            
            function displayResult(data) {
                let className = 'safe';
                let status = '✅ Safe';
                
                if (data.is_phishing) {
                    className = 'danger';
                    status = '❌ Dangerous';
                } else if (data.confidence < 0.7) {
                    className = 'warning';
                    status = '⚠️ Suspicious';
                }
                
                let riskFactors = data.risk_factors.length > 0 
                    ? '<br><strong>Risk factors:</strong> ' + data.risk_factors.join(', ')
                    : '';
                
                document.getElementById('result').innerHTML = 
                    '<div class="result ' + className + '">' +
                    '<strong>' + status + '</strong><br>' +
                    'URL: ' + data.url + '<br>' +
                    'Confidence: ' + Math.round(data.confidence * 100) + '%' +
                    riskFactors +
                    '</div>';
            }
        </script>
    </body>
    </html>
    """)

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/scan", response_model=ScanResult)
async def scan_url(submission: URLSubmission):
    try:
        if not submission.url.startswith(('http://', 'https://')):
            submission.url = 'http://' + submission.url
        
        result = classify_url(submission.url)
        
        return ScanResult(
            url=submission.url,
            is_phishing=result['is_phishing'],
            confidence=result['confidence'],
            risk_factors=result['risk_factors'],
            safe_to_visit=result['safe_to_visit']
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# For Vercel
def handler(request):
    return app(request)
