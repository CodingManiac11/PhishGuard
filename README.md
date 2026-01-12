# 🛡️ PhishGuard - AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-green)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An advanced AI-powered phishing and malware detection system that uses machine learning to analyze URLs and protect users from threats.

## 🎯 Key Features

- **🤖 Hybrid ML Detection**: Ensemble model (RandomForest + GradientBoosting + LogisticRegression)
- **⚖️ Compare Scans**: Side-by-side PhishGuard ML + VirusTotal analysis
- **🔐 SSL Certificate Analysis**: Certificate validation and security checks
- **📧 Email Header Analysis**: SPF/DKIM/DMARC spoofing detection
- **50+ URL Features**: URL structure, typosquatting, brand impersonation, malware patterns
- **166 Trusted Domains**: Zero false positives on legitimate sites
- **📁 Local JSON Storage**: No external database required

## Screenshots

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/e28de7a4-6e2c-40da-8224-24646d65e662" />

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/2e644890-f6e4-4e34-8d92-3c0932ef43e9" />

## 🚀 Quick Start

### Prerequisites
- Python 3.8+

### Installation

```bash
# Clone repository
git clone https://github.com/CodingManiac11/PhishGuard.git
cd phishguard-mvp

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in root directory (optional):

```env
# VirusTotal API (optional - for Compare Scans feature)
PHISHGUARD_VIRUSTOTAL_API_KEY=your_api_key_here
```

### Run the Server

```bash
cd backend
python main.py
```

Access the application at: **http://localhost:8000**

## 📁 Project Structure

```
phishguard-mvp/
├── backend/
│   ├── main.py                 # FastAPI server
│   ├── classifier.py           # ML classification engine
│   ├── feature_extractor.py    # URL feature extraction (50+ features)
│   ├── json_storage.py         # Local JSON file storage
│   ├── virustotal.py           # VirusTotal API integration
│   ├── ssl_analyzer.py         # SSL certificate analysis
│   ├── email_analyzer.py       # Email header analysis
│   ├── config.py               # Configuration
│   ├── schemas.py              # API schemas
│   ├── data/                   # JSON storage directory
│   └── frontend/               # Web interface
├── requirements.txt            # Dependencies
├── Procfile                    # Railway deployment
└── README.md
```

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/submit` | Analyze URL for threats |
| POST | `/scan/virustotal` | VirusTotal scan |
| POST | `/scan/ssl` | SSL certificate analysis |
| POST | `/scan/email` | Email header analysis |
| GET | `/stats` | System statistics |
| GET | `/alerts` | Recent threat detections |
| GET | `/` | Web interface |
| GET | `/docs` | API documentation |
| GET | `/health` | Health check |

## 🤖 Detection Capabilities

### URL Analysis
- URL length, entropy, and structure analysis
- Subdomain count and domain depth
- IP address detection
- Suspicious TLD detection (30+ risky TLDs)

### Typosquatting Detection
- Character substitution (g00gle, amaz0n)
- Missing/extra characters
- Homograph attacks (Cyrillic lookalikes)

### Malware Detection
- Suspicious file extensions (.exe, .scr, .lim, etc.)
- HTTP downloads flagged
- Random URL path patterns

### Brand Protection
- Brand name in subdomain detection
- Brand name in path detection
- Double extension detection (.com.tk)

### Security Analysis
- **SSL Certificate**: Validity, expiration, issuer verification
- **Email Headers**: SPF, DKIM, DMARC authentication checks
- **VirusTotal**: 70+ antivirus engine checks

## 📊 Classification Results

| URL Type | Classification | Confidence |
|----------|---------------|------------|
| google.com | ✅ Benign | 99% |
| paypal.com | ✅ Benign | 99% |
| secure-paypal.tk | 🔴 Phishing | 85% |
| 192.168.1.1/login | 🔴 Phishing | 90% |
| example.com/file.exe | 🔴 Phishing | 82% |

## 🔧 Configuration Options

Edit `backend/config.py`:

```python
enable_whois: bool = True     # WHOIS lookups
enable_dns: bool = True       # DNS lookups
virustotal_api_key: str       # VirusTotal API key
```

## 🚀 Deployment (Railway)

1. Push code to GitHub
2. Connect Railway to your GitHub repo
3. Add environment variables (optional):
   - `PHISHGUARD_VIRUSTOTAL_API_KEY`
4. Deploy automatically

## 📝 License

MIT License - see LICENSE file for details.

---

**PhishGuard** - Protecting users from phishing attacks with AI precision! 🛡️
