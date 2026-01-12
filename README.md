# 🛡️ PhishGuard - AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-green)](https://fastapi.tiangolo.com)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green)](https://mongodb.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An advanced AI-powered phishing and malware detection system that uses machine learning and **Google Safe Browsing API** to analyze URLs and protect users from threats.

## 🎯 Key Features

- **Hybrid ML Detection**: Ensemble model (RandomForest + GradientBoosting + LogisticRegression)
- **Google Safe Browsing API**: Real-time threat checking against Google's database
- **50+ URL Features**: URL structure, typosquatting, brand impersonation, malware patterns
- **166 Trusted Domains**: Zero false positives on legitimate sites
- **Malware Detection**: Suspicious file extensions, HTTP downloads, random URL patterns

## Screenshots

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/e28de7a4-6e2c-40da-8224-24646d65e662" />

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/2e644890-f6e4-4e34-8d92-3c0932ef43e9" />

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/892bc006-a83f-4a74-884f-0982e43c39c3" />

<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/9fcf8b99-ffbd-4ac4-837c-5703e9bb0e1c" />

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MongoDB Atlas account (free tier available)

### Installation

```bash
# Clone repository
git clone https://github.com/CodingManiac11/PhishGuard.git
cd phishguard-mvp

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in root directory:

```env
# MongoDB Atlas (Required)
MONGO_CONNECTION_STRING=mongodb+srv://username:password@cluster.mongodb.net/
MONGO_DATABASE_NAME=phishguard

# Google Safe Browsing API (Recommended)
PHISHGUARD_GOOGLE_SAFE_BROWSING_API_KEY=your_api_key
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
│   ├── feature_extractor.py    # URL feature extraction
│   ├── threat_intelligence.py  # Google Safe Browsing API
│   ├── mongo_monitor.py        # URL scanning service
│   ├── mongo_database.py       # MongoDB operations
│   ├── mongo_models.py         # Data models
│   ├── config.py               # Configuration
│   └── schemas.py              # API schemas
├── frontend/                   # Web interface
├── .env                        # Environment config
├── requirements.txt            # Dependencies
├── Procfile                    # Railway deployment
└── README.md
```

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/submit` | Analyze URL for threats |
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

### External Threat Intelligence
- **Google Safe Browsing API** integration
- Real-time malware/phishing database lookup
- Automatic threat override for known threats

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
mongodb_url: str              # MongoDB connection string
database_name: str            # Database name
enable_whois: bool = True     # WHOIS lookups
enable_dns: bool = True       # DNS lookups
google_safe_browsing_api_key  # Google API key
```

## 🚀 Deployment (Railway)

1. Push code to GitHub
2. Connect Railway to your GitHub repo
3. Add environment variables:
   - `MONGO_CONNECTION_STRING`
   - `PHISHGUARD_GOOGLE_SAFE_BROWSING_API_KEY`
4. Deploy automatically

## 📝 License

MIT License - see LICENSE file for details.

---

**PhishGuard** - Protecting users from phishing attacks with AI precision! 🛡️
