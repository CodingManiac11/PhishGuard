from pydantic_settings import BaseSettings
from typing import Optional
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root (for local development)
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)


class Settings(BaseSettings):
    # MongoDB Atlas Configuration (Required)
    # Check multiple possible env var names for flexibility
    mongodb_url: str = os.getenv("MONGO_CONNECTION_STRING") or os.getenv("PHISHGUARD_MONGODB_URL") or "mongodb://localhost:27017"
    database_name: str = os.getenv("MONGO_DATABASE_NAME") or os.getenv("PHISHGUARD_DATABASE_NAME") or "phishguard"
    
    # Application settings
    schedule_seconds: int = 600
    enable_whois: bool = True
    enable_dns: bool = True
    ua: str = "PhishGuard/1.0"
    
    # External API Keys (optional but recommended)
    google_safe_browsing_api_key: str = os.getenv("PHISHGUARD_GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or ""
    
    class Config:
        extra = "ignore"


settings = Settings()
