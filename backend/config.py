from pydantic_settings import BaseSettings
from typing import Optional
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)


class Settings(BaseSettings):
    # MongoDB Atlas Configuration (Required)
    mongodb_url: str = os.getenv("MONGO_CONNECTION_STRING", "mongodb://localhost:27017")
    database_name: str = os.getenv("MONGO_DATABASE_NAME", "phishguard")
    
    # Application settings
    schedule_seconds: int = 600
    enable_whois: bool = True
    enable_dns: bool = True
    ua: str = "PhishGuard/1.0"
    
    # External API Keys (optional but recommended)
    google_safe_browsing_api_key: str = os.getenv("PHISHGUARD_GOOGLE_SAFE_BROWSING_API_KEY", "")
    
    class Config:
        extra = "ignore"


settings = Settings()
