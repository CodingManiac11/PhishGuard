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
    # Application settings
    schedule_seconds: int = 600
    enable_whois: bool = True
    enable_dns: bool = True
    ua: str = "PhishGuard/1.0"
    
    # External API Keys (optional but recommended)
    google_safe_browsing_api_key: str = os.getenv("PHISHGUARD_GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or ""
    virustotal_api_key: str = os.getenv("PHISHGUARD_VIRUSTOTAL_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY") or ""
    
    class Config:
        extra = "ignore"


settings = Settings()
