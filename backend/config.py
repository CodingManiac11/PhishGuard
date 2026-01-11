from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # MongoDB Atlas Configuration (Required)
    mongodb_url: str = "mongodb://localhost:27017"
    database_name: str = "phishguard"
    
    # Application settings
    schedule_seconds: int = 600
    enable_whois: bool = True
    enable_dns: bool = True
    ua: str = "PhishGuard/1.0"
    
    # External API Keys (optional but recommended)
    google_safe_browsing_api_key: str = ""  # Get from: https://console.cloud.google.com/
    
    class Config:
        env_prefix = "PHISHGUARD_"
        env_file = "../.env"  # Look in parent directory
        extra = "ignore"  # Ignore unknown environment variables


settings = Settings()
