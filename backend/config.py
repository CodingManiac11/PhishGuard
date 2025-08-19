from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # MongoDB Atlas Configuration
    mongodb_url: str = "mongodb://localhost:27017"
    database_name: str = "phishguard"
    
    # Legacy SQLite support (fallback)
    db_url: str = "sqlite:///./phishguard.db"
    use_mongodb: bool = True
    
    # Application settings
    schedule_seconds: int = 600
    enable_whois: bool = True
    enable_dns: bool = True
    enable_screenshot: bool = True  # Enable screenshots for evidence collection
    ua: str = "PhishGuard/1.0"
    
    class Config:
        env_prefix = "PHISHGUARD_"
        env_file = "../.env"  # Look in parent directory


settings = Settings()
