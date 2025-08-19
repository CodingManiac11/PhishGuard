from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from typing import Optional
import logging

from config import settings
from mongo_models import URLRecord, Detection, Label

logger = logging.getLogger(__name__)

# Global MongoDB client
client: Optional[AsyncIOMotorClient] = None
database = None


async def connect_to_mongo():
    """Create database connection"""
    global client, database
    
    try:
        client = AsyncIOMotorClient(settings.mongodb_url)
        database = client[settings.database_name]
        
        # Initialize Beanie with the document models
        await init_beanie(database=database, document_models=[URLRecord, Detection, Label])
        
        logger.info(f"✅ Connected to MongoDB: {settings.database_name}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to connect to MongoDB: {e}")
        return False


async def close_mongo_connection():
    """Close database connection"""
    global client
    if client:
        client.close()
        logger.info("✅ Disconnected from MongoDB")


async def get_database():
    """Get database instance"""
    return database


# For backward compatibility with SQLAlchemy-style dependency
async def get_db():
    """Database dependency for FastAPI"""
    return database
