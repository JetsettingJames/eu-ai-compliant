"""
Cache service for the RepoScanner application.
Provides caching functionality for frequently accessed data.
"""
import json
import logging
from typing import Any, Dict, Optional, TypeVar, Generic, Type, List, Union
import redis.asyncio as redis
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)

T = TypeVar('T')

class CacheService(Generic[T]):
    """Generic cache service for storing and retrieving data."""
    
    def __init__(self, model_class: Type[T], prefix: str, ttl: int = 3600):
        """
        Initialize the cache service.
        
        Args:
            model_class: The Pydantic model class to use for serialization/deserialization
            prefix: Prefix for cache keys to avoid collisions
            ttl: Time-to-live in seconds for cached items (default: 1 hour)
        """
        self.redis = None
        self.model_class = model_class
        self.prefix = prefix
        self.ttl = ttl
        self._initialize_redis()
    
    def _initialize_redis(self):
        """Initialize Redis connection if REDIS_URL is configured."""
        if hasattr(settings, 'REDIS_URL') and settings.REDIS_URL:
            try:
                self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
                logger.info(f"Redis cache initialized for {self.prefix}")
            except Exception as e:
                logger.warning(f"Failed to initialize Redis cache: {str(e)}")
                self.redis = None
        else:
            logger.info("Redis URL not configured, caching disabled")
            self.redis = None
    
    async def get(self, key: str) -> Optional[T]:
        """
        Get an item from the cache.
        
        Args:
            key: The cache key
            
        Returns:
            The cached item or None if not found
        """
        if not self.redis:
            return None
            
        try:
            full_key = f"{self.prefix}:{key}"
            data = await self.redis.get(full_key)
            if data:
                # Convert JSON string to dict and then to Pydantic model
                return self.model_class.parse_raw(data)
            return None
        except Exception as e:
            logger.warning(f"Error getting item from cache: {str(e)}")
            return None
    
    async def set(self, key: str, value: T) -> bool:
        """
        Set an item in the cache.
        
        Args:
            key: The cache key
            value: The value to cache (must be a Pydantic model)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis:
            return False
            
        try:
            full_key = f"{self.prefix}:{key}"
            # Convert Pydantic model to JSON string
            json_data = value.json()
            await self.redis.set(full_key, json_data, ex=self.ttl)
            return True
        except Exception as e:
            logger.warning(f"Error setting item in cache: {str(e)}")
            return False
    
    async def delete(self, key: str) -> bool:
        """
        Delete an item from the cache.
        
        Args:
            key: The cache key
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis:
            return False
            
        try:
            full_key = f"{self.prefix}:{key}"
            await self.redis.delete(full_key)
            return True
        except Exception as e:
            logger.warning(f"Error deleting item from cache: {str(e)}")
            return False
    
    async def get_many(self, pattern: str) -> List[T]:
        """
        Get multiple items from the cache using a pattern.
        
        Args:
            pattern: The pattern to match keys against
            
        Returns:
            List of cached items
        """
        if not self.redis:
            return []
            
        try:
            full_pattern = f"{self.prefix}:{pattern}"
            keys = await self.redis.keys(full_pattern)
            if not keys:
                return []
                
            # Get all values for the matched keys
            pipeline = self.redis.pipeline()
            for key in keys:
                pipeline.get(key)
            values = await pipeline.execute()
            
            # Convert JSON strings to Pydantic models
            result = []
            for value in values:
                if value:
                    try:
                        result.append(self.model_class.parse_raw(value))
                    except Exception as e:
                        logger.warning(f"Error parsing cached item: {str(e)}")
            
            return result
        except Exception as e:
            logger.warning(f"Error getting items from cache: {str(e)}")
            return []
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate multiple cache entries using a pattern.
        
        Args:
            pattern: The pattern to match keys against
            
        Returns:
            Number of invalidated keys
        """
        if not self.redis:
            return 0
            
        try:
            full_pattern = f"{self.prefix}:{pattern}"
            keys = await self.redis.keys(full_pattern)
            if not keys:
                return 0
                
            # Delete all matched keys
            count = await self.redis.delete(*keys)
            return count
        except Exception as e:
            logger.warning(f"Error invalidating cache pattern: {str(e)}")
            return 0
