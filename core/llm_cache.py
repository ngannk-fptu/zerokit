import os
import sqlite3
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict

logger = logging.getLogger(__name__)

class LLMCache:
    """
    SQLite-based cache for LLM responses to reduce API costs.
    Uses SHA256 hashing for prompt deduplication.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("CACHE_DB_PATH", ".agent/artifacts/llm_cache.db")
        self.ttl_hours = int(os.getenv("CACHE_TTL_HOURS", "168"))
        self.enabled = os.getenv("ENABLE_CACHE", "true").lower() == "true"
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self._init_db()
        logger.info(f"LLM Cache initialized: {self.db_path} (TTL: {self.ttl_hours}h, Enabled: {self.enabled})")
    
    def _init_db(self):
        """Create cache table if not exists."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS llm_cache (
                prompt_hash TEXT PRIMARY KEY,
                prompt_text TEXT NOT NULL,
                response TEXT NOT NULL,
                model TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tokens_used INTEGER DEFAULT 0,
                cost_usd REAL DEFAULT 0.0
            )
        """)
        conn.commit()
        conn.close()
    
    def _hash_prompt(self, prompt: str, model: str) -> str:
        """Generate SHA256 hash for prompt + model combination."""
        combined = f"{model}::{prompt}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def get(self, prompt: str, model: str = None) -> Optional[str]:
        """
        Retrieve cached response for a given prompt.
        Returns None if not found or expired.
        """
        if not self.enabled:
            return None
        
        model = model or "antigravity"
        prompt_hash = self._hash_prompt(prompt, model)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for non-expired entry
        expiry_time = datetime.now() - timedelta(hours=self.ttl_hours)
        cursor.execute("""
            SELECT response FROM llm_cache 
            WHERE prompt_hash = ? AND created_at > ?
        """, (prompt_hash, expiry_time))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            logger.info(f"✅ Cache HIT: {prompt_hash[:8]}...")
            return result[0]
        
        logger.info(f"❌ Cache MISS: {prompt_hash[:8]}...")
        return None
    
    def set(self, prompt: str, response: str, tokens: int = 0, cost: float = 0.0, model: str = None):
        """Store LLM response in cache."""
        if not self.enabled:
            return
        
        model = model or "antigravity"
        prompt_hash = self._hash_prompt(prompt, model)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO llm_cache 
            (prompt_hash, prompt_text, response, model, tokens_used, cost_usd, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (prompt_hash, prompt, response, model, tokens, cost))
        
        conn.commit()
        conn.close()
        logger.info(f"💾 Cache SET: {prompt_hash[:8]}... ({tokens} tokens, ${cost:.4f})")
    
    def clear_expired(self):
        """Remove expired cache entries."""
        expiry_time = datetime.now() - timedelta(hours=self.ttl_hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM llm_cache WHERE created_at < ?", (expiry_time,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted > 0:
            logger.info(f"🗑️ Cleared {deleted} expired cache entries")
        return deleted
    
    def get_stats(self) -> Dict:
        """Get cache statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*), SUM(tokens_used), SUM(cost_usd) FROM llm_cache")
        total_entries, total_tokens, total_cost = cursor.fetchone()
        
        cursor.execute("""
            SELECT COUNT(*) FROM llm_cache 
            WHERE created_at > ?
        """, (datetime.now() - timedelta(hours=self.ttl_hours),))
        active_entries = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_entries": total_entries or 0,
            "active_entries": active_entries or 0,
            "total_tokens_cached": total_tokens or 0,
            "total_cost_saved_usd": total_cost or 0.0,
            "db_path": self.db_path
        }
    
    def clear_all(self):
        """Clear entire cache (for testing/debugging)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM llm_cache")
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        logger.warning(f"⚠️ Cleared ALL cache entries ({deleted} total)")
        return deleted
