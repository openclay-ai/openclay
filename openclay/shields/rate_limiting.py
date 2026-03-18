"""
Adaptive Rate Limiting

Threat-aware rate limiting that adapts thresholds based on user behavior.
Higher threat users get stricter limits.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Optional
import logging

logger = logging.getLogger("openclay.rate_limiting")

class AdaptiveRateLimiter:
    """
    Rate limiter with adaptive thresholds based on threat levels.
    
    Features:
    - Per-user rate limiting
    - Adaptive thresholds (lower limits for suspicious users)
    - Exponential moving average for threat scores
    - DDoS protection
    - Thread-safe operations
    
    Usage:
        limiter = AdaptiveRateLimiter(base_limit=100)
        
        result = limiter.check_limit(user_id, threat_level=0.3)
        if not result["allowed"]:
            return 429  # Too Many Requests
    """
    
    def __init__(
        self,
        base_limit: int = 100,
        high_threat_limit: int = 10,
        threat_threshold: float = 0.7,
        window_seconds: int = 60,
        ema_alpha: float = 0.3
    ):
        """
        Initialize adaptive rate limiter.
        
        Args:
            base_limit: Requests per window for normal users
            high_threat_limit: Requests per window for high-threat users
            threat_threshold: Threat score threshold for strict limiting
            window_seconds: Time window for rate limiting (default: 60s)
            ema_alpha: Alpha for exponential moving average (0-1)
        """
        self.base_limit = base_limit
        self.high_threat_limit = high_threat_limit
        self.threat_threshold = threat_threshold
        self.window_seconds = window_seconds
        self.ema_alpha = ema_alpha
        
        # Per-user tracking
        self.request_counts = defaultdict(list)  # user_id: [timestamps]
        self.threat_scores = defaultdict(float)  # user_id: threat_score
        self.block_counts = defaultdict(int)     # user_id: blocks
        
        self._lock = Lock()
    
    def check_limit(
        self,
        user_id: str,
        threat_level: float = 0.0
    ) -> Dict:
        """
        Check if user is within rate limits.
        
        Args:
            user_id: Unique user identifier
            threat_level: Current request threat level (0.0-1.0)
        
        Returns:
            Dictionary:
            {
                "allowed": bool,
                "remaining": int,
                "limit": int,
                "threat_score": float,
                "retry_after": int (seconds, if blocked)
            }
        """
        with self._lock:
            now = time.time()
            
            # Clean old requests (outside window)
            self.request_counts[user_id] = [
                ts for ts in self.request_counts[user_id]
                if now - ts < self.window_seconds
            ]
            
            # Update threat score with exponential moving average
            old_score = self.threat_scores[user_id]
            new_score = (
                (1 - self.ema_alpha) * old_score +
                self.ema_alpha * threat_level
            )
            self.threat_scores[user_id] = new_score
            
            # Determine adaptive limit
            if new_score >= self.threat_threshold:
                limit = self.high_threat_limit
            else:
                # Gradual transition
                ratio = new_score / self.threat_threshold
                limit = int(
                    self.high_threat_limit +
                    (self.base_limit - self.high_threat_limit) * (1 - ratio)
                )
            
            # Check current count
            current_count = len(self.request_counts[user_id])
            
            if current_count >= limit:
                # Rate limit exceeded
                self.block_counts[user_id] += 1
                
                # Calculate retry_after (oldest request + window)
                if self.request_counts[user_id]:
                    oldest = min(self.request_counts[user_id])
                    retry_after = int(self.window_seconds - (now - oldest)) + 1
                else:
                    retry_after = self.window_seconds
                
                return {
                    "allowed": False,
                    "remaining": 0,
                    "limit": limit,
                    "threat_score": new_score,
                    "retry_after": retry_after,
                    "total_blocks": self.block_counts[user_id]
                }
            
            # Allow request
            self.request_counts[user_id].append(now)
            
            return {
                "allowed": True,
                "remaining": limit - current_count - 1,
                "limit": limit,
                "threat_score": new_score,
                "retry_after": 0
            }
    
    def reset_user(self, user_id: str):
        """Reset rate limit for specific user (admin function)"""
        with self._lock:
            self.request_counts.pop(user_id, None)
            self.threat_scores.pop(user_id, None)
            self.block_counts.pop(user_id, None)
    
    def get_user_stats(self, user_id: str) -> Dict:
        """Get rate limit stats for user"""
        with self._lock:
            return {
                "current_count": len(self.request_counts.get(user_id, [])),
                "threat_score": self.threat_scores.get(user_id, 0.0),
                "total_blocks": self.block_counts.get(user_id, 0)
            }
    
    def get_global_stats(self) -> Dict:
        """Get global rate limiting statistics"""
        with self._lock:
            total_users = len(self.request_counts)
            total_requests = sum(len(reqs) for reqs in self.request_counts.values())
            total_blocks = sum(self.block_counts.values())
            
            # Calculate average threat score
            if self.threat_scores:
                avg_threat = sum(self.threat_scores.values()) / len(self.threat_scores)
            else:
                avg_threat = 0.0
            
            # Top blocked users
            top_blocked = sorted(
                self.block_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            return {
                "total_users": total_users,
                "total_requests": total_requests,
                "total_blocks": total_blocks,
                "average_threat_score": avg_threat,
                "top_blocked_users": top_blocked
            }
    
    def cleanup_old_data(self, max_age_seconds: int = 3600):
        """
        Cleanup old tracking data to prevent memory bloat.
        
        Args:
            max_age_seconds: Remove users inactive for this long
        """
        with self._lock:
            now = time.time()
            users_to_remove = []
            
            for user_id, timestamps in self.request_counts.items():
                if timestamps and (now - max(timestamps)) > max_age_seconds:
                    users_to_remove.append(user_id)
            
            for user_id in users_to_remove:
                self.request_counts.pop(user_id, None)
                self.threat_scores.pop(user_id, None)
                # Keep block counts for audit
            
            if users_to_remove:
                logger.info("🧹 Cleaned up %d inactive users", len(users_to_remove))

# Example usage
if __name__ == "__main__":
    limiter = AdaptiveRateLimiter(base_limit=10, high_threat_limit=3)
    
    # Simulate normal user
    print("Normal user (threat=0.1):")
    for i in range(12):
        result = limiter.check_limit("user1", threat_level=0.1)
        print(f"  Request {i+1}: {result['allowed']} (remaining: {result['remaining']}, limit: {result['limit']})")
    
    # Simulate suspicious user
    print("\nSuspicious user (threat=0.9):")
    for i in range(6):
        result = limiter.check_limit("user2", threat_level=0.9)
        print(f"  Request {i+1}: {result['allowed']} (remaining: {result['remaining']}, limit: {result['limit']})")
    
    # Global stats
    print("\nGlobal Stats:")
    stats = limiter.get_global_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
