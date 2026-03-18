"""
OpenClay Webhook System

Fire HTTP alerts when the shield detects high-severity threats.
Supports Slack, PagerDuty, Discord, or any generic webhook endpoint.

Usage:
    shield = Shield.balanced(webhook_url="https://hooks.slack.com/...")
    # Now every P0 block will fire a POST to that URL with threat details.
"""

import json
import time
import logging
import hmac
import hashlib
from typing import Dict, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError
import threading

logger = logging.getLogger("openclay.webhooks")


class WebhookNotifier:
    """
    Asynchronous webhook notifier for shield detection events.
    
    Fires non-blocking HTTP POST requests to a configured URL
    whenever a threat is detected and blocked.
    
    Args:
        url: Webhook endpoint URL
        min_threat_level: Minimum threat level to trigger a webhook (0.0-1.0)
        timeout: HTTP request timeout in seconds
        include_input: Whether to include the blocked input text in the payload
    """
    
    def __init__(
        self,
        url: str,
        min_threat_level: float = 0.5,
        timeout: int = 5,
        include_input: bool = False,
        secret: Optional[str] = None,
    ):
        self.url = url
        self.min_threat_level = min_threat_level
        self.timeout = timeout
        self.include_input = include_input
        self.secret = secret
        self._stats = {"sent": 0, "failed": 0, "skipped": 0}
        self._lock = threading.Lock()
    
    def notify(self, result: Dict[str, Any], user_input: Optional[str] = None):
        """
        Send a webhook notification if the result meets the threshold.
        
        This method is non-blocking — it fires the HTTP request in a background thread.
        
        Args:
            result: The shield result dictionary from protect_input()
            user_input: The original user input (only included if include_input is True)
        """
        logger.debug("notify called with blocked=%s, threat=%s", result.get('blocked'), result.get('threat_level'))
        if not result.get("blocked", False):
            with self._lock:
                self._stats["skipped"] += 1
            return
        
        threat_level = result.get("threat_level", 0.0)
        if threat_level < self.min_threat_level:
            logger.debug("notify skipped: threat_level %s < %s", threat_level, self.min_threat_level)
            with self._lock:
                self._stats["skipped"] += 1
            return
        
        # Build payload
        payload = {
            "event": "openclay_threat_detected",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "threat_level": threat_level,
            "reason": result.get("reason", "unknown"),
            "blocked": True,
            "metadata": result.get("metadata", {}),
            "threat_breakdown": result.get("threat_breakdown", {}),
        }
        
        if self.include_input and user_input:
            # Truncate to avoid sending huge payloads
            payload["input_preview"] = user_input[:200]
        
        logger.debug("notify starting thread for %s", payload.get('reason'))
        # Fire in background thread to avoid blocking the request
        thread = threading.Thread(
            target=self._send, args=(payload,)
        )
        thread.start()
    
    def _send(self, payload: Dict[str, Any]):
        """Send the webhook HTTP POST request."""
        logger.debug("_send thread started")
        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            
            if self.secret:
                signature = hmac.new(
                    self.secret.encode("utf-8"), 
                    data, 
                    hashlib.sha256
                ).hexdigest()
                headers["X-OpenClay-Signature"] = f"sha256={signature}"
                
            req = Request(
                self.url,
                data=data,
                headers=headers,
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as response:
                if response.status < 300:
                    with self._lock:
                        self._stats["sent"] += 1
                    logger.info("Webhook sent: %s", payload.get('reason'))
                    logger.debug("Webhook sent successfully %s", payload.get('reason'))
                else:
                    with self._lock:
                        self._stats["failed"] += 1
                    logger.warning("Webhook returned status %s", response.status)
                    logger.debug("Webhook returned status %s", response.status)
        except URLError as e:
            with self._lock:
                self._stats["failed"] += 1
            logger.warning("Webhook failed: %s", e)
            logger.debug("Webhook failed with URLError: %s", e)
        except Exception as e:
            with self._lock:
                self._stats["failed"] += 1
            logger.error("Webhook error: %s", e)
            logger.debug("Webhook threw Exception: %s", e)
    
    def get_stats(self) -> Dict[str, int]:
        """Get webhook delivery statistics."""
        with self._lock:
            return dict(self._stats)
