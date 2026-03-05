"""
FastAPI Middleware for PromptShield.

Automatically scans incoming request bodies for prompt injection attacks.

Usage:
    from fastapi import FastAPI
    from promptshield import Shield
    from promptshield.integrations.fastapi import PromptShieldMiddleware

    app = FastAPI()
    shield = Shield.balanced()
    app.add_middleware(PromptShieldMiddleware, shield=shield)

Configuration:
    app.add_middleware(
        PromptShieldMiddleware,
        shield=Shield.secure(),
        input_paths=["/api/chat", "/api/complete"],  # only scan these paths
        text_fields=["message", "prompt", "input", "query", "content"],
        block_status_code=403,
        on_block=lambda req, result: log_attack(req, result),
    )
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional, Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class PromptShieldMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that intercepts requests and scans for prompt injection.

    Works with FastAPI, Starlette, and any ASGI framework.

    Features:
    - Scans JSON request bodies for attack text
    - Auto-detects common input fields (message, prompt, input, query)
    - Configurable path filtering (scan only specific routes)
    - Custom block handler for logging/alerting
    - Returns threat_breakdown in block response
    """

    def __init__(
        self,
        app,
        shield,
        input_paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        text_fields: Optional[List[str]] = None,
        system_prompt: str = "",
        block_status_code: int = 403,
        on_block: Optional[Callable] = None,
        on_allow: Optional[Callable] = None,
    ):
        """
        Initialize middleware.

        Args:
            app: ASGI application
            shield: Shield instance (or AsyncShield)
            input_paths: Only scan requests to these paths (None = scan all)
            exclude_paths: Never scan requests to these paths
            text_fields: JSON field names to extract and scan
            system_prompt: System context for Shield.protect_input()
            block_status_code: HTTP status code for blocked requests (default 403)
            on_block: Callback(request, result) on blocked request
            on_allow: Callback(request, result) on allowed request
        """
        super().__init__(app)
        self.shield = shield
        self.input_paths: Optional[Set[str]] = set(input_paths) if input_paths else None
        self.exclude_paths: Set[str] = set(exclude_paths or ["/health", "/docs", "/openapi.json", "/favicon.ico"])
        self.text_fields: List[str] = text_fields or [
            "message", "prompt", "input", "query", "content",
            "text", "user_input", "question", "messages",
        ]
        self.system_prompt = system_prompt
        self.block_status_code = block_status_code
        self.on_block = on_block
        self.on_allow = on_allow

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process each request through the shield."""
        path = request.url.path

        # Skip excluded paths
        if path in self.exclude_paths:
            return await call_next(request)

        # Skip if input_paths is set and path is not in it
        if self.input_paths and path not in self.input_paths:
            return await call_next(request)

        # Only scan POST/PUT/PATCH (methods with bodies)
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        # Extract text from request body
        text_to_scan = await self._extract_text(request)
        if not text_to_scan:
            return await call_next(request)

        # Run shield check
        start = time.time()

        # Use async if available, else run in thread
        import asyncio
        if hasattr(self.shield, 'aprotect_input'):
            result = await self.shield.aprotect_input(
                text_to_scan,
                self.system_prompt,
                user_id=request.client.host if request.client else None,
            )
        else:
            result = await asyncio.to_thread(
                self.shield.protect_input,
                text_to_scan,
                self.system_prompt,
                user_id=request.client.host if request.client else None,
            )

        latency_ms = (time.time() - start) * 1000

        if result.get("blocked"):
            # Fire block callback
            if self.on_block:
                try:
                    self.on_block(request, result)
                except Exception:
                    pass

            return JSONResponse(
                status_code=self.block_status_code,
                content={
                    "error": "prompt_injection_detected",
                    "reason": result.get("reason", "unknown"),
                    "threat_level": result.get("threat_level", 0),
                    "threat_breakdown": result.get("threat_breakdown", {}),
                    "shield_latency_ms": round(latency_ms, 2),
                },
            )

        # Fire allow callback
        if self.on_allow:
            try:
                self.on_allow(request, result)
            except Exception:
                pass

        # Continue to route handler
        response = await call_next(request)

        # Add shield headers
        response.headers["X-PromptShield-Latency-Ms"] = str(round(latency_ms, 2))
        response.headers["X-PromptShield-Threat-Level"] = str(
            round(result.get("threat_level", 0), 3)
        )

        return response

    async def _extract_text(self, request: Request) -> Optional[str]:
        """
        Extract scannable text from request body.

        Handles:
        - JSON bodies with common field names
        - OpenAI-style messages arrays
        - Plain text bodies
        """
        content_type = request.headers.get("content-type", "")

        try:
            if "application/json" in content_type:
                body = await request.json()
                return self._extract_from_dict(body)
            elif "text/plain" in content_type:
                body = await request.body()
                return body.decode("utf-8", errors="ignore")
        except Exception:
            pass

        return None

    def _extract_from_dict(self, data: Any) -> Optional[str]:
        """Recursively extract text fields from a dict/list."""
        texts = []

        if isinstance(data, dict):
            for field in self.text_fields:
                value = data.get(field)
                if isinstance(value, str) and value.strip():
                    texts.append(value)
                elif isinstance(value, list):
                    # Handle OpenAI-style messages: [{"role": "user", "content": "..."}]
                    for item in value:
                        if isinstance(item, dict):
                            content = item.get("content", "")
                            role = item.get("role", "")
                            if isinstance(content, str) and role in ("user", ""):
                                texts.append(content)
                        elif isinstance(item, str):
                            texts.append(item)

        elif isinstance(data, list):
            for item in data:
                result = self._extract_from_dict(item)
                if result:
                    texts.append(result)

        return " ".join(texts) if texts else None
