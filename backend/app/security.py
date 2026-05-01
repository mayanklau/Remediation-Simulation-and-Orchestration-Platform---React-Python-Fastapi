from time import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "strict-origin-when-cross-origin"
        response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
        if get_settings().environment == "production":
            response.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
        return response


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    buckets: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        key = request.client.host if request.client else "unknown"
        now = time()
        window = [stamp for stamp in self.buckets.get(key, []) if now - stamp < 60]
        if len(window) >= settings.rate_limit_per_minute:
            return Response("rate limit exceeded", status_code=429)
        window.append(now)
        self.buckets[key] = window
        response = await call_next(request)
        response.headers["x-ratelimit-limit"] = str(settings.rate_limit_per_minute)
        response.headers["x-ratelimit-remaining"] = str(max(0, settings.rate_limit_per_minute - len(window)))
        return response

