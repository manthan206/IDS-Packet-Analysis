from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response, HTTPException, status
import time

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: https:;"
        return response

class SimpleRateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_counts = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()

        # Clean old entries
        if client_ip in self.request_counts:
            timestamps = [ts for ts in self.request_counts[client_ip] if now - ts < self.window_seconds]
            self.request_counts[client_ip] = timestamps
        else:
            self.request_counts[client_ip] = []

        if len(self.request_counts[client_ip]) >= self.max_requests:
            return Response(
                content="Rate limit exceeded. Please try again later.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS
            )

        self.request_counts[client_ip].append(now)
        response = await call_next(request)
        return response
