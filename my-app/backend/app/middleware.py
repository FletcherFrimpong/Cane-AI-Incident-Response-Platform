import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("cane_ai")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        logger.info(
            "%s %s %d %.3fs",
            request.method,
            request.url.path,
            response.status_code,
            duration,
        )
        return response
