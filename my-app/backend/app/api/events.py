import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.config import get_settings
from app.dependencies import get_current_active_user
from app.models.user import User
from app.services.events import CHANNEL

router = APIRouter()

HEARTBEAT_SECONDS = 20


@router.get("/stream")
async def stream_events(request: Request, current_user: User = Depends(get_current_active_user)):
    """Server-sent events: one small message whenever an incident or the action queue
    changes, so open pages refresh at once instead of waiting for their next poll.
    Messages carry no incident content, only which thing changed."""
    import redis.asyncio as aioredis

    async def events():
        client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        pubsub = client.pubsub()
        await pubsub.subscribe(CHANNEL)
        try:
            yield "retry: 3000\n\n"
            idle = 0.0
            while True:
                if await request.is_disconnected():
                    break
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    idle = 0.0
                    yield f"data: {message['data']}\n\n"
                else:
                    idle += 1.0
                    if idle >= HEARTBEAT_SECONDS:
                        idle = 0.0
                        yield ": keep-alive\n\n"  # comment line; keeps proxies from closing the stream
        except asyncio.CancelledError:
            raise
        finally:
            await pubsub.unsubscribe(CHANNEL)
            await pubsub.aclose()
            await client.aclose()

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
