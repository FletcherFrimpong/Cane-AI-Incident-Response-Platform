"""Inbound calls from other systems (signed by them, not by a user token)."""

import json
import logging
import uuid
from urllib.parse import parse_qs

import httpx
from fastapi import APIRouter, BackgroundTasks, Request, Response
from sqlalchemy import func, select

from app.database import async_session_factory
from app.dependencies import require_tier2  # noqa: F401 - documents the role this endpoint enforces by hand
from app.exceptions import UnauthorizedError
from app.models.user import User, UserRole
from app.services.action_service import approve_action, reject_action
from app.services.integration_service import active_clients, close_clients

logger = logging.getLogger("cane_ai.hooks")
router = APIRouter()

_MAY_APPROVE = {UserRole.TIER2_ANALYST, UserRole.MANAGER, UserRole.ADMIN}


async def _reply(response_url: str | None, text: str) -> None:
    """Replace the Slack message's buttons with the outcome."""
    if not response_url or not response_url.startswith("https://hooks.slack.com/"):
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(response_url, json={"replace_original": False, "response_type": "in_channel", "text": text})
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not post the outcome back to Slack: %s", e)


async def _handle_slack_decision(decision: str, action_id: str, slack_user_id: str, response_url: str | None,
                                 slack_integration_id: uuid.UUID) -> None:
    """Runs after Slack has been answered (Slack allows 3 seconds; an action can take longer)."""
    async with async_session_factory() as db:
        clients = await active_clients(db, category="notification")
        try:
            slack = next((c for c in clients if c.integration_id == slack_integration_id), None)
            email = await slack.get_user_email(slack_user_id) if slack else None
        finally:
            await close_clients(clients)
        if not email:
            await _reply(response_url, "Could not identify you in Slack, so nothing was changed. "
                                       "The Slack app needs the users:read.email scope.")
            return

        user = (await db.execute(select(User).where(func.lower(User.email) == email.lower()))).scalar_one_or_none()
        # The Slack button is a convenience, not a second way in: the person clicking
        # must be an active Cane AI user who could approve this in the app itself.
        if not user or not user.is_active or user.role not in _MAY_APPROVE:
            await _reply(response_url, f"<@{slack_user_id}> is not allowed to approve actions in Cane AI "
                                       "(needs an active tier 2 analyst, manager or admin account with the same email).")
            return
        try:
            if decision == "cane_approve":
                action = await approve_action(db, uuid.UUID(action_id), user.id, user.email, "Approved from Slack")
                await db.commit()
                if action.status.value == "completed":
                    dry = (action.result or {}).get("dry_run")
                    await _reply(response_url, f":white_check_mark: {user.full_name} approved "
                                               f"*{action.action_type.replace('_', ' ')}*"
                                               + (" (simulated: integration is in dry-run mode)." if dry else "; it has run."))
                else:
                    await _reply(response_url, f":x: {user.full_name} approved "
                                               f"*{action.action_type.replace('_', ' ')}* but it failed: {action.error_message}")
            else:
                action = await reject_action(db, uuid.UUID(action_id), user.id, "Rejected from Slack", user.email)
                await db.commit()
                await _reply(response_url, f":no_entry_sign: {user.full_name} rejected "
                                           f"*{action.action_type.replace('_', ' ')}*. It will not run.")
        except Exception as e:  # noqa: BLE001 - e.g. already approved by someone else
            await db.rollback()
            detail = getattr(e, "detail", None) or str(e)
            await _reply(response_url, f"Nothing was changed: {detail}")


@router.post("/slack/actions")
async def slack_actions(request: Request, background: BackgroundTasks):
    """Slack interactivity endpoint: the Approve / Reject buttons on an approval message.

    Set this URL as the Slack app's Interactivity Request URL. Every request is
    verified against the signing secret of a connected Slack integration before
    anything in it is read."""
    from app.integrations.slack import verify_slack_signature

    raw = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    async with async_session_factory() as db:
        clients = [c for c in await active_clients(db, category="notification") if c.platform_name == "slack"]
        try:
            verified = next(
                (c for c in clients
                 if verify_slack_signature(c.credentials.get("signing_secret", ""), timestamp, raw, signature)),
                None,
            )
            integration_id = verified.integration_id if verified else None
        finally:
            await close_clients(clients)
    if integration_id is None:
        raise UnauthorizedError("Invalid Slack signature")

    try:
        payload = json.loads(parse_qs(raw.decode("utf-8")).get("payload", ["{}"])[0])
        clicked = (payload.get("actions") or [{}])[0]
        decision = clicked.get("action_id")
        action_id = clicked.get("value") or ""
        slack_user_id = (payload.get("user") or {}).get("id") or ""
        uuid.UUID(action_id) if decision in ("cane_approve", "cane_reject") else None
    except (ValueError, KeyError, IndexError, TypeError):
        return Response(status_code=200)  # acknowledge; nothing we can act on

    if decision in ("cane_approve", "cane_reject") and slack_user_id:
        background.add_task(_handle_slack_decision, decision, action_id, slack_user_id,
                            payload.get("response_url"), integration_id)
    return Response(status_code=200)
