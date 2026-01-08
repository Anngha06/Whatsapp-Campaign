"""
Supabase storage helpers for inbound/outbound messages and status updates.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from supabase import create_client, Client


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_supabase() -> Client:
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip()
    if not url or not key:
        raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_ANON_KEY)")
    return create_client(url, key)


def upsert_contact(*, wa_id: str, name: Optional[str] = None) -> None:
    sb = get_supabase()
    sb.table("contacts").upsert(
        {"wa_id": wa_id, "name": name, "updated_at": _utc_now_iso()},
        on_conflict="wa_id",
    ).execute()


def insert_message(
    *,
    direction: str,  # "inbound" | "outbound"
    wa_id: str,
    body: str,
    message_type: str = "text",
    wamid: Optional[str] = None,
    status: Optional[str] = None,
    ts_utc_iso: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    sb = get_supabase()
    sb.table("messages").insert(
        {
            "direction": direction,
            "wa_id": wa_id,
            "wamid": wamid,
            "message_type": message_type,
            "body": body,
            "status": status,
            "ts_utc": ts_utc_iso or _utc_now_iso(),
            "raw": raw or {},
        }
    ).execute()


def insert_status_update(
    *,
    wa_id: str,
    wamid: str,
    status: str,
    ts_utc_iso: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    sb = get_supabase()
    sb.table("status_updates").insert(
        {
            "wa_id": wa_id,
            "wamid": wamid,
            "status": status,
            "ts_utc": ts_utc_iso or _utc_now_iso(),
            "raw": raw or {},
        }
    ).execute()


def fetch_recent_conversations(limit_messages: int = 200):
    sb = get_supabase()
    # Fetch latest messages with contact names
    resp = (
        sb.table("messages_view")
        .select("*")
        .order("ts_utc", desc=True)
        .limit(limit_messages)
        .execute()
    )
    return resp.data or []
