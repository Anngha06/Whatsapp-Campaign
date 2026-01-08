from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, request, make_response

# Make common modules importable on Vercel
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1] / ".."))  # project root
sys.path.append(str(Path(__file__).resolve().parents[1]))         # vercel_webhook

from common.supabase_store import upsert_contact, insert_message, insert_status_update

app = Flask(__name__)


def _utc_iso_from_unix_seconds(s: str) -> str:
    try:
        ts = int(s)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _verify_signature_if_configured(raw_body: bytes) -> bool:
    """
    Verifies X-Hub-Signature-256 if META_APP_SECRET is set.
    Signature format: sha256=<hex>
    """
    app_secret = (os.getenv("META_APP_SECRET") or "").strip()
    if not app_secret:
        return True  # signature verification disabled

    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not sig_header.startswith("sha256="):
        return False
    their_sig = sig_header.split("=", 1)[1].strip()

    mac = hmac.new(app_secret.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
    our_sig = mac.hexdigest()
    return hmac.compare_digest(our_sig, their_sig)


@app.route("/api/webhook", methods=["GET"])
def verify_webhook():
    """
    Meta webhook verification:
    - If hub.mode == 'subscribe' and hub.verify_token matches, return hub.challenge as plain text.
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")
    verify_token = (os.getenv("WEBHOOK_VERIFY_TOKEN") or "").strip()

    if mode == "subscribe" and token and verify_token and token == verify_token:
        resp = make_response(challenge, 200)
        resp.mimetype = "text/plain"
        return resp
    return make_response("Forbidden", 403)


@app.route("/api/webhook", methods=["POST"])
def receive_webhook():
    raw = request.get_data() or b""

    if not _verify_signature_if_configured(raw):
        return make_response("Invalid signature", 403)

    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        return make_response("Bad JSON", 400)

    # Parse WhatsApp webhook payload
    # It can include "messages" (incoming) and/or "statuses" (delivery updates)
    try:
        entries = payload.get("entry", []) if isinstance(payload, dict) else []
        for entry in entries:
            changes = entry.get("changes", []) or []
            for ch in changes:
                value = ch.get("value", {}) or {}
                # Incoming messages
                messages = value.get("messages", []) or []
                contacts = value.get("contacts", []) or []
                # Build wa_id -> name map from contacts block
                contact_names = {}
                for c in contacts:
                    wa_id = c.get("wa_id")
                    name = (c.get("profile") or {}).get("name")
                    if wa_id:
                        contact_names[wa_id] = name

                for m in messages:
                    wa_id = m.get("from") or ""
                    mtype = m.get("type") or ""
                    ts_iso = _utc_iso_from_unix_seconds(m.get("timestamp", "0"))
                    body = ""
                    if mtype == "text":
                        body = ((m.get("text") or {}).get("body")) or ""
                    else:
                        # Store a minimal representation for non-text messages
                        body = json.dumps(m, ensure_ascii=False)[:5000]

                    name = contact_names.get(wa_id)
                    if wa_id:
                        upsert_contact(wa_id=wa_id, name=name)
                        insert_message(
                            direction="inbound",
                            wa_id=wa_id,
                            body=body,
                            message_type=mtype or "unknown",
                            wamid=m.get("id"),
                            status=None,
                            ts_utc_iso=ts_iso,
                            raw=m,
                        )

                # Status updates for outgoing messages
                statuses = value.get("statuses", []) or []
                for st in statuses:
                    wa_id = st.get("recipient_id") or ""
                    wamid = st.get("id") or ""
                    status = st.get("status") or ""
                    ts_iso = _utc_iso_from_unix_seconds(st.get("timestamp", "0"))

                    if wa_id:
                        upsert_contact(wa_id=wa_id, name=None)
                    if wa_id and wamid and status:
                        insert_status_update(
                            wa_id=wa_id,
                            wamid=wamid,
                            status=status,
                            ts_utc_iso=ts_iso,
                            raw=st,
                        )
    except Exception as e:
        # Always return 200 to prevent retries storms if a single event fails parsing.
        # Store could be failing; you can inspect Vercel logs.
        return make_response("OK (parse error)", 200)

    return make_response("OK", 200)
