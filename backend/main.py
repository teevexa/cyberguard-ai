import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import secrets
import time
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import desc, text
from sqlalchemy.orm import Session, joinedload, selectinload

import notifications
import triage
from auth import (
    CurrentUser,
    OrgMember,
    get_current_user,
    require_ingest_key,
    require_org_member,
    require_org_role,
    require_role,
    resolve_org_for_api_key,
)
from database import SessionLocal, get_db
from detection.predict import explain_event, get_feature_importance, reload_model, score_event
from detection.train import DATA_PATH as TRAIN_DATA_PATH
from detection.train import train_model
from models import ApiKey, AppSettings, AuditLog, Incident, IncidentNote, LogEvent, NotificationSettings, SystemLog, Threat
from schemas import (
    ApiKeyCreatedOut,
    ApiKeyIn,
    ApiKeyOut,
    AppSettingsIn,
    AppSettingsOut,
    EventIn,
    EventOut,
    IncidentIn,
    IncidentNoteIn,
    IncidentOut,
    IncidentUpdate,
    LogStatsOut,
    MeOut,
    ModelMetricsOut,
    NotificationSettingsIn,
    NotificationSettingsOut,
    OrgAuditEventIn,
    SeverityCounts,
    SummaryOut,
    SystemHealthOut,
    SystemLogOut,
    ThreatExplanationItem,
    ThreatOut,
    UserBanUpdate,
    UserOut,
    UserRoleUpdate,
)
from syslog_server import SyslogProtocol

logger = logging.getLogger("cyberguard.notifications")
audit_logger = logging.getLogger("cyberguard.audit")

limiter = Limiter(key_func=get_remote_address)

_APP_START = time.time()

SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "1514"))


def _persist_syslog_message(parsed: dict) -> None:
    """Called synchronously from the asyncio UDP protocol's datagram_received
    — opens its own session since there's no request to hang a DB dependency
    off of here. Plain UDP has no header for auth/org routing, but a sender
    can embed a real per-org API key as a "[key:...]" token at the start of
    the message (see syslog_server._ORG_KEY_RE) to get routed to that org
    instead of the bootstrap default — same trust store as /events/ingest's
    X-API-Key. No token, an unknown key, or a revoked key all fall back to
    the default org rather than dropping the message."""
    db = SessionLocal()
    try:
        org_key = parsed.pop("org_key", None)
        org_id: str | None = None
        if org_key:
            try:
                org_id = resolve_org_for_api_key(db, org_key)
            except HTTPException:
                # Revoked key — there's no sender to hand a 401 to over UDP.
                db.rollback()
                org_id = None
        if org_id is None:
            org_row = db.execute(text("SELECT id FROM neon_auth.organization WHERE slug = :slug"), {"slug": DEFAULT_ORG_SLUG}).first()
            org_id = str(org_row.id) if org_row else None
        db.add(SystemLog(organization_id=org_id, **parsed))
        db.commit()
    except Exception:
        logger.exception("Failed to persist syslog message")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    transport = None
    try:
        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(on_message=_persist_syslog_message),
            local_addr=("0.0.0.0", SYSLOG_PORT),
        )
        logger.info("Syslog UDP listener started on port %d", SYSLOG_PORT)
    except OSError:
        logger.exception("Could not bind syslog UDP listener on port %d — log ingestion disabled", SYSLOG_PORT)
    purge_task = asyncio.create_task(_retention_purge_loop())
    yield
    purge_task.cancel()
    if transport is not None:
        transport.close()


app = FastAPI(
    title="CyberGuard AI API",
    description=(
        "Threat detection, alerting, and incident management — multi-tenant, one organization's data per "
        "request. Authenticate browser/dashboard calls with a Neon Auth bearer token plus an "
        "X-Organization-Id header; authenticate POST /events/ingest with a per-organization X-API-Key "
        "issued from Settings > Organization > API Keys (see /api-keys)."
    ),
    version="1.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)

METRICS_PATH = Path(__file__).parent / "detection" / "metrics.json"
MODEL_PATH = Path(__file__).parent / "detection" / "model.joblib"

# The syslog UDP listener has no per-request auth mechanism at all (plain
# UDP has no concept of a header/key), so unlike /events/ingest — which now
# resolves a real per-org key via require_ingest_key — syslog messages still
# land in this bootstrap org. A real fix would need senders to embed a
# per-org token in the message itself; out of scope for now, documented in
# the README rather than silently pretended away.
DEFAULT_ORG_SLUG = "default"

RETENTION_CHECK_INTERVAL_SECONDS = int(os.environ.get("RETENTION_CHECK_INTERVAL_SECONDS", str(60 * 60)))


def _purge_expired_data(db: Session) -> None:
    """Enforces each organization's own app_settings.log_retention_days by
    deleting ingested events/threats/logs older than the cutoff. A threat
    still referenced by an incident is preserved regardless of age — an
    incident's evidence trail (and the compliance export it feeds) must
    outlive routine retention cleanup of raw ingested data. incident_notes/
    incidents/audit_log are never touched here; retention only applies to
    the raw, high-volume data it was actually meant for."""
    orgs = db.execute(text("SELECT organization_id, log_retention_days FROM app_settings")).all()
    for row in orgs:
        if not row.log_retention_days or row.log_retention_days <= 0:
            continue
        cutoff = datetime.now(timezone.utc) - timedelta(days=row.log_retention_days)
        threats_deleted = db.execute(
            text(
                "DELETE FROM threats WHERE organization_id = :org AND created_at < :cutoff "
                "AND id NOT IN (SELECT threat_id FROM incidents WHERE threat_id IS NOT NULL)"
            ),
            {"org": row.organization_id, "cutoff": cutoff},
        ).rowcount
        events_deleted = db.execute(
            text(
                "DELETE FROM log_events WHERE organization_id = :org AND ts < :cutoff "
                "AND id NOT IN (SELECT event_id FROM threats)"
            ),
            {"org": row.organization_id, "cutoff": cutoff},
        ).rowcount
        logs_deleted = db.execute(
            text("DELETE FROM system_logs WHERE organization_id = :org AND received_at < :cutoff"),
            {"org": row.organization_id, "cutoff": cutoff},
        ).rowcount
        db.commit()
        if threats_deleted or events_deleted or logs_deleted:
            record_audit(
                db, str(row.organization_id), "system", "system.retention_purge",
                f"{events_deleted} event(s), {threats_deleted} threat(s), {logs_deleted} log(s) "
                f"deleted past the {row.log_retention_days}-day retention window",
            )


async def _retention_purge_loop() -> None:
    """Runs alongside the syslog listener in the same event loop (started
    from lifespan below) rather than as a separate cron/scheduler process —
    consistent with this app's one-process-does-everything design. Never
    lets one bad run kill the loop; the next tick tries again."""
    while True:
        try:
            db = SessionLocal()
            try:
                _purge_expired_data(db)
            finally:
                db.close()
        except Exception:
            logger.exception("Retention purge run failed")
        await asyncio.sleep(RETENTION_CHECK_INTERVAL_SECONDS)


def record_audit(db: Session, org_id: str | None, actor_email: str, action: str, detail: str = "") -> None:
    """Writes to both the audit_log table (queryable, exportable — see
    GET /compliance/export) and the cyberguard.audit logger (visible in
    real-time ops output). Never raises — a broken audit write shouldn't
    block the action it's recording."""
    audit_logger.info("%s by %s%s", action, actor_email, f" — {detail}" if detail else "")
    try:
        db.add(AuditLog(organization_id=org_id, actor_email=actor_email, action=action, detail=detail))
        db.commit()
    except Exception:
        logger.exception("Failed to persist audit log entry")
        db.rollback()


def get_or_create_settings(db: Session, org_id: str) -> NotificationSettings:
    settings = db.query(NotificationSettings).filter(NotificationSettings.organization_id == org_id).first()
    if settings is None:
        settings = NotificationSettings(organization_id=org_id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def get_or_create_app_settings(db: Session, org_id: str) -> AppSettings:
    settings = db.query(AppSettings).filter(AppSettings.organization_id == org_id).first()
    if settings is None:
        settings = AppSettings(organization_id=org_id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def severity_is_enabled(settings: NotificationSettings, severity: str) -> bool:
    return {
        "critical": settings.alert_on_critical,
        "high": settings.alert_on_high,
        "medium": settings.alert_on_medium,
    }.get(severity, False)


def dispatch_alert(db: Session, threat: Threat, event: LogEvent) -> None:
    """Best-effort fan-out to every enabled channel. Never raises — a broken
    Slack webhook shouldn't take down ingestion."""
    settings = get_or_create_settings(db, threat.organization_id)
    if not settings.notifications_enabled or not severity_is_enabled(settings, threat.severity):
        return

    message = (
        f"[{threat.severity.upper()}] {threat.label} detected — "
        f"{event.source_ip} -> {event.dest_ip} ({event.protocol}), confidence {threat.score:.0%}"
    )

    if settings.slack_enabled and settings.slack_webhook_url:
        try:
            notifications.send_slack(settings.slack_webhook_url, message)
            record_audit(db, threat.organization_id, "system", "alert.slack.dispatched", f"threat {threat.id} ({threat.label})")
        except Exception:
            logger.exception("Slack alert delivery failed")

    if settings.email_enabled and settings.email_recipients:
        recipients = [r.strip() for r in settings.email_recipients.split(",") if r.strip()]
        try:
            notifications.send_email(recipients, f"CyberGuard AI alert: {threat.label}", message)
            record_audit(db, threat.organization_id, "system", "alert.email.dispatched", f"threat {threat.id} ({threat.label})")
        except Exception:
            logger.exception("Email alert delivery failed")

    if settings.webhook_enabled and settings.webhook_url:
        try:
            notifications.send_webhook(
                settings.webhook_url,
                {
                    "threat_id": threat.id,
                    "severity": threat.severity,
                    "label": threat.label,
                    "score": threat.score,
                    "source_ip": event.source_ip,
                    "dest_ip": event.dest_ip,
                    "protocol": event.protocol,
                    "created_at": threat.created_at.isoformat(),
                },
                secret=settings.webhook_secret,
            )
        except Exception:
            logger.exception("Custom webhook alert delivery failed")


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected"}


@app.post("/events/ingest", response_model=EventOut)
@limiter.limit("60/minute")
def ingest_event(request: Request, payload: EventIn, db: Session = Depends(get_db), org_id: str = Depends(require_ingest_key)):
    # Not user-JWT-gated on purpose: this is a service/pipeline endpoint (seed
    # scripts, log-source ingestion), not called from the browser — it
    # authenticates via a real per-org X-API-Key (require_ingest_key), which
    # also resolves which organization this event belongs to.
    try:
        result = score_event(payload.features)
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Detection model not trained yet — run `python -m detection.train` in backend/.",
        )

    event = LogEvent(
        organization_id=org_id,
        source_ip=payload.source_ip,
        dest_ip=payload.dest_ip,
        protocol=payload.protocol,
        bytes=payload.bytes,
        raw_payload=json.dumps(payload.features),
    )
    db.add(event)
    db.flush()

    threat = None
    if result["is_threat"]:
        threat = Threat(
            organization_id=org_id,
            event_id=event.id,
            score=result["score"],
            label=result["label"],
            severity=result["severity"],
        )
        db.add(threat)

    db.commit()
    db.refresh(event)

    if threat is not None:
        db.refresh(threat)
        dispatch_alert(db, threat, event)

    return event


@app.get("/events", response_model=list[EventOut])
def list_events(
    limit: int = 50,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    return (
        db.query(LogEvent)
        .filter(LogEvent.organization_id == member.org_id)
        .options(selectinload(LogEvent.threats))
        .order_by(desc(LogEvent.ts))
        .limit(limit)
        .all()
    )


@app.get("/threats", response_model=list[ThreatOut])
def list_threats(
    limit: int = 50,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    rows = (
        db.query(Threat)
        .filter(Threat.organization_id == member.org_id)
        .options(joinedload(Threat.event))
        .order_by(desc(Threat.created_at))
        .limit(limit)
        .all()
    )
    return [
        ThreatOut(
            id=t.id,
            score=t.score,
            label=t.label,
            severity=t.severity,
            summary=t.summary,
            created_at=t.created_at,
            event_id=t.event_id,
            source_ip=t.event.source_ip if t.event else None,
            dest_ip=t.event.dest_ip if t.event else None,
            protocol=t.event.protocol if t.event else None,
            bytes=t.event.bytes if t.event else None,
        )
        for t in rows
    ]


@app.get("/stats/summary", response_model=SummaryOut)
def stats_summary(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    total_events = db.query(LogEvent).filter(LogEvent.organization_id == member.org_id).count()
    threats = db.query(Threat).filter(Threat.organization_id == member.org_id).all()
    events = db.query(LogEvent).filter(LogEvent.organization_id == member.org_id).all()

    severity_counter = Counter(t.severity for t in threats)
    category_counter = Counter(t.label for t in threats)
    protocol_counter = Counter(e.protocol for e in events)

    return SummaryOut(
        total_events=total_events,
        total_threats=len(threats),
        by_severity=SeverityCounts(
            critical=severity_counter.get("critical", 0),
            high=severity_counter.get("high", 0),
            medium=severity_counter.get("medium", 0),
        ),
        by_category=dict(category_counter),
        by_protocol=dict(protocol_counter),
    )


@app.get("/model/metrics", response_model=ModelMetricsOut)
def model_metrics(user: CurrentUser = Depends(get_current_user)):
    if not METRICS_PATH.exists() or not MODEL_PATH.exists():
        return ModelMetricsOut(trained=False)

    report = json.loads(METRICS_PATH.read_text())
    per_class = {
        k: v
        for k, v in report.items()
        if isinstance(v, dict) and k not in ("accuracy",)
    }
    trained_at = MODEL_PATH.stat().st_mtime
    from datetime import datetime, timezone

    return ModelMetricsOut(
        trained=True,
        trained_at=datetime.fromtimestamp(trained_at, tz=timezone.utc).isoformat(),
        accuracy=report.get("accuracy"),
        macro_f1=report.get("macro avg", {}).get("f1-score"),
        weighted_f1=report.get("weighted avg", {}).get("f1-score"),
        per_class=per_class,
        feature_importance=get_feature_importance(),
    )


@app.get("/users/me", response_model=MeOut)
def get_me(user: CurrentUser = Depends(get_current_user)):
    return MeOut(id=user.id, email=user.email, role=user.role)


@app.get("/settings/notifications", response_model=NotificationSettingsOut)
def get_notification_settings(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    settings = get_or_create_settings(db, member.org_id)
    # Build a detached Pydantic copy rather than mutating the ORM-tracked
    # instance in place — mutating `settings` directly here would be a trap
    # for a future change: any `db.commit()` elsewhere in the same request
    # would persist the mask and destroy the real secret in the database.
    out = NotificationSettingsOut.model_validate(settings)
    if member.org_role not in ("owner", "admin"):
        # slack_webhook_url and webhook_secret are bearer secrets — anyone who
        # holds them can post to the Slack channel or forge signed webhook
        # calls. Every other field (enabled flags, recipients, thresholds) is
        # fine for any org member to see, so only these two are hidden rather
        # than gating the whole endpoint behind an org admin role.
        out.slack_webhook_url = None
        out.webhook_secret = None
    return out


@app.put("/settings/notifications", response_model=NotificationSettingsOut)
def update_notification_settings(
    payload: NotificationSettingsIn,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    settings = get_or_create_settings(db, member.org_id)
    for field, value in payload.model_dump().items():
        setattr(settings, field, value)
    db.commit()
    db.refresh(settings)
    record_audit(db, member.org_id, member.user.email, "settings.notifications.updated")
    return settings


@app.post("/settings/notifications/test/slack")
@limiter.limit("5/minute")
def test_slack(
    request: Request,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    settings = get_or_create_settings(db, member.org_id)
    if not settings.slack_webhook_url:
        raise HTTPException(status_code=400, detail="No Slack webhook URL saved yet.")
    try:
        notifications.send_slack(
            settings.slack_webhook_url,
            "🔧 CyberGuard AI test alert — if you can see this, Slack delivery is working.",
        )
    except notifications.NotificationError as e:
        raise HTTPException(status_code=502, detail=str(e))
    record_audit(db, member.org_id, member.user.email, "settings.notifications.test_slack")
    return {"status": "sent"}


@app.post("/settings/notifications/test/email")
@limiter.limit("5/minute")
def test_email(
    request: Request,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    settings = get_or_create_settings(db, member.org_id)
    recipients = [r.strip() for r in settings.email_recipients.split(",") if r.strip()]
    if not recipients:
        raise HTTPException(status_code=400, detail="No email recipients saved yet.")
    try:
        notifications.send_email(
            recipients,
            "CyberGuard AI test alert",
            "This is a test alert from CyberGuard AI. If you're reading this, email delivery is working.",
        )
    except notifications.NotificationError as e:
        raise HTTPException(status_code=502, detail=str(e))
    record_audit(db, member.org_id, member.user.email, "settings.notifications.test_email")
    return {"status": "sent"}


@app.post("/settings/notifications/test/webhook")
@limiter.limit("5/minute")
def test_webhook(
    request: Request,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    settings = get_or_create_settings(db, member.org_id)
    if not settings.webhook_url:
        raise HTTPException(status_code=400, detail="No webhook URL saved yet.")
    try:
        notifications.send_webhook(
            settings.webhook_url,
            {"event": "test", "message": "CyberGuard AI test webhook delivery"},
            secret=settings.webhook_secret,
        )
    except notifications.NotificationError as e:
        raise HTTPException(status_code=502, detail=str(e))
    record_audit(db, member.org_id, member.user.email, "settings.notifications.test_webhook")
    return {"status": "sent"}


@app.post("/threats/{threat_id}/triage", response_model=ThreatOut)
def triage_threat(
    threat_id: str,
    regenerate: bool = False,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    t = (
        db.query(Threat)
        .options(joinedload(Threat.event))
        .filter(Threat.id == threat_id, Threat.organization_id == member.org_id)
        .first()
    )
    if t is None:
        raise HTTPException(status_code=404, detail="Threat not found")

    if not t.summary or regenerate:
        raw_features = json.loads(t.event.raw_payload) if t.event and t.event.raw_payload else {}
        try:
            t.summary = triage.generate_triage(
                label=t.label,
                severity=t.severity,
                score=t.score,
                source_ip=t.event.source_ip if t.event else "unknown",
                dest_ip=t.event.dest_ip if t.event else "unknown",
                protocol=t.event.protocol if t.event else "unknown",
                bytes_transferred=t.event.bytes if t.event else 0,
                raw_features=raw_features,
            )
        except triage.TriageError as e:
            raise HTTPException(status_code=502, detail=str(e))
        db.commit()
        db.refresh(t)

    return ThreatOut(
        id=t.id,
        score=t.score,
        label=t.label,
        severity=t.severity,
        summary=t.summary,
        created_at=t.created_at,
        event_id=t.event_id,
        source_ip=t.event.source_ip if t.event else None,
        dest_ip=t.event.dest_ip if t.event else None,
        protocol=t.event.protocol if t.event else None,
        bytes=t.event.bytes if t.event else None,
    )


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    return (
        db.query(Incident)
        .filter(Incident.organization_id == member.org_id)
        .options(selectinload(Incident.notes))
        .order_by(desc(Incident.created_at))
        .all()
    )


@app.post("/incidents", response_model=IncidentOut)
def create_incident(
    payload: IncidentIn,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    if payload.threat_id and not db.query(Threat).filter(
        Threat.id == payload.threat_id, Threat.organization_id == member.org_id
    ).first():
        raise HTTPException(status_code=404, detail="Linked threat not found")

    incident = Incident(
        organization_id=member.org_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        threat_id=payload.threat_id,
        created_by_email=member.user.email,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    record_audit(db, member.org_id, member.user.email, "incident.created", f"{incident.id}: {incident.title}")
    return incident


@app.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.notes))
        .filter(Incident.id == incident_id, Incident.organization_id == member.org_id)
        .first()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.organization_id == member.org_id
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    db.commit()
    db.refresh(incident)
    record_audit(
        db, member.org_id, member.user.email, "incident.updated",
        f"{incident.id}: {payload.model_dump(exclude_unset=True)}",
    )
    return incident


@app.post("/incidents/{incident_id}/notes", response_model=IncidentOut)
def add_incident_note(
    incident_id: str,
    payload: IncidentNoteIn,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    incident = db.query(Incident).filter(
        Incident.id == incident_id, Incident.organization_id == member.org_id
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    db.add(IncidentNote(incident_id=incident_id, author_email=member.user.email, content=payload.content))
    db.commit()

    return (
        db.query(Incident)
        .options(selectinload(Incident.notes))
        .filter(Incident.id == incident_id)
        .first()
    )


# ---------------------------------------------------------------------------
# Organization membership audit trail — invite/remove/role-change happen
# client-side, straight against Neon Auth's real `organization` plugin (see
# src/lib/OrgContext.tsx), so they never otherwise reach this backend. This
# lets the frontend record that a real, already-successful membership change
# happened, so GET /compliance/export actually captures it — the same
# owner/admin gate as performing the change itself in the first place.
# ---------------------------------------------------------------------------

@app.post("/organizations/audit-event")
def record_org_audit_event(
    payload: OrgAuditEventIn,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    record_audit(db, member.org_id, member.user.email, payload.action, payload.detail)
    return {"status": "recorded"}


# ---------------------------------------------------------------------------
# Public API — per-organization ingest keys. Each key authenticates
# POST /events/ingest and resolves which org an event belongs to (see
# auth.require_ingest_key). Only the SHA-256 hash is ever stored; the raw
# secret is returned exactly once, in the create response. Full request/
# response schemas for this and every other endpoint are self-documenting
# via FastAPI's real OpenAPI generation — see /docs (Swagger UI) or /redoc.
# ---------------------------------------------------------------------------

@app.get("/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    return (
        db.query(ApiKey)
        .filter(ApiKey.organization_id == member.org_id)
        .order_by(desc(ApiKey.created_at))
        .all()
    )


@app.post("/api-keys", response_model=ApiKeyCreatedOut)
def create_api_key(
    payload: ApiKeyIn,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    secret = f"cgai_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(secret.encode()).hexdigest()

    key = ApiKey(
        organization_id=member.org_id,
        name=payload.name,
        key_prefix=secret[:12],
        key_hash=key_hash,
        created_by_email=member.user.email,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    record_audit(db, member.org_id, member.user.email, "api_key.created", payload.name)

    return ApiKeyCreatedOut(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        created_by_email=key.created_by_email,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
        revoked=key.revoked,
        secret=secret,
    )


@app.delete("/api-keys/{key_id}")
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.organization_id == member.org_id).first()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    key.revoked = True
    db.commit()
    record_audit(db, member.org_id, member.user.email, "api_key.revoked", key.name)
    return {"status": "revoked"}


# ---------------------------------------------------------------------------
# Compliance evidence export — a real, timestamped bundle of this org's
# incidents (with notes), detected threats, and audit log entries in a date
# range, as a downloadable ZIP of CSVs. Genuinely useful for the "show us
# what happened and how you responded" ask behind a SOC2/ISO27001 evidence
# request — not a fabricated compliance badge or checklist.
# ---------------------------------------------------------------------------

def _csv_bytes(fieldnames: list[str], rows: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")


@app.get("/compliance/export")
def compliance_export(
    start: str | None = None,
    end: str | None = None,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    try:
        start_dt = datetime.fromisoformat(start).replace(tzinfo=timezone.utc) if start else datetime.now(timezone.utc) - timedelta(days=90)
        if end:
            end_dt = datetime.fromisoformat(end).replace(tzinfo=timezone.utc)
            # A bare "YYYY-MM-DD" parses to that day's midnight — the start
            # of the day, not the end — which would silently exclude
            # everything created later that same day. Push to end-of-day so
            # "end=today" actually includes today.
            if len(end) == 10:
                end_dt += timedelta(days=1) - timedelta(microseconds=1)
        else:
            end_dt = datetime.now(timezone.utc)
    except ValueError:
        raise HTTPException(status_code=400, detail="start/end must be ISO dates, e.g. 2026-01-01")

    incidents = (
        db.query(Incident)
        .filter(Incident.organization_id == member.org_id, Incident.created_at.between(start_dt, end_dt))
        .order_by(Incident.created_at)
        .all()
    )
    threats = (
        db.query(Threat)
        .filter(Threat.organization_id == member.org_id, Threat.created_at.between(start_dt, end_dt))
        .order_by(Threat.created_at)
        .all()
    )
    audit_entries = (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == member.org_id, AuditLog.created_at.between(start_dt, end_dt))
        .order_by(AuditLog.created_at)
        .all()
    )
    note_rows = (
        db.query(IncidentNote)
        .join(Incident, IncidentNote.incident_id == Incident.id)
        .filter(Incident.organization_id == member.org_id, IncidentNote.created_at.between(start_dt, end_dt))
        .order_by(IncidentNote.created_at)
        .all()
    )

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("incidents.csv", _csv_bytes(
            ["id", "title", "severity", "status", "created_by_email", "assignee_email", "threat_id", "created_at", "updated_at"],
            [
                {
                    "id": i.id, "title": i.title, "severity": i.severity, "status": i.status,
                    "created_by_email": i.created_by_email, "assignee_email": i.assignee_email or "",
                    "threat_id": i.threat_id or "", "created_at": i.created_at.isoformat(), "updated_at": i.updated_at.isoformat(),
                }
                for i in incidents
            ],
        ))
        zf.writestr("incident_notes.csv", _csv_bytes(
            ["incident_id", "author_email", "content", "created_at"],
            [
                {"incident_id": n.incident_id, "author_email": n.author_email, "content": n.content, "created_at": n.created_at.isoformat()}
                for n in note_rows
            ],
        ))
        zf.writestr("threats.csv", _csv_bytes(
            ["id", "event_id", "label", "severity", "score", "triaged", "created_at"],
            [
                {
                    "id": t.id, "event_id": t.event_id, "label": t.label, "severity": t.severity,
                    "score": t.score, "triaged": bool(t.summary), "created_at": t.created_at.isoformat(),
                }
                for t in threats
            ],
        ))
        zf.writestr("audit_log.csv", _csv_bytes(
            ["actor_email", "action", "detail", "created_at"],
            [
                {"actor_email": a.actor_email, "action": a.action, "detail": a.detail, "created_at": a.created_at.isoformat()}
                for a in audit_entries
            ],
        ))

    record_audit(
        db, member.org_id, member.user.email, "compliance.exported",
        f"{start_dt.date()} to {end_dt.date()}: {len(incidents)} incidents, {len(threats)} threats, {len(audit_entries)} audit entries",
    )

    filename = f"cyberguard-compliance-export-{start_dt.date()}-to-{end_dt.date()}.zip"
    return Response(
        content=zip_buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# User management — intentionally platform-wide, not org-scoped. This is the
# deployment operator's view of every account that has ever signed up, kept
# distinct from per-org membership (invite/remove/role-within-org), which is
# handled by Neon Auth's real `organization` plugin, called directly from
# the frontend via the Better Auth client — not proxied through our backend.
# ---------------------------------------------------------------------------

@app.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("Admin")),
):
    rows = db.execute(
        text('SELECT id, email, role, banned, "createdAt" AS created_at FROM neon_auth."user" ORDER BY "createdAt" DESC')
    ).all()
    return [UserOut(id=str(r.id), email=r.email, role=r.role, banned=r.banned, created_at=r.created_at) for r in rows]


@app.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("Admin")),
):
    if user_id == user.id:
        # Same guard as update_user_ban below: an Admin who demotes themself
        # with no other Admin around has no self-service way back in short
        # of shell access to run promote_admin.py.
        raise HTTPException(status_code=400, detail="You can't change your own role")

    row = db.execute(
        text('SELECT id, email, role, banned, "createdAt" AS created_at FROM neon_auth."user" WHERE id = :id'),
        {"id": user_id},
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    db.execute(
        text('UPDATE neon_auth."user" SET role = :role WHERE id = :id'),
        {"role": payload.role, "id": user_id},
    )
    db.commit()
    record_audit(db, None, user.email, "user.role_changed", f"{row.email} -> {payload.role}")
    return UserOut(id=str(row.id), email=row.email, role=payload.role, banned=row.banned, created_at=row.created_at)


@app.patch("/users/{user_id}/ban", response_model=UserOut)
def update_user_ban(
    user_id: str,
    payload: UserBanUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("Admin")),
):
    if user_id == user.id and payload.banned:
        raise HTTPException(status_code=400, detail="You can't suspend your own account")

    row = db.execute(
        text('SELECT id, email, role, banned, "createdAt" AS created_at FROM neon_auth."user" WHERE id = :id'),
        {"id": user_id},
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    db.execute(
        text('UPDATE neon_auth."user" SET banned = :banned WHERE id = :id'),
        {"banned": payload.banned, "id": user_id},
    )
    db.commit()
    record_audit(db, None, user.email, "user.ban_changed", f"{row.email} {'suspended' if payload.banned else 'reinstated'}")
    return UserOut(id=str(row.id), email=row.email, role=row.role, banned=payload.banned, created_at=row.created_at)


# ---------------------------------------------------------------------------
# General settings
# ---------------------------------------------------------------------------

@app.get("/settings/general", response_model=AppSettingsOut)
def get_general_settings(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    return get_or_create_app_settings(db, member.org_id)


@app.put("/settings/general", response_model=AppSettingsOut)
def update_general_settings(
    payload: AppSettingsIn,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    settings = get_or_create_app_settings(db, member.org_id)
    for field, value in payload.model_dump().items():
        setattr(settings, field, value)
    db.commit()
    db.refresh(settings)
    record_audit(db, member.org_id, member.user.email, "settings.general.updated")
    return settings


# ---------------------------------------------------------------------------
# Model retraining
# ---------------------------------------------------------------------------

@app.post("/model/retrain", response_model=ModelMetricsOut)
@limiter.limit("3/hour")
def retrain_model(
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("Admin")),
):
    if not TRAIN_DATA_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="Training dataset not found — run `./data/download.sh` in backend/ first.",
        )
    record_audit(db, None, user.email, "model.retrain_started")
    report = train_model()
    reload_model()
    record_audit(db, None, user.email, "model.retrain_completed", f"accuracy={report.get('accuracy', 0):.3f}")

    from datetime import datetime, timezone

    per_class = {k: v for k, v in report.items() if isinstance(v, dict) and k not in ("accuracy",)}
    return ModelMetricsOut(
        trained=True,
        trained_at=datetime.now(tz=timezone.utc).isoformat(),
        accuracy=report.get("accuracy"),
        macro_f1=report.get("macro avg", {}).get("f1-score"),
        weighted_f1=report.get("weighted avg", {}).get("f1-score"),
        per_class=per_class,
        feature_importance=get_feature_importance(),
    )


@app.get("/threats/{threat_id}/explain", response_model=list[ThreatExplanationItem])
def explain_threat(
    threat_id: str,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    t = (
        db.query(Threat)
        .options(joinedload(Threat.event))
        .filter(Threat.id == threat_id, Threat.organization_id == member.org_id)
        .first()
    )
    if t is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    if not t.event or not t.event.raw_payload:
        return []

    features = json.loads(t.event.raw_payload)
    return explain_event(features)


# ---------------------------------------------------------------------------
# System logs (real UDP syslog receiver — backend/syslog_server.py)
# ---------------------------------------------------------------------------

@app.get("/logs", response_model=list[SystemLogOut])
def list_logs(
    limit: int = 100,
    severity: str | None = None,
    flagged_only: bool = False,
    search: str | None = None,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    query = db.query(SystemLog).filter(SystemLog.organization_id == member.org_id)
    if severity:
        query = query.filter(SystemLog.severity == severity)
    if flagged_only:
        query = query.filter(SystemLog.flagged.is_(True))
    if search:
        query = query.filter(SystemLog.message.ilike(f"%{search}%"))
    return query.order_by(desc(SystemLog.received_at)).limit(limit).all()


@app.get("/logs/stats", response_model=LogStatsOut)
def log_stats(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_member),
):
    rows = (
        db.query(SystemLog.severity, SystemLog.facility, SystemLog.source_host, SystemLog.flagged)
        .filter(SystemLog.organization_id == member.org_id)
        .all()
    )
    return LogStatsOut(
        total_logs=len(rows),
        flagged_logs=sum(1 for r in rows if r.flagged),
        unique_hosts=len({r.source_host for r in rows}),
        by_severity=dict(Counter(r.severity for r in rows)),
        by_facility=dict(Counter(r.facility for r in rows)),
        listening_port=SYSLOG_PORT,
    )


# ---------------------------------------------------------------------------
# System health & danger zone — deployment-wide (all orgs), not org-scoped:
# this is the platform operator's view (DB connectivity, shared model
# status, uptime, and aggregate counts across every organization). Gated by
# the site-wide Admin role rather than org membership — previously this only
# required being logged in, which was fine with a single tenant but became a
# real cross-org information leak (any user in any org could see every other
# org's aggregate event/threat/incident counts) once multi-tenancy landed.
# Deliberately different scope from /stats/summary, which is per-org.
# ---------------------------------------------------------------------------

@app.get("/system/health", response_model=SystemHealthOut)
def system_health(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("Admin")),
):
    db_connected = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_connected = False

    model_trained = METRICS_PATH.exists() and MODEL_PATH.exists()
    model_accuracy = None
    model_trained_at = None
    if model_trained:
        report = json.loads(METRICS_PATH.read_text())
        model_accuracy = report.get("accuracy")
        from datetime import datetime, timezone

        model_trained_at = datetime.fromtimestamp(MODEL_PATH.stat().st_mtime, tz=timezone.utc).isoformat()

    dataset_rows = None
    if TRAIN_DATA_PATH.exists():
        with open(TRAIN_DATA_PATH) as f:
            dataset_rows = sum(1 for _ in f) - 1  # minus header

    active_sessions = db.execute(
        text('SELECT COUNT(*) FROM neon_auth.session WHERE "expiresAt" > now()')
    ).scalar()

    return SystemHealthOut(
        database_connected=db_connected,
        model_trained=model_trained,
        model_accuracy=model_accuracy,
        model_trained_at=model_trained_at,
        dataset_rows=dataset_rows,
        total_events=db.query(LogEvent).count(),
        total_threats=db.query(Threat).count(),
        total_incidents=db.query(Incident).count(),
        active_sessions=active_sessions or 0,
        uptime_seconds=time.time() - _APP_START,
        ingest_rate_limit="60/minute per IP",
        alert_test_rate_limit="5/minute per IP",
        log_level=logging.getLevelName(logging.getLogger().getEffectiveLevel()),
    )


@app.post("/settings/notifications/reset")
def reset_notification_settings(
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner", "admin")),
):
    settings = get_or_create_settings(db, member.org_id)
    for field, value in NotificationSettingsIn().model_dump().items():
        setattr(settings, field, value)
    db.commit()
    record_audit(db, member.org_id, member.user.email, "settings.notifications.reset")
    return {"status": "reset"}


@app.post("/system/factory-reset")
def factory_reset(
    confirm: str,
    db: Session = Depends(get_db),
    member: OrgMember = Depends(require_org_role("owner")),
):
    """Wipes this organization's own ingested detection data (events,
    threats, incidents) — not users, not other organizations, not
    configuration. Requires the literal string "RESET" to guard against
    accidental clicks; there is no undo. Restricted to org owners since it's
    the most destructive org-scoped action available."""
    if confirm != "RESET":
        raise HTTPException(status_code=400, detail='Type "RESET" to confirm this action.')

    db.execute(
        text(
            "DELETE FROM incident_notes WHERE incident_id IN "
            "(SELECT id FROM incidents WHERE organization_id = :org_id)"
        ),
        {"org_id": member.org_id},
    )
    # incidents.threat_id references threats — must delete incidents first,
    # or the DELETE on threats below violates that foreign key.
    for table in ("incidents", "threats", "log_events", "system_logs"):
        db.execute(text(f"DELETE FROM {table} WHERE organization_id = :org_id"), {"org_id": member.org_id})
    db.commit()
    record_audit(db, member.org_id, member.user.email, "system.factory_reset", "events/threats/incidents/logs wiped")
    return {"status": "reset"}
