"""_purge_expired_data is the function behind the "Log Retention Period"
setting (src/pages/Settings.tsx GeneralTab) actually doing something —
previously that dropdown was explicitly labeled "informational for now,
nothing auto-deletes data past this yet." These tests call it directly
rather than through the hourly background loop, same as any other pure
backend-logic test in this suite.

IDs are captured as plain strings before _purge_expired_data runs: it
issues raw SQL DELETEs and commits on the same session, which expires
SQLAlchemy's in-memory objects — re-reading an attribute off a row that
raw SQL just deleted raises ObjectDeletedError instead of just returning
None, so the ids must be read out first."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from main import _purge_expired_data
from models import AppSettings, AuditLog, Incident, LogEvent, SystemLog, Threat


def _backdate(db_session, table, id_, column, days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db_session.execute(text(f"UPDATE {table} SET {column} = :ts WHERE id = :id"), {"ts": cutoff, "id": id_})
    db_session.commit()


def _seed_event_and_threat(db_session, org_id) -> tuple[str, str]:
    event = LogEvent(organization_id=org_id, source_ip="1.1.1.1", dest_ip="2.2.2.2", protocol="tcp", bytes=1)
    db_session.add(event)
    db_session.flush()
    threat = Threat(organization_id=org_id, event_id=event.id, score=0.9, label="DoS", severity="critical")
    db_session.add(threat)
    db_session.commit()
    return event.id, threat.id


def test_purge_deletes_events_and_threats_past_retention(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=30))
    db_session.commit()
    event_id, threat_id = _seed_event_and_threat(db_session, default_org)
    _backdate(db_session, "log_events", event_id, "ts", 40)
    _backdate(db_session, "threats", threat_id, "created_at", 40)

    _purge_expired_data(db_session)

    assert db_session.query(LogEvent).filter(LogEvent.id == event_id).first() is None
    assert db_session.query(Threat).filter(Threat.id == threat_id).first() is None


def test_purge_preserves_recent_data(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=30))
    db_session.commit()
    event_id, threat_id = _seed_event_and_threat(db_session, default_org)

    _purge_expired_data(db_session)

    assert db_session.query(LogEvent).filter(LogEvent.id == event_id).first() is not None
    assert db_session.query(Threat).filter(Threat.id == threat_id).first() is not None


def test_purge_preserves_threats_linked_to_incidents(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=30))
    db_session.commit()
    event_id, threat_id = _seed_event_and_threat(db_session, default_org)
    db_session.add(
        Incident(
            organization_id=default_org, title="Old but tracked", severity="critical",
            threat_id=threat_id, created_by_email="a@b.com",
        )
    )
    db_session.commit()
    _backdate(db_session, "log_events", event_id, "ts", 40)
    _backdate(db_session, "threats", threat_id, "created_at", 40)

    _purge_expired_data(db_session)

    # The threat survives because an incident still references it, and its
    # event survives because a surviving threat still references it.
    assert db_session.query(Threat).filter(Threat.id == threat_id).first() is not None
    assert db_session.query(LogEvent).filter(LogEvent.id == event_id).first() is not None


def test_purge_deletes_old_system_logs(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=7))
    log = SystemLog(
        organization_id=default_org, source_host="h", facility="auth", severity="info",
        tag=None, message="m", raw="m", flagged=False, flag_reason=None,
    )
    db_session.add(log)
    db_session.commit()
    log_id = log.id
    _backdate(db_session, "system_logs", log_id, "received_at", 10)

    _purge_expired_data(db_session)

    assert db_session.query(SystemLog).filter(SystemLog.id == log_id).first() is None


def test_purge_skips_orgs_with_no_retention_limit(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=0))
    event_id, _ = _seed_event_and_threat(db_session, default_org)
    _backdate(db_session, "log_events", event_id, "ts", 9999)

    _purge_expired_data(db_session)

    assert db_session.query(LogEvent).filter(LogEvent.id == event_id).first() is not None


def test_purge_records_an_audit_entry(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=1))
    event_id, threat_id = _seed_event_and_threat(db_session, default_org)
    # The threat must age out too — an event is preserved as long as any
    # threat still references it, so a fresh threat pointing at a stale
    # event blocks deletion entirely (exercised by
    # test_purge_preserves_threats_linked_to_incidents' sibling logic).
    _backdate(db_session, "log_events", event_id, "ts", 5)
    _backdate(db_session, "threats", threat_id, "created_at", 5)

    _purge_expired_data(db_session)

    entry = db_session.query(AuditLog).filter(AuditLog.action == "system.retention_purge").first()
    assert entry is not None
    assert entry.organization_id == default_org


def test_purge_writes_no_audit_entry_when_nothing_deleted(db_session, default_org):
    db_session.add(AppSettings(organization_id=default_org, log_retention_days=30))
    db_session.commit()

    _purge_expired_data(db_session)

    assert db_session.query(AuditLog).filter(AuditLog.action == "system.retention_purge").first() is None
