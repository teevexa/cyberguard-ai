import csv
import io
import zipfile
from datetime import datetime, timezone

from models import AuditLog, Incident, IncidentNote, LogEvent, Threat


def test_export_requires_org_admin_role(authed_client):
    resp = authed_client.get("/compliance/export")
    assert resp.status_code == 403


def test_export_requires_org_membership(client):
    assert client.get("/compliance/export").status_code == 401


def test_export_returns_a_real_zip_with_all_four_files(admin_client, admin_org_member, db_session):
    incident = Incident(
        organization_id=admin_org_member.org_id, title="Suspicious login", severity="high",
        created_by_email="admin@test.local",
    )
    db_session.add(incident)
    db_session.flush()
    db_session.add(IncidentNote(incident_id=incident.id, author_email="admin@test.local", content="Investigated, false positive."))

    event = LogEvent(organization_id=admin_org_member.org_id, source_ip="10.0.0.1", dest_ip="10.0.0.2", protocol="tcp", bytes=1)
    db_session.add(event)
    db_session.flush()
    db_session.add(Threat(organization_id=admin_org_member.org_id, event_id=event.id, score=0.9, label="Exploits", severity="high"))
    db_session.commit()

    resp = admin_client.get("/compliance/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "attachment" in resp.headers["content-disposition"]

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(zf.namelist())
    assert names == {"incidents.csv", "incident_notes.csv", "threats.csv", "audit_log.csv"}

    incidents_rows = list(csv.DictReader(io.StringIO(zf.read("incidents.csv").decode())))
    assert len(incidents_rows) == 1
    assert incidents_rows[0]["title"] == "Suspicious login"

    notes_rows = list(csv.DictReader(io.StringIO(zf.read("incident_notes.csv").decode())))
    assert len(notes_rows) == 1
    assert notes_rows[0]["content"] == "Investigated, false positive."

    threats_rows = list(csv.DictReader(io.StringIO(zf.read("threats.csv").decode())))
    assert len(threats_rows) == 1
    assert threats_rows[0]["label"] == "Exploits"


def test_export_only_includes_calling_orgs_data(admin_client, admin_org_member, db_session):
    other_org = "00000000-0000-0000-0000-0000000000d1"
    db_session.add(Incident(organization_id=other_org, title="Other org's incident", severity="low", created_by_email="x@other.test"))
    db_session.add(Incident(organization_id=admin_org_member.org_id, title="Our incident", severity="low", created_by_email="admin@test.local"))
    db_session.commit()

    resp = admin_client.get("/compliance/export")
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rows = list(csv.DictReader(io.StringIO(zf.read("incidents.csv").decode())))
    assert [r["title"] for r in rows] == ["Our incident"]


def test_export_respects_date_range(admin_client, admin_org_member, db_session):
    old_incident = Incident(
        organization_id=admin_org_member.org_id, title="Old incident", severity="low",
        created_by_email="admin@test.local", created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    recent_incident = Incident(
        organization_id=admin_org_member.org_id, title="Recent incident", severity="low",
        created_by_email="admin@test.local",
    )
    db_session.add_all([old_incident, recent_incident])
    db_session.commit()

    resp = admin_client.get("/compliance/export?start=2026-01-01&end=2026-12-31")
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rows = list(csv.DictReader(io.StringIO(zf.read("incidents.csv").decode())))
    assert [r["title"] for r in rows] == ["Recent incident"]


def test_export_rejects_malformed_dates(admin_client):
    resp = admin_client.get("/compliance/export?start=not-a-date")
    assert resp.status_code == 400


def test_export_end_equals_today_includes_items_created_today(admin_client, admin_org_member, db_session):
    """Regression test: a bare end=YYYY-MM-DD date used to parse to that
    day's midnight (start of day), silently excluding anything created
    later the same day — found via live browser verification, not a code
    read. An incident created seconds before export, with end=today, must
    still appear in the export."""
    db_session.add(Incident(
        organization_id=admin_org_member.org_id, title="Just now", severity="low", created_by_email="admin@test.local",
    ))
    db_session.commit()

    today = datetime.now(timezone.utc).date().isoformat()
    resp = admin_client.get(f"/compliance/export?start=2020-01-01&end={today}")
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rows = list(csv.DictReader(io.StringIO(zf.read("incidents.csv").decode())))
    assert [r["title"] for r in rows] == ["Just now"]


def test_export_itself_is_audit_logged(admin_client, admin_org_member, db_session):
    admin_client.get("/compliance/export")
    row = db_session.query(AuditLog).filter(AuditLog.action == "compliance.exported").first()
    assert row is not None
    assert row.organization_id == admin_org_member.org_id


def test_org_audit_event_requires_owner_or_admin(authed_client):
    resp = authed_client.post("/organizations/audit-event", json={"action": "member.invited", "detail": "x@y.test"})
    assert resp.status_code == 403


def test_org_audit_event_rejects_unknown_action(admin_client):
    resp = admin_client.post("/organizations/audit-event", json={"action": "member.did_something_unlisted"})
    assert resp.status_code == 422  # closed enum — this endpoint records evidence, it doesn't accept free text


def test_org_audit_event_is_recorded_and_exportable(admin_client, admin_org_member, db_session):
    """Organization membership changes (invite/remove/role-change) happen
    client-side against Neon Auth's own organization plugin and otherwise
    never touch this backend — this endpoint is what makes them show up in
    compliance export at all."""
    resp = admin_client.post(
        "/organizations/audit-event",
        json={"action": "member.invited", "detail": "newperson@example.com as member"},
    )
    assert resp.status_code == 200

    row = db_session.query(AuditLog).filter(AuditLog.action == "member.invited").first()
    assert row is not None
    assert row.organization_id == admin_org_member.org_id
    assert row.actor_email == "admin@test.local"
    assert "newperson@example.com" in row.detail

    export = admin_client.get("/compliance/export")
    zf = zipfile.ZipFile(io.BytesIO(export.content))
    audit_rows = list(csv.DictReader(io.StringIO(zf.read("audit_log.csv").decode())))
    assert any(r["action"] == "member.invited" for r in audit_rows)
