from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

IncidentSeverity = Literal["critical", "high", "medium", "low"]
IncidentStatus = Literal["open", "investigating", "mitigating", "resolved", "closed"]


class MeOut(BaseModel):
    id: str
    email: str
    role: str


class EventIn(BaseModel):
    source_ip: str
    dest_ip: str
    protocol: str
    bytes: int = 0
    features: dict[str, float | int | str]


class ThreatOut(BaseModel):
    id: str
    score: float
    label: str
    severity: str
    summary: str | None
    created_at: datetime
    event_id: str
    source_ip: str | None = None
    dest_ip: str | None = None
    protocol: str | None = None
    bytes: int | None = None

    model_config = ConfigDict(from_attributes=True)


class EventOut(BaseModel):
    id: str
    ts: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    bytes: int
    threats: list[ThreatOut] = []

    model_config = ConfigDict(from_attributes=True)


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0


class SummaryOut(BaseModel):
    total_events: int
    total_threats: int
    by_severity: SeverityCounts
    by_category: dict[str, int]
    by_protocol: dict[str, int]


class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float


class ModelMetricsOut(BaseModel):
    trained: bool
    trained_at: str | None = None
    accuracy: float | None = None
    macro_f1: float | None = None
    weighted_f1: float | None = None
    per_class: dict[str, dict[str, float]] = {}
    feature_importance: list[FeatureImportanceItem] = []


class ThreatExplanationItem(BaseModel):
    feature: str
    value: float
    normal_mean: float
    normal_std: float
    z_score: float
    importance: float


class NotificationSettingsIn(BaseModel):
    notifications_enabled: bool = True
    email_enabled: bool = False
    email_recipients: str = ""
    slack_enabled: bool = False
    slack_webhook_url: str | None = None
    slack_channel: str | None = None
    webhook_enabled: bool = False
    webhook_url: str | None = None
    webhook_secret: str | None = None
    alert_on_critical: bool = True
    alert_on_high: bool = True
    alert_on_medium: bool = False


class NotificationSettingsOut(NotificationSettingsIn):
    id: str
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentNoteIn(BaseModel):
    content: str


class IncidentNoteOut(BaseModel):
    id: str
    author_email: str
    content: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentIn(BaseModel):
    title: str
    description: str = ""
    severity: IncidentSeverity
    threat_id: str | None = None


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    assignee_email: str | None = None
    severity: IncidentSeverity | None = None


class IncidentOut(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str
    assignee_email: str | None
    created_by_email: str
    threat_id: str | None
    created_at: datetime
    updated_at: datetime
    notes: list[IncidentNoteOut] = []

    model_config = ConfigDict(from_attributes=True)


class UserOut(BaseModel):
    """User record for the admin user-management list."""

    id: str
    email: str
    role: str
    banned: bool
    created_at: datetime


class UserRoleUpdate(BaseModel):
    role: str


class UserBanUpdate(BaseModel):
    banned: bool


class AppSettingsIn(BaseModel):
    org_name: str = "CyberGuard Security"
    contact_email: str = ""
    timezone: str = "utc"
    log_retention_days: int = 90


class AppSettingsOut(AppSettingsIn):
    id: str
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SystemLogOut(BaseModel):
    id: str
    received_at: datetime
    source_host: str
    facility: str
    severity: str
    tag: str | None
    message: str
    flagged: bool
    flag_reason: str | None

    model_config = ConfigDict(from_attributes=True)


class LogStatsOut(BaseModel):
    total_logs: int
    flagged_logs: int
    unique_hosts: int
    by_severity: dict[str, int]
    by_facility: dict[str, int]
    listening_port: int


class ApiKeyIn(BaseModel):
    name: str


class ApiKeyOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_by_email: str
    created_at: datetime
    last_used_at: datetime | None
    revoked: bool

    model_config = ConfigDict(from_attributes=True)


class ApiKeyCreatedOut(ApiKeyOut):
    """Returned only once, at creation — the raw secret is never retrievable
    again, only its hash is stored."""

    secret: str


OrgAuditAction = Literal["member.invited", "member.removed", "member.role_changed"]


class OrgAuditEventIn(BaseModel):
    """Organization membership (invite/remove/role-change) is managed
    client-side, directly against Neon Auth's own `organization` plugin —
    see src/lib/OrgContext.tsx — so unlike every other admin action it never
    otherwise touches our backend or its audit_log table. The frontend calls
    this right after a real, successful membership change so compliance
    export (GET /compliance/export) actually covers it. The action is a
    closed enum, not free text — this endpoint records evidence of an
    action that already happened elsewhere, it doesn't perform one, so it
    must not become a place to write arbitrary audit-log entries."""

    action: OrgAuditAction
    detail: str = ""


class SystemHealthOut(BaseModel):
    database_connected: bool
    model_trained: bool
    model_accuracy: float | None
    model_trained_at: str | None
    dataset_rows: int | None
    total_events: int
    total_threats: int
    total_incidents: int
    active_sessions: int
    uptime_seconds: float
    ingest_rate_limit: str
    alert_test_rate_limit: str
    log_level: str
