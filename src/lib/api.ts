import { getAccessToken } from "@/lib/auth-client"
import { getActiveOrgId } from "@/lib/activeOrg"

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000"

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await getAccessToken()
  const orgId = getActiveOrgId()
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(orgId ? { "X-Organization-Id": orgId } : {}),
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    throw new ApiError(res.status, body?.detail ?? `${path} failed: ${res.status} ${res.statusText}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

/** Triggers a real browser download — the export endpoint returns a binary
 * ZIP, not JSON, so it can't go through request<T>(). */
async function downloadFile(path: string, filenameFallback: string): Promise<void> {
  const token = await getAccessToken()
  const orgId = getActiveOrgId()
  const res = await fetch(`${API_URL}${path}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(orgId ? { "X-Organization-Id": orgId } : {}),
    },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    throw new ApiError(res.status, body?.detail ?? `${path} failed: ${res.status} ${res.statusText}`)
  }
  const disposition = res.headers.get("content-disposition") ?? ""
  const match = disposition.match(/filename="?([^"]+)"?/)
  const filename = match?.[1] ?? filenameFallback

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export interface ThreatDto {
  id: string
  score: number
  label: string
  severity: string
  summary: string | null
  created_at: string
  event_id: string
  source_ip: string | null
  dest_ip: string | null
  protocol: string | null
  bytes: number | null
}

export interface EventDto {
  id: string
  ts: string
  source_ip: string
  dest_ip: string
  protocol: string
  bytes: number
  threats: ThreatDto[]
}

export interface SummaryDto {
  total_events: number
  total_threats: number
  by_severity: { critical: number; high: number; medium: number }
  by_category: Record<string, number>
  by_protocol: Record<string, number>
}

export interface FeatureImportanceDto {
  feature: string
  importance: number
}

export interface ModelMetricsDto {
  trained: boolean
  trained_at: string | null
  accuracy: number | null
  macro_f1: number | null
  weighted_f1: number | null
  per_class: Record<string, { precision: number; recall: number; "f1-score": number; support: number }>
  feature_importance: FeatureImportanceDto[]
}

export interface ThreatExplanationDto {
  feature: string
  value: number
  normal_mean: number
  normal_std: number
  z_score: number
  importance: number
}

export interface MeDto {
  id: string
  email: string
  role: string
}

export interface NotificationSettingsDto {
  id: string
  notifications_enabled: boolean
  email_enabled: boolean
  email_recipients: string
  slack_enabled: boolean
  slack_webhook_url: string | null
  slack_channel: string | null
  webhook_enabled: boolean
  webhook_url: string | null
  webhook_secret: string | null
  alert_on_critical: boolean
  alert_on_high: boolean
  alert_on_medium: boolean
  updated_at: string
}

export type NotificationSettingsInput = Omit<NotificationSettingsDto, "id" | "updated_at">

export interface IncidentNoteDto {
  id: string
  author_email: string
  content: string
  created_at: string
}

export interface IncidentDto {
  id: string
  title: string
  description: string
  severity: "critical" | "high" | "medium" | "low"
  status: "open" | "investigating" | "mitigating" | "resolved" | "closed"
  assignee_email: string | null
  created_by_email: string
  threat_id: string | null
  created_at: string
  updated_at: string
  notes: IncidentNoteDto[]
}

export interface IncidentInput {
  title: string
  description: string
  severity: IncidentDto["severity"]
  threat_id?: string | null
}

export interface UserDto {
  id: string
  email: string
  role: string
  banned: boolean
  created_at: string
}

export interface AppSettingsDto {
  id: string
  org_name: string
  contact_email: string
  timezone: string
  log_retention_days: number
  updated_at: string
}

export type AppSettingsInput = Omit<AppSettingsDto, "id" | "updated_at">

export interface SystemLogDto {
  id: string
  received_at: string
  source_host: string
  facility: string
  severity: string
  tag: string | null
  message: string
  flagged: boolean
  flag_reason: string | null
}

export interface LogStatsDto {
  total_logs: number
  flagged_logs: number
  unique_hosts: number
  by_severity: Record<string, number>
  by_facility: Record<string, number>
  listening_port: number
}

export interface ApiKeyDto {
  id: string
  name: string
  key_prefix: string
  created_by_email: string
  created_at: string
  last_used_at: string | null
  revoked: boolean
}

export interface ApiKeyCreatedDto extends ApiKeyDto {
  secret: string
}

export interface SystemHealthDto {
  database_connected: boolean
  model_trained: boolean
  model_accuracy: number | null
  model_trained_at: string | null
  dataset_rows: number | null
  total_events: number
  total_threats: number
  total_incidents: number
  active_sessions: number
  uptime_seconds: number
  ingest_rate_limit: string
  alert_test_rate_limit: string
  log_level: string
}

export const api = {
  threats: (limit = 50) => request<ThreatDto[]>(`/threats?limit=${limit}`),
  events: (limit = 50) => request<EventDto[]>(`/events?limit=${limit}`),
  summary: () => request<SummaryDto>("/stats/summary"),
  modelMetrics: () => request<ModelMetricsDto>("/model/metrics"),
  me: () => request<MeDto>("/users/me"),
  notificationSettings: () => request<NotificationSettingsDto>("/settings/notifications"),
  saveNotificationSettings: (payload: NotificationSettingsInput) =>
    request<NotificationSettingsDto>("/settings/notifications", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  testSlack: () => request<{ status: string }>("/settings/notifications/test/slack", { method: "POST" }),
  testEmail: () => request<{ status: string }>("/settings/notifications/test/email", { method: "POST" }),
  testWebhook: () => request<{ status: string }>("/settings/notifications/test/webhook", { method: "POST" }),
  triageThreat: (threatId: string, regenerate = false) =>
    request<ThreatDto>(`/threats/${threatId}/triage${regenerate ? "?regenerate=true" : ""}`, { method: "POST" }),
  explainThreat: (threatId: string) => request<ThreatExplanationDto[]>(`/threats/${threatId}/explain`),
  apiKeys: () => request<ApiKeyDto[]>("/api-keys"),
  createApiKey: (name: string) =>
    request<ApiKeyCreatedDto>("/api-keys", { method: "POST", body: JSON.stringify({ name }) }),
  revokeApiKey: (id: string) => request<{ status: string }>(`/api-keys/${id}`, { method: "DELETE" }),
  exportCompliance: (start: string, end: string) => {
    const qs = new URLSearchParams({ start, end })
    return downloadFile(`/compliance/export?${qs.toString()}`, `cyberguard-compliance-export.zip`)
  },
  incidents: () => request<IncidentDto[]>("/incidents"),
  createIncident: (payload: IncidentInput) =>
    request<IncidentDto>("/incidents", { method: "POST", body: JSON.stringify(payload) }),
  updateIncident: (id: string, payload: Partial<Pick<IncidentDto, "status" | "assignee_email" | "severity">>) =>
    request<IncidentDto>(`/incidents/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  addIncidentNote: (id: string, content: string) =>
    request<IncidentDto>(`/incidents/${id}/notes`, { method: "POST", body: JSON.stringify({ content }) }),
  users: () => request<UserDto[]>("/users"),
  updateUserRole: (id: string, role: string) =>
    request<UserDto>(`/users/${id}/role`, { method: "PATCH", body: JSON.stringify({ role }) }),
  updateUserBan: (id: string, banned: boolean) =>
    request<UserDto>(`/users/${id}/ban`, { method: "PATCH", body: JSON.stringify({ banned }) }),
  generalSettings: () => request<AppSettingsDto>("/settings/general"),
  saveGeneralSettings: (payload: AppSettingsInput) =>
    request<AppSettingsDto>("/settings/general", { method: "PUT", body: JSON.stringify(payload) }),
  retrainModel: () => request<ModelMetricsDto>("/model/retrain", { method: "POST" }),
  systemHealth: () => request<SystemHealthDto>("/system/health"),
  logs: (params: { limit?: number; severity?: string; flaggedOnly?: boolean; search?: string } = {}) => {
    const qs = new URLSearchParams()
    if (params.limit) qs.set("limit", String(params.limit))
    if (params.severity) qs.set("severity", params.severity)
    if (params.flaggedOnly) qs.set("flagged_only", "true")
    if (params.search) qs.set("search", params.search)
    return request<SystemLogDto[]>(`/logs?${qs.toString()}`)
  },
  logStats: () => request<LogStatsDto>("/logs/stats"),
  resetNotificationSettings: () => request<{ status: string }>("/settings/notifications/reset", { method: "POST" }),
  factoryReset: (confirm: string) =>
    request<{ status: string }>(`/system/factory-reset?confirm=${encodeURIComponent(confirm)}`, { method: "POST" }),
  /** Organization membership (invite/remove/role-change) is managed
   * client-side, straight against Neon Auth's own organization plugin — it
   * never otherwise reaches this backend, so without this call those real
   * actions are invisible to GET /compliance/export. Call only after the
   * underlying Better Auth call actually succeeded. */
  recordOrgAuditEvent: (action: "member.invited" | "member.removed" | "member.role_changed", detail = "") =>
    request<{ status: string }>("/organizations/audit-event", { method: "POST", body: JSON.stringify({ action, detail }) }),
}
