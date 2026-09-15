import { useEffect, useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { toast } from "@/hooks/use-toast"
import {
  Settings as SettingsIcon, Bell, Mail, Webhook, Shield, Database, Cpu,
  TestTube2, AlertTriangle, Lock, RotateCw, Activity, Clock,
} from "lucide-react"
import { LoadingState, ErrorState } from "@/components/QueryState"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api, ApiError, type NotificationSettingsInput, type AppSettingsInput } from "@/lib/api"
import { useAuth } from "@/lib/AuthContext"
import { useOrg } from "@/lib/OrgContext"
import { orgClient } from "@/lib/auth-client"
import { getRealtimeEnabled, setRealtimeEnabled } from "@/lib/realtimePreference"
import { Users as UsersIcon, Trash2, FileDown } from "lucide-react"

function NotificationsTab() {
  const { activeOrgRole } = useOrg()
  // /settings/notifications is gated server-side by *org* role
  // (owner/admin), not the site-wide role — matching that here, instead of
  // the site-wide "Admin" check this used to use, fixes a real mismatch: an
  // org owner who isn't a platform-wide Admin used to see this permanently
  // disabled, while a platform Admin who's just a "member" of the active
  // org used to see it enabled and then get a 403 on save.
  const isAdmin = activeOrgRole === "owner" || activeOrgRole === "admin"
  const queryClient = useQueryClient()
  const { data, isPending, isError, error } = useQuery({
    queryKey: ["notification-settings"],
    queryFn: api.notificationSettings,
  })
  const [form, setForm] = useState<NotificationSettingsInput | null>(null)

  useEffect(() => {
    if (data) setForm(data)
  }, [data])

  const save = useMutation({
    mutationFn: (payload: NotificationSettingsInput) => api.saveNotificationSettings(payload),
    onSuccess: (saved) => {
      queryClient.setQueryData(["notification-settings"], saved)
      toast({ title: "Settings saved", description: "Notification configuration updated." })
    },
    onError: (err: ApiError) => toast({ title: "Save failed", description: err.message, variant: "destructive" }),
  })

  const runTest = useMutation({
    mutationFn: (channel: "slack" | "email" | "webhook") =>
      channel === "slack" ? api.testSlack() : channel === "email" ? api.testEmail() : api.testWebhook(),
    onSuccess: (_res, channel) =>
      toast({ title: "Test sent", description: `Check your ${channel} destination — a real message was just sent.` }),
    onError: (err: ApiError) => toast({ title: "Test failed", description: err.message, variant: "destructive" }),
  })

  if (isPending || !form) return <LoadingState label="Loading notification settings…" />
  if (isError) return <ErrorState message={(error as Error).message} />

  const set = <K extends keyof NotificationSettingsInput>(key: K, value: NotificationSettingsInput[K]) =>
    setForm((f) => (f ? { ...f, [key]: value } : f))

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Alert Notifications
          </span>
          <Button size="sm" disabled={!isAdmin || save.isPending} onClick={() => save.mutate(form)}>
            {save.isPending ? "Saving…" : "Save Changes"}
          </Button>
        </CardTitle>
        <CardDescription>
          Real delivery — Slack via Incoming Webhook, email via SMTP, and a generic signed webhook. Saving and
          testing requires the owner or admin role within this organization.
        </CardDescription>
        {!isAdmin && (
          <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 border border-warning/30 rounded-md px-3 py-2 mt-2">
            <Lock className="h-4 w-4 shrink-0" />
            You're a "{activeOrgRole ?? "member"}" in this organization — an owner or admin needs to grant you
            access before you can change these settings.
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label className="text-base">Enable Notifications</Label>
            <p className="text-sm text-muted-foreground">Master toggle for all alert notifications</p>
          </div>
          <Switch
            disabled={!isAdmin}
            checked={form.notifications_enabled}
            onCheckedChange={(v) => set("notifications_enabled", v)}
          />
        </div>

        <Separator />

        {/* Email Notifications */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label className="text-base flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Email Alerts
              </Label>
              <p className="text-sm text-muted-foreground">Sent via the SMTP account configured on the backend</p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={!isAdmin || runTest.isPending} onClick={() => runTest.mutate("email")}>
                <TestTube2 className="h-3 w-3 mr-1" />
                Test
              </Button>
              <Switch disabled={!isAdmin} checked={form.email_enabled} onCheckedChange={(v) => set("email_enabled", v)} />
            </div>
          </div>

          {form.email_enabled && (
            <div className="ml-6 space-y-4 p-4 border rounded-lg">
              <div className="space-y-2">
                <Label htmlFor="email-recipients">Recipients (comma-separated)</Label>
                <Textarea
                  id="email-recipients"
                  placeholder="admin@company.com, security@company.com"
                  rows={2}
                  disabled={!isAdmin}
                  value={form.email_recipients}
                  onChange={(e) => set("email_recipients", e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <Separator />

        {/* Slack Notifications */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label className="text-base">Slack Integration</Label>
              <p className="text-sm text-muted-foreground">Send alerts via an Incoming Webhook</p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={!isAdmin || runTest.isPending} onClick={() => runTest.mutate("slack")}>
                <TestTube2 className="h-3 w-3 mr-1" />
                Test
              </Button>
              <Switch disabled={!isAdmin} checked={form.slack_enabled} onCheckedChange={(v) => set("slack_enabled", v)} />
            </div>
          </div>

          {form.slack_enabled && (
            <div className="ml-6 space-y-4 p-4 border rounded-lg">
              <div className="space-y-2">
                <Label htmlFor="slack-webhook">Webhook URL</Label>
                <Input
                  id="slack-webhook"
                  placeholder="https://hooks.slack.com/services/..."
                  type="password"
                  disabled={!isAdmin}
                  value={form.slack_webhook_url ?? ""}
                  onChange={(e) => set("slack_webhook_url", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="slack-channel">Channel (informational — set at webhook creation time)</Label>
                <Input
                  id="slack-channel"
                  placeholder="#security-alerts"
                  disabled={!isAdmin}
                  value={form.slack_channel ?? ""}
                  onChange={(e) => set("slack_channel", e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <Separator />

        {/* Webhook Notifications */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label className="text-base flex items-center gap-2">
                <Webhook className="h-4 w-4" />
                Custom Webhook
              </Label>
              <p className="text-sm text-muted-foreground">POSTs a JSON payload, HMAC-SHA256 signed if a secret is set</p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={!isAdmin || runTest.isPending} onClick={() => runTest.mutate("webhook")}>
                <TestTube2 className="h-3 w-3 mr-1" />
                Test
              </Button>
              <Switch disabled={!isAdmin} checked={form.webhook_enabled} onCheckedChange={(v) => set("webhook_enabled", v)} />
            </div>
          </div>

          {form.webhook_enabled && (
            <div className="ml-6 space-y-4 p-4 border rounded-lg">
              <div className="space-y-2">
                <Label htmlFor="webhook-url">Webhook URL</Label>
                <Input
                  id="webhook-url"
                  placeholder="https://api.company.com/alerts"
                  disabled={!isAdmin}
                  value={form.webhook_url ?? ""}
                  onChange={(e) => set("webhook_url", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="webhook-secret">Secret Key (optional — signs the payload)</Label>
                <Input
                  id="webhook-secret"
                  type="password"
                  placeholder="webhook_secret_key"
                  disabled={!isAdmin}
                  value={form.webhook_secret ?? ""}
                  onChange={(e) => set("webhook_secret", e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <Separator />

        <div className="space-y-4">
          <Label className="text-base">Alert Severity Thresholds</Label>
          <p className="text-sm text-muted-foreground -mt-2">
            Only these severities trigger delivery. No "low" tier — the model doesn't produce one.
          </p>
          <div className="grid grid-cols-3 gap-4 max-w-sm">
            <div className="space-y-2">
              <Label className="text-sm text-critical">Critical</Label>
              <Switch disabled={!isAdmin} checked={form.alert_on_critical} onCheckedChange={(v) => set("alert_on_critical", v)} />
            </div>
            <div className="space-y-2">
              <Label className="text-sm text-warning">High</Label>
              <Switch disabled={!isAdmin} checked={form.alert_on_high} onCheckedChange={(v) => set("alert_on_high", v)} />
            </div>
            <div className="space-y-2">
              <Label className="text-sm text-accent">Medium</Label>
              <Switch disabled={!isAdmin} checked={form.alert_on_medium} onCheckedChange={(v) => set("alert_on_medium", v)} />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function GeneralTab() {
  const { activeOrgRole } = useOrg()
  // Same fix as NotificationsTab — /settings/general is gated by org role
  // server-side, not the site-wide role.
  const isAdmin = activeOrgRole === "owner" || activeOrgRole === "admin"
  const queryClient = useQueryClient()
  const { data, isPending, isError, error } = useQuery({ queryKey: ["general-settings"], queryFn: api.generalSettings })
  const [form, setForm] = useState<AppSettingsInput | null>(null)
  const [realtimeOn, setRealtimeOn] = useState(getRealtimeEnabled())

  useEffect(() => {
    if (data) setForm(data)
  }, [data])

  const save = useMutation({
    mutationFn: (payload: AppSettingsInput) => api.saveGeneralSettings(payload),
    onSuccess: (saved) => {
      queryClient.setQueryData(["general-settings"], saved)
      toast({ title: "Settings saved" })
    },
    onError: (err: ApiError) => toast({ title: "Save failed", description: err.message, variant: "destructive" }),
  })

  if (isPending || !form) return <LoadingState label="Loading settings…" />
  if (isError) return <ErrorState message={(error as Error).message} />

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <SettingsIcon className="h-5 w-5" />
            Organization Settings
          </span>
          <Button size="sm" disabled={!isAdmin || save.isPending} onClick={() => save.mutate(form)}>
            {save.isPending ? "Saving…" : "Save Changes"}
          </Button>
        </CardTitle>
        <CardDescription>Persisted for real — shared across everyone in this organization.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-2">
            <Label htmlFor="org-name">Organization Name</Label>
            <Input id="org-name" disabled={!isAdmin} value={form.org_name} onChange={(e) => setForm({ ...form, org_name: e.target.value })} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="contact-email">Contact Email</Label>
            <Input id="contact-email" type="email" disabled={!isAdmin} value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="timezone">Default Timezone</Label>
          <Select disabled={!isAdmin} value={form.timezone} onValueChange={(v) => setForm({ ...form, timezone: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="utc">UTC</SelectItem>
              <SelectItem value="est">Eastern Time</SelectItem>
              <SelectItem value="pst">Pacific Time</SelectItem>
              <SelectItem value="cet">Central European Time</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="retention">Log Retention Period</Label>
          <Select disabled={!isAdmin} value={String(form.log_retention_days)} onValueChange={(v) => setForm({ ...form, log_retention_days: Number(v) })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="30">30 days</SelectItem>
              <SelectItem value="90">90 days</SelectItem>
              <SelectItem value="180">180 days</SelectItem>
              <SelectItem value="365">1 year</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            Enforced hourly: events, threats not linked to an open incident, and syslog messages older than this are
            purged automatically.
          </p>
        </div>

        <Separator />

        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <Label className="text-base">Real-time Updates</Label>
            <p className="text-sm text-muted-foreground">Poll the dashboard every 15s for new data. Applies immediately, this browser only.</p>
          </div>
          <Switch
            checked={realtimeOn}
            onCheckedChange={(v) => { setRealtimeOn(v); setRealtimeEnabled(v) }}
          />
        </div>
      </CardContent>
    </Card>
  )
}

function SecurityTab() {
  const { user } = useAuth()
  const isAdmin = user?.role === "Admin"
  const { data, isPending, isError, error } = useQuery({
    queryKey: ["system-health"],
    queryFn: api.systemHealth,
    enabled: isAdmin,
  })

  if (!isAdmin) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 border border-warning/30 rounded-md px-3 py-2">
            <Lock className="h-4 w-4 shrink-0" />
            You're signed in as "{user?.role ?? "unknown"}" — this deployment-wide security view requires the Admin role.
          </div>
        </CardContent>
      </Card>
    )
  }

  if (isPending) return <LoadingState label="Loading security info…" />
  if (isError) return <ErrorState message={(error as Error).message} />

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Security
        </CardTitle>
        <CardDescription>What's actually enforced — no editable toggles that wouldn't do anything.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm">Active sessions right now</span>
            <Badge variant="outline">{data.active_sessions}</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Authentication provider</span>
            <Badge variant="outline">Neon Auth (Better Auth)</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">JWT verification</span>
            <Badge variant="outline">EdDSA via JWKS, 401 on expiry/tamper</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Account suspension</span>
            <Badge variant="outline">Enforced — blocks sign-in and rejects live tokens</Badge>
          </div>
        </div>

        <Separator />

        <div className="space-y-3">
          <Label className="text-base">Rate Limiting</Label>
          <div className="flex items-center justify-between">
            <span className="text-sm">Event ingestion (<code>/events/ingest</code>)</span>
            <Badge variant="outline">{data.ingest_rate_limit}</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Alert test endpoints</span>
            <Badge variant="outline">{data.alert_test_rate_limit}</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Event ingestion auth</span>
            <Badge variant="outline">Per-organization API key (X-API-Key), hashed at rest</Badge>
          </div>
        </div>

        <Separator />

        <div className="flex items-start gap-2 text-sm text-muted-foreground bg-muted/50 p-3 rounded-lg">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
          <p>
            Not implemented: multi-factor authentication, configurable session timeout, and password composition
            rules — these would need a Better Auth plugin we haven't enabled, so we're not showing switches for
            settings that wouldn't actually do anything.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

function ModelsTab() {
  const { user } = useAuth()
  const isAdmin = user?.role === "Admin"
  const queryClient = useQueryClient()
  const { data, isPending, isError, error } = useQuery({ queryKey: ["model-metrics"], queryFn: api.modelMetrics })

  const retrain = useMutation({
    mutationFn: api.retrainModel,
    onSuccess: (metrics) => {
      queryClient.setQueryData(["model-metrics"], metrics)
      toast({ title: "Retraining complete", description: `New accuracy: ${(metrics.accuracy! * 100).toFixed(1)}%` })
    },
    onError: (err: ApiError) => toast({ title: "Retraining failed", description: err.message, variant: "destructive" }),
  })

  if (isPending) return <LoadingState label="Loading model info…" />
  if (isError) return <ErrorState message={(error as Error).message} />

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Cpu className="h-5 w-5" />
            AI Model
          </span>
          <Button size="sm" disabled={!isAdmin || retrain.isPending} onClick={() => retrain.mutate()}>
            <RotateCw className={`h-4 w-4 mr-2 ${retrain.isPending ? "animate-spin" : ""}`} />
            {retrain.isPending ? "Retraining… (~60-90s)" : "Retrain Now"}
          </Button>
        </CardTitle>
        <CardDescription>
          Retrain actually re-runs the RandomForest and hot-swaps the live model — not a simulated progress bar. It
          trains on the same fixed UNSW-NB15 dataset with a fixed random seed each time, though, not on your
          org's own ingested traffic, so results are deterministic: this demonstrates the retrain pipeline and lets
          you recover after e.g. deleting <code>model.joblib</code>, it isn't continuous learning from live data.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {data.trained ? (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <Label className="text-xs text-muted-foreground">Accuracy</Label>
                <p className="text-lg font-semibold">{(data.accuracy! * 100).toFixed(1)}%</p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Weighted F1</Label>
                <p className="text-lg font-semibold">{(data.weighted_f1! * 100).toFixed(1)}%</p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Macro F1</Label>
                <p className="text-lg font-semibold">{(data.macro_f1! * 100).toFixed(1)}%</p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Last Trained</Label>
                <p className="text-lg font-semibold">{new Date(data.trained_at!).toLocaleDateString()}</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Full per-category breakdown is on the <a href="/models" className="underline">Models</a> page.
            </p>
          </>
        ) : (
          <p className="text-sm text-muted-foreground">No model trained yet — click Retrain Now to train the first one.</p>
        )}

        <Separator />

        <div className="flex items-start gap-2 text-sm text-muted-foreground bg-muted/50 p-3 rounded-lg">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
          <p>
            Not implemented: automatic retraining on a schedule, configurable hyperparameters, and data-drift
            monitoring — these need real MLOps infrastructure (a scheduler, a drift-detection pipeline) that's
            long-term roadmap, not a settings toggle. Retraining today is a real, manually-triggered action.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

function SystemTab() {
  const { user } = useAuth()
  const isAdmin = user?.role === "Admin"
  const { activeOrgRole } = useOrg()
  // The health stats below are genuinely deployment-wide (aggregate counts
  // across every organization) and correctly require the site-wide Admin
  // role, matching GET /system/health server-side. But "Reset Notification
  // Settings" and "Factory Reset" are org-scoped actions gated server-side
  // by *org* role (owner/admin, and owner-only for factory reset) — they
  // used to be nested under the site-Admin-only gate too, which meant a
  // real org owner who wasn't also a platform Admin could never even see
  // this section, while a platform Admin who was merely a "member" of the
  // active org would see enabled buttons that the backend would reject.
  const canManageOrg = activeOrgRole === "owner" || activeOrgRole === "admin"
  const isOrgOwner = activeOrgRole === "owner"
  const queryClient = useQueryClient()
  const { data, isPending, isError, error } = useQuery({
    queryKey: ["system-health"],
    queryFn: api.systemHealth,
    enabled: isAdmin,
  })
  const [confirmText, setConfirmText] = useState("")

  const resetNotifications = useMutation({
    mutationFn: api.resetNotificationSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notification-settings"] })
      toast({ title: "Notification settings reset to defaults" })
    },
    onError: (err: ApiError) => toast({ title: "Reset failed", description: err.message, variant: "destructive" }),
  })

  const factoryReset = useMutation({
    mutationFn: (confirm: string) => api.factoryReset(confirm),
    onSuccess: () => {
      queryClient.invalidateQueries()
      setConfirmText("")
      toast({ title: "Factory reset complete", description: "All ingested events, threats, and incidents were wiped." })
    },
    onError: (err: ApiError) => toast({ title: "Reset failed", description: err.message, variant: "destructive" }),
  })

  if (!isAdmin && !canManageOrg) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            System
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 border border-warning/30 rounded-md px-3 py-2">
            <Lock className="h-4 w-4 shrink-0" />
            This requires either the platform Admin role (for deployment-wide health data) or the owner/admin role
            within this organization (for the actions below).
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Database className="h-5 w-5" />
          System
        </CardTitle>
        <CardDescription>Real health data — no fake CPU/memory sliders for infrastructure we don't control (serverless Postgres, no fixed connection pool to size).</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {isAdmin ? (
          isPending ? (
            <LoadingState label="Loading system info…" />
          ) : isError ? (
            <ErrorState message={(error as Error).message} />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-success" />
                <div>
                  <p className="text-xs text-muted-foreground">Database</p>
                  <p className="text-sm font-medium">{data.database_connected ? "Connected" : "Down"}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-xs text-muted-foreground">Uptime</p>
                  <p className="text-sm font-medium">{Math.floor(data.uptime_seconds / 60)}m {Math.floor(data.uptime_seconds % 60)}s</p>
                </div>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Log Level</p>
                <p className="text-sm font-medium">{data.log_level}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Events Ingested</p>
                <p className="text-sm font-medium">{data.total_events.toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Threats Detected</p>
                <p className="text-sm font-medium">{data.total_threats.toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Incidents Tracked</p>
                <p className="text-sm font-medium">{data.total_incidents.toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Training Dataset</p>
                <p className="text-sm font-medium">{data.dataset_rows?.toLocaleString() ?? "not downloaded"} rows</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Model Accuracy</p>
                <p className="text-sm font-medium">{data.model_accuracy ? `${(data.model_accuracy * 100).toFixed(1)}%` : "untrained"}</p>
              </div>
            </div>
          )
        ) : (
          <p className="text-sm text-muted-foreground">Deployment-wide health metrics require the platform Admin role.</p>
        )}

        {canManageOrg && (
          <>
            <Separator />
            <div className="p-4 border border-warning/30 rounded-lg bg-warning/5">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-warning mt-0.5" />
                <div className="flex-1 space-y-3">
                  <div>
                    <h4 className="font-medium text-warning">Danger Zone</h4>
                    <p className="text-sm text-muted-foreground mt-1">
                      These actions are real and, for Factory Reset, irreversible.
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" disabled={resetNotifications.isPending} onClick={() => resetNotifications.mutate()}>
                      Reset Notification Settings
                    </Button>
                  </div>
                  {isOrgOwner ? (
                    <div className="flex gap-2 items-center pt-2 border-t">
                      <Input
                        placeholder='Type "RESET" to confirm'
                        value={confirmText}
                        onChange={(e) => setConfirmText(e.target.value)}
                        className="max-w-xs"
                      />
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={confirmText !== "RESET" || factoryReset.isPending}
                        onClick={() => factoryReset.mutate(confirmText)}
                      >
                        Factory Reset (wipe events/threats/incidents)
                      </Button>
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground pt-2 border-t">
                      Only this organization's owner can run a factory reset.
                    </p>
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function OrganizationTab() {
  const { user } = useAuth()
  const {
    activeOrg, members: data, isLoadingMembers: isPending, isMembersError: isError, membersError: error,
    activeOrgRole, refetchMembers,
  } = useOrg()
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState<"member" | "admin">("member")

  const members = data
  const canManage = activeOrgRole === "owner" || activeOrgRole === "admin"

  // Better Auth's client methods resolve with {data, error} on failure
  // rather than rejecting the promise — so onSuccess must check res.error
  // itself, or a failed call (insufficient permission, stale id, network
  // hiccup surfaced as a body instead of a throw) shows a false "success"
  // toast while nothing actually happened. invite already checked this;
  // removeMember/changeRole didn't, which was the actual bug.
  const invite = useMutation({
    mutationFn: () => orgClient.organization.inviteMember({ email: inviteEmail.trim(), role: inviteRole, organizationId: activeOrg!.id }),
    onSuccess: (res) => {
      if (res.error) {
        toast({ title: "Invite failed", description: res.error.message, variant: "destructive" })
        return
      }
      setInviteEmail("")
      toast({ title: "Invitation sent", description: `${inviteEmail} can now accept an invite to join ${activeOrg?.name}.` })
      api.recordOrgAuditEvent("member.invited", `${inviteEmail} as ${inviteRole}`).catch(() => {})
    },
    onError: (err: Error) => toast({ title: "Invite failed", description: err.message, variant: "destructive" }),
  })

  const removeMember = useMutation({
    mutationFn: (memberIdOrEmail: string) =>
      orgClient.organization.removeMember({ memberIdOrEmail, organizationId: activeOrg!.id }),
    onSuccess: (res, memberIdOrEmail) => {
      if (res.error) {
        toast({ title: "Couldn't remove member", description: res.error.message, variant: "destructive" })
        return
      }
      refetchMembers()
      toast({ title: "Member removed" })
      api.recordOrgAuditEvent("member.removed", memberIdOrEmail).catch(() => {})
    },
    onError: (err: Error) => toast({ title: "Couldn't remove member", description: err.message, variant: "destructive" }),
  })

  const changeRole = useMutation({
    mutationFn: ({ memberId, role }: { memberId: string; role: string }) =>
      orgClient.organization.updateMemberRole({ memberId, role: role as "member" | "admin" | "owner", organizationId: activeOrg!.id }),
    onSuccess: (res, vars) => {
      if (res.error) {
        toast({ title: "Couldn't update role", description: res.error.message, variant: "destructive" })
        return
      }
      refetchMembers()
      toast({ title: "Role updated" })
      api.recordOrgAuditEvent("member.role_changed", `${vars.memberId} -> ${vars.role}`).catch(() => {})
    },
    onError: (err: Error) => toast({ title: "Couldn't update role", description: err.message, variant: "destructive" }),
  })

  if (!activeOrg) return <LoadingState label="Loading organization…" />
  if (isPending) return <LoadingState label="Loading members…" />
  if (isError) return <ErrorState message={error?.message ?? "Couldn't load organization members."} />

  return (
    <div className="space-y-6">
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <UsersIcon className="h-5 w-5" />
          {activeOrg.name} — Members
        </CardTitle>
        <CardDescription>
          Real Neon Auth organization membership — invites, roles, and removal all call Better Auth's own
          `organization` plugin directly, not a hand-rolled system.
        </CardDescription>
        {!canManage && (
          <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 border border-warning/30 rounded-md px-3 py-2 mt-2">
            <Lock className="h-4 w-4 shrink-0" />
            You're a "{activeOrgRole ?? "member"}" in this organization — only owners/admins can invite or manage members.
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-3">
          {members.map((m) => (
            <div key={m.id} className="flex items-center justify-between border-b pb-2 last:border-0">
              <div>
                <p className="text-sm font-medium">{m.user?.email}</p>
                <p className="text-xs text-muted-foreground">{m.role}</p>
              </div>
              {canManage && m.userId !== user?.id && (
                <div className="flex items-center gap-2">
                  <Select value={m.role} onValueChange={(role) => changeRole.mutate({ memberId: m.id, role })}>
                    <SelectTrigger className="w-28 h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="member">member</SelectItem>
                      <SelectItem value="admin">admin</SelectItem>
                      <SelectItem value="owner">owner</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => removeMember.mutate(m.id)}>
                    <Trash2 className="h-4 w-4 text-critical" />
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>

        {canManage && (
          <>
            <Separator />
            <div className="space-y-2">
              <Label className="text-base">Invite a member</Label>
              <div className="flex gap-2">
                <Input placeholder="teammate@example.com" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} className="flex-1" />
                <Select value={inviteRole} onValueChange={(v) => setInviteRole(v as "member" | "admin")}>
                  <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="member">member</SelectItem>
                    <SelectItem value="admin">admin</SelectItem>
                  </SelectContent>
                </Select>
                <Button disabled={!inviteEmail.trim() || invite.isPending} onClick={() => invite.mutate()}>
                  {invite.isPending ? "Sending…" : "Invite"}
                </Button>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>

    <ApiKeysCard canManage={canManage} />
    <ComplianceExportCard canManage={canManage} />
    </div>
  )
}

function ApiKeysCard({ canManage }: { canManage: boolean }) {
  const queryClient = useQueryClient()
  const [newKeyName, setNewKeyName] = useState("")
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null)

  const { data, isPending, isError, error } = useQuery({ queryKey: ["api-keys"], queryFn: api.apiKeys })

  const create = useMutation({
    mutationFn: (name: string) => api.createApiKey(name),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] })
      setNewKeyName("")
      setRevealedSecret(created.secret)
    },
    onError: (err: ApiError) => toast({ title: "Couldn't create key", description: err.message, variant: "destructive" }),
  })

  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeApiKey(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] })
      toast({ title: "Key revoked" })
    },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Webhook className="h-5 w-5" />
          API Keys
        </CardTitle>
        <CardDescription>
          Per-organization keys for <code className="text-xs">POST /events/ingest</code> — only a SHA-256 hash is
          stored server-side; the raw key is shown once, at creation. Full endpoint docs at{" "}
          <a href={`${import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000"}/docs`} target="_blank" rel="noreferrer" className="underline">
            /docs
          </a>.
        </CardDescription>
        {!canManage && (
          <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 border border-warning/30 rounded-md px-3 py-2 mt-2">
            <Lock className="h-4 w-4 shrink-0" />
            Only owners/admins can create or revoke API keys.
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {revealedSecret && (
          <div className="space-y-2 border border-warning/40 bg-warning/10 rounded-md p-3">
            <p className="text-sm font-medium">Copy this key now — it won't be shown again.</p>
            <code className="block text-xs bg-muted p-2 rounded break-all">{revealedSecret}</code>
            <Button size="sm" variant="outline" onClick={() => setRevealedSecret(null)}>Done</Button>
          </div>
        )}

        {isPending ? (
          <LoadingState label="Loading API keys…" />
        ) : isError ? (
          <ErrorState message={(error as Error).message} />
        ) : (
          <div className="space-y-3">
            {data.length === 0 && <p className="text-sm text-muted-foreground">No API keys yet.</p>}
            {data.map((k) => (
              <div key={k.id} className="flex items-center justify-between border-b pb-2 last:border-0">
                <div>
                  <p className="text-sm font-medium">{k.name}</p>
                  <p className="text-xs text-muted-foreground font-mono">{k.key_prefix}… · created by {k.created_by_email}</p>
                </div>
                {k.revoked ? (
                  <Badge variant="outline" className="text-xs">revoked</Badge>
                ) : canManage ? (
                  <Button variant="ghost" size="sm" onClick={() => revoke.mutate(k.id)}>
                    <Trash2 className="h-4 w-4 text-critical" />
                  </Button>
                ) : null}
              </div>
            ))}
          </div>
        )}

        {canManage && (
          <>
            <Separator />
            <div className="flex gap-2">
              <Input placeholder="Key name, e.g. prod-ingest" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} className="flex-1" />
              <Button disabled={!newKeyName.trim() || create.isPending} onClick={() => create.mutate(newKeyName.trim())}>
                {create.isPending ? "Creating…" : "Create Key"}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function ComplianceExportCard({ canManage }: { canManage: boolean }) {
  const today = new Date().toISOString().slice(0, 10)
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
  const [start, setStart] = useState(ninetyDaysAgo)
  const [end, setEnd] = useState(today)

  const exportMutation = useMutation({
    mutationFn: () => api.exportCompliance(start, end),
    onSuccess: () => toast({ title: "Export downloaded", description: "A ZIP of incidents, threats, and the audit log for this range." }),
    onError: (err: ApiError) => toast({ title: "Export failed", description: err.message, variant: "destructive" }),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileDown className="h-5 w-5" />
          Compliance Evidence Export
        </CardTitle>
        <CardDescription>
          A real ZIP of this organization's incidents (with notes), detected threats, and audit log for the range
          below — CSV files, not a fabricated compliance badge.
        </CardDescription>
        {!canManage && (
          <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 border border-warning/30 rounded-md px-3 py-2 mt-2">
            <Lock className="h-4 w-4 shrink-0" />
            Only owners/admins can export compliance evidence.
          </div>
        )}
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label htmlFor="export-start">From</Label>
            <Input id="export-start" type="date" value={start} onChange={(e) => setStart(e.target.value)} disabled={!canManage} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="export-end">To</Label>
            <Input id="export-end" type="date" value={end} onChange={(e) => setEnd(e.target.value)} disabled={!canManage} />
          </div>
          <Button disabled={!canManage || exportMutation.isPending} onClick={() => exportMutation.mutate()}>
            {exportMutation.isPending ? "Exporting…" : "Download Export"}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default function Settings() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          <p className="text-muted-foreground">Configure system preferences and integrations</p>
        </div>
      </div>

      <Tabs defaultValue="notifications" className="space-y-6">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="organization">Organization</TabsTrigger>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="models">AI Models</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
        </TabsList>

        <TabsContent value="organization" className="space-y-6">
          <OrganizationTab />
        </TabsContent>

        <TabsContent value="general" className="space-y-6">
          <GeneralTab />
        </TabsContent>

        <TabsContent value="notifications" className="space-y-6">
          <NotificationsTab />
        </TabsContent>

        <TabsContent value="security" className="space-y-6">
          <SecurityTab />
        </TabsContent>

        <TabsContent value="models" className="space-y-6">
          <ModelsTab />
        </TabsContent>

        <TabsContent value="system" className="space-y-6">
          <SystemTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}
