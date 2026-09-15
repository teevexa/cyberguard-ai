import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { MetricCard } from "@/components/MetricCard"
import { LoadingState, ErrorState } from "@/components/QueryState"
import { BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { FileText, AlertCircle, Server, Radio, Search, Terminal } from "lucide-react"
import { useLogs, useLogStats } from "@/hooks/useApi"

const SEVERITY_COLORS: Record<string, string> = {
  emerg: "hsl(var(--critical))",
  alert: "hsl(var(--critical))",
  crit: "hsl(var(--critical))",
  err: "hsl(var(--critical))",
  warning: "hsl(var(--warning))",
  notice: "hsl(var(--primary))",
  info: "hsl(var(--primary))",
  debug: "hsl(var(--muted-foreground))",
}

function severityBadgeClass(severity: string) {
  if (["emerg", "alert", "crit", "err"].includes(severity)) return "bg-critical text-critical-foreground"
  if (severity === "warning") return "bg-warning text-warning-foreground"
  return ""
}

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp)
  const diffMs = Date.now() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  if (diffMins < 1) return "Just now"
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  return date.toLocaleString()
}

export default function Logs() {
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [search, setSearch] = useState("")

  const statsQuery = useLogStats()
  const logsQuery = useLogs({
    limit: 200,
    severity: severityFilter === "all" ? undefined : severityFilter,
    flaggedOnly,
    search: search || undefined,
  })

  if (statsQuery.isPending) return <LoadingState label="Loading log analytics…" />
  if (statsQuery.isError) return <ErrorState message={(statsQuery.error as Error).message} />

  const stats = statsQuery.data
  const severityChartData = Object.entries(stats.by_severity)
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => b.count - a.count)
  const facilityChartData = Object.entries(stats.by_facility)
    .map(([facility, count]) => ({ facility, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Log Analytics</h1>
        <p className="text-muted-foreground">
          Real RFC 3164 syslog messages received over UDP — send a test message with{" "}
          <code className="text-xs bg-muted px-1 py-0.5 rounded">logger -n 127.0.0.1 -P {stats.listening_port} "test message"</code>
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          Plain UDP has no header to carry your organization — messages land here only if they embed one of this
          org's API keys as <code className="bg-muted px-1 py-0.5 rounded">[key:...]</code> at the start of the
          message text (see Settings &gt; Organization &gt; API Keys), otherwise they're attributed to the
          deployment's default organization instead.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard title="Total Logs" value={stats.total_logs.toLocaleString()} icon={FileText} variant="default" />
        <MetricCard title="Flagged" value={stats.flagged_logs.toLocaleString()} icon={AlertCircle} variant={stats.flagged_logs > 0 ? "critical" : "success"} />
        <MetricCard title="Unique Hosts" value={stats.unique_hosts} icon={Server} variant="default" />
        <MetricCard title="Listening Port (UDP)" value={stats.listening_port} icon={Radio} variant="success" />
      </div>

      {stats.total_logs === 0 ? (
        <Card>
          <CardContent className="pt-6 text-center space-y-3">
            <Terminal className="h-10 w-10 mx-auto text-muted-foreground" />
            <p className="font-medium">No syslog messages received yet</p>
            <p className="text-sm text-muted-foreground">
              The backend runs a real UDP syslog listener on port {stats.listening_port}. Point a syslog sender at it,
              or send a test packet:
            </p>
            <p className="text-xs font-mono bg-muted rounded p-2 inline-block">
              logger -n 127.0.0.1 -P {stats.listening_port} "Failed password for invalid user admin"
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Messages by Severity</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={severityChartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis dataKey="severity" stroke="hsl(var(--muted-foreground))" />
                    <YAxis stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
                    <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px" }} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {severityChartData.map((entry) => (
                        <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "hsl(var(--primary))"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Messages by Facility</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={facilityChartData} layout="vertical" margin={{ left: 16 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={false} />
                    <XAxis type="number" stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
                    <YAxis type="category" dataKey="facility" stroke="hsl(var(--muted-foreground))" width={80} tick={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px" }} />
                    <Bar dataKey="count" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Search & Filter</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-4 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input placeholder="Search message text…" className="pl-10" value={search} onChange={(e) => setSearch(e.target.value)} />
                </div>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    {Object.keys(stats.by_severity).map((s) => (
                      <SelectItem key={s} value={s}>{s}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <div className="flex items-center gap-2">
                  <Switch checked={flaggedOnly} onCheckedChange={setFlaggedOnly} id="flagged-only" />
                  <label htmlFor="flagged-only" className="text-sm">Flagged only</label>
                </div>
              </div>

              {logsQuery.isPending ? (
                <LoadingState label="Loading logs…" />
              ) : logsQuery.isError ? (
                <ErrorState message={(logsQuery.error as Error).message} />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Received</TableHead>
                      <TableHead>Host</TableHead>
                      <TableHead>Facility</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Message</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {logsQuery.data.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">{formatTimestamp(log.received_at)}</TableCell>
                        <TableCell className="font-mono text-xs">{log.source_host}</TableCell>
                        <TableCell className="text-xs">{log.facility}{log.tag ? `/${log.tag}` : ""}</TableCell>
                        <TableCell>
                          <Badge variant={severityBadgeClass(log.severity) ? "default" : "outline"} className={`text-xs ${severityBadgeClass(log.severity)}`}>
                            {log.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.message}
                          {log.flagged && (
                            <span className="block text-xs text-critical mt-0.5">flagged: {log.flag_reason}</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                    {logsQuery.data.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                          No logs match these filters
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
