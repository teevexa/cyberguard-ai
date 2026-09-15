import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { MetricCard } from "@/components/MetricCard"
import { LoadingState, ErrorState } from "@/components/QueryState"
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { Network as NetworkIcon, Activity, Shield, AlertTriangle, Globe, Server, Search } from "lucide-react"
import { useEvents, useThreats } from "@/hooks/useApi"
import { NetworkTopologyGraph } from "@/components/NetworkTopology"

function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), sizes.length - 1)
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i]
}

const PIE_COLORS = ['#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b', '#94a3b8']

export default function Network() {
  const events = useEvents(300)
  const threats = useThreats(300)
  const [searchQuery, setSearchQuery] = useState("")

  if (events.isPending || threats.isPending) return <LoadingState label="Loading network data…" />
  if (events.isError) return <ErrorState message={(events.error as Error).message} />

  const eventList = events.data!
  const threatList = threats.data!
  const threatenedIps = new Set(
    threatList.flatMap(t => [t.source_ip, t.dest_ip]).filter((ip): ip is string => !!ip)
  )

  const protocolCounts = computeProtocolCounts(eventList)
  const topTalkers = computeTopTalkers(eventList, threatenedIps)
  const filteredTalkers = topTalkers.filter(h =>
    h.ip.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const distinctHosts = new Set(eventList.flatMap(e => [e.source_ip, e.dest_ip])).size

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Network Monitor</h1>
          <p className="text-muted-foreground">Traffic captured from ingested flow records, scored by the detector</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard title="Flows Captured" value={eventList.length} icon={Activity} variant="default" />
        <MetricCard title="Distinct Hosts" value={distinctHosts} icon={NetworkIcon} variant="default" />
        <MetricCard title="Anomalies Detected" value={threatList.length} icon={AlertTriangle} variant="warning" />
        <MetricCard
          title="Critical Threats"
          value={threatList.filter(t => t.severity === 'critical').length}
          icon={Shield}
          variant="critical"
        />
      </div>

      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threats">Threat Detection</TabsTrigger>
          <TabsTrigger value="topology">Network Map</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Bytes Transferred by Protocol
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={protocolCounts.slice(0, 8)}>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                    <XAxis dataKey="protocol" className="text-muted-foreground" />
                    <YAxis className="text-muted-foreground" />
                    <Tooltip
                      contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px" }}
                    />
                    <Bar dataKey="bytes" fill="hsl(var(--primary))" name="Bytes" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Protocol Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={protocolCounts.slice(0, 5)}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      dataKey="count"
                      label={({ protocol, count }) => `${protocol}: ${count}`}
                    >
                      {protocolCounts.slice(0, 5).map((_, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Top Hosts by Traffic
              </CardTitle>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by IP..."
                  className="pl-8 w-64"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Flows</TableHead>
                    <TableHead>Bytes</TableHead>
                    <TableHead>Risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredTalkers.slice(0, 15).map((host) => (
                    <TableRow key={host.ip}>
                      <TableCell className="font-mono">{host.ip}</TableCell>
                      <TableCell>{host.flows}</TableCell>
                      <TableCell>{formatBytes(host.bytes)}</TableCell>
                      <TableCell>
                        <Badge variant={host.flagged ? "destructive" : "outline"}>
                          {host.flagged ? "FLAGGED" : "CLEAN"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-warning" />
                Recent Network Anomalies
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Dest</TableHead>
                    <TableHead>Severity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {threatList.slice(0, 15).map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="font-mono text-xs">{new Date(t.created_at).toLocaleTimeString()}</TableCell>
                      <TableCell>{t.label}</TableCell>
                      <TableCell className="font-mono">{t.source_ip}</TableCell>
                      <TableCell className="font-mono">{t.dest_ip}</TableCell>
                      <TableCell>
                        <Badge variant={t.severity === 'critical' || t.severity === 'high' ? 'destructive' : 'secondary'}>
                          {t.severity.toUpperCase()}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="topology" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Network Topology</CardTitle>
              <p className="text-sm text-muted-foreground">
                Host-to-host connections from the {eventList.length} flow record(s) above — node size by traffic
                volume, red for a host that appears in a detected threat, capped to the top 24 hosts by traffic so
                the layout stays readable. Hover a node for details.
              </p>
            </CardHeader>
            <CardContent>
              <NetworkTopologyGraph events={eventList} flaggedIps={threatenedIps} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export function computeProtocolCounts(events: { protocol: string; bytes: number }[]) {
  const map = new Map<string, { protocol: string; count: number; bytes: number }>()
  for (const e of events) {
    const entry = map.get(e.protocol) ?? { protocol: e.protocol, count: 0, bytes: 0 }
    entry.count += 1
    entry.bytes += e.bytes
    map.set(e.protocol, entry)
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count)
}

export function computeTopTalkers(
  events: { source_ip: string; bytes: number }[],
  flaggedIps: Set<string>
) {
  const map = new Map<string, { ip: string; flows: number; bytes: number; flagged: boolean }>()
  for (const e of events) {
    const entry = map.get(e.source_ip) ?? { ip: e.source_ip, flows: 0, bytes: 0, flagged: flaggedIps.has(e.source_ip) }
    entry.flows += 1
    entry.bytes += e.bytes
    map.set(e.source_ip, entry)
  }
  return Array.from(map.values()).sort((a, b) => b.bytes - a.bytes)
}
