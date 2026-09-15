import { useMemo, useState } from "react"

interface TopologyEvent {
  source_ip: string
  dest_ip: string
  bytes: number
}

interface TopologyNode {
  id: string
  bytes: number
  flows: number
  flagged: boolean
}

interface TopologyEdge {
  source: string
  target: string
  count: number
}

/** Aggregates raw flow events into a bounded node/edge set — capped at
 * maxNodes (by total traffic) so the force layout stays readable and cheap
 * to compute on every render; a real deployment can have far more distinct
 * hosts than fit legibly on one map. */
export function buildTopology(
  events: TopologyEvent[],
  flaggedIps: Set<string>,
  maxNodes = 24,
): { nodes: TopologyNode[]; edges: TopologyEdge[] } {
  const hostStats = new Map<string, { bytes: number; flows: number }>()
  for (const e of events) {
    for (const ip of [e.source_ip, e.dest_ip]) {
      const entry = hostStats.get(ip) ?? { bytes: 0, flows: 0 }
      entry.bytes += e.bytes
      entry.flows += 1
      hostStats.set(ip, entry)
    }
  }

  const topIps = new Set(
    Array.from(hostStats.entries())
      .sort((a, b) => b[1].bytes - a[1].bytes)
      .slice(0, maxNodes)
      .map(([ip]) => ip),
  )

  const nodes: TopologyNode[] = Array.from(topIps).map((ip) => ({
    id: ip,
    bytes: hostStats.get(ip)!.bytes,
    flows: hostStats.get(ip)!.flows,
    flagged: flaggedIps.has(ip),
  }))

  const edgeCounts = new Map<string, number>()
  for (const e of events) {
    if (e.source_ip === e.dest_ip) continue
    if (!topIps.has(e.source_ip) || !topIps.has(e.dest_ip)) continue
    const key = [e.source_ip, e.dest_ip].sort().join("|")
    edgeCounts.set(key, (edgeCounts.get(key) ?? 0) + 1)
  }
  const edges: TopologyEdge[] = Array.from(edgeCounts.entries()).map(([key, count]) => {
    const [source, target] = key.split("|")
    return { source, target, count }
  })

  return { nodes, edges }
}

export interface LayoutPosition {
  x: number
  y: number
}

/** A small, dependency-free force-directed layout (Fruchterman-Reingold
 * style: nodes repel each other, edges pull connected nodes together, all
 * nodes are pulled gently toward center to stay on-canvas). Deterministic
 * for a given node/edge set — same data always lays out the same way,
 * which matters for it to be testable and for the map not to jump around
 * on every refetch of the same underlying data. */
export function computeForceLayout(
  nodes: { id: string }[],
  edges: { source: string; target: string }[],
  width: number,
  height: number,
  iterations = 200,
): Map<string, LayoutPosition> {
  const n = nodes.length
  const state = new Map<string, { x: number; y: number; vx: number; vy: number }>()
  const seedRadius = Math.min(width, height) / 3

  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1)
    state.set(node.id, {
      x: width / 2 + seedRadius * Math.cos(angle),
      y: height / 2 + seedRadius * Math.sin(angle),
      vx: 0,
      vy: 0,
    })
  })

  if (n <= 1) {
    const result = new Map<string, LayoutPosition>()
    state.forEach((v, id) => result.set(id, { x: v.x, y: v.y }))
    return result
  }

  const k = Math.sqrt((width * height) / n)
  const centerX = width / 2
  const centerY = height / 2
  const margin = 28

  for (let iter = 0; iter < iterations; iter++) {
    const cooling = 1 - iter / iterations

    for (const a of nodes) {
      const pa = state.get(a.id)!
      let fx = 0
      let fy = 0
      for (const b of nodes) {
        if (a.id === b.id) continue
        const pb = state.get(b.id)!
        const dx = pa.x - pb.x
        const dy = pa.y - pb.y
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 0.01)
        const force = (k * k) / dist
        fx += (dx / dist) * force
        fy += (dy / dist) * force
      }
      fx += (centerX - pa.x) * 0.01
      fy += (centerY - pa.y) * 0.01
      pa.vx = fx
      pa.vy = fy
    }

    for (const edge of edges) {
      const a = state.get(edge.source)
      const b = state.get(edge.target)
      if (!a || !b) continue
      const dx = a.x - b.x
      const dy = a.y - b.y
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 0.01)
      const force = (dist * dist) / k
      const fx = (dx / dist) * force
      const fy = (dy / dist) * force
      a.vx -= fx
      a.vy -= fy
      b.vx += fx
      b.vy += fy
    }

    for (const node of nodes) {
      const p = state.get(node.id)!
      p.x = Math.min(width - margin, Math.max(margin, p.x + p.vx * 0.02 * cooling))
      p.y = Math.min(height - margin, Math.max(margin, p.y + p.vy * 0.02 * cooling))
    }
  }

  const result = new Map<string, LayoutPosition>()
  state.forEach((v, id) => result.set(id, { x: v.x, y: v.y }))
  return result
}

const WIDTH = 800
const HEIGHT = 420

export function NetworkTopologyGraph({ events, flaggedIps }: { events: TopologyEvent[]; flaggedIps: Set<string> }) {
  const { nodes, edges } = useMemo(() => buildTopology(events, flaggedIps), [events, flaggedIps])
  const positions = useMemo(() => computeForceLayout(nodes, edges, WIDTH, HEIGHT), [nodes, edges])
  const [hoveredId, setHoveredId] = useState<string | null>(null)

  if (nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-center text-muted-foreground">
        No flow data yet to map — ingest some events first.
      </div>
    )
  }

  const maxBytes = Math.max(...nodes.map((node) => node.bytes), 1)
  const radiusFor = (bytes: number) => 5 + Math.sqrt(bytes / maxBytes) * 16
  const labelIds = new Set(
    [...nodes].sort((a, b) => b.bytes - a.bytes).slice(0, 8).map((node) => node.id),
  )

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full h-auto" role="img" aria-label="Host-to-host network topology map">
      {edges.map((edge) => {
        const a = positions.get(edge.source)
        const b = positions.get(edge.target)
        if (!a || !b) return null
        const flagged = flaggedIps.has(edge.source) || flaggedIps.has(edge.target)
        return (
          <line
            key={`${edge.source}->${edge.target}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke={flagged ? "hsl(var(--critical))" : "hsl(var(--border))"}
            strokeWidth={Math.min(1 + Math.log2(edge.count + 1), 4)}
            strokeOpacity={flagged ? 0.6 : 0.45}
          />
        )
      })}
      {nodes.map((node) => {
        const pos = positions.get(node.id)
        if (!pos) return null
        const r = radiusFor(node.bytes)
        const dimmed = hoveredId !== null && hoveredId !== node.id
        return (
          <g
            key={node.id}
            onMouseEnter={() => setHoveredId(node.id)}
            onMouseLeave={() => setHoveredId((id) => (id === node.id ? null : id))}
          >
            <circle
              cx={pos.x}
              cy={pos.y}
              r={r}
              fill={node.flagged ? "hsl(var(--critical))" : "hsl(var(--primary))"}
              fillOpacity={dimmed ? 0.35 : 0.9}
              stroke="hsl(var(--background))"
              strokeWidth={1.5}
            >
              <title>{`${node.id}\n${node.flows} flow(s) · ${node.bytes.toLocaleString()} bytes${node.flagged ? "\nFLAGGED" : ""}`}</title>
            </circle>
            {labelIds.has(node.id) && (
              <text
                x={pos.x}
                y={pos.y - r - 4}
                textAnchor="middle"
                fontSize={10}
                fontFamily="monospace"
                className="fill-muted-foreground"
              >
                {node.id}
              </text>
            )}
          </g>
        )
      })}
    </svg>
  )
}
