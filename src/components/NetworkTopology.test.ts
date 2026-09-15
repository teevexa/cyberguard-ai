import { describe, expect, it } from "vitest"
import { buildTopology, computeForceLayout } from "./NetworkTopology"

describe("buildTopology", () => {
  it("aggregates bytes/flows per host across both directions", () => {
    const { nodes } = buildTopology(
      [
        { source_ip: "10.0.0.1", dest_ip: "10.0.0.2", bytes: 100 },
        { source_ip: "10.0.0.1", dest_ip: "10.0.0.3", bytes: 50 },
      ],
      new Set(),
    )
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
    expect(byId["10.0.0.1"].bytes).toBe(150)
    expect(byId["10.0.0.1"].flows).toBe(2)
    expect(byId["10.0.0.2"].bytes).toBe(100)
  })

  it("marks nodes flagged when their ip is in the flagged set", () => {
    const { nodes } = buildTopology(
      [{ source_ip: "10.0.0.1", dest_ip: "10.0.0.2", bytes: 1 }],
      new Set(["10.0.0.2"]),
    )
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
    expect(byId["10.0.0.1"].flagged).toBe(false)
    expect(byId["10.0.0.2"].flagged).toBe(true)
  })

  it("builds one undirected edge per host pair with a count, ignoring self-loops", () => {
    const { edges } = buildTopology(
      [
        { source_ip: "10.0.0.1", dest_ip: "10.0.0.2", bytes: 1 },
        { source_ip: "10.0.0.2", dest_ip: "10.0.0.1", bytes: 1 },
        { source_ip: "10.0.0.1", dest_ip: "10.0.0.1", bytes: 1 },
      ],
      new Set(),
    )
    expect(edges).toHaveLength(1)
    expect(edges[0].count).toBe(2)
  })

  it("caps nodes to maxNodes, keeping the highest-traffic hosts", () => {
    const events = [
      { source_ip: "big", dest_ip: "x1", bytes: 1000 },
      { source_ip: "small-a", dest_ip: "x2", bytes: 1 },
      { source_ip: "small-b", dest_ip: "x3", bytes: 1 },
    ]
    const { nodes } = buildTopology(events, new Set(), 2)
    expect(nodes).toHaveLength(2)
    expect(nodes.some((n) => n.id === "big")).toBe(true)
  })

  it("returns no nodes or edges for no events", () => {
    const { nodes, edges } = buildTopology([], new Set())
    expect(nodes).toEqual([])
    expect(edges).toEqual([])
  })
})

describe("computeForceLayout", () => {
  it("returns one finite, in-bounds position per node", () => {
    const nodes = [{ id: "a" }, { id: "b" }, { id: "c" }]
    const edges = [{ source: "a", target: "b" }]
    const positions = computeForceLayout(nodes, edges, 800, 400, 50)

    expect(positions.size).toBe(3)
    for (const node of nodes) {
      const pos = positions.get(node.id)
      expect(pos).toBeDefined()
      expect(Number.isFinite(pos!.x)).toBe(true)
      expect(Number.isFinite(pos!.y)).toBe(true)
      expect(pos!.x).toBeGreaterThanOrEqual(0)
      expect(pos!.x).toBeLessThanOrEqual(800)
      expect(pos!.y).toBeGreaterThanOrEqual(0)
      expect(pos!.y).toBeLessThanOrEqual(400)
    }
  })

  it("is deterministic for the same input", () => {
    const nodes = [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }]
    const edges = [{ source: "a", target: "b" }, { source: "b", target: "c" }]
    const first = computeForceLayout(nodes, edges, 800, 400, 80)
    const second = computeForceLayout(nodes, edges, 800, 400, 80)
    for (const node of nodes) {
      expect(first.get(node.id)).toEqual(second.get(node.id))
    }
  })

  it("handles zero and one node without throwing", () => {
    expect(computeForceLayout([], [], 800, 400).size).toBe(0)
    const single = computeForceLayout([{ id: "solo" }], [], 800, 400)
    expect(single.get("solo")).toBeDefined()
  })
})
