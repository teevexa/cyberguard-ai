import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, render, screen, waitFor } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

vi.mock("@/lib/AuthContext", () => ({
  useAuth: () => ({ user: { id: "u1", email: "a@b.com", role: "user" } }),
}))

const list = vi.fn()
const setActive = vi.fn()
const listMembers = vi.fn()

vi.mock("@/lib/auth-client", () => ({
  orgClient: {
    organization: {
      list: (...args: unknown[]) => list(...args),
      setActive: (...args: unknown[]) => setActive(...args),
      listMembers: (...args: unknown[]) => listMembers(...args),
      create: vi.fn(),
    },
  },
}))

import { OrgProvider, useOrg } from "./OrgContext"

function Probe() {
  const { activeOrgId, activeOrgRole, isLoading, switchOrg } = useOrg()
  if (isLoading) return <div>loading</div>
  return (
    <div>
      <div data-testid="active-org">{activeOrgId}</div>
      <div data-testid="active-role">{activeOrgRole ?? "none"}</div>
      <button onClick={() => switchOrg("org-b")}>switch</button>
    </div>
  )
}

describe("OrgProvider.switchOrg", () => {
  beforeEach(() => {
    localStorage.clear()
    list.mockResolvedValue({
      data: [
        { id: "org-a", name: "Org A", slug: "org-a" },
        { id: "org-b", name: "Org B", slug: "org-b" },
      ],
    })
    setActive.mockResolvedValue({})
    listMembers.mockImplementation(({ query }: { query: { organizationId: string } }) =>
      Promise.resolve({
        data: {
          members: [
            { id: "m-a", userId: "u1", role: query.organizationId === "org-a" ? "owner" : "member" },
          ],
        },
      }),
    )
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it("invalidates every cached query so a switch can't leave stale cross-org data on screen", async () => {
    const queryClient = new QueryClient()
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries")

    render(
      <QueryClientProvider client={queryClient}>
        <OrgProvider>
          <Probe />
        </OrgProvider>
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByTestId("active-org").textContent).toBe("org-a"))
    await waitFor(() => expect(screen.getByTestId("active-role").textContent).toBe("owner"))
    invalidateSpy.mockClear()

    await act(async () => {
      screen.getByText("switch").click()
    })

    await waitFor(() => expect(screen.getByTestId("active-org").textContent).toBe("org-b"))
    expect(setActive).toHaveBeenCalledWith({ organizationId: "org-b" })
    expect(invalidateSpy).toHaveBeenCalled()
    // The org-scoped role must also flip with the switch — this is what
    // NotificationsTab/GeneralTab/SystemTab in Settings.tsx gate on now.
    await waitFor(() => expect(screen.getByTestId("active-role").textContent).toBe("member"))
  })
})
