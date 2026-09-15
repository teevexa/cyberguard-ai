import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { orgClient } from "@/lib/auth-client"
import { useAuth } from "@/lib/AuthContext"
import { getActiveOrgId, setActiveOrgId, subscribeActiveOrg } from "@/lib/activeOrg"

export interface Organization {
  id: string
  name: string
  slug: string
}

export interface OrgMember {
  id: string
  userId: string
  role: string
  user?: { email?: string }
}

interface OrgContextValue {
  organizations: Organization[]
  activeOrgId: string | null
  activeOrg: Organization | null
  isLoading: boolean
  members: OrgMember[]
  isLoadingMembers: boolean
  isMembersError: boolean
  membersError: Error | null
  /** This user's role within activeOrg ("owner" | "admin" | "member"), or
   * null while loading / if they're somehow not resolvable as a member.
   * The one place to check "can I manage this org's settings" — several
   * screens used to gate org-scoped actions on the *site-wide* role
   * instead (src/pages/Settings.tsx's NotificationsTab/GeneralTab/SystemTab),
   * which is a different permission system entirely and could show an
   * enabled button that the backend would then reject, or hide one from
   * someone who actually had access. */
  activeOrgRole: string | null
  refetchMembers: () => void
  switchOrg: (orgId: string) => Promise<void>
  createOrg: (name: string, slug: string) => Promise<{ error: string | null }>
  refetch: () => Promise<void>
}

const OrgContext = createContext<OrgContextValue | null>(null)

function slugify(name: string) {
  return name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "")
}

export function OrgProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const activeOrgId = useSyncExternalStore(subscribeActiveOrg, getActiveOrgId, () => null)

  const loadOrgs = async () => {
    if (!user) {
      setOrganizations([])
      setIsLoading(false)
      return
    }
    setIsLoading(true)
    const { data } = await orgClient.organization.list()
    const orgs = (data ?? []) as Organization[]
    setOrganizations(orgs)

    const current = getActiveOrgId()
    const stillValid = current && orgs.some((o) => o.id === current)
    if (!stillValid && orgs.length > 0) {
      setActiveOrgId(orgs[0].id)
      await orgClient.organization.setActive({ organizationId: orgs[0].id })
    } else if (orgs.length === 0) {
      setActiveOrgId(null)
    }
    setIsLoading(false)
  }

  useEffect(() => {
    loadOrgs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id])

  // Single source of truth for "who is a member of the active org, and what
  // is my role in it" — used both by the Organization settings tab's member
  // list and by every other tab that needs to know if the current user can
  // manage this org (gating org-scoped actions on the *org* role, since
  // that's what the backend actually enforces for them).
  const membersQuery = useQuery({
    queryKey: ["org-members", activeOrgId],
    queryFn: () => orgClient.organization.listMembers({ query: { organizationId: activeOrgId! } }),
    enabled: !!activeOrgId,
  })
  const members = (membersQuery.data?.data?.members ?? []) as OrgMember[]
  const activeOrgRole = membersQuery.isSuccess
    ? (members.find((m) => m.userId === user?.id)?.role ?? null)
    : null

  const switchOrg = async (orgId: string) => {
    await orgClient.organization.setActive({ organizationId: orgId })
    setActiveOrgId(orgId)
    // Every data query reads the active org from a header attached at fetch
    // time (src/lib/api.ts), not from its React Query key — so without this,
    // screens keep showing the previous org's threats/incidents/API
    // keys/webhook URLs until something else happens to trigger a refetch.
    await queryClient.invalidateQueries()
  }

  const createOrg = async (name: string, slug: string) => {
    const { data, error } = await orgClient.organization.create({ name, slug })
    if (error) return { error: error.message ?? "Failed to create organization" }
    await loadOrgs()
    if (data?.id) await switchOrg(data.id)
    return { error: null }
  }

  const activeOrg = organizations.find((o) => o.id === activeOrgId) ?? null

  return (
    <OrgContext.Provider
      value={{
        organizations,
        activeOrgId,
        activeOrg,
        isLoading,
        members,
        isLoadingMembers: membersQuery.isPending,
        isMembersError: membersQuery.isError,
        membersError: membersQuery.error as Error | null,
        activeOrgRole,
        refetchMembers: () => { membersQuery.refetch() },
        switchOrg,
        createOrg,
        refetch: loadOrgs,
      }}
    >
      {children}
    </OrgContext.Provider>
  )
}

export function useOrg() {
  const ctx = useContext(OrgContext)
  if (!ctx) throw new Error("useOrg must be used within OrgProvider")
  return ctx
}

export { slugify }
