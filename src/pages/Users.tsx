import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { MetricCard } from "@/components/MetricCard"
import { Users as UsersIcon, Shield, ShieldOff, Search, Lock } from "lucide-react"
import { LoadingState, ErrorState } from "@/components/QueryState"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api, ApiError, type UserDto } from "@/lib/api"
import { toast } from "@/hooks/use-toast"
import { useAuth } from "@/lib/AuthContext"

// Not using the shadcn "secondary" variant for SecurityAnalyst: in this
// theme's dark mode, --secondary and --destructive resolve to the exact same
// red (0 84% 55%), which would make it visually indistinguishable from Admin.
function RoleBadge({ role }: { role: string }) {
  if (role === "Admin") return <Badge variant="destructive">{role}</Badge>
  if (role === "SecurityAnalyst") return <Badge className="bg-warning text-white border-transparent">{role}</Badge>
  return <Badge variant="outline">{role}</Badge>
}

function UserDirectory() {
  const { data, isPending, isError, error } = useQuery({ queryKey: ["users"], queryFn: api.users })
  const { user: me } = useAuth()
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState("")
  const [roleFilter, setRoleFilter] = useState("all")

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["users"] })

  const updateRole = useMutation({
    mutationFn: (p: { id: string; role: string }) => api.updateUserRole(p.id, p.role),
    onSuccess: () => { invalidate(); toast({ title: "Role updated" }) },
    onError: (err: ApiError) => toast({ title: "Couldn't update role", description: err.message, variant: "destructive" }),
  })

  const updateBan = useMutation({
    mutationFn: (p: { id: string; banned: boolean }) => api.updateUserBan(p.id, p.banned),
    onSuccess: (_res, vars) => { invalidate(); toast({ title: vars.banned ? "User suspended" : "User reinstated" }) },
    onError: (err: ApiError) => toast({ title: "Couldn't update user", description: err.message, variant: "destructive" }),
  })

  if (isPending) return <LoadingState label="Loading users…" />
  if (isError) return <ErrorState message={(error as Error).message} />

  const filtered = data.filter((u) => {
    const matchesSearch = u.email.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesRole = roleFilter === "all" || u.role === roleFilter
    return matchesSearch && matchesRole
  })

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <MetricCard title="Total Users" value={data.length} icon={UsersIcon} variant="default" />
        <MetricCard title="Admins" value={data.filter((u) => u.role === "Admin").length} icon={Shield} variant="success" />
        <MetricCard title="Suspended" value={data.filter((u) => u.banned).length} icon={ShieldOff} variant="warning" />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>User Directory</CardTitle>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search by email..." className="pl-8 w-64" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
            </div>
            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Filter by role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                <SelectItem value="Admin">Admin</SelectItem>
                <SelectItem value="SecurityAnalyst">Security Analyst</SelectItem>
                <SelectItem value="user">User</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Joined</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <Avatar className="h-8 w-8">
                        <AvatarFallback>{u.email[0].toUpperCase()}</AvatarFallback>
                      </Avatar>
                      <p className="font-medium">{u.email}</p>
                      {u.id === me?.id && <Badge variant="outline" className="text-xs">You</Badge>}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Select
                      value={u.role}
                      onValueChange={(role) => updateRole.mutate({ id: u.id, role })}
                      disabled={u.id === me?.id || updateRole.isPending}
                    >
                      <SelectTrigger className="w-40" title={u.id === me?.id ? "You can't change your own role" : undefined}>
                        <RoleBadge role={u.role} />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Admin">Admin</SelectItem>
                        <SelectItem value="SecurityAnalyst">Security Analyst</SelectItem>
                        <SelectItem value="user">User</SelectItem>
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell>
                    <Badge variant={u.banned ? "destructive" : "default"}>{u.banned ? "Suspended" : "Active"}</Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{new Date(u.created_at).toLocaleDateString()}</TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={u.id === me?.id || updateBan.isPending}
                      onClick={() => updateBan.mutate({ id: u.id, banned: !u.banned })}
                      title={u.id === me?.id ? "You can't suspend your own account" : undefined}
                    >
                      {u.banned ? "Reinstate" : "Suspend"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </>
  )
}

export default function Users() {
  const { user } = useAuth()

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">User Management</h1>
        <p className="text-muted-foreground">Real users signed up via Neon Auth — roles and suspension are enforced, not decorative</p>
      </div>

      {user?.role !== "Admin" ? (
        <Card>
          <CardContent className="pt-6 text-center space-y-2">
            <Lock className="h-10 w-10 mx-auto text-muted-foreground" />
            <p className="font-medium">Admin access required</p>
            <p className="text-sm text-muted-foreground">You're signed in as "{user?.role ?? "unknown"}" — user management is Admin-only.</p>
          </CardContent>
        </Card>
      ) : (
        <Tabs defaultValue="users" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="users">Users</TabsTrigger>
            <TabsTrigger value="permissions">Permissions</TabsTrigger>
          </TabsList>

          <TabsContent value="users" className="space-y-6">
            <UserDirectory />
          </TabsContent>

          <TabsContent value="permissions" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Role-Based Access Control</CardTitle>
                <p className="text-sm text-muted-foreground">
                  What's actually enforced in the backend today — two tiers, not the three the role dropdown might suggest.
                  "Security Analyst" is available as a role label for your own organizational use, but doesn't currently
                  grant different API access than "User"; every authenticated user can view the dashboard, triage threats,
                  and manage incidents. Only Admin is a distinct, enforced tier.
                </p>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Card>
                    <CardHeader><CardTitle className="text-lg">Admin</CardTitle></CardHeader>
                    <CardContent className="space-y-2">
                      {["Dashboard, threats, incidents, AI triage", "Manage notification settings", "Manage users & roles, suspend accounts", "Ingest API key configuration"].map((p) => (
                        <div key={p} className="flex items-center justify-between">
                          <span className="text-sm">{p}</span>
                          <Badge variant="default">✓</Badge>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle className="text-lg">User / Security Analyst</CardTitle></CardHeader>
                    <CardContent className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Dashboard, threats, incidents, AI triage</span>
                        <Badge variant="default">✓</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Manage notification settings</span>
                        <Badge variant="secondary">✗</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Manage users & roles</span>
                        <Badge variant="secondary">✗</Badge>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
