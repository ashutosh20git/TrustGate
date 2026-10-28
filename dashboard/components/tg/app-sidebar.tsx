"use client"

import { Suspense } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { Activity, BadgeCheck, Bell, ClipboardCheck, LayoutGrid, LineChart, LogOut, ShieldCheck, Users, Zap } from "lucide-react"

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { signOut, usePaged, useTg } from "@/lib/api"
import type { Escalation, Me, Metrics } from "@/lib/types"

const WORK = [
  { href: "/", label: "Overview", icon: LayoutGrid },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/review", label: "Review queue", icon: ClipboardCheck, badge: true },
  { href: "/actions", label: "Actions taken", icon: Zap },
  { href: "/activity", label: "Activity log", icon: Activity },
]
const MORE = [
  { href: "/insights", label: "Insights", icon: LineChart },
  { href: "/compliance", label: "Compliance & tools", icon: BadgeCheck },
]
const ADMIN = { href: "/team", label: "Team", icon: Users }

function NavItems({ list, path, waiting }: { list: typeof WORK; path: string | null; waiting: number }) {
  const active = (href: string) => path !== null && (href === "/" ? path === "/" : path.startsWith(href))
  return list.map((item) => (
    <SidebarMenuItem key={item.href}>
      <SidebarMenuButton asChild isActive={active(item.href)} className="h-9 text-[14px]">
        <Link href={item.href}>
          <item.icon />
          <span>{item.label}</span>
        </Link>
      </SidebarMenuButton>
      {"badge" in item && waiting > 0 && (
        <SidebarMenuBadge className="rounded-full bg-warning/15 text-warning">{waiting}</SidebarMenuBadge>
      )}
    </SidebarMenuItem>
  ))
}

// The current path is request data, so only the highlight waits for it.
function ActiveNavItems(props: { list: typeof WORK; waiting: number }) {
  return <NavItems {...props} path={usePathname()} />
}

export function AppSidebar() {
  const { total: open } = usePaged<Escalation>("/v1/escalations?status=open&limit=1")
  const { data: metrics } = useTg<Metrics>("/v1/metrics")
  const { data: me } = useTg<Me>("/v1/me", { refreshInterval: 60_000 })
  const waiting = open ?? 0
  const items = (list: typeof WORK) => (
    <Suspense fallback={<NavItems list={list} path={null} waiting={waiting} />}>
      <ActiveNavItems list={list} waiting={waiting} />
    </Suspense>
  )

  return (
    <Sidebar variant="inset">
      <SidebarHeader className="px-3 pt-4 pb-2">
        <div className="flex items-center gap-2.5">
          <div className="flex size-8 items-center justify-center rounded-[10px] bg-primary text-primary-foreground">
            <ShieldCheck className="size-[18px]" />
          </div>
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight">TrustGate</div>
            <div className="text-xs text-muted-foreground">Action gate for AI agents</div>
          </div>
        </div>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>{items(WORK)}</SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        <SidebarGroup>
          <SidebarGroupLabel>More</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>{items(me?.role === "admin" ? [...MORE, ADMIN] : MORE)}</SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="gap-3 p-3">
        {metrics && (
          <div className="rounded-xl border bg-card px-3 py-2.5 text-xs">
            <div className="flex items-center gap-2 font-medium">
              <span className={`size-2 rounded-full ${metrics.mode === "enforce" ? "bg-success" : "bg-warning"}`} />
              {metrics.mode === "enforce" ? "Enforcing" : "Monitor only"}
            </div>
            <div className="mt-0.5 text-muted-foreground">
              Audit log {metrics.audit_chain_ok ? "intact" : "BROKEN"} · {metrics.pack} policy
            </div>
          </div>
        )}
        {me && (
          <div className="px-2 text-xs text-muted-foreground">
            Signed in as <span className="font-medium text-foreground">{me.name}</span>
            {me.role === "admin" && " · Admin"}
          </div>
        )}
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={signOut} className="h-9 text-muted-foreground">
              <LogOut />
              <span>Sign out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}
