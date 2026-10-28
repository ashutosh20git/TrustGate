import { AppSidebar } from "@/components/tg/app-sidebar"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"

export default function AppLayout({ children }: LayoutProps<"/">) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-12 items-center px-4 md:hidden">
          <SidebarTrigger />
        </header>
        <div className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-8 sm:py-10">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  )
}
