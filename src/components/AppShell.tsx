import { Link, useRouter, useRouterState } from "@tanstack/react-router";
import { ShieldCheck, LayoutDashboard, ScanSearch, History, Settings2, LogOut, Skull } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth, useIsAdmin } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import type { ReactNode } from "react";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan", label: "Scan Email", icon: ScanSearch },
  { to: "/history", label: "Scan History", icon: History },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { isAdmin } = useIsAdmin(user?.id);
  const router = useRouter();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  async function signOut() {
    await supabase.auth.signOut();
    router.navigate({ to: "/auth", replace: true });
  }

  return (
    <div className="min-h-screen flex">
      <aside className="hidden md:flex w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar/80 backdrop-blur">
        <div className="flex items-center gap-2 px-5 py-5 border-b border-sidebar-border">
          <div className="relative">
            <div className="absolute inset-0 blur-md bg-primary/50" />
            <ShieldCheck className="relative h-7 w-7 text-primary" />
          </div>
          <div className="leading-tight">
            <div className="font-semibold text-sidebar-foreground">PhishGuard</div>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Threat Console</div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map((n) => {
            const active = pathname.startsWith(n.to);
            const Icon = n.icon;
            return (
              <Link
                key={n.to}
                to={n.to}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-[var(--glow-primary)]"
                    : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
                }`}
              >
                <Icon className="h-4 w-4" />
                {n.label}
              </Link>
            );
          })}
          {isAdmin && (
            <Link
              to="/admin"
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                pathname.startsWith("/admin")
                  ? "bg-destructive/20 text-destructive shadow-[var(--glow-danger)]"
                  : "text-destructive/80 hover:bg-destructive/10"
              }`}
            >
              <Settings2 className="h-4 w-4" />
              Admin Panel
            </Link>
          )}
        </nav>
        <div className="px-3 py-4 border-t border-sidebar-border space-y-2">
          <div className="px-2 text-xs">
            <div className="text-sidebar-foreground/90 truncate">{user?.email}</div>
            <div className="text-muted-foreground">{isAdmin ? "Administrator" : "Analyst"}</div>
          </div>
          <Button variant="ghost" size="sm" className="w-full justify-start" onClick={signOut}>
            <LogOut className="h-4 w-4 mr-2" /> Sign out
          </Button>
        </div>
      </aside>

      <main className="flex-1 min-w-0">
        <header className="md:hidden flex items-center justify-between border-b border-border px-4 py-3">
          <Link to="/dashboard" className="flex items-center gap-2">
            <Skull className="h-5 w-5 text-primary" />
            <span className="font-semibold">PhishGuard</span>
          </Link>
          <Button variant="ghost" size="sm" onClick={signOut}>
            <LogOut className="h-4 w-4" />
          </Button>
        </header>
        <div className="p-4 md:p-8 max-w-7xl mx-auto">{children}</div>
      </main>
    </div>
  );
}