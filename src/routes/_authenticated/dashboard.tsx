import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { ShieldCheck, AlertTriangle, Skull, ScanSearch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard · PhishGuard" }] }),
  component: Dashboard,
});

type Row = {
  id: string;
  subject: string | null;
  sender: string | null;
  classification: "safe" | "suspicious" | "phishing";
  risk_score: number;
  created_at: string;
};

function useScans() {
  return useQuery({
    queryKey: ["scans", "mine"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("scan_history")
        .select("id,subject,sender,classification,risk_score,created_at")
        .order("created_at", { ascending: false })
        .limit(200);
      if (error) throw error;
      return data as Row[];
    },
  });
}

function Dashboard() {
  const { data = [], isLoading } = useScans();
  const total = data.length;
  const safe = data.filter((r) => r.classification === "safe").length;
  const suspicious = data.filter((r) => r.classification === "suspicious").length;
  const phishing = data.filter((r) => r.classification === "phishing").length;
  const recent = data.slice(0, 6);

  // Trend: count per day for last 7 days
  const days = Array.from({ length: 7 }).map((_, i) => {
    const d = new Date(); d.setDate(d.getDate() - (6 - i));
    const key = d.toISOString().slice(0, 10);
    return {
      key,
      label: d.toLocaleDateString(undefined, { weekday: "short" }),
      safe: 0, suspicious: 0, phishing: 0,
    };
  });
  for (const r of data) {
    const k = r.created_at.slice(0, 10);
    const bucket = days.find((d) => d.key === k);
    if (bucket) bucket[r.classification] += 1;
  }

  const pie = [
    { name: "Safe", value: safe, color: "var(--success)" },
    { name: "Suspicious", value: suspicious, color: "var(--warning)" },
    { name: "Phishing", value: phishing, color: "var(--destructive)" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Threat Console</h1>
          <p className="text-sm text-muted-foreground">Overview of your phishing detection activity.</p>
        </div>
        <Link to="/scan"><Button><ScanSearch className="h-4 w-4 mr-2" /> New Scan</Button></Link>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Emails Scanned" value={total} icon={ShieldCheck} accent="primary" />
        <StatCard label="Safe" value={safe} icon={ShieldCheck} accent="success" />
        <StatCard label="Suspicious" value={suspicious} icon={AlertTriangle} accent="warning" />
        <StatCard label="Phishing" value={phishing} icon={Skull} accent="destructive" />
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl border border-border bg-[var(--gradient-card)] p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold">Scan Activity</h3>
              <p className="text-xs text-muted-foreground">Last 7 days</p>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={days} stackOffset="none">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="label" stroke="var(--muted-foreground)" fontSize={12} />
                <YAxis stroke="var(--muted-foreground)" fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8 }} />
                <Bar dataKey="safe" stackId="a" fill="var(--success)" />
                <Bar dataKey="suspicious" stackId="a" fill="var(--warning)" />
                <Bar dataKey="phishing" stackId="a" fill="var(--destructive)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
          <h3 className="font-semibold mb-4">Risk Distribution</h3>
          {total === 0 ? (
            <div className="text-sm text-muted-foreground h-64 flex items-center justify-center text-center">
              Run your first scan to see analytics here.
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={pie} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={4} stroke="none">
                    {pie.map((p) => <Cell key={p.name} fill={p.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Recent Scans</h3>
          <Link to="/history" className="text-xs text-primary hover:underline">View all →</Link>
        </div>
        {isLoading ? <Skeleton /> : recent.length === 0 ? (
          <EmptyState />
        ) : (
          <ScanTable rows={recent} />
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, accent }: { label: string; value: number; icon: React.ComponentType<{ className?: string }>; accent: "primary" | "success" | "warning" | "destructive" }) {
  const colorVar = `var(--${accent === "primary" ? "primary" : accent})`;
  return (
    <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-4 relative overflow-hidden">
      <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full blur-2xl opacity-30" style={{ background: colorVar }} />
      <div className="relative">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-widest text-muted-foreground">{label}</span>
          <Icon className="h-4 w-4" />
        </div>
        <div className="text-3xl font-bold mt-2 tabular-nums" style={{ color: colorVar }}>{value}</div>
      </div>
    </div>
  );
}

export function ScanTable({ rows }: { rows: Row[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase tracking-widest text-muted-foreground border-b border-border">
            <th className="py-2 pr-4">Subject</th>
            <th className="py-2 pr-4">Sender</th>
            <th className="py-2 pr-4">Score</th>
            <th className="py-2 pr-4">Class</th>
            <th className="py-2 pr-4">Date</th>
            <th className="py-2"></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-border/50 hover:bg-accent/30">
              <td className="py-3 pr-4 max-w-xs truncate">{r.subject || "(no subject)"}</td>
              <td className="py-3 pr-4 text-muted-foreground max-w-xs truncate">{r.sender || "—"}</td>
              <td className="py-3 pr-4 font-mono tabular-nums">{r.risk_score}</td>
              <td className="py-3 pr-4"><ClassBadge c={r.classification} /></td>
              <td className="py-3 pr-4 text-muted-foreground whitespace-nowrap">{new Date(r.created_at).toLocaleString()}</td>
              <td className="py-3 text-right"><Link to="/report/$id" params={{ id: r.id }} className="text-primary hover:underline">Report →</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ClassBadge({ c }: { c: "safe" | "suspicious" | "phishing" }) {
  const color = c === "safe" ? "var(--success)" : c === "suspicious" ? "var(--warning)" : "var(--destructive)";
  const label = c === "safe" ? "Safe" : c === "suspicious" ? "Suspicious" : "Phishing";
  return (
    <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider" style={{ background: `color-mix(in oklab, ${color} 18%, transparent)`, color }}>
      {label}
    </span>
  );
}

function Skeleton() {
  return <div className="space-y-2">{[0,1,2].map(i => <div key={i} className="h-10 rounded bg-muted/50 animate-pulse" />)}</div>;
}

function EmptyState() {
  return (
    <div className="text-center py-10">
      <ShieldCheck className="h-10 w-10 mx-auto text-muted-foreground" />
      <p className="mt-3 text-sm text-muted-foreground">No scans yet.</p>
      <Link to="/scan" className="text-primary text-sm hover:underline">Run your first scan</Link>
    </div>
  );
}

// Hide unused warning
void useEffect; void useState;