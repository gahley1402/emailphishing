import { createFileRoute, redirect } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { toast } from "sonner";
import { Trash2, Plus, Users, ListChecks, Globe } from "lucide-react";
import { ClassBadge } from "./dashboard";

export const Route = createFileRoute("/_authenticated/admin")({
  head: () => ({ meta: [{ title: "Admin Panel · EmailShield" }] }),
  beforeLoad: async () => {
    const { data: u } = await supabase.auth.getUser();
    if (!u.user) throw redirect({ to: "/auth" });
    const { data: role } = await supabase.from("user_roles").select("role").eq("user_id", u.user.id).eq("role", "admin").maybeSingle();
    if (!role) throw redirect({ to: "/dashboard" });
  },
  component: AdminPage,
});

function AdminPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          Admin Panel
          <span className="text-[10px] uppercase tracking-widest border border-destructive/40 text-destructive rounded px-1.5 py-0.5">Restricted</span>
        </h1>
        <p className="text-sm text-muted-foreground">Manage detection rules, threat intelligence, users, and global scan history.</p>
      </div>

      <Tabs defaultValue="keywords">
        <TabsList>
          <TabsTrigger value="keywords"><ListChecks className="h-4 w-4 mr-1" /> Keywords</TabsTrigger>
          <TabsTrigger value="blacklist"><Globe className="h-4 w-4 mr-1" /> Blacklist</TabsTrigger>
          <TabsTrigger value="users"><Users className="h-4 w-4 mr-1" /> Users</TabsTrigger>
          <TabsTrigger value="all-scans">All Scans</TabsTrigger>
        </TabsList>
        <TabsContent value="keywords"><KeywordsPanel /></TabsContent>
        <TabsContent value="blacklist"><BlacklistPanel /></TabsContent>
        <TabsContent value="users"><UsersPanel /></TabsContent>
        <TabsContent value="all-scans"><AllScansPanel /></TabsContent>
      </Tabs>
    </div>
  );
}

function KeywordsPanel() {
  const qc = useQueryClient();
  const [keyword, setKeyword] = useState(""); const [weight, setWeight] = useState(10);
  const { data = [] } = useQuery({
    queryKey: ["adm-kw"],
    queryFn: async () => (await supabase.from("suspicious_keywords").select("*").order("keyword")).data || [],
  });
  async function add() {
    if (!keyword.trim()) return;
    const { error } = await supabase.from("suspicious_keywords").insert({ keyword: keyword.trim().toLowerCase(), weight });
    if (error) toast.error(error.message); else { setKeyword(""); qc.invalidateQueries({ queryKey: ["adm-kw"] }); qc.invalidateQueries({ queryKey: ["rules"] }); }
  }
  async function del(id: string) {
    const { error } = await supabase.from("suspicious_keywords").delete().eq("id", id);
    if (error) toast.error(error.message); else { qc.invalidateQueries({ queryKey: ["adm-kw"] }); qc.invalidateQueries({ queryKey: ["rules"] }); }
  }
  return (
    <div className="mt-4 rounded-xl border border-border bg-[var(--gradient-card)] p-5">
      <div className="flex gap-2 mb-4">
        <Input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="suspicious keyword (e.g. 'reset password')" maxLength={100} />
        <Input type="number" value={weight} onChange={(e) => setWeight(parseInt(e.target.value) || 10)} className="w-24" min={1} max={50} />
        <Button onClick={add}><Plus className="h-4 w-4 mr-1" /> Add</Button>
      </div>
      <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-2">
        {data.map((k) => (
          <div key={k.id} className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2 text-sm">
            <span><span className="font-mono">{k.keyword}</span> <span className="text-xs text-muted-foreground">+{k.weight}</span></span>
            <button onClick={() => del(k.id)} className="text-muted-foreground hover:text-destructive"><Trash2 className="h-4 w-4" /></button>
          </div>
        ))}
      </div>
    </div>
  );
}

function BlacklistPanel() {
  const qc = useQueryClient();
  const [domain, setDomain] = useState(""); const [reason, setReason] = useState("");
  const { data = [] } = useQuery({
    queryKey: ["adm-bl"],
    queryFn: async () => (await supabase.from("blacklisted_domains").select("*").order("domain")).data || [],
  });
  async function add() {
    if (!domain.trim()) return;
    const { error } = await supabase.from("blacklisted_domains").insert({ domain: domain.trim().toLowerCase(), reason: reason || null });
    if (error) toast.error(error.message); else { setDomain(""); setReason(""); qc.invalidateQueries({ queryKey: ["adm-bl"] }); qc.invalidateQueries({ queryKey: ["rules"] }); }
  }
  async function del(id: string) {
    const { error } = await supabase.from("blacklisted_domains").delete().eq("id", id);
    if (error) toast.error(error.message); else { qc.invalidateQueries({ queryKey: ["adm-bl"] }); qc.invalidateQueries({ queryKey: ["rules"] }); }
  }
  return (
    <div className="mt-4 rounded-xl border border-border bg-[var(--gradient-card)] p-5">
      <div className="flex flex-wrap gap-2 mb-4">
        <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="paypa1.com" className="max-w-xs" />
        <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason (optional)" className="max-w-sm" />
        <Button onClick={add}><Plus className="h-4 w-4 mr-1" /> Add</Button>
      </div>
      <div className="space-y-1">
        {data.map((b) => (
          <div key={b.id} className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2 text-sm">
            <div><span className="font-mono">{b.domain}</span> {b.reason && <span className="text-xs text-muted-foreground ml-2">— {b.reason}</span>}</div>
            <button onClick={() => del(b.id)} className="text-muted-foreground hover:text-destructive"><Trash2 className="h-4 w-4" /></button>
          </div>
        ))}
      </div>
    </div>
  );
}

function UsersPanel() {
  const { data = [] } = useQuery({
    queryKey: ["adm-users"],
    queryFn: async () => {
      const [profiles, roles] = await Promise.all([
        supabase.from("profiles").select("id,email,display_name,created_at"),
        supabase.from("user_roles").select("user_id,role"),
      ]);
      const roleMap = new Map<string, string[]>();
      for (const r of roles.data || []) {
        const arr = roleMap.get(r.user_id) || []; arr.push(r.role); roleMap.set(r.user_id, arr);
      }
      return (profiles.data || []).map((p) => ({ ...p, roles: roleMap.get(p.id) || [] }));
    },
  });
  return (
    <div className="mt-4 rounded-xl border border-border bg-[var(--gradient-card)] p-5 overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs uppercase tracking-widest text-muted-foreground border-b border-border">
          <th className="py-2">Email</th><th>Name</th><th>Roles</th><th>Joined</th>
        </tr></thead>
        <tbody>
          {data.map((u) => (
            <tr key={u.id} className="border-b border-border/40">
              <td className="py-3">{u.email}</td>
              <td className="py-3 text-muted-foreground">{u.display_name || "—"}</td>
              <td className="py-3">{u.roles.map((r) => (
                <span key={r} className={`text-[10px] uppercase tracking-widest mr-1 px-1.5 py-0.5 rounded ${r === "admin" ? "bg-destructive/20 text-destructive" : "bg-muted text-muted-foreground"}`}>{r}</span>
              ))}</td>
              <td className="py-3 text-muted-foreground">{new Date(u.created_at).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AllScansPanel() {
  const { data = [] } = useQuery({
    queryKey: ["adm-scans"],
    queryFn: async () => (await supabase.from("scan_history").select("id,subject,sender,classification,risk_score,created_at,user_id").order("created_at", { ascending: false }).limit(200)).data || [],
  });
  return (
    <div className="mt-4 rounded-xl border border-border bg-[var(--gradient-card)] p-5 overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs uppercase tracking-widest text-muted-foreground border-b border-border">
          <th className="py-2 pr-4">Subject</th><th className="pr-4">Sender</th><th className="pr-4">Score</th><th className="pr-4">Class</th><th>Date</th>
        </tr></thead>
        <tbody>
          {data.map((r) => (
            <tr key={r.id} className="border-b border-border/40">
              <td className="py-3 pr-4 max-w-xs truncate">{r.subject || "—"}</td>
              <td className="py-3 pr-4 text-muted-foreground max-w-xs truncate">{r.sender || "—"}</td>
              <td className="py-3 pr-4 font-mono">{r.risk_score}</td>
              <td className="py-3 pr-4"><ClassBadge c={r.classification as "safe" | "suspicious" | "phishing"} /></td>
              <td className="py-3 text-muted-foreground whitespace-nowrap">{new Date(r.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}