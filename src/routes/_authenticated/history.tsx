import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";
import { ScanTable } from "./dashboard";

export const Route = createFileRoute("/_authenticated/history")({
  head: () => ({ meta: [{ title: "Scan History · PhishGuard" }] }),
  component: HistoryPage,
});

function HistoryPage() {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const { data = [], isLoading } = useQuery({
    queryKey: ["history"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("scan_history")
        .select("id,subject,sender,classification,risk_score,created_at")
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data;
    },
  });

  const filtered = data.filter((r) => {
    if (!q) return true;
    const s = q.toLowerCase();
    return (r.subject || "").toLowerCase().includes(s) || (r.sender || "").toLowerCase().includes(s);
  });

  async function clearAll() {
    if (!confirm("Delete all your scan history? This cannot be undone.")) return;
    const { data: u } = await supabase.auth.getUser();
    if (!u.user) return;
    const { error } = await supabase.from("scan_history").delete().eq("user_id", u.user.id);
    if (error) toast.error(error.message); else { toast.success("History cleared"); qc.invalidateQueries({ queryKey: ["history"] }); qc.invalidateQueries({ queryKey: ["scans","mine"] }); }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scan History</h1>
          <p className="text-sm text-muted-foreground">All emails you have analyzed.</p>
        </div>
        <div className="flex gap-2">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search subject or sender…" className="w-64" />
          <Button variant="outline" onClick={clearAll}><Trash2 className="h-4 w-4 mr-1" /> Clear</Button>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
        {isLoading ? <div className="text-sm text-muted-foreground">Loading…</div> :
          filtered.length === 0 ? <div className="text-sm text-muted-foreground py-10 text-center">No scans match.</div> :
          <ScanTable rows={filtered} />}
      </div>
    </div>
  );
}