import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { RiskMeter } from "@/components/RiskMeter";
import { ArrowLeft, Download, ShieldCheck } from "lucide-react";
import jsPDF from "jspdf";
import type { Finding } from "@/lib/detection-engine";

export const Route = createFileRoute("/_authenticated/report/$id")({
  head: () => ({ meta: [{ title: "Detection Report · EmailShield" }] }),
  component: ReportPage,
});

function ReportPage() {
  const { id } = Route.useParams();
  const { data, isLoading, error } = useQuery({
    queryKey: ["scan", id],
    queryFn: async () => {
      const { data, error } = await supabase.from("scan_history").select("*").eq("id", id).single();
      if (error) throw error;
      return data;
    },
  });

  if (isLoading) return <div className="text-sm text-muted-foreground">Loading report…</div>;
  if (error || !data) return <div className="text-sm text-destructive">Report not found.</div>;

  const scan = data;
  const findings = (data.findings as unknown as Finding[]) || [];
  const details = (data.details as Record<string, unknown>) || {};
  const classification = data.classification as "safe" | "suspicious" | "phishing";

  const recommendation =
    classification === "phishing"
      ? "Do NOT click any links, do NOT open attachments, and do NOT reply. Report this email to your IT/security team and delete it. If you already entered credentials, change your password immediately and enable MFA."
      : classification === "suspicious"
      ? "Treat this email with caution. Verify the sender through a known channel (phone, official website) before clicking links or opening attachments. Do not provide credentials or payment information."
      : "No high-confidence phishing indicators were detected by the current rule set. Continue to apply normal email vigilance — rules are not a substitute for judgement.";

  function exportPdf() {
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const W = doc.internal.pageSize.getWidth();
    let y = 48;
    doc.setFillColor(99, 102, 241); doc.rect(0, 0, W, 8, "F");
    doc.setFontSize(20); doc.text("EmailShield — Detection Report", 48, y); y += 14;
    doc.setFontSize(10); doc.setTextColor(110); doc.text(new Date(scan.created_at).toLocaleString(), 48, y); y += 24;
    doc.setTextColor(20); doc.setFontSize(12);
    doc.text(`Classification: ${classification.toUpperCase()}    Score: ${scan.risk_score}/100`, 48, y); y += 22;
    doc.setFontSize(11);
    const head = [
      ["Sender", scan.sender || "—"],
      ["Subject", scan.subject || "(no subject)"],
      ["Sender Domain", String(details.senderDomain ?? "—")],
      ["Return-Path", String(details.returnPath ?? "—")],
    ];
    for (const [k, v] of head) {
      doc.setFont("helvetica", "bold"); doc.text(`${k}:`, 48, y);
      doc.setFont("helvetica", "normal"); doc.text(doc.splitTextToSize(v, W - 160), 140, y);
      y += 18;
    }
    y += 8;
    doc.setFont("helvetica", "bold"); doc.text("Threat Indicators", 48, y); y += 14;
    doc.setFont("helvetica", "normal");
    if (findings.length === 0) { doc.text("No indicators found.", 48, y); y += 16; }
    for (const f of findings) {
      if (y > 760) { doc.addPage(); y = 48; }
      doc.setFont("helvetica", "bold"); doc.text(`• ${f.title} (+${f.weight})`, 48, y); y += 14;
      doc.setFont("helvetica", "normal");
      const lines = doc.splitTextToSize(f.detail, W - 96);
      doc.text(lines, 60, y); y += lines.length * 12 + 6;
    }
    y += 8;
    if (y > 700) { doc.addPage(); y = 48; }
    doc.setFont("helvetica", "bold"); doc.text("Recommended Actions", 48, y); y += 14;
    doc.setFont("helvetica", "normal");
    const recLines = doc.splitTextToSize(recommendation, W - 96);
    doc.text(recLines, 48, y);
    doc.save(`EmailShield-report-${id.slice(0, 8)}.pdf`);
  }

  return (
    <div className="space-y-6 print:bg-white">
      <div className="flex items-center justify-between print:hidden">
        <Link to="/history" className="text-sm text-muted-foreground hover:text-foreground inline-flex items-center"><ArrowLeft className="h-4 w-4 mr-1" /> Back to history</Link>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => window.print()}>Print</Button>
          <Button onClick={exportPdf}><Download className="h-4 w-4 mr-2" /> Export PDF</Button>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-6">
        <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-muted-foreground"><ShieldCheck className="h-4 w-4 text-primary" /> Detection Report</div>
        <div className="mt-1 text-sm text-muted-foreground">{new Date(data.created_at).toLocaleString()}</div>
        <h1 className="mt-2 text-2xl font-bold">{data.subject || "(no subject)"}</h1>
        <div className="text-sm text-muted-foreground mt-1">From: <span className="text-foreground">{data.sender || "—"}</span></div>
        <div className="mt-6"><RiskMeter score={data.risk_score} classification={classification} /></div>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
          <h3 className="font-semibold mb-3">Email Summary</h3>
          <dl className="text-sm space-y-2">
            <Row k="Sender Domain" v={String(details.senderDomain ?? "—")} />
            <Row k="Return-Path" v={String(details.returnPath ?? "—")} />
            <Row k="Links" v={String((details.links as unknown[] | undefined)?.length ?? 0)} />
            <Row k="Attachments" v={String((details.attachments as unknown[] | undefined)?.length ?? 0)} />
          </dl>
        </div>
        <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
          <h3 className="font-semibold mb-3">Recommended Actions</h3>
          <p className="text-sm text-muted-foreground">{recommendation}</p>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
        <h3 className="font-semibold mb-3">Threat Indicators ({findings.length})</h3>
        {findings.length === 0 ? (
          <div className="text-sm text-muted-foreground">No indicators found by the current rule set.</div>
        ) : (
          <ul className="space-y-2">
            {findings.map((f, i) => (
              <li key={i} className="rounded-md border border-border/60 p-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-xs uppercase tracking-widest text-muted-foreground">{f.category}</div>
                    <div className="font-medium text-sm">{f.title}</div>
                    <div className="text-xs text-muted-foreground mt-1 break-all">{f.detail}</div>
                  </div>
                  <span className="text-xs font-mono shrink-0 ml-3 text-primary">+{f.weight}</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-border/40 py-1.5">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="text-foreground text-right break-all">{v}</dd>
    </div>
  );
}