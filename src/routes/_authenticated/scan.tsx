import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { parseEml, parsePlainText } from "@/lib/eml-parser";
import { runDetection, type ScanResult } from "@/lib/detection-engine";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { RiskMeter } from "@/components/RiskMeter";
import { toast } from "sonner";
import { Upload, ScanSearch, AlertTriangle, Mail, Link2, Paperclip, FileWarning } from "lucide-react";

export const Route = createFileRoute("/_authenticated/scan")({
  head: () => ({ meta: [{ title: "Scan Email · EmailShield" }] }),
  component: ScanPage,
});

const SAMPLE = `From: "PayPal Security" <security@paypa1.com>
Return-Path: <bounce@suspicious-mailer.ru>
Subject: URGENT: Verify Account or service will be suspended
Authentication-Results: spf=fail dkim=fail dmarc=fail

Dear customer,

We detected unusual activity on your account. You must verify your identity immediately
or your account will be suspended within 24 hours.

Click here to login immediately: http://192.168.1.45/paypal-login

Or use this secure link: https://bit.ly/3xPhish

Thank you,
PayPal Security Team`;

function useRules() {
  return useQuery({
    queryKey: ["rules"],
    queryFn: async () => {
      const [k, b] = await Promise.all([
        supabase.from("suspicious_keywords").select("keyword,weight"),
        supabase.from("blacklisted_domains").select("domain,reason"),
      ]);
      return {
        keywords: (k.data || []) as { keyword: string; weight: number }[],
        blacklist: (b.data || []) as { domain: string; reason: string | null }[],
      };
    },
  });
}

function ScanPage() {
  const router = useRouter();
  const fileRef = useRef<HTMLInputElement>(null);
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [saving, setSaving] = useState(false);
  const { data: rules } = useRules();

  function scanText(text: string, isEml: boolean) {
    if (!rules) { toast.error("Rule database still loading"); return; }
    if (!text.trim()) { toast.error("Nothing to scan"); return; }
    const parsed = isEml ? parseEml(text) : parsePlainText(text);
    const r = runDetection(parsed, rules);
    setResult(r);
  }

  function onFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || "");
      setRaw(text);
      scanText(text, file.name.toLowerCase().endsWith(".eml"));
    };
    reader.readAsText(file);
  }

  async function saveScan() {
    if (!result) return;
    setSaving(true);
    try {
      const { data: userData } = await supabase.auth.getUser();
      if (!userData.user) throw new Error("Not signed in");
      const { data, error } = await supabase.from("scan_history").insert({
        user_id: userData.user.id,
        subject: result.email.subject,
        sender: result.email.sender,
        classification: result.classification,
        risk_score: result.score,
        email_preview: result.email.body.slice(0, 2000),
        findings: result.findings as unknown as never,
        details: {
          senderDomain: result.email.senderDomain,
          returnPath: result.email.returnPath,
          links: result.email.links.slice(0, 50),
          attachments: result.email.attachments,
          headers: result.email.headers,
        } as unknown as never,
      }).select("id").single();
      if (error) throw error;
      toast.success("Scan saved");
      router.navigate({ to: "/report/$id", params: { id: data.id } });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not save scan");
    } finally { setSaving(false); }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Email Scanner</h1>
        <p className="text-sm text-muted-foreground">Paste an email, or upload a <code className="text-primary">.txt</code> / <code className="text-primary">.eml</code> file.</p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
          <Tabs defaultValue="paste">
            <TabsList>
              <TabsTrigger value="paste">Paste</TabsTrigger>
              <TabsTrigger value="upload">Upload</TabsTrigger>
            </TabsList>
            <TabsContent value="paste" className="mt-4 space-y-3">
              <Textarea
                rows={16} value={raw} onChange={(e) => setRaw(e.target.value)}
                placeholder="Paste full email here (with or without headers)..."
                className="font-mono text-xs"
              />
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => scanText(raw, /^(from|received|return-path|authentication-results):/im.test(raw))}>
                  <ScanSearch className="h-4 w-4 mr-2" /> Run Detection
                </Button>
                <Button variant="outline" onClick={() => { setRaw(SAMPLE); scanText(SAMPLE, true); }}>
                  Try a phishing sample
                </Button>
                <Button variant="ghost" onClick={() => { setRaw(""); setResult(null); }}>Clear</Button>
              </div>
            </TabsContent>
            <TabsContent value="upload" className="mt-4">
              <label
                onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) onFile(f); }}
                onDragOver={(e) => e.preventDefault()}
                className="block border-2 border-dashed border-border rounded-lg p-10 text-center cursor-pointer hover:border-primary/60 transition"
              >
                <Upload className="h-8 w-8 mx-auto text-muted-foreground" />
                <div className="mt-3 text-sm">Drop <code>.eml</code> or <code>.txt</code> here</div>
                <div className="text-xs text-muted-foreground">or click to select</div>
                <input ref={fileRef} type="file" accept=".eml,.txt,message/rfc822,text/plain" className="hidden"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); }} />
              </label>
            </TabsContent>
          </Tabs>
        </div>

        <div className="rounded-xl border border-border bg-[var(--gradient-card)] p-5">
          {!result ? (
            <div className="h-full min-h-[300px] flex flex-col items-center justify-center text-center text-muted-foreground">
              <ScanSearch className="h-10 w-10" />
              <p className="mt-3 text-sm">Detection results will appear here.</p>
            </div>
          ) : (
            <ResultPanel result={result} onSave={saveScan} saving={saving} />
          )}
        </div>
      </div>
    </div>
  );
}

function ResultPanel({ result, onSave, saving }: { result: ScanResult; onSave: () => void; saving: boolean }) {
  const grouped = {
    keyword: result.findings.filter(f => f.category === "keyword"),
    sender: result.findings.filter(f => f.category === "sender"),
    url: result.findings.filter(f => f.category === "url"),
    attachment: result.findings.filter(f => f.category === "attachment"),
    header: result.findings.filter(f => f.category === "header"),
  };
  return (
    <div className="space-y-5">
      <RiskMeter score={result.score} classification={result.classification} />

      <div className="grid grid-cols-2 gap-3 text-xs">
        <Field label="Sender" value={result.email.sender || "—"} />
        <Field label="Domain" value={result.email.senderDomain || "—"} />
        <Field label="Subject" value={result.email.subject} />
        <Field label="Return-Path" value={result.email.returnPath || "—"} />
      </div>

      <div className="grid grid-cols-3 gap-2 text-xs">
        <Mini icon={Link2} label="Links" value={result.email.links.length} />
        <Mini icon={Paperclip} label="Attachments" value={result.email.attachments.length} />
        <Mini icon={FileWarning} label="Findings" value={result.findings.length} />
      </div>

      <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
        {result.findings.length === 0 && <div className="text-sm text-muted-foreground">No issues detected by current rules.</div>}
        {(Object.keys(grouped) as (keyof typeof grouped)[]).map((cat) => grouped[cat].length > 0 && (
          <div key={cat}>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-2 mb-1 flex items-center gap-1">
              {cat === "sender" && <Mail className="h-3 w-3" />}
              {cat === "url" && <Link2 className="h-3 w-3" />}
              {cat === "attachment" && <Paperclip className="h-3 w-3" />}
              {cat === "header" && <FileWarning className="h-3 w-3" />}
              {cat === "keyword" && <AlertTriangle className="h-3 w-3" />}
              {cat}
            </div>
            {grouped[cat].map((f, i) => (
              <div key={i} className="rounded-md border border-border/60 bg-background/40 p-3 mb-1.5">
                <div className="flex items-start justify-between gap-2">
                  <div className="text-sm font-medium">{f.title}</div>
                  <span className="text-[10px] font-mono text-muted-foreground">+{f.weight}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1 break-all">{f.detail}</div>
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="flex justify-end">
        <Button onClick={onSave} disabled={saving}>{saving ? "Saving…" : "Save & Open Report"}</Button>
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="text-sm break-all">{value}</div>
    </div>
  );
}
function Mini({ icon: Icon, label, value }: { icon: React.ComponentType<{ className?: string }>; label: string; value: number }) {
  return (
    <div className="rounded-md border border-border/60 px-3 py-2">
      <div className="flex items-center justify-between text-muted-foreground text-[10px] uppercase tracking-widest"><span>{label}</span><Icon className="h-3 w-3" /></div>
      <div className="text-lg font-bold tabular-nums">{value}</div>
    </div>
  );
}

void useEffect;