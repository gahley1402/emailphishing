import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldCheck, ScanSearch, FileBarChart2, Lock, Mail, AlertTriangle, Link2, Paperclip, FileWarning } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "PhishGuard — Rule-Based Phishing Email Detection" },
      { name: "description", content: "Transparent, rule-based phishing detection. No AI, no black boxes — verifiable cybersecurity signals." },
      { property: "og:title", content: "PhishGuard — Phishing Email Detection" },
      { property: "og:description", content: "Analyze emails for phishing using keywords, sender, URL, attachment and header rules." },
    ],
  }),
  component: Landing,
});

function Landing() {
  return (
    <div className="min-h-screen">
      {/* Nav */}
      <header className="border-b border-border/60 backdrop-blur sticky top-0 z-10 bg-background/70">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-primary" />
            <span className="font-semibold tracking-tight">PhishGuard</span>
            <span className="ml-2 text-[10px] uppercase tracking-widest text-muted-foreground border border-border rounded px-1.5 py-0.5">v1.0</span>
          </Link>
          <div className="flex items-center gap-2">
            <Link to="/auth"><Button variant="ghost" size="sm">Sign in</Button></Link>
            <Link to="/auth"><Button size="sm">Launch Console</Button></Link>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 cyber-grid opacity-40" aria-hidden />
        <div className="relative max-w-6xl mx-auto px-6 py-24 md:py-32 text-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground mb-6">
            <span className="relative flex h-2 w-2"><span className="absolute inset-0 rounded-full bg-primary animate-ping opacity-75" /><span className="relative rounded-full h-2 w-2 bg-primary" /></span>
            Rule-based engine · No AI / ML
          </div>
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight">
            Detect <span className="text-gradient-cyber">phishing emails</span><br />
            with cybersecurity rules you can audit.
          </h1>
          <p className="mt-6 text-lg text-muted-foreground max-w-2xl mx-auto">
            Paste an email, drop a <code className="text-primary">.eml</code> file, and PhishGuard inspects sender authenticity,
            URLs, attachments, headers, and known phishing language — and explains every finding.
          </p>
          <div className="mt-10 flex flex-wrap justify-center gap-3">
            <Link to="/auth"><Button size="lg" className="shadow-[var(--glow-primary)]">Start Scanning <ScanSearch className="ml-2 h-4 w-4" /></Button></Link>
            <a href="#how"><Button size="lg" variant="outline">How it works</Button></a>
          </div>
        </div>
      </section>

      {/* Detection modules */}
      <section id="how" className="max-w-6xl mx-auto px-6 py-20">
        <div className="text-center mb-12">
          <div className="text-xs uppercase tracking-widest text-primary mb-2">Detection Modules</div>
          <h2 className="text-3xl md:text-4xl font-bold">Five layers of inspection</h2>
        </div>
        <div className="grid md:grid-cols-3 gap-4">
          {[
            { icon: AlertTriangle, title: "Suspicious Keywords", desc: "Urgency phrases, credential prompts, payment lures — matched against an editable threat dictionary." },
            { icon: Mail, title: "Sender Analysis", desc: "Typosquats, brand impersonation, free-provider abuse, return-path mismatches." },
            { icon: Link2, title: "URL Inspection", desc: "Raw IPs, shorteners, blacklisted domains, anchor-text vs. href mismatches." },
            { icon: Paperclip, title: "Attachment Flags", desc: ".exe, .bat, .scr, .js, .vbs and other code-executing payloads." },
            { icon: FileWarning, title: "Header Forensics", desc: "SPF, DKIM, DMARC failure detection; missing authentication records." },
            { icon: FileBarChart2, title: "Risk Scoring + Reports", desc: "0–100 score with classification, PDF export, and full audit trail in your history." },
          ].map((f) => (
            <div key={f.title} className="rounded-xl border border-border bg-[var(--gradient-card)] p-5 hover:border-primary/40 transition">
              <f.icon className="h-6 w-6 text-primary mb-3" />
              <div className="font-semibold">{f.title}</div>
              <div className="text-sm text-muted-foreground mt-1">{f.desc}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-6xl mx-auto px-6 pb-24">
        <div className="rounded-2xl border border-border bg-[var(--gradient-card)] p-10 text-center">
          <Lock className="h-8 w-8 text-primary mx-auto" />
          <h3 className="mt-4 text-2xl font-bold">Built for the SOC desk.</h3>
          <p className="mt-2 text-muted-foreground max-w-xl mx-auto">
            Every finding is explained. Every score is reproducible. Every scan is logged for review.
          </p>
          <div className="mt-6"><Link to="/auth"><Button size="lg">Create your analyst account</Button></Link></div>
        </div>
      </section>

      <footer className="border-t border-border py-6 text-center text-xs text-muted-foreground">
        PhishGuard · BCA Cyber Security Internship Project
      </footer>
    </div>
  );
}
