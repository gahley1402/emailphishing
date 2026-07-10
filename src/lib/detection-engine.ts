// EmailShield rule-based phishing detection engine.
// Pure TypeScript — no AI/ML. Each rule emits findings with a weight that
// contributes to a final risk score (0-100).

export type Severity = "low" | "medium" | "high";
export type FindingCategory =
  | "keyword"
  | "sender"
  | "url"
  | "attachment"
  | "header";

export interface Finding {
  category: FindingCategory;
  severity: Severity;
  weight: number;
  title: string;
  detail: string;
}

export interface ParsedEmail {
  sender: string;
  senderDomain: string;
  returnPath: string;
  subject: string;
  body: string;
  headers: Record<string, string>;
  links: { href: string; text: string }[];
  attachments: { filename: string; ext: string }[];
  raw: string;
}

export interface ScanResult {
  email: ParsedEmail;
  findings: Finding[];
  score: number;
  classification: "safe" | "suspicious" | "phishing";
}

const FREE_EMAIL_PROVIDERS = [
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
  "live.com", "aol.com", "protonmail.com", "icloud.com", "mail.com",
];

const KNOWN_BRANDS = [
  "paypal", "microsoft", "apple", "amazon", "google", "facebook",
  "netflix", "bank", "instagram", "linkedin", "dropbox", "adobe",
];

const DANGEROUS_EXTS = ["exe", "bat", "scr", "js", "vbs", "cmd", "ps1", "jar", "msi", "com"];
const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
  "rebrand.ly","shorte.st","cutt.ly","rb.gy","tiny.cc",
]);

const IP_REGEX = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/i;
const URL_REGEX = /https?:\/\/[^\s<>"')]+/gi;

function domainOf(emailOrUrl: string): string {
  try {
    if (emailOrUrl.includes("@")) return emailOrUrl.split("@").pop()!.trim().toLowerCase();
    const u = new URL(emailOrUrl);
    return u.hostname.toLowerCase();
  } catch {
    return "";
  }
}

function looksLikeTyposquat(domain: string): string | null {
  const d = domain.toLowerCase();
  for (const brand of KNOWN_BRANDS) {
    if (d.includes(brand)) continue;
    // contains brand with a digit substitution
    const variants = [
      brand.replace("o", "0"),
      brand.replace("i", "1"),
      brand.replace("l", "1"),
      brand.replace("e", "3"),
      brand.replace("a", "@"),
    ];
    for (const v of variants) {
      if (d.includes(v)) return brand;
    }
    // hyphenated brand impersonation like "microsoft-support.com"
    if (d.includes(`${brand}-`) || d.includes(`-${brand}`)) return brand;
  }
  return null;
}

export interface DetectionConfig {
  keywords: { keyword: string; weight: number }[];
  blacklist: { domain: string; reason?: string | null }[];
}

export function runDetection(email: ParsedEmail, config: DetectionConfig): ScanResult {
  const findings: Finding[] = [];
  const haystack = `${email.subject}\n${email.body}`.toLowerCase();

  // 1. Suspicious keywords
  for (const k of config.keywords) {
    if (haystack.includes(k.keyword.toLowerCase())) {
      findings.push({
        category: "keyword",
        severity: "low",
        weight: k.weight || 10,
        title: `Suspicious keyword: "${k.keyword}"`,
        detail: "Common phishing language designed to create urgency or panic.",
      });
    }
  }

  // 2. Sender analysis
  const senderDomain = email.senderDomain;
  if (senderDomain) {
    if (config.blacklist.some((b) => b.domain.toLowerCase() === senderDomain)) {
      findings.push({
        category: "sender",
        severity: "high",
        weight: 25,
        title: `Sender domain is blacklisted: ${senderDomain}`,
        detail: "Domain matches an entry in the threat intelligence blacklist.",
      });
    }
    const typo = looksLikeTyposquat(senderDomain);
    if (typo) {
      findings.push({
        category: "sender",
        severity: "high",
        weight: 25,
        title: `Possible typosquat of "${typo}" — ${senderDomain}`,
        detail: "Domain looks like a misspelled version of a well-known brand.",
      });
    }
    // Free provider claiming to be a brand
    if (FREE_EMAIL_PROVIDERS.includes(senderDomain)) {
      const subjectLower = email.subject.toLowerCase();
      const claimsBrand = KNOWN_BRANDS.find((b) => subjectLower.includes(b));
      if (claimsBrand) {
        findings.push({
          category: "sender",
          severity: "medium",
          weight: 20,
          title: `Free email provider claims to represent "${claimsBrand}"`,
          detail: `Sender is on ${senderDomain} but message references ${claimsBrand}.`,
        });
      }
    }
    // Return-path mismatch
    if (email.returnPath) {
      const rp = domainOf(email.returnPath);
      if (rp && rp !== senderDomain) {
        findings.push({
          category: "header",
          severity: "medium",
          weight: 20,
          title: "Return-Path domain does not match sender",
          detail: `From: ${senderDomain} | Return-Path: ${rp}`,
        });
      }
    }
  } else {
    findings.push({
      category: "sender",
      severity: "medium",
      weight: 15,
      title: "Sender address could not be parsed",
      detail: "Missing or malformed From header.",
    });
  }

  // 3. URL analysis
  for (const link of email.links) {
    const href = link.href;
    const dom = domainOf(href);
    if (IP_REGEX.test(href)) {
      findings.push({
        category: "url",
        severity: "high",
        weight: 20,
        title: "Link uses raw IP address",
        detail: href,
      });
    }
    if (dom && SHORTENERS.has(dom)) {
      findings.push({
        category: "url",
        severity: "medium",
        weight: 20,
        title: `URL shortener detected (${dom})`,
        detail: href,
      });
    }
    if (dom && config.blacklist.some((b) => b.domain.toLowerCase() === dom)) {
      findings.push({
        category: "url",
        severity: "high",
        weight: 25,
        title: `Link points to blacklisted domain (${dom})`,
        detail: href,
      });
    }
    const typo = dom ? looksLikeTyposquat(dom) : null;
    if (typo) {
      findings.push({
        category: "url",
        severity: "high",
        weight: 25,
        title: `Link domain typosquats "${typo}"`,
        detail: `${dom} → ${href}`,
      });
    }
    // Mismatched anchor text vs href
    if (link.text && /https?:\/\//i.test(link.text)) {
      const textDom = domainOf(link.text);
      if (textDom && dom && textDom !== dom) {
        findings.push({
          category: "url",
          severity: "high",
          weight: 20,
          title: "Link text does not match destination URL",
          detail: `Displayed: ${textDom} | Actual: ${dom}`,
        });
      }
    }
  }

  // 4. Attachment analysis
  for (const a of email.attachments) {
    if (DANGEROUS_EXTS.includes(a.ext.toLowerCase())) {
      findings.push({
        category: "attachment",
        severity: "high",
        weight: 25,
        title: `Dangerous attachment: ${a.filename}`,
        detail: `.${a.ext} files can execute code on your machine.`,
      });
    }
  }

  // 5. Header authentication checks
  const auth = (email.headers["authentication-results"] || "").toLowerCase();
  const received = email.headers["received-spf"] || "";
  if (Object.keys(email.headers).length > 0) {
    if (!auth && !received) {
      findings.push({
        category: "header",
        severity: "medium",
        weight: 20,
        title: "Missing email authentication records",
        detail: "No Authentication-Results or Received-SPF header present.",
      });
    }
    if (auth.includes("spf=fail") || /\bfail\b/i.test(received)) {
      findings.push({
        category: "header",
        severity: "high",
        weight: 20,
        title: "SPF check failed",
        detail: auth || received,
      });
    }
    if (auth.includes("dkim=fail")) {
      findings.push({
        category: "header",
        severity: "high",
        weight: 20,
        title: "DKIM signature failed",
        detail: auth,
      });
    }
    if (auth.includes("dmarc=fail")) {
      findings.push({
        category: "header",
        severity: "high",
        weight: 20,
        title: "DMARC alignment failed",
        detail: auth,
      });
    }
  }

  // Score: sum capped at 100
  const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
  const classification: ScanResult["classification"] =
    score <= 30 ? "safe" : score <= 60 ? "suspicious" : "phishing";

  return { email, findings, score, classification };
}