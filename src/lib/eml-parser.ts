import type { ParsedEmail } from "./detection-engine";

// Lightweight .eml / raw-email parser. Handles the common cases needed for
// phishing analysis: headers, plain text body, simple HTML body, links, and
// attachment filenames. Not a full RFC 5322 implementation.

function unfoldHeaders(raw: string): string {
  return raw.replace(/\r\n[\t ]+/g, " ").replace(/\n[\t ]+/g, " ");
}

function decodeBase64(s: string): string {
  try {
    return atob(s.replace(/\s+/g, ""));
  } catch {
    return s;
  }
}

function decodeQuotedPrintable(s: string): string {
  return s
    .replace(/=\r?\n/g, "")
    .replace(/=([A-Fa-f0-9]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function extractEmailAddress(s: string): string {
  const m = s.match(/<([^>]+)>/);
  if (m) return m[1].trim();
  const m2 = s.match(/[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}/);
  return m2 ? m2[0] : s.trim();
}

export function parseEml(raw: string): ParsedEmail {
  const text = raw.replace(/\r\n/g, "\n");
  const splitIdx = text.indexOf("\n\n");
  const headerBlock = splitIdx >= 0 ? text.slice(0, splitIdx) : text;
  let body = splitIdx >= 0 ? text.slice(splitIdx + 2) : "";

  const unfolded = unfoldHeaders(headerBlock);
  const headers: Record<string, string> = {};
  for (const line of unfolded.split("\n")) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    headers[k] = headers[k] ? `${headers[k]} | ${v}` : v;
  }

  // MIME parts
  const attachments: ParsedEmail["attachments"] = [];
  const ct = headers["content-type"] || "";
  const boundaryMatch = ct.match(/boundary=("?)([^";]+)\1/i);
  if (boundaryMatch) {
    const boundary = boundaryMatch[2];
    const parts = body.split(`--${boundary}`);
    let plainBody = "";
    for (const part of parts) {
      if (!part.trim() || part.trim() === "--") continue;
      const ph = part.indexOf("\n\n");
      if (ph < 0) continue;
      const partHeaders = unfoldHeaders(part.slice(0, ph)).toLowerCase();
      const partBody = part.slice(ph + 2);
      const dispMatch = partHeaders.match(/content-disposition:[^\n]*filename=("?)([^";\n]+)\1/i);
      const nameMatch = partHeaders.match(/content-type:[^\n]*name=("?)([^";\n]+)\1/i);
      const filename = dispMatch?.[2] || nameMatch?.[2];
      if (filename) {
        const ext = filename.split(".").pop() || "";
        attachments.push({ filename, ext });
      } else if (partHeaders.includes("content-type: text/plain")) {
        const enc = partHeaders.match(/content-transfer-encoding:\s*(\S+)/)?.[1];
        let decoded = partBody;
        if (enc === "base64") decoded = decodeBase64(partBody);
        else if (enc === "quoted-printable") decoded = decodeQuotedPrintable(partBody);
        plainBody += decoded + "\n";
      } else if (!plainBody && partHeaders.includes("content-type: text/html")) {
        const enc = partHeaders.match(/content-transfer-encoding:\s*(\S+)/)?.[1];
        let decoded = partBody;
        if (enc === "base64") decoded = decodeBase64(partBody);
        else if (enc === "quoted-printable") decoded = decodeQuotedPrintable(partBody);
        plainBody = decoded;
      }
    }
    if (plainBody) body = plainBody;
  } else {
    const enc = (headers["content-transfer-encoding"] || "").toLowerCase();
    if (enc === "base64") body = decodeBase64(body);
    else if (enc === "quoted-printable") body = decodeQuotedPrintable(body);
  }

  // Extract links
  const links: ParsedEmail["links"] = [];
  const anchorRe = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = anchorRe.exec(body))) {
    links.push({ href: m[1], text: m[2].replace(/<[^>]+>/g, "").trim() });
  }
  const seen = new Set(links.map((l) => l.href));
  const urlMatches = body.match(/https?:\/\/[^\s<>"')]+/gi) || [];
  for (const u of urlMatches) if (!seen.has(u)) links.push({ href: u, text: "" });

  const fromHeader = headers["from"] || "";
  const sender = extractEmailAddress(fromHeader);
  const returnPath = extractEmailAddress(headers["return-path"] || "");
  const senderDomain = sender.split("@").pop()?.toLowerCase() || "";

  return {
    sender,
    senderDomain,
    returnPath,
    subject: headers["subject"] || "(no subject)",
    body: body.replace(/<[^>]+>/g, " "),
    headers,
    links,
    attachments,
    raw,
  };
}

// Parse a plain pasted email (no headers) — try to guess From/Subject from
// the first few lines, otherwise treat the whole thing as the body.
export function parsePlainText(text: string): ParsedEmail {
  // If it has headers, route through parseEml.
  if (/^(from|subject|to|received):/im.test(text.split("\n").slice(0, 10).join("\n"))) {
    return parseEml(text);
  }
  const links: ParsedEmail["links"] = [];
  const urlMatches = text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
  for (const u of urlMatches) links.push({ href: u, text: "" });
  // Try to infer From/Subject from "From: foo / Subject: bar" lines
  const fromLine = text.match(/^from:\s*(.+)$/im)?.[1] ?? "";
  const subjectLine = text.match(/^subject:\s*(.+)$/im)?.[1] ?? "(pasted email)";
  const sender = fromLine ? extractEmailAddress(fromLine) : "";
  return {
    sender,
    senderDomain: sender.split("@").pop()?.toLowerCase() || "",
    returnPath: "",
    subject: subjectLine,
    body: text,
    headers: {},
    links,
    attachments: [],
    raw: text,
  };
}