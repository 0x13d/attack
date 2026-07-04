/**
 * T1566.001 — Spearphishing Attachment. Pure detection: a download that looks like a **phishing attachment** —
 * an attachment-lure file type **delivered from a phishing context** (a webmail / file-share / messaging
 * referrer, or an otherwise suspicious referring origin).
 *
 * **Separable angle (honest-framing gate):** unlike T1105 (raw script/quasi-exe transfer) and T1204.002 (lure
 * containers), T1566.001 is keyed on the **delivery vector** — the download's `referrer`. The file classes are
 * also disjoint: macro-enabled office docs + smuggling-prone web formats. A direct download with no delivery
 * context is **not** flagged here (it isn't spearphishing). Detect + alert. Chrome-free + unit-testable.
 */
export interface AttachmentLike {
  filename: string;
  url: string;
  /** The referring page the download came from (chrome.downloads.DownloadItem.referrer); may be ''. */
  referrer: string;
}

export interface AttachmentAssessment {
  spearphish: boolean;
  reasons: string[];
  extension: string | null;
}

export function assessAttachment(
  item: AttachmentLike,
  attachmentExtensions: string[],
  deliveryOrigins: string[],
): AttachmentAssessment {
  const name = basename(item.filename || pathOf(item.url)).toLowerCase();
  const parts = name.split('.').filter(Boolean);
  const ext = parts.length > 1 ? parts[parts.length - 1] : '';
  const lures = new Set(attachmentExtensions.map((e) => e.toLowerCase().replace(/^\./, '')));
  if (ext === '' || !lures.has(ext)) return { spearphish: false, reasons: [], extension: null };

  const context = deliveryContext(item.referrer, deliveryOrigins);
  if (!context) return { spearphish: false, reasons: [], extension: null };

  return { spearphish: true, reasons: [`spearphishing attachment: .${ext} ${context}`], extension: ext };
}

/** Describe the delivery context, or null when the referrer isn't a phishing-delivery vector. */
function deliveryContext(referrer: string, deliveryOrigins: string[]): string | null {
  const host = hostOf(referrer);
  if (!host) return null; // no referrer → not a delivery vector → not spearphishing
  const known = deliveryOrigins.some((d) => host === d.toLowerCase() || host.endsWith(`.${d.toLowerCase()}`));
  if (known) return `delivered from ${host} (webmail / file-share / messaging)`;

  let u: URL | null = null;
  try {
    u = new URL(referrer);
  } catch {
    return null;
  }
  if (u.protocol === 'http:') return `delivered from an insecure-HTTP origin (${host})`;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return `delivered from a bare-IP origin (${host})`;
  return null;
}

function hostOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function basename(path: string): string {
  const cut = path.replace(/\\/g, '/');
  return cut.slice(cut.lastIndexOf('/') + 1);
}

function pathOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname;
  } catch {
    return rawUrl;
  }
}
