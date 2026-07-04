/**
 * T1105 — Ingress Tool Transfer. Pure detection: a downloaded artifact that looks like a tool/payload being
 * pulled onto the host — a rarely-legitimate script/quasi-executable extension, an executable **masked by a
 * double extension** (`invoice.pdf.exe`), and/or delivery from a **suspicious origin**. Chrome-free + unit-testable.
 *
 * Conservative by design (acceptance criterion: flag the risky download, *not* normal downloads). A plain
 * `.exe`/`.msi` from `https` is **not** flagged on its own — too common; it only trips via a double-extension
 * mask or a suspicious origin. The standalone-risky set is policy-tunable (`policy.riskyDownloadExtensions`).
 */
export interface DownloadLike {
  /** The target filename (basename's extension(s) are what matter). */
  filename: string;
  /** The download URL (prefer the post-redirect finalUrl). */
  url: string;
  /** Optional declared MIME type (unused today; reserved for a MIME-mismatch reason). */
  mime?: string;
}

export interface DownloadAssessment {
  transferRisk: boolean;
  reasons: string[];
  /** The triggering extension (lowercased, no dot) for the alert meta; null when no artifact match. */
  extension: string | null;
}

/** Benign-looking extensions an attacker hides behind in a double-extension mask (`report.pdf.exe`). */
const BENIGN_LOOKING = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif',
  'txt', 'csv', 'zip', 'rtf', 'htm', 'html', 'mp4', 'mp3',
]);

/** Executable/installer extensions that count when *masked* by a double extension (broader than standalone). */
const EXECUTABLE_EXTS = new Set([
  'exe', 'msi', 'dll', 'lnk', 'iso', 'img', 'app', 'dmg', 'pkg',
  'hta', 'scr', 'pif', 'vbs', 'vbe', 'jse', 'wsf', 'bat', 'cmd', 'ps1', 'com', 'jar',
]);

export function assessDownload(item: DownloadLike, riskyExtensions: string[]): DownloadAssessment {
  const reasons: string[] = [];
  const name = basename(item.filename || pathOf(item.url)).toLowerCase();
  const parts = name.split('.').filter(Boolean);
  const ext = parts.length > 1 ? parts[parts.length - 1] : '';
  const prevExt = parts.length > 2 ? parts[parts.length - 2] : '';

  const risky = new Set(riskyExtensions.map((e) => e.toLowerCase().replace(/^\./, '')));
  const isStandaloneRisky = ext !== '' && risky.has(ext);
  const isDoubleExtMask = ext !== '' && EXECUTABLE_EXTS.has(ext) && prevExt !== '' && BENIGN_LOOKING.has(prevExt);

  if (isDoubleExtMask) reasons.push(`double extension masks an executable (.${prevExt}.${ext})`);
  else if (isStandaloneRisky) reasons.push(`rarely-legitimate executable/script artifact (.${ext})`);

  const transferRisk = isStandaloneRisky || isDoubleExtMask;

  const origin = suspiciousOrigin(item.url);
  if (origin) reasons.push(origin);

  return { transferRisk, reasons, extension: transferRisk ? ext : null };
}

/** Origin red flags that aggravate (but don't by themselves trigger) a download. */
function suspiciousOrigin(rawUrl: string): string | null {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (u.username || u.password) return 'URL embeds credentials/userinfo (phishing/redirect trick)';
  if (u.protocol === 'http:') return 'delivered over insecure HTTP (interceptable / non-reputable)';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) || u.hostname.includes(':')) return 'served from a bare IP host (no domain reputation)';
  return null;
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
