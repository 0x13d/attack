/**
 * The community scenario corpus — labeled synthetic signals for all 16 techniques, each with malicious cases
 * (a rule should fire) and benign false-positive tripwires (nothing should fire). It's plain data: ship it,
 * share it, load it into a tuning tool, or extend it. Grow this file to harden a rule against false positives.
 *
 * Every payload mirrors the real `chrome.*` shape the corresponding signal source produces, so a case that
 * fires here fires in the extension. Keep benign cases realistic — they are the whole point of the exercise.
 */
import { Scope } from '../types';
import type { ScenarioCase } from './run';

const nav = (url: string, extra: Record<string, unknown> = {}) => ({ url, transitionType: 'link', ...extra });
const cookie = (c: Record<string, unknown>, cause = 'explicit') => ({ cookie: c, cause });

export const CORPUS: ScenarioCase[] = [
  // ── T1176.001 Browser Extensions (rogue install) ──────────────────────────────────────────────
  m('sideloaded broad-host VPN', Scope.MANAGEMENT, ext({ id: 'a1', name: 'Free VPN', installType: 'sideload', permissions: ['proxy', 'cookies'], hostPermissions: ['<all_urls>'] }), 'T1176.001'),
  m('dev-mode debugger ext', Scope.MANAGEMENT, ext({ id: 'a2', name: 'DevHelper', installType: 'development', permissions: ['debugger', 'management'] }), 'T1176.001'),
  m('store ext with all-URLs + webRequest', Scope.MANAGEMENT, ext({ id: 'a3', name: 'Coupon Finder', installType: 'normal', permissions: ['webRequest'], hostPermissions: ['<all_urls>'] }), 'T1176.001'),
  b('normal store ext, storage only', Scope.MANAGEMENT, ext({ id: 'a4', name: 'Dark Reader', installType: 'normal', permissions: ['storage'] }), 'T1176.001'),
  // Admin (enterprise-policy) installs aren't flagged for their source alone — only a high-risk *capability*
  // trips the rule, and the operator allowlists a sanctioned one. (An admin ext holding e.g. `management`
  // does fire, by design — capability-based, not source-based; add it to approvedExtensionIds to exempt.)
  b('admin-pushed ext, storage only', Scope.MANAGEMENT, ext({ id: 'a5', name: 'Corp Policy', installType: 'admin', permissions: ['storage'] }), 'T1176.001'),

  // ── T1176 tamper (re-enable of an EDR-disabled extension) ─────────────────────────────────────
  { ...m('re-enable of EDR-disabled ext', Scope.MANAGEMENT, ext({ id: 'tamper-1', name: 'Rogue', installType: 'sideload', permissions: ['proxy'] }), 'T1176'), name: 'management.enabled', seedEdrDisabledId: 'tamper-1' },
  { ...b('re-enable of a normal, never-disabled ext', Scope.MANAGEMENT, ext({ id: 'clean-1', name: 'Reader', installType: 'normal', permissions: ['storage'] }), 'T1176'), name: 'management.enabled' },

  // ── T1217 Browser Information Discovery (recon capability) ─────────────────────────────────────
  m('ext holding history+bookmarks', Scope.MANAGEMENT, ext({ id: 'r1', name: 'Session Buddy', installType: 'normal', permissions: ['history', 'bookmarks'] }), 'T1217'),
  m('ext holding topSites', Scope.MANAGEMENT, ext({ id: 'r2', name: 'Speed Dial', installType: 'normal', permissions: ['topSites', 'storage'] }), 'T1217'),
  b('ext with storage + tabs only', Scope.MANAGEMENT, ext({ id: 'r3', name: 'Tab Manager', installType: 'normal', permissions: ['storage', 'tabs'] }), 'T1217'),

  // ── T1566.002 Spearphishing Link (lookalike login) ────────────────────────────────────────────
  m('paypal homoglyph', Scope.WEB_NAVIGATION, nav('https://paypa1.com/login'), 'T1566.002'),
  m('brand-as-subdomain', Scope.WEB_NAVIGATION, nav('https://paypal.com.secure-verify.example/signin'), 'T1566.002'),
  m('okta typosquat', Scope.WEB_NAVIGATION, nav('https://0kta.com/app/login'), 'T1566.002'),
  b('real paypal', Scope.WEB_NAVIGATION, nav('https://www.paypal.com/signin'), 'T1566.002'),
  b('real github login', Scope.WEB_NAVIGATION, nav('https://github.com/login'), 'T1566.002'),
  b('unrelated news site', Scope.WEB_NAVIGATION, nav('https://www.reuters.com/tech/'), 'T1566.002'),

  // ── T1528 Illicit OAuth Consent ───────────────────────────────────────────────────────────────
  m('gmail full-mailbox scope', Scope.WEB_NAVIGATION, nav('https://accounts.google.com/o/oauth2/auth?client_id=x&scope=https://mail.google.com/'), 'T1528'),
  m('offline_access + mail.readwrite', Scope.WEB_NAVIGATION, nav('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=y&scope=offline_access%20mail.readwrite'), 'T1528'),
  b('benign openid/email/profile', Scope.WEB_NAVIGATION, nav('https://accounts.google.com/o/oauth2/auth?client_id=x&scope=openid%20email%20profile'), 'T1528'),
  b('authorize with no scope param', Scope.WEB_NAVIGATION, nav('https://accounts.google.com/o/oauth2/auth?client_id=x'), 'T1528'),

  // ── T1189 Drive-by Compromise (auto-redirect chain) ───────────────────────────────────────────
  m('5-hop client redirect', Scope.WEB_NAVIGATION, nav('https://cdn.evil.example/x', { transitionType: 'client_redirect', redirectChainLength: 5 }), 'T1189'),
  m('exactly-threshold 3-hop', Scope.WEB_NAVIGATION, nav('https://hop.example/y', { transitionType: 'client_redirect', redirectChainLength: 3 }), 'T1189'),
  b('single client redirect', Scope.WEB_NAVIGATION, nav('https://example.com/app', { transitionType: 'client_redirect', redirectChainLength: 1 }), 'T1189'),
  b('normal link navigation', Scope.WEB_NAVIGATION, nav('https://example.com/page'), 'T1189'),

  // ── T1656 Impersonation (brand + auth keyword off-domain) ─────────────────────────────────────
  m('microsoft verify off-domain', Scope.WEB_NAVIGATION, nav('https://secure-microsoft-login.example/verify-account'), 'T1656'),
  m('apple id unlock off-domain', Scope.WEB_NAVIGATION, nav('https://apple-id.support-desk.example/unlock'), 'T1656'),
  b('blog post mentioning microsoft', Scope.WEB_NAVIGATION, nav('https://devblog.example/leaving-microsoft-azure'), 'T1656'),

  // ── T1566.003 Spearphishing via Service (open-redirect) ───────────────────────────────────────
  m('trusted-service open redirect off-domain', Scope.WEB_NAVIGATION, nav('https://t.trusted-mailer.example/c?url=https://evil-phish.example/login'), 'T1566.003'),
  m('redirect_uri laundered off-domain', Scope.WEB_NAVIGATION, nav('https://link.newsletter.example/track?redirect_uri=https://credential-harvest.example/'), 'T1566.003'),
  b('same-domain redirect param', Scope.WEB_NAVIGATION, nav('https://shop.example/go?url=https://shop.example/cart'), 'T1566.003'),
  b('no redirect param', Scope.WEB_NAVIGATION, nav('https://shop.example/products?page=2'), 'T1566.003'),

  // ── T1204.001 Malicious Link (threat blocklist IOC) ───────────────────────────────────────────
  m('navigation to blocklisted host', Scope.WEB_NAVIGATION, nav('https://known-bad.test/payload'), 'T1204.001'),
  m('navigation to blocklisted delivery host', Scope.WEB_NAVIGATION, nav('https://malware-delivery.example/dropper'), 'T1204.001'),
  b('navigation to non-blocklisted host', Scope.WEB_NAVIGATION, nav('https://legit-site.example/home'), 'T1204.001'),

  // ── T1606.002 Forge Web Credentials: SAML ─────────────────────────────────────────────────────
  m('SAMLResponse to non-allowlisted host', Scope.WEB_NAVIGATION, nav('https://sp.unexpected.example/acs?SAMLResponse=b64blob'), 'T1606.002'),
  m('ACS path SAML flow', Scope.WEB_NAVIGATION, nav('https://portal.example/saml2/acs'), 'T1606.002'),
  b('ordinary navigation, no SAML', Scope.WEB_NAVIGATION, nav('https://portal.example/dashboard'), 'T1606.002'),

  // ── T1185 Browser Session Hijacking (reverse tabnabbing) ──────────────────────────────────────
  { ...m('opener tab rewritten cross-origin', Scope.WEB_NAVIGATION, nav('https://phish.example/login', { fromOrigin: 'https://trusted.example', toOrigin: 'https://phish.example' }), 'T1185'), name: 'webNavigation.reverseTabnab' },
  { ...b('committed nav (not a tabnab event)', Scope.WEB_NAVIGATION, nav('https://phish.example/login', { fromOrigin: 'https://trusted.example', toOrigin: 'https://phish.example' }), 'T1185'), name: 'webNavigation.committed' },

  // ── T1105 Ingress Tool Transfer (risky download) ──────────────────────────────────────────────
  m('.hta download', Scope.DOWNLOAD, dl({ filename: 'invoice.hta', finalUrl: 'https://x.example/invoice.hta' }), 'T1105'),
  m('double-extension pdf.exe', Scope.DOWNLOAD, dl({ filename: 'report.pdf.exe', finalUrl: 'https://x.example/report.pdf.exe' }), 'T1105'),
  m('.ps1 script pull', Scope.DOWNLOAD, dl({ filename: 'update.ps1', finalUrl: 'https://x.example/update.ps1' }), 'T1105'),
  b('ordinary pdf', Scope.DOWNLOAD, dl({ filename: 'report.pdf', finalUrl: 'https://x.example/report.pdf', mime: 'application/pdf' }), 'T1105'),
  b('ordinary zip', Scope.DOWNLOAD, dl({ filename: 'photos.zip', finalUrl: 'https://x.example/photos.zip', mime: 'application/zip' }), 'T1105'),
  b('plain exe over https (too common to flag)', Scope.DOWNLOAD, dl({ filename: 'setup.exe', finalUrl: 'https://vendor.example/setup.exe' }), 'T1105'),

  // ── T1204.002 User Execution: Malicious File (lure container) ─────────────────────────────────
  m('.iso lure', Scope.DOWNLOAD, dl({ filename: 'invoice.iso', finalUrl: 'https://x.example/invoice.iso' }), 'T1204.002'),
  m('.lnk shortcut lure', Scope.DOWNLOAD, dl({ filename: 'document.lnk', finalUrl: 'https://x.example/document.lnk' }), 'T1204.002'),
  b('ordinary docx (not a lure container)', Scope.DOWNLOAD, dl({ filename: 'notes.docx', finalUrl: 'https://x.example/notes.docx' }), 'T1204.002'),

  // ── T1566.001 Spearphishing Attachment (delivery vector) ──────────────────────────────────────
  m('macro doc from webmail', Scope.DOWNLOAD, dl({ filename: 'invoice.docm', finalUrl: 'https://x.example/invoice.docm', referrer: 'https://mail.google.com/mail/u/0' }), 'T1566.001'),
  m('svg smuggler from file-share', Scope.DOWNLOAD, dl({ filename: 'statement.svg', finalUrl: 'https://x.example/statement.svg', referrer: 'https://wetransfer.com/downloads/abc' }), 'T1566.001'),
  b('macro doc from a direct download (no delivery referrer)', Scope.DOWNLOAD, dl({ filename: 'invoice.docm', finalUrl: 'https://vendor.example/invoice.docm', referrer: '' }), 'T1566.001'),

  // ── T1539 Steal Web Session Cookie (weak-flag session cookie) ─────────────────────────────────
  m('session cookie missing Secure+HttpOnly', Scope.COOKIE, cookie({ name: 'SESSIONID', secure: false, httpOnly: false, sameSite: 'no_restriction', session: true }), 'T1539'),
  m('auth token SameSite=None', Scope.COOKIE, cookie({ name: 'auth_token', secure: true, httpOnly: false, sameSite: 'no_restriction', session: true }), 'T1539'),
  b('properly-flagged session cookie', Scope.COOKIE, cookie({ name: 'SESSIONID', secure: true, httpOnly: true, sameSite: 'lax', session: true }), 'T1539'),
  b('non-session preference cookie', Scope.COOKIE, cookie({ name: 'theme', secure: false, httpOnly: false, sameSite: 'lax', session: true }), 'T1539'),

  // ── T1550.004 Use of Web Session Cookie (session made persistent) ─────────────────────────────
  m('session cookie pinned with expiry', Scope.COOKIE, cookie({ name: 'sessionid', secure: true, httpOnly: true, sameSite: 'lax', session: false, expirationDate: 4102444800 }), 'T1550.004'),
  m('auth cookie made persistent', Scope.COOKIE, cookie({ name: 'jwt', secure: true, httpOnly: true, sameSite: 'lax', session: false, expirationDate: 4102444800 }), 'T1550.004'),
  b('true (expire-on-close) session cookie', Scope.COOKIE, cookie({ name: 'sessionid', secure: true, httpOnly: true, sameSite: 'lax', session: true }), 'T1550.004'),
  b('persistent non-session cookie', Scope.COOKIE, cookie({ name: 'locale', secure: true, httpOnly: false, sameSite: 'lax', session: false, expirationDate: 4102444800 }), 'T1550.004'),
];

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────
function m(label: string, scope: Scope, payload: unknown, technique: string): ScenarioCase {
  return { label, scope, payload, malicious: true, technique };
}
function b(label: string, scope: Scope, payload: unknown, technique: string): ScenarioCase {
  return { label, scope, payload, malicious: false, technique };
}
function ext(e: { id: string; name: string; installType: string; permissions?: string[]; hostPermissions?: string[] }) {
  return { enabled: true, permissions: [], hostPermissions: [], ...e };
}
function dl(d: { filename: string; finalUrl: string; url?: string; mime?: string; referrer?: string }) {
  return { url: d.finalUrl, mime: 'application/octet-stream', referrer: '', ...d };
}
