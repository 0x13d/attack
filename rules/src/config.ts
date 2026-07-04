/**
 * Operator policy for the detection rules. Everything here is a *local* configuration knob — no secrets, no
 * remote fetch of policy. The defaults are conservative and **egress-free**.
 */
export interface Policy {
  /** Extension IDs known-good in this environment — never flagged (e.g. the org's approved add-ons + self). */
  approvedExtensionIds: string[];
  /** Permissions that, on a non-approved extension, are strong rogue indicators. */
  highRiskPermissions: string[];
  /** Host-permission patterns that count as "broad host access". */
  broadHostPatterns: string[];
  /** Brand login domains to protect from lookalike/typosquat navigation (T1566.002). Registrable domains. */
  protectedDomains: string[];
  /** Substrings (lowercased) that mark a cookie as a session/auth cookie for T1539 weak-flag detection. */
  sessionCookiePatterns: string[];
  /** OAuth scopes that signal an illicit-consent grab (T1528). Matched as case-insensitive substrings. */
  highRiskOAuthScopes: string[];
  /** OAuth `client_id`s known-good in this environment. Empty = rely on scopes only. */
  approvedOAuthClients: string[];
  /**
   * File extensions (no dot, lowercased) that are rarely-legitimate as a *standalone* download and flag T1105
   * on their own. `.exe`/`.msi` are intentionally absent (too common) — caught only via a double-extension mask
   * or a suspicious origin. Tune per environment.
   */
  riskyDownloadExtensions: string[];
  /**
   * Container / shortcut / installer extensions that are **user-execution lures** (T1204.002) — double-clicked
   * to run. Disjoint from `riskyDownloadExtensions` (T1105) so the two rules never double-fire on one artifact.
   */
  userExecutionLureExtensions: string[];
  /** Attachment-lure file types for T1566.001 — macro-enabled office docs + smuggling-prone web formats. */
  attachmentExtensions: string[];
  /** Hosts that mark a download's referrer as a phishing-delivery vector (webmail / file-share / messaging). */
  attachmentDeliveryOrigins: string[];
  /** Query-param names that carry a redirect target — abused as open-redirects for T1566.003 (case-insensitive). */
  openRedirectParams: string[];
  /** Known-bad destination IOCs (host/registrable-domain) for T1204.001 — operators replace with their feed. */
  threatBlocklist: string[];
  /** T1189: consecutive auto client-redirect hops in a tab that count as a drive-by chain. */
  driveByRedirectThreshold: number;
  /** T1656: auth-context keywords that, alongside a brand term on a non-brand domain, signal login impersonation. */
  impersonationAuthKeywords: string[];
  /** T1606.002: trusted IdP/SP hosts whose SAML flows are expected (allowlist). Empty = flag all SAML flows. */
  samlTrustedHosts: string[];
  /** T1217: extension permissions that signal browser-data-discovery (recon) capability. */
  reconPermissions: string[];
}

export const DEFAULT_POLICY: Policy = {
  approvedExtensionIds: [],
  highRiskPermissions: [
    'debugger',
    'proxy',
    'nativeMessaging',
    'management',
    'cookies',
    'webRequest',
    'webRequestBlocking',
    'declarativeNetRequest',
    'scripting',
    'downloads',
  ],
  broadHostPatterns: ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'],
  protectedDomains: ['paypal.com', 'google.com', 'microsoft.com', 'github.com', 'okta.com', 'apple.com', 'amazon.com'],
  sessionCookiePatterns: ['session', 'sess', 'sid', 'auth', 'token', 'jwt', 'sso', 'login'],
  highRiskOAuthScopes: [
    'offline_access',
    'mail.read',
    'mail.readwrite',
    'mail.send',
    'files.read.all',
    'files.readwrite.all',
    'directory.read.all',
    'user.read.all',
    'full_access',
    'https://mail.google.com/',
    'gmail.modify',
    'drive',
  ],
  approvedOAuthClients: [],
  riskyDownloadExtensions: ['hta', 'scr', 'pif', 'vbs', 'vbe', 'jse', 'wsf', 'bat', 'cmd', 'ps1', 'com', 'jar'],
  userExecutionLureExtensions: ['lnk', 'iso', 'img', 'vhd', 'vhdx', 'msi', 'msix', 'appx', 'chm'],
  attachmentExtensions: ['docm', 'dotm', 'xlsm', 'xltm', 'xlsb', 'pptm', 'potm', 'html', 'htm', 'svg', 'xhtml'],
  attachmentDeliveryOrigins: [
    'mail.google.com',
    'drive.google.com',
    'outlook.office.com',
    'outlook.office365.com',
    'outlook.live.com',
    'mail.yahoo.com',
    'mail.proton.me',
    'dropbox.com',
    'wetransfer.com',
    'we.tl',
    '1drv.ms',
    'mega.nz',
  ],
  openRedirectParams: ['url', 'redirect', 'redirect_uri', 'redirecturl', 'next', 'returnurl', 'return', 'dest', 'destination', 'continue', 'target', 'goto', 'out', 'link'],
  // Sample reserved-TLD IOCs (harmless, demo-able). Replace with a real threat feed in production.
  threatBlocklist: ['known-bad.test', 'malware-delivery.example'],
  driveByRedirectThreshold: 3,
  impersonationAuthKeywords: ['login', 'signin', 'sign-in', 'log-in', 'verify', 'secure', 'account', 'update', 'confirm', 'password', 'auth', 'sso', 'validate', 'unlock', 'recover'],
  samlTrustedHosts: [], // operator allowlists their IdP/SP hosts; empty flags all SAML flows for visibility
  reconPermissions: ['bookmarks', 'history', 'topSites'],
};
