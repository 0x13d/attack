/**
 * The alert log — the in-extension console that doesn't depend on OS notifications (which an enterprise may
 * disable). Persisted in `chrome.storage.local` so it survives the ephemeral MV3 service worker, drives the
 * toolbar **badge** (count of unacknowledged, in red), and backs the popup's alert table.
 *
 * Shared by the service worker (writes on a hit, keeps the badge in sync) and the popup (reads + acknowledges).
 */

export interface AlertRecord {
  id: string;
  technique: string;
  ruleName: string;
  signalName: string;
  extensionName?: string;
  reasons: string[];
  timestamp: number;
  acknowledged: boolean;
}

const STORAGE_KEY = 'alerts';
const MAX_ALERTS = 200;
const BADGE_COLOR = '#B02B2C'; // red — unacknowledged

export async function getAlerts(): Promise<AlertRecord[]> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return (stored[STORAGE_KEY] as AlertRecord[] | undefined) ?? [];
}

async function setAlerts(alerts: AlertRecord[]): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: alerts.slice(0, MAX_ALERTS) });
}

/** Record a new (unacknowledged) alert, newest first, and refresh the badge. */
export async function recordAlert(rec: Omit<AlertRecord, 'acknowledged'>): Promise<void> {
  const alerts = await getAlerts();
  alerts.unshift({ ...rec, acknowledged: false });
  await setAlerts(alerts);
  await refreshBadge();
}

export async function acknowledge(ids: string[]): Promise<void> {
  const set = new Set(ids);
  const alerts = await getAlerts();
  for (const a of alerts) if (set.has(a.id)) a.acknowledged = true;
  await setAlerts(alerts);
  await refreshBadge();
}

export async function acknowledgeAll(): Promise<void> {
  const alerts = await getAlerts();
  for (const a of alerts) a.acknowledged = true;
  await setAlerts(alerts);
  await refreshBadge();
}

export async function clearAlerts(): Promise<void> {
  await setAlerts([]);
  await refreshBadge();
}

/** Recompute the toolbar badge from storage — the count of unacknowledged alerts, in red. */
export async function refreshBadge(): Promise<void> {
  if (!chrome.action?.setBadgeText) return;
  const unacked = (await getAlerts()).filter((a) => !a.acknowledged).length;
  await chrome.action.setBadgeText({ text: unacked > 0 ? String(unacked) : '' });
  await chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR });
}
