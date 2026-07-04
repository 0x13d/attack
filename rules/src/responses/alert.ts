import { recordAlert } from '../alerts';
import { Response, Rule, Signal } from '../types';

/**
 * The "D" telemetry of EDR: surface a hit. Always **visible** (a desktop notification + a structured console
 * record) and always **local** — the community edition has no network egress at all; the build self-check
 * fails if any `fetch(` reaches the bundle.
 */
export function makeAlertResponse<T>(): Response<T> {
  return {
    id: 'response.alert',
    name: 'Alert (notify + structured log + optional SIEM ship)',
    action: (rule: Rule<T>, signal: Signal<T>) => {
      const record = {
        kind: 'attack.alert',
        technique: rule.technique,
        ruleId: rule.id,
        ruleName: rule.name,
        signalId: signal.id,
        signalName: signal.name,
        timestamp: signal.timestamp,
        meta: signal.meta ?? {},
      };

      console.warn('[attack] ALERT', record);

      // In-extension console (badge + popup) — does not depend on OS notifications.
      void recordAlert({
        id: signal.id,
        technique: rule.technique,
        ruleName: rule.name,
        signalName: signal.name,
        extensionName: signal.meta?.extensionName as string | undefined,
        reasons: (signal.meta?.reasons as string[] | undefined) ?? [],
        timestamp: signal.timestamp,
      }).catch((err) => console.error('[attack] recordAlert failed', err));

      notify(rule, signal);
    },
  };
}

function notify<T>(rule: Rule<T>, signal: Signal<T>): void {
  if (!chrome.notifications?.create) return;
  const reasons = (signal.meta?.reasons as string[] | undefined) ?? [];
  // Callback form so a rejected promise (e.g. user disabled OS notifications) can't surface as uncaught.
  chrome.notifications.create(
    {
      type: 'basic',
      iconUrl: 'icon128.png',
      title: `attack — ${rule.technique} detected`,
      message: `${rule.name}\n${signal.name}${reasons.length ? `\n• ${reasons.join('\n• ')}` : ''}`,
      priority: 2,
    },
    () => void chrome.runtime.lastError, // read + discard lastError to keep it from logging as uncaught
  );
}

