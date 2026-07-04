import { Response, Rule, Signal } from '../types';
import { CookiePayload } from '../signals/cookie';

/**
 * Active prevention for T1539: remove the weak session cookie (`chrome.cookies.remove`) — kill the
 * theft-exposed session so it can't be replayed. Needs the `cookies` permission + host access (same gate as
 * observing it).
 */
export const removeCookieResponse: Response<CookiePayload> = {
  id: 'response.removeCookie',
  name: 'Remove the weak session cookie (cookies.remove)',
  action: (_rule: Rule<CookiePayload>, signal: Signal<CookiePayload>) => {
    const c = signal.payload.cookie;
    if (!chrome.cookies?.remove) return;
    const url = `http${c.secure ? 's' : ''}://${c.domain.replace(/^\./, '')}${c.path}`;
    chrome.cookies.remove({ url, name: c.name }, () => {
      if (chrome.runtime.lastError) return;
      console.warn(`[attack] PREVENTED — removed weak session cookie "${c.name}" for ${c.domain}`);
    });
  },
};
