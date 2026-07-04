/**
 * Service-worker entry point. Constructs the engine, registers the active rule set, and initializes every
 * signal source. MV3 service workers are ephemeral — registering event listeners at the top level (as each
 * signal source's `init` does) is what lets the worker wake on the event.
 */
import { DEFAULT_POLICY } from '0x13d-attack-rules-community';
import { Engine } from './engine';
import { buildRules } from '0x13d-attack-rules-community';
import { refreshBadge } from '0x13d-attack-rules-community';
import { loadUserRulesInto } from './userRules';
import { getManagedPolicy, mergePolicy, userRulesAllowed } from './policy/managed';
import { hydrateDisabledByEdr } from '0x13d-attack-rules-community';
import managementSignals from './signals/management';
import webNavigationSignals from './signals/webNavigation';
import cookieSignals from './signals/cookie';
import downloadSignals from './signals/downloads';

const engine = new Engine();

// Signal sources + the message handler register their listeners SYNCHRONOUSLY at top level so the ephemeral
// service worker wakes on events. Rules depend on the (async) managed policy, so they load just after.
const signalSources = [managementSignals, webNavigationSignals, cookieSignals, downloadSignals];
for (const source of signalSources) source.init(engine);

// Resolve the effective policy (a managed org policy overrides local defaults), then install the built-in
// rules and — unless the org disables it — the user's authored rules.
(async () => {
  await hydrateDisabledByEdr(); // restore the EDR-disabled-id set so T1176 tamper survives the ephemeral worker
  const managed = await getManagedPolicy();
  const policy = mergePolicy(DEFAULT_POLICY, managed);
  engine.registerRules(buildRules(policy));

  if (userRulesAllowed(managed)) {
    await loadUserRulesInto(engine, policy);
  } else {
    engine.setUserRules([]); // org locked out user rules
  }
  void refreshBadge();
  const counts = engine.describeRules();
  console.log(
    `[attack] Browser EDR ready — ${counts.builtin.length} built-in + ${counts.user.length} user rule(s), ` +
      `${signalSources.length} signal source(s)` +
      (managed ? ` — managed by ${managed.orgName ?? 'your organization'}` : ''),
  );
})();

// Keep the toolbar badge correct across the ephemeral service worker: recompute whenever the stored alerts
// change (e.g. the popup acknowledges some). The initial compute runs in the policy IIFE above.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.alerts) void refreshBadge();
});

// Messages from the popup + the admin dashboard (options page).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg?.type) {
    case 'attack:getTrace':
      sendResponse(engine.getTrace());
      return false;
    case 'attack:getRules':
      sendResponse(engine.describeRules());
      return false;
    case 'attack:reloadUserRules':
      (async () => {
        const managed = await getManagedPolicy();
        if (userRulesAllowed(managed)) await loadUserRulesInto(engine, mergePolicy(DEFAULT_POLICY, managed));
        else engine.setUserRules([]); // org locked out user rules — never load them
        sendResponse({ ok: true });
      })();
      return true; // async response
    default:
      return false;
  }
});
