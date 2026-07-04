/**
 * The admin dashboard (ATK-207): list active rules, and add/enable/disable/remove **declarative** user rules.
 * Imported rules are validated (ADR-002) before storage; the background hot-reloads them via a message.
 */
import { getUserRules, setUserRules, validateRule } from './src/userRules';
import { getManagedPolicy, userRulesAllowed, type ManagedPolicy } from './src/policy/managed';
import type { AuthoredRule } from './src/schema/types';
import type { RuleSummary } from './src/engine';

const builtinEl = document.getElementById('builtin') as HTMLDivElement;
const userEl = document.getElementById('user') as HTMLDivElement;
const jsonEl = document.getElementById('json') as HTMLTextAreaElement;
const addBtn = document.getElementById('add') as HTMLButtonElement;
const exampleBtn = document.getElementById('example') as HTMLButtonElement;
const msgEl = document.getElementById('msg') as HTMLSpanElement;
const bannerEl = document.getElementById('banner') as HTMLDivElement;

let managed: ManagedPolicy | null = null;
const locked = () => managed !== null && !userRulesAllowed(managed);

const EXAMPLE: AuthoredRule = {
  id: 'user.t1176.dev-extensions',
  name: 'Block all developer-loaded extensions',
  technique: 'T1176.001',
  scope: 'management',
  condition: { field: 'payload.installType', op: 'eq', value: 'development' },
  responses: ['alert', 'disableExtension'],
  enabled: true,
};

function el(tag: string, className?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

function ruleRow(s: { id: string; name: string; technique: string; scope: string[] }, source: 'builtin' | 'user'): HTMLElement {
  const row = el('div', 'rule');
  row.append(el('span', 'tech', s.technique));
  const meta = el('div', 'meta');
  meta.append(el('div', 'name', s.name));
  meta.append(el('div', 'scope', `scope: ${s.scope.join(', ')}`));
  row.append(meta);
  row.append(el('span', 'src', source));
  return row;
}

async function reloadEngine(): Promise<void> {
  await chrome.runtime.sendMessage({ type: 'attack:reloadUserRules' });
}

async function renderBuiltin(): Promise<void> {
  const res = (await chrome.runtime.sendMessage({ type: 'attack:getRules' })) as { builtin: RuleSummary[] };
  builtinEl.replaceChildren();
  if (!res?.builtin?.length) {
    builtinEl.append(el('div', 'empty', 'No built-in rules loaded.'));
    return;
  }
  for (const r of res.builtin) builtinEl.append(ruleRow(r, 'builtin'));
}

async function renderUser(): Promise<void> {
  const rules = await getUserRules();
  userEl.replaceChildren();
  if (rules.length === 0) {
    userEl.append(el('div', 'empty', 'No user rules yet. Add one below.'));
    return;
  }
  rules.forEach((rule, i) => {
    const row = ruleRow({ ...rule, scope: [rule.scope] }, 'user');

    if (locked()) {
      row.append(el('span', 'src', 'locked'));
      userEl.append(row);
      return; // org-managed: read-only, no toggle/remove
    }

    const toggle = el('label', 'toggle') as HTMLLabelElement;
    const cb = el('input') as HTMLInputElement;
    cb.type = 'checkbox';
    cb.checked = rule.enabled !== false;
    cb.addEventListener('change', async () => {
      const next = await getUserRules();
      next[i].enabled = cb.checked;
      await setUserRules(next);
      await reloadEngine();
    });
    toggle.append(cb, document.createTextNode('enabled'));

    const remove = el('button', 'danger', 'Remove') as HTMLButtonElement;
    remove.addEventListener('click', async () => {
      const next = (await getUserRules()).filter((r) => r.id !== rule.id);
      await setUserRules(next);
      await reloadEngine();
      await renderUser();
    });

    row.append(toggle, remove);
    userEl.append(row);
  });
}

function setMsg(text: string, kind: '' | 'err' | 'ok'): void {
  msgEl.textContent = text;
  msgEl.className = `msg ${kind}`;
}

addBtn.addEventListener('click', async () => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonEl.value);
  } catch (e) {
    setMsg(`Not valid JSON: ${(e as Error).message}`, 'err');
    return;
  }
  const result = validateRule(parsed);
  if (!result.ok) {
    setMsg(`Rejected:\n• ${result.errors.join('\n• ')}`, 'err');
    return;
  }
  const rule = parsed as AuthoredRule;
  const rules = await getUserRules();
  const without = rules.filter((r) => r.id !== rule.id); // replace on id collision
  without.push({ enabled: true, ...rule });
  await setUserRules(without);
  await reloadEngine();
  jsonEl.value = '';
  setMsg(`Added "${rule.name}".`, 'ok');
  await renderUser();
});

exampleBtn.addEventListener('click', () => {
  jsonEl.value = JSON.stringify(EXAMPLE, null, 2);
  setMsg('Example loaded — review, then Validate & add.', '');
});

async function applyManaged(): Promise<void> {
  managed = await getManagedPolicy();
  if (!managed) return;
  bannerEl.hidden = false;
  const org = managed.orgName ?? 'your organization';
  bannerEl.textContent = locked()
    ? `🔒 Settings controlled by ${org}. Adding or changing rules is disabled by policy.`
    : `🔒 Settings controlled by ${org}.`;
  if (locked()) {
    addBtn.disabled = true;
    exampleBtn.disabled = true;
    jsonEl.disabled = true;
    jsonEl.placeholder = 'Disabled by organization policy.';
  }
}

(async () => {
  await applyManaged();
  await renderBuiltin();
  await renderUser();
})();
