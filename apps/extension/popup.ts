/**
 * The popup alert console: a table of all detections, **unacknowledged in red**, with per-row and bulk
 * acknowledge + clear. Reads/writes the same `chrome.storage.local` log the service worker writes; the
 * background keeps the badge in sync via a `storage.onChanged` listener.
 */
import { AlertRecord, getAlerts, acknowledge, acknowledgeAll, clearAlerts } from '0x13d-attack-rules-community';

const rowsEl = document.getElementById('rows') as HTMLTableSectionElement;
const emptyEl = document.getElementById('empty') as HTMLDivElement;
const summaryEl = document.getElementById('summary') as HTMLDivElement;
const ackAllBtn = document.getElementById('ackAll') as HTMLButtonElement;
const exportTraceBtn = document.getElementById('exportTrace') as HTMLButtonElement;
const rulesBtn = document.getElementById('rules') as HTMLButtonElement;
const clearBtn = document.getElementById('clear') as HTMLButtonElement;

rulesBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());

function fmtTime(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function text(el: HTMLElement, value: string): void {
  el.textContent = value;
}

function render(alerts: AlertRecord[]): void {
  rowsEl.replaceChildren();
  const unacked = alerts.filter((a) => !a.acknowledged).length;

  text(summaryEl, alerts.length === 0 ? '—' : `${alerts.length} detection(s) · ${unacked} unacknowledged`);
  emptyEl.hidden = alerts.length > 0;
  ackAllBtn.disabled = unacked === 0;
  clearBtn.disabled = alerts.length === 0;

  for (const a of alerts) {
    const tr = document.createElement('tr');
    if (!a.acknowledged) tr.className = 'unack';

    const tech = document.createElement('td');
    tech.className = 'tech';
    text(tech, a.technique);

    const detail = document.createElement('td');
    const name = document.createElement('div');
    text(name, a.extensionName ? `${a.ruleName} — ${a.extensionName}` : a.ruleName);
    const reasons = document.createElement('div');
    reasons.className = 'reasons';
    text(reasons, a.reasons.join(' · '));
    detail.append(name, reasons);

    const when = document.createElement('td');
    when.className = 'when';
    text(when, fmtTime(a.timestamp));

    const status = document.createElement('td');
    status.className = 'status';
    if (a.acknowledged) {
      text(status, 'acknowledged');
    } else {
      const dot = document.createElement('span');
      dot.className = 'dot';
      text(dot, '● ');
      const btn = document.createElement('button');
      text(btn, 'Acknowledge');
      btn.addEventListener('click', async () => {
        await acknowledge([a.id]);
        await refresh();
      });
      status.append(dot, btn);
    }

    tr.append(tech, detail, when, status);
    rowsEl.append(tr);
  }
}

async function refresh(): Promise<void> {
  render(await getAlerts());
}

ackAllBtn.addEventListener('click', async () => {
  await acknowledgeAll();
  await refresh();
});

clearBtn.addEventListener('click', async () => {
  await clearAlerts();
  await refresh();
});

// Fetch the engine's in-memory event trace and download it as JSON — the input the brochure replay /
// admin dashboard consume. No `downloads` permission needed: a blob URL + an anchor click under a user gesture.
exportTraceBtn.addEventListener('click', async () => {
  const doc = await chrome.runtime.sendMessage({ type: 'attack:getTrace' });
  const text = JSON.stringify(doc, null, 2);
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'attack-trace.json';
  a.click();
  URL.revokeObjectURL(url);
});

void refresh();
