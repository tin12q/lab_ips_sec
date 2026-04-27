const state = {
  offset: 0,
  maxAlerts: 120,
  alerts: [],
};

const elements = {
  connectionStatus: document.querySelector('#connection-status'),
  heroPanel: document.querySelector('.hero-panel'),
  ruleCount: document.querySelector('#rule-count'),
  rulesMeta: document.querySelector('#rules-meta'),
  alertCount: document.querySelector('#alert-count'),
  alertsMeta: document.querySelector('#alerts-meta'),
  dropCount: document.querySelector('#drop-count'),
  tailOffset: document.querySelector('#tail-offset'),
  topSid: document.querySelector('#top-sid'),
  topSidMeta: document.querySelector('#top-sid-meta'),
  tcpCount: document.querySelector('#tcp-count'),
  icmpCount: document.querySelector('#icmp-count'),
  latestAction: document.querySelector('#latest-action'),
  alertFeed: document.querySelector('#alert-feed'),
  clearAlerts: document.querySelector('#clear-alerts'),
  reloadRules: document.querySelector('#reload-rules'),
  saveRules: document.querySelector('#save-rules'),
  formatRules: document.querySelector('#format-rules'),
  rulesText: document.querySelector('#rules-text'),
  writeToken: document.querySelector('#write-token'),
  saveMessage: document.querySelector('#save-message'),
  ruleHints: document.querySelector('#rule-hints'),
  snippets: document.querySelectorAll('.snippet'),
};

async function readJson(url, options = {}) {
  const response = await fetch(url, {
    cache: 'no-store',
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    const message = payload.details ? payload.details.join('; ') : payload.error || response.statusText;
    throw new Error(message);
  }
  return payload;
}

function setConnection(isLive) {
  elements.heroPanel.classList.toggle('is-live', isLive);
  elements.connectionStatus.textContent = isLive ? 'Live' : 'Disconnected';
}

function setSaveMessage(message, kind = '') {
  elements.saveMessage.textContent = message;
  elements.saveMessage.className = kind;
}

function activeRuleLines() {
  return elements.rulesText.value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

function updateRuleHints() {
  const lines = activeRuleLines();
  const missingMsg = lines.filter((line) => !/(^|[;(])\s*msg\s*:/i.test(line)).length;
  const missingSid = lines.filter((line) => !/;\s*sid\s*:\s*[1-9][0-9]*\s*;/i.test(line)).length;
  const duplicateSids = new Set();
  const seenSids = new Set();

  for (const line of lines) {
    const sid = line.match(/;\s*sid\s*:\s*([1-9][0-9]*)\s*;/i)?.[1];
    if (!sid) {
      continue;
    }
    if (seenSids.has(sid)) {
      duplicateSids.add(sid);
    }
    seenSids.add(sid);
  }

  const hints = [`${lines.length} active rules`];
  if (missingMsg > 0) {
    hints.push(`${missingMsg} missing msg`);
  }
  if (missingSid > 0) {
    hints.push(`${missingSid} missing sid`);
  }
  if (duplicateSids.size > 0) {
    hints.push(`duplicate sid: ${Array.from(duplicateSids).join(', ')}`);
  }

  elements.ruleHints.replaceChildren(...hints.map((hint) => {
    const item = document.createElement('span');
    item.textContent = hint;
    item.className = hint.includes('missing') || hint.includes('duplicate') ? 'hint-bad' : 'hint-good';
    return item;
  }));
  elements.ruleCount.textContent = String(lines.length);
}

async function loadStatus() {
  const status = await readJson('/api/status');
  elements.rulesMeta.textContent = `${status.rulesSize} bytes · ${status.rulesPath}`;
  elements.alertsMeta.textContent = `${status.alertSize} bytes · ${status.alertPath}`;
  setConnection(true);
}

async function loadRules() {
  const payload = await readJson('/api/rules');
  elements.rulesText.value = payload.rules;
  updateRuleHints();
  setSaveMessage(`Loaded ${payload.path}`, 'is-ok');
}

function parseAlert(line) {
  const sid = line.match(/\[1:(\d+):\d+\]/)?.[1] || 'unknown';
  const message = line.match(/\] ([^\[]+) \[\*\*\]/)?.[1]?.trim() || 'Unknown alert';
  const action = line.match(/\[Action: ([^\]]+)\]/)?.[1] || 'unknown';
  const proto = line.match(/\{([^}]+)\}/)?.[1] || 'unknown';
  const flow = line.match(/\} (.+)$/)?.[1] || '';
  return { line, sid, message, action, proto, flow };
}

function renderAlert(alert) {
  const item = document.createElement('li');
  const header = document.createElement('div');
  const sid = document.createElement('span');
  const action = document.createElement('span');
  const message = document.createElement('strong');
  const flow = document.createElement('code');

  header.className = 'alert-line-heading';
  sid.className = 'alert-chip sid-chip';
  action.className = `alert-chip action-${alert.action}`;
  message.className = 'alert-message';
  flow.className = 'alert-flow';

  sid.textContent = `SID ${alert.sid}`;
  action.textContent = alert.action;
  message.textContent = alert.message;
  flow.textContent = alert.flow || alert.line;

  header.append(sid, action, message);
  item.append(header, flow);
  return item;
}

function updateAlertStats() {
  const sidCounts = new Map();
  let dropCount = 0;
  let tcpCount = 0;
  let icmpCount = 0;

  for (const alert of state.alerts) {
    sidCounts.set(alert.sid, (sidCounts.get(alert.sid) || 0) + 1);
    if (alert.action === 'drop') {
      dropCount += 1;
    }
    if (alert.proto === 'TCP') {
      tcpCount += 1;
    }
    if (alert.proto === 'ICMP') {
      icmpCount += 1;
    }
  }

  const top = Array.from(sidCounts.entries()).sort((a, b) => b[1] - a[1])[0];
  elements.alertCount.textContent = String(state.alerts.length);
  elements.dropCount.textContent = String(dropCount);
  elements.tcpCount.textContent = String(tcpCount);
  elements.icmpCount.textContent = String(icmpCount);
  elements.latestAction.textContent = state.alerts.at(-1)?.action || '—';
  elements.topSid.textContent = top ? top[0] : '—';
  elements.topSidMeta.textContent = top ? `${top[1]} alerts in current view` : 'No alerts yet';
}

function appendAlerts(lines) {
  for (const line of lines) {
    state.alerts.push(parseAlert(line));
  }

  while (state.alerts.length > state.maxAlerts) {
    state.alerts.shift();
  }

  elements.alertFeed.replaceChildren(...state.alerts.map(renderAlert));
  updateAlertStats();

  if (lines.length > 0) {
    elements.alertFeed.lastElementChild.scrollIntoView({ block: 'nearest' });
  }
}

async function pollAlerts() {
  const payload = await readJson(`/api/alerts?since=${state.offset}`);
  state.offset = payload.offset;
  elements.tailOffset.textContent = `${state.offset} bytes consumed`;
  if (payload.lines.length > 0) {
    appendAlerts(payload.lines);
  }
  setConnection(true);
}

async function saveRules() {
  setSaveMessage('Saving...');
  await readJson('/api/rules', {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Dashboard-Token': elements.writeToken.value,
    },
    body: elements.rulesText.value,
  });
  setSaveMessage('Rules saved with backup', 'is-ok');
  await loadStatus();
}

function insertSnippet(snippet) {
  const start = elements.rulesText.selectionStart;
  const end = elements.rulesText.selectionEnd;
  const current = elements.rulesText.value;
  const prefix = current.slice(0, start).replace(/\s*$/, '\n');
  const suffix = current.slice(end).replace(/^\s*/, '\n');
  elements.rulesText.value = `${prefix}${snippet}${suffix}`.trimStart();
  elements.rulesText.focus();
  elements.rulesText.selectionStart = prefix.length + snippet.length;
  elements.rulesText.selectionEnd = elements.rulesText.selectionStart;
  updateRuleHints();
}

function formatRules() {
  const formatted = elements.rulesText.value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join('\n\n');
  elements.rulesText.value = `${formatted}\n`;
  updateRuleHints();
  setSaveMessage('Editor spacing formatted', 'is-ok');
}

async function safeRun(action, options = {}) {
  try {
    await action();
  } catch (error) {
    setConnection(false);
    if (options.showSaveError !== false) {
      setSaveMessage(error.message, 'is-error');
    }
  }
}

elements.clearAlerts.addEventListener('click', () => {
  state.alerts = [];
  elements.alertFeed.replaceChildren();
  updateAlertStats();
});

elements.reloadRules.addEventListener('click', () => safeRun(loadRules));
elements.saveRules.addEventListener('click', () => safeRun(saveRules));
elements.formatRules.addEventListener('click', formatRules);
elements.rulesText.addEventListener('input', updateRuleHints);
elements.rulesText.addEventListener('dragover', (event) => event.preventDefault());
elements.rulesText.addEventListener('drop', (event) => {
  event.preventDefault();
  const snippet = event.dataTransfer.getData('text/plain');
  if (snippet) {
    insertSnippet(snippet);
  }
});

for (const snippet of elements.snippets) {
  snippet.addEventListener('dragstart', (event) => {
    event.dataTransfer.setData('text/plain', snippet.dataset.snippet);
  });
  snippet.addEventListener('click', () => insertSnippet(snippet.dataset.snippet));
}

safeRun(async () => {
  await loadStatus();
  await loadRules();
  await pollAlerts();
});

window.setInterval(() => safeRun(loadStatus, { showSaveError: false }), 5000);
window.setInterval(() => safeRun(pollAlerts, { showSaveError: false }), 1000);
