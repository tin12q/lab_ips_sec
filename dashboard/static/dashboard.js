const state = {
  offset: 0,
  maxAlerts: 120,
  alerts: [],
  isPolling: false,
  isSaving: false,
  lastSavedText: '',
  isDirty: false,
  autoScroll: true,
  filterDropOnly: false,
};

const ruleEditorState = {
  rules: [],
  editingRuleId: null,
  editorMode: 'list',
};

const elements = {
  connectionStatus: document.querySelector('#connection-status'),
  statusText: document.querySelector('.cyber-status-text'),
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
  clearSession: document.querySelector('#clear-session'),
  autoScroll: document.querySelector('#auto-scroll'),
  filterDrop: document.querySelector('#filter-drop'),
  validateRules: document.querySelector('#validate-rules'),
  reloadRules: document.querySelector('#reload-rules'),
  saveRules: document.querySelector('#save-rules'),
  formatRules: document.querySelector('#format-rules'),
  rulesText: document.querySelector('#rules-text'),
  writeToken: document.querySelector('#write-token'),
  saveMessage: document.querySelector('#save-message'),
  ruleHints: document.querySelector('#rule-hints'),
  dirtyIndicator: document.querySelector('#dirty-indicator'),
  snippets: document.querySelectorAll('.cyber-snippet'),
  modeListBtn: document.querySelector('#mode-list'),
  modeTextBtn: document.querySelector('#mode-text'),
  listMode: document.querySelector('#list-mode'),
  textMode: document.querySelector('#text-mode'),
  ruleList: document.querySelector('#rule-list'),
  ruleListCount: document.querySelector('#rule-list-count'),
  addRuleBtn: document.querySelector('#add-rule-btn'),
  ruleDialog: document.querySelector('#rule-dialog'),
  ruleForm: document.querySelector('#rule-form'),
  dialogTitle: document.querySelector('#dialog-title'),
  dialogClose: document.querySelector('#rule-dialog-close'),
  dialogCancel: document.querySelector('#rule-dialog-cancel'),
  tabBtns: document.querySelectorAll('.cyber-tab'),
};

let ruleIdCounter = 1;

function nextRuleId() {
  const id = `rule-${Date.now()}-${ruleIdCounter}`;
  ruleIdCounter += 1;
  return id;
}

function escapeOptionValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function splitOptionTokens(optionsStr) {
  const tokens = [];
  let current = '';
  let inQuote = false;
  let escaped = false;

  for (const char of optionsStr) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === '\\') {
      current += char;
      escaped = true;
      continue;
    }

    if (char === '"') {
      inQuote = !inQuote;
      current += char;
      continue;
    }

    if (char === ';' && !inQuote) {
      const trimmed = current.trim();
      if (trimmed) {
        tokens.push(trimmed);
      }
      current = '';
      continue;
    }

    current += char;
  }

  const last = current.trim();
  if (last) {
    tokens.push(last);
  }
  return tokens;
}

function parseRuleOptions(optionsStr) {
  const options = {
    msg: '',
    sid: null,
    rev: 1,
    content: '',
    nocase: false,
    http_uri: false,
    http_header: false,
    http_client_body: false,
    pcre: '',
    flow: '',
    threshold: '',
    classtype: '',
    priority: null,
    itype: null,
    icode: null,
    flags: '',
    reference: '',
    extra: [],
  };

  const tokens = splitOptionTokens(optionsStr);

  for (const token of tokens) {
    const lower = token.toLowerCase();

    if (lower === 'nocase') {
      options.nocase = true;
      continue;
    }

    if (lower === 'http_uri') {
      options.http_uri = true;
      continue;
    }

    if (lower === 'http_header') {
      options.http_header = true;
      continue;
    }

    if (lower === 'http_client_body') {
      options.http_client_body = true;
      continue;
    }

    const splitAt = token.indexOf(':');
    if (splitAt === -1) {
      options.extra.push(token);
      continue;
    }

    const key = token.slice(0, splitAt).trim().toLowerCase();
    const value = token.slice(splitAt + 1).trim();
    const quoted = value.startsWith('"') && value.endsWith('"')
      ? value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\')
      : value;

    if (key === 'msg') {
      options.msg = quoted;
      continue;
    }

    if (key === 'sid') {
      const sid = Number.parseInt(value, 10);
      options.sid = Number.isFinite(sid) && sid > 0 ? sid : null;
      continue;
    }

    if (key === 'rev') {
      const rev = Number.parseInt(value, 10);
      options.rev = Number.isFinite(rev) && rev > 0 ? rev : 1;
      continue;
    }

    if (key === 'content') {
      options.content = quoted;
      continue;
    }

    if (key === 'pcre') {
      options.pcre = quoted;
      continue;
    }

    if (key === 'flow') {
      options.flow = value;
      continue;
    }

    if (key === 'threshold') {
      options.threshold = value;
      continue;
    }

    if (key === 'classtype') {
      options.classtype = value;
      continue;
    }

    if (key === 'priority') {
      const priority = Number.parseInt(value, 10);
      options.priority = Number.isFinite(priority) ? priority : null;
      continue;
    }

    if (key === 'itype') {
      const itype = Number.parseInt(value, 10);
      options.itype = Number.isFinite(itype) ? itype : null;
      continue;
    }

    if (key === 'icode') {
      const icode = Number.parseInt(value, 10);
      options.icode = Number.isFinite(icode) ? icode : null;
      continue;
    }

    if (key === 'flags') {
      options.flags = value;
      continue;
    }

    if (key === 'reference') {
      options.reference = value;
      continue;
    }

    options.extra.push(token);
  }

  return options;
}

function parseRuleLine(line) {
  const match = line.match(/^(alert|drop|pass|log)\s+(ip|tcp|udp|icmp)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$/i);
  if (!match) {
    return null;
  }

  const [, action, protocol, srcIp, srcPort, dstIp, dstPort, optionsStr] = match;
  return {
    id: nextRuleId(),
    enabled: true,
    action: action.toLowerCase(),
    protocol: protocol.toLowerCase(),
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    options: parseRuleOptions(optionsStr),
  };
}

function parseRuleText(text) {
  const lines = text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const rules = [];

  for (const rawLine of lines) {
    let enabled = true;
    let line = rawLine;

    if (line.startsWith('#')) {
      enabled = false;
      line = line.slice(1).trim();
    }

    if (!line || line.startsWith('#')) {
      continue;
    }

    const parsed = parseRuleLine(line);
    if (!parsed) {
      continue;
    }

    parsed.enabled = enabled;
    rules.push(parsed);
  }

  return rules;
}

function serializeRule(rule) {
  const options = [];

  if (rule.options.msg) options.push(`msg:"${escapeOptionValue(rule.options.msg)}"`);
  if (rule.options.content) options.push(`content:"${escapeOptionValue(rule.options.content)}"`);
  if (rule.options.nocase) options.push('nocase');
  if (rule.options.http_uri) options.push('http_uri');
  if (rule.options.http_header) options.push('http_header');
  if (rule.options.http_client_body) options.push('http_client_body');
  if (rule.options.pcre) options.push(`pcre:"${escapeOptionValue(rule.options.pcre)}"`);
  if (rule.options.flow) options.push(`flow:${rule.options.flow}`);
  if (rule.options.threshold) options.push(`threshold:${rule.options.threshold}`);
  if (rule.options.classtype) options.push(`classtype:${rule.options.classtype}`);
  if (Number.isFinite(rule.options.priority)) options.push(`priority:${rule.options.priority}`);
  if (Number.isFinite(rule.options.itype)) options.push(`itype:${rule.options.itype}`);
  if (Number.isFinite(rule.options.icode)) options.push(`icode:${rule.options.icode}`);
  if (rule.options.flags) options.push(`flags:${rule.options.flags}`);
  if (rule.options.reference) options.push(`reference:${rule.options.reference}`);

  for (const extra of rule.options.extra || []) {
    if (extra.trim()) {
      options.push(extra.trim());
    }
  }

  if (Number.isFinite(rule.options.sid) && rule.options.sid > 0) options.push(`sid:${rule.options.sid}`);
  if (Number.isFinite(rule.options.rev) && rule.options.rev > 0) options.push(`rev:${rule.options.rev}`);

  const optionText = `${options.join('; ')};`;
  const ruleLine = `${rule.action} ${rule.protocol} ${rule.srcIp} ${rule.srcPort} -> ${rule.dstIp} ${rule.dstPort} (${optionText})`;
  return rule.enabled ? ruleLine : `# ${ruleLine}`;
}

function serializeAllRules(rules) {
  if (rules.length === 0) {
    return '';
  }
  return `${rules.map(serializeRule).join('\n\n')}\n`;
}

function currentRulesText() {
  if (ruleEditorState.editorMode === 'text') {
    return elements.rulesText.value;
  }
  return serializeAllRules(ruleEditorState.rules);
}

function setConnection(isLive) {
  elements.connectionStatus.dataset.status = isLive ? 'live' : 'offline';
  elements.connectionStatus.textContent = isLive ? 'Live' : 'Offline';
  if (elements.statusText) {
    elements.statusText.textContent = isLive ? 'SYSTEM_LIVE' : 'SYSTEM_OFFLINE';
  }
}

function setSaveMessage(message, kind = '') {
  elements.saveMessage.textContent = message;
  elements.saveMessage.className = `cyber-message ${kind}`;
}

function activeRuleLinesFromText(text) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

function updateRuleHints() {
  const lines = activeRuleLinesFromText(currentRulesText());
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
    item.className = hint.includes('missing') || hint.includes('duplicate') ? 'cyber-hint-bad' : 'cyber-hint-good';
    return item;
  }));
  elements.ruleCount.textContent = String(lines.length);
}

function checkDirty() {
  const currentText = currentRulesText();
  state.isDirty = currentText !== state.lastSavedText;

  if (elements.dirtyIndicator) {
    elements.dirtyIndicator.hidden = !state.isDirty;
  }

  if (elements.saveRules) {
    elements.saveRules.disabled = !state.isDirty || state.isSaving;
  }
}

function markDirty() {
  checkDirty();
  updateRuleHints();
}

function ruleSidUsed(sid, excludeRuleId = null) {
  return ruleEditorState.rules.some((rule) => rule.id !== excludeRuleId && rule.options.sid === sid);
}

function switchDialogTab(tabName) {
  for (const btn of elements.tabBtns) {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  }

  for (const tab of elements.ruleForm.querySelectorAll('.cyber-form-tab')) {
    const active = tab.id === `tab-${tabName}`;
    tab.classList.toggle('active', active);
    tab.hidden = !active;
  }
}

function openRuleDialog(ruleId = null) {
  const form = elements.ruleForm;
  switchDialogTab('basic');

  if (!ruleId) {
    const maxSid = Math.max(999999, ...ruleEditorState.rules.map((rule) => rule.options.sid || 0));
    form.reset();
    form.elements.srcIp.value = 'any';
    form.elements.srcPort.value = 'any';
    form.elements.dstIp.value = '$HOME_NET';
    form.elements.dstPort.value = 'any';
    form.elements.rev.value = '1';
    form.elements.sid.value = String(maxSid + 1);
    ruleEditorState.editingRuleId = null;
    elements.dialogTitle.textContent = 'ADD_RULE';
    elements.ruleDialog.showModal();
    return;
  }

  const rule = ruleEditorState.rules.find((item) => item.id === ruleId);
  if (!rule) {
    return;
  }

  form.reset();
  form.elements.action.value = rule.action;
  form.elements.protocol.value = rule.protocol;
  form.elements.srcIp.value = rule.srcIp;
  form.elements.srcPort.value = rule.srcPort;
  form.elements.dstIp.value = rule.dstIp;
  form.elements.dstPort.value = rule.dstPort;
  form.elements.msg.value = rule.options.msg || '';
  form.elements.sid.value = rule.options.sid ? String(rule.options.sid) : '';
  form.elements.rev.value = rule.options.rev ? String(rule.options.rev) : '1';
  form.elements.content.value = rule.options.content || '';
  form.elements.nocase.checked = Boolean(rule.options.nocase);
  form.elements.pcre.value = rule.options.pcre || '';
  form.elements.itype.value = Number.isFinite(rule.options.itype) ? String(rule.options.itype) : '';
  form.elements.icode.value = Number.isFinite(rule.options.icode) ? String(rule.options.icode) : '';
  form.elements.flags.value = rule.options.flags || '';
  form.elements.flow.value = rule.options.flow || '';
  form.elements.threshold.value = rule.options.threshold || '';
  form.elements.classtype.value = rule.options.classtype || '';
  form.elements.priority.value = Number.isFinite(rule.options.priority) ? String(rule.options.priority) : '';
  form.elements.reference.value = rule.options.reference || '';
  form.elements.rawOptions.value = (rule.options.extra || []).join('; ');

  if (rule.options.http_uri) form.elements.httpBuffer.value = 'http_uri';
  else if (rule.options.http_header) form.elements.httpBuffer.value = 'http_header';
  else if (rule.options.http_client_body) form.elements.httpBuffer.value = 'http_client_body';
  else form.elements.httpBuffer.value = '';

  ruleEditorState.editingRuleId = ruleId;
  elements.dialogTitle.textContent = 'EDIT_RULE';
  elements.ruleDialog.showModal();
}

function closeRuleDialog() {
  elements.ruleDialog.close();
  ruleEditorState.editingRuleId = null;
}

function buildRuleFromForm(form) {
  const formData = new FormData(form);
  const sid = Number.parseInt(String(formData.get('sid') || ''), 10);
  const rev = Number.parseInt(String(formData.get('rev') || '1'), 10);
  const priorityRaw = String(formData.get('priority') || '').trim();
  const itypeRaw = String(formData.get('itype') || '').trim();
  const icodeRaw = String(formData.get('icode') || '').trim();
  const rawOptions = String(formData.get('rawOptions') || '').trim();

  const options = {
    msg: String(formData.get('msg') || '').trim(),
    sid: Number.isFinite(sid) && sid > 0 ? sid : null,
    rev: Number.isFinite(rev) && rev > 0 ? rev : 1,
    content: String(formData.get('content') || '').trim(),
    nocase: formData.get('nocase') === 'on',
    http_uri: false,
    http_header: false,
    http_client_body: false,
    pcre: String(formData.get('pcre') || '').trim(),
    flow: String(formData.get('flow') || '').trim(),
    threshold: String(formData.get('threshold') || '').trim(),
    classtype: String(formData.get('classtype') || '').trim(),
    priority: priorityRaw ? Number.parseInt(priorityRaw, 10) : null,
    itype: itypeRaw ? Number.parseInt(itypeRaw, 10) : null,
    icode: icodeRaw ? Number.parseInt(icodeRaw, 10) : null,
    flags: String(formData.get('flags') || '').trim(),
    reference: String(formData.get('reference') || '').trim(),
    extra: rawOptions
      ? rawOptions
          .split(';')
          .map((item) => item.trim())
          .filter(Boolean)
      : [],
  };

  const httpBuffer = String(formData.get('httpBuffer') || '');
  if (httpBuffer === 'http_uri') options.http_uri = true;
  if (httpBuffer === 'http_header') options.http_header = true;
  if (httpBuffer === 'http_client_body') options.http_client_body = true;

  return {
    id: ruleEditorState.editingRuleId || nextRuleId(),
    enabled: true,
    action: String(formData.get('action') || 'alert').toLowerCase(),
    protocol: String(formData.get('protocol') || 'tcp').toLowerCase(),
    srcIp: String(formData.get('srcIp') || 'any').trim() || 'any',
    srcPort: String(formData.get('srcPort') || 'any').trim() || 'any',
    dstIp: String(formData.get('dstIp') || 'any').trim() || 'any',
    dstPort: String(formData.get('dstPort') || 'any').trim() || 'any',
    options,
  };
}

function createRuleCard(rule) {
  const card = document.createElement('article');
  card.className = `rule-card${rule.enabled ? '' : ' is-disabled'}`;
  card.dataset.ruleId = rule.id;

  const httpBuffer = rule.options.http_uri
    ? 'http_uri'
    : rule.options.http_header
      ? 'http_header'
      : rule.options.http_client_body
        ? 'http_client_body'
        : '';

  card.innerHTML = `
    <div class="rule-card-header">
      <label class="rule-toggle">
        <input type="checkbox" data-rule-enable="${rule.id}" ${rule.enabled ? 'checked' : ''}>
        <span>ENABLED</span>
      </label>
      <span class="rule-action-badge action-${rule.action}">${rule.action.toUpperCase()}</span>
      <span class="rule-protocol">${rule.protocol.toUpperCase()}</span>
      <span class="rule-sid">SID: ${rule.options.sid || 'N/A'}</span>
    </div>
    <div class="rule-card-body">
      <p class="rule-message">${rule.options.msg || 'No message'}</p>
      <code class="rule-flow">${rule.srcIp}:${rule.srcPort} → ${rule.dstIp}:${rule.dstPort}</code>
      <div class="rule-meta">
        ${rule.options.classtype ? `<span>${rule.options.classtype}</span>` : ''}
        ${Number.isFinite(rule.options.priority) ? `<span>Priority ${rule.options.priority}</span>` : ''}
        ${httpBuffer ? `<span>${httpBuffer}</span>` : ''}
      </div>
    </div>
    <div class="rule-card-actions">
      <button type="button" class="cyber-btn" data-rule-edit="${rule.id}">EDIT</button>
      <button type="button" class="cyber-btn cyber-btn-danger" data-rule-delete="${rule.id}">DELETE</button>
    </div>
  `;

  return card;
}

function renderRuleList() {
  elements.ruleList.replaceChildren(...ruleEditorState.rules.map(createRuleCard));
  elements.ruleListCount.textContent = String(ruleEditorState.rules.length);
}

function switchEditorMode(mode) {
  if (mode === ruleEditorState.editorMode) {
    return;
  }

  if (mode === 'text') {
    elements.rulesText.value = serializeAllRules(ruleEditorState.rules);
  } else {
    ruleEditorState.rules = parseRuleText(elements.rulesText.value);
    renderRuleList();
  }

  ruleEditorState.editorMode = mode;
  elements.listMode.hidden = mode !== 'list';
  elements.textMode.hidden = mode !== 'text';
  elements.modeListBtn.classList.toggle('active', mode === 'list');
  elements.modeTextBtn.classList.toggle('active', mode === 'text');
  updateRuleHints();
  checkDirty();
}

function toggleRuleEnabled(ruleId) {
  const rule = ruleEditorState.rules.find((item) => item.id === ruleId);
  if (!rule) {
    return;
  }

  rule.enabled = !rule.enabled;
  renderRuleList();
  markDirty();
}

function deleteRule(ruleId) {
  if (!confirm('Delete this rule?')) {
    return;
  }

  ruleEditorState.rules = ruleEditorState.rules.filter((rule) => rule.id !== ruleId);
  renderRuleList();
  markDirty();
}

function handleRuleFormSubmit(event) {
  event.preventDefault();
  const rule = buildRuleFromForm(elements.ruleForm);

  if (!rule.options.sid || !rule.options.msg) {
    setSaveMessage('Rule requires msg and positive sid', 'is-error');
    return;
  }

  if (ruleSidUsed(rule.options.sid, rule.id)) {
    setSaveMessage(`SID ${rule.options.sid} is already used`, 'is-error');
    return;
  }

  if (ruleEditorState.editingRuleId) {
    const index = ruleEditorState.rules.findIndex((item) => item.id === rule.id);
    if (index !== -1) {
      rule.enabled = ruleEditorState.rules[index].enabled;
      ruleEditorState.rules[index] = rule;
    }
  } else {
    ruleEditorState.rules.push(rule);
  }

  renderRuleList();
  closeRuleDialog();
  markDirty();
}

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

async function loadStatus() {
  const status = await readJson('/api/status');
  elements.rulesMeta.textContent = `${status.rulesSize} bytes · ${status.rulesPath}`;
  elements.alertsMeta.textContent = `${status.alertSize} bytes · ${status.alertPath}`;
  setConnection(true);
}

async function loadRules() {
  const payload = await readJson('/api/rules');
  const rulesText = payload.rules;

  ruleEditorState.rules = parseRuleText(rulesText);
  renderRuleList();
  elements.rulesText.value = rulesText;
  state.lastSavedText = rulesText;
  state.isDirty = false;

  if (elements.dirtyIndicator) {
    elements.dirtyIndicator.hidden = true;
  }
  if (elements.saveRules) {
    elements.saveRules.disabled = true;
  }

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
  const timestamp = document.createElement('span');
  const sid = document.createElement('span');
  const action = document.createElement('span');
  const message = document.createElement('strong');
  const flow = document.createElement('code');

  header.className = 'alert-line-heading';
  timestamp.className = 'alert-timestamp';
  sid.className = 'alert-chip sid-chip';
  action.className = `alert-chip action-${alert.action}`;
  message.className = 'alert-message';
  flow.className = 'alert-flow';

  const now = new Date();
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  timestamp.textContent = `[${timeStr}]`;
  sid.textContent = `SID ${alert.sid}`;
  action.textContent = alert.action;
  message.textContent = alert.message;
  flow.textContent = alert.flow || alert.line;

  header.append(timestamp, sid, action, message);
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

function renderAlerts() {
  const alertsToShow = state.filterDropOnly
    ? state.alerts.filter((alert) => alert.action === 'drop')
    : state.alerts;

  elements.alertFeed.replaceChildren(...alertsToShow.map(renderAlert));
}

function appendAlerts(lines) {
  for (const line of lines) {
    state.alerts.push(parseAlert(line));
  }

  while (state.alerts.length > state.maxAlerts) {
    state.alerts.shift();
  }

  renderAlerts();
  updateAlertStats();

  if (lines.length > 0 && state.autoScroll) {
    elements.alertFeed.lastElementChild?.scrollIntoView({ block: 'nearest' });
  }
}

async function pollAlertsLive() {
  if (state.isPolling) return;
  state.isPolling = true;

  try {
    const payload = await readJson(`/api/alerts/live?since=${state.offset}&timeout=1200`);
    state.offset = payload.offset;
    elements.tailOffset.textContent = `${state.offset} bytes consumed`;
    if (payload.lines.length > 0) {
      appendAlerts(payload.lines);
    }
    setConnection(true);
  } finally {
    state.isPolling = false;
  }
}

async function alertLoop() {
  while (true) {
    try {
      await pollAlertsLive();
    } catch (error) {
      setConnection(false);
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

async function saveRules() {
  if (state.isSaving || !state.isDirty) {
    return;
  }

  state.isSaving = true;
  elements.saveRules.disabled = true;
  elements.saveRules.classList.add('is-saving');
  setSaveMessage('Saving and applying rules...');

  try {
    if (ruleEditorState.editorMode === 'text') {
      ruleEditorState.rules = parseRuleText(elements.rulesText.value);
      renderRuleList();
    }

    const textPayload = serializeAllRules(ruleEditorState.rules);
    const payload = await readJson('/api/rules', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Dashboard-Token': elements.writeToken.value,
      },
      body: textPayload,
    });

    elements.rulesText.value = textPayload;
    state.lastSavedText = textPayload;
    state.isDirty = false;
    checkDirty();

    if (payload.reloadError) {
      setSaveMessage(`Rules saved but IPS reload failed: ${payload.reloadError}`, 'is-error');
    } else {
      setSaveMessage('Rules saved and IPS reload triggered', 'is-ok');
    }

    await loadStatus();
  } finally {
    state.isSaving = false;
    elements.saveRules.classList.remove('is-saving');
    checkDirty();
  }
}

function insertSnippet(snippet) {
  if (ruleEditorState.editorMode === 'list') {
    switchEditorMode('text');
  }

  const start = elements.rulesText.selectionStart;
  const end = elements.rulesText.selectionEnd;
  const current = elements.rulesText.value;
  const prefix = current.slice(0, start).replace(/\s*$/, '\n');
  const suffix = current.slice(end).replace(/^\s*/, '\n');
  elements.rulesText.value = `${prefix}${snippet}${suffix}`.trimStart();
  elements.rulesText.focus();
  elements.rulesText.selectionStart = prefix.length + snippet.length;
  elements.rulesText.selectionEnd = elements.rulesText.selectionStart;
  markDirty();
}

function formatRules() {
  if (ruleEditorState.editorMode !== 'text') {
    switchEditorMode('text');
  }

  const formatted = elements.rulesText.value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .join('\n\n');
  elements.rulesText.value = formatted ? `${formatted}\n` : '';
  markDirty();
  setSaveMessage('Editor spacing formatted', 'is-ok');
}

async function clearSession() {
  if (!confirm('Clear all alerts from the log file? This cannot be undone.')) {
    return;
  }

  try {
    await readJson('/api/alerts/clear', {
      method: 'POST',
      headers: {
        'X-Dashboard-Token': elements.writeToken.value,
      },
    });

    state.offset = 0;
    state.alerts = [];
    elements.alertFeed.replaceChildren();
    elements.tailOffset.textContent = '0 bytes consumed';
    updateAlertStats();
    setSaveMessage('Session cleared', 'is-ok');
  } catch (error) {
    setSaveMessage(`Clear failed: ${error.message}`, 'is-error');
  }
}

async function validateRules() {
  const lines = activeRuleLinesFromText(currentRulesText());
  if (lines.length === 0) {
    setSaveMessage('No active rules to validate', 'is-error');
    return;
  }

  const missingMsg = lines.filter((line) => !/(^|[;(])\s*msg\s*:/i.test(line));
  const missingSid = lines.filter((line) => !/;\s*sid\s*:\s*[1-9][0-9]*\s*;/i.test(line));
  const duplicateSids = new Set();
  const seenSids = new Set();

  for (const line of lines) {
    const sid = line.match(/;\s*sid\s*:\s*([1-9][0-9]*)\s*;/i)?.[1];
    if (sid) {
      if (seenSids.has(sid)) {
        duplicateSids.add(sid);
      }
      seenSids.add(sid);
    }
  }

  const errors = [];
  if (missingMsg.length > 0) {
    errors.push(`${missingMsg.length} rules missing msg`);
  }
  if (missingSid.length > 0) {
    errors.push(`${missingSid.length} rules missing sid`);
  }
  if (duplicateSids.size > 0) {
    errors.push(`Duplicate SIDs: ${Array.from(duplicateSids).join(', ')}`);
  }

  if (errors.length > 0) {
    setSaveMessage(`Validation failed: ${errors.join('; ')}`, 'is-error');
  } else {
    setSaveMessage(`${lines.length} rules validated successfully`, 'is-ok');
  }
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

if (elements.clearSession) {
  elements.clearSession.addEventListener('click', () => safeRun(clearSession));
}

if (elements.autoScroll) {
  elements.autoScroll.addEventListener('change', (event) => {
    state.autoScroll = event.target.checked;
  });
}

if (elements.filterDrop) {
  elements.filterDrop.addEventListener('change', (event) => {
    state.filterDropOnly = event.target.checked;
    renderAlerts();
  });
}

if (elements.validateRules) {
  elements.validateRules.addEventListener('click', validateRules);
}

elements.reloadRules.addEventListener('click', () => safeRun(loadRules));
elements.saveRules.addEventListener('click', () => safeRun(saveRules));
elements.formatRules.addEventListener('click', formatRules);
elements.rulesText.addEventListener('input', () => {
  if (ruleEditorState.editorMode === 'text') {
    markDirty();
  }
});
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

elements.modeListBtn.addEventListener('click', () => switchEditorMode('list'));
elements.modeTextBtn.addEventListener('click', () => switchEditorMode('text'));
elements.addRuleBtn.addEventListener('click', () => openRuleDialog());

elements.ruleList.addEventListener('click', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const editId = target.dataset.ruleEdit;
  if (editId) {
    openRuleDialog(editId);
    return;
  }

  const deleteId = target.dataset.ruleDelete;
  if (deleteId) {
    deleteRule(deleteId);
  }
});

elements.ruleList.addEventListener('change', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }

  const toggleId = target.dataset.ruleEnable;
  if (toggleId) {
    toggleRuleEnabled(toggleId);
  }
});

for (const tabBtn of elements.tabBtns) {
  tabBtn.addEventListener('click', () => switchDialogTab(tabBtn.dataset.tab));
}

elements.dialogClose.addEventListener('click', closeRuleDialog);
elements.dialogCancel.addEventListener('click', closeRuleDialog);
elements.ruleForm.addEventListener('submit', handleRuleFormSubmit);

safeRun(async () => {
  await loadStatus();
  await loadRules();
  await pollAlertsLive();
  alertLoop();
});

window.setInterval(() => safeRun(loadStatus, { showSaveError: false }), 5000);
