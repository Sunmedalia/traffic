'use strict';

// Rule file management and read-only rule testing (#/rules).

// ---- managed rules and local analysis ----
// Both are routed pages (#/rules, #/analysis) rather than overlays, so they can be
// linked, reloaded and used side by side with a session in another tab.
const ruleUI = { files: [], builtins: [], dir: '', loaded: false, selected: null, revision: '', dirty: false, busy: false, seq: 0, hash: '', parsed: null, checkSeq: 0, checking: 0, ptab: saved('rules-ptab', 'rules'), sid: saved('rules-session', ''), hits: null, hitsSeq: 0 };
// The rule test reruns on every edit once a sample is chosen, like a regex playground.
const testUI = { source: saved('test-source', 'session'), sample: null, seq: 0, picksSeq: 0, picking: 0, result: null, error: '' };
const TEST_REQUEST = 'GET /index.php?id=1%20union%20select%201,2 HTTP/1.1\nHost: example.com\nUser-Agent: sqlmap/1.7\n\n';
const jobUI = { job: null, history: [], poll: 0, completed: '', page: null };
const RULE_TEMPLATE = '- id: CUSTOM-001\n  version: 1\n  severity: medium\n  field: url\n  pattern: \'(?i)/suspicious-endpoint\'\n';
const NEW_RULE = '~new';
const ruleHash = (name) => (name === NEW_RULE ? '#/rules/' + NEW_RULE : name ? '#/rules/' + encodeURIComponent(name) : '#/rules');

function parsePage() {
  let match = /^#\/rules(?:\/([^?]+))?(?:\?(.*))?$/.exec(location.hash);
  if (match) {
    let name = '';
    try { name = match[1] ? decodeURIComponent(match[1]) : ''; } catch (_) { /* malformed link opens the built-in rules */ }
    const params = new URLSearchParams(match[2] || '');
    return { view: 'rules', name, sid: params.get('sid') || '', rid: params.get('rid') || '' };
  }
  match = /^#\/analysis(?:\?(.*))?$/.exec(location.hash);
  if (match) {
    const params = new URLSearchParams(match[1] || '');
    return { view: 'analysis', session: params.get('session') || '', rules: params.get('rules') || '' };
  }
  return null;
}

function ruleMessage(text, kind = '') {
  $('rules-validation').textContent = text;
  $('rules-validation').className = 'rules-message ' + kind;
}

function updateRuleControls() {
  const builtin = ruleUI.selected === '';
  const fresh = ruleUI.selected === null;
  $('rules-body').classList.toggle('readonly', builtin);
  $('rules-save').disabled = ruleUI.busy || builtin || (!ruleUI.dirty && !fresh);
  $('rules-validate').disabled = ruleUI.busy || builtin;
  $('rules-save').hidden = $('rules-validate').hidden = builtin;
  $('rules-new').disabled = $('rules-upload').disabled = ruleUI.busy;
  $('rules-delete').hidden = builtin || fresh;
  $('rules-delete').disabled = ruleUI.busy || !ruleUI.revision;
  $('rules-content').readOnly = builtin || ruleUI.busy;
  $('rules-name').readOnly = !fresh || ruleUI.busy;
  const ready = builtin || (ruleUI.revision && !ruleUI.dirty);
  const analyze = $('rules-analyze');
  analyze.classList.toggle('disabled', !ready);
  analyze.setAttribute('aria-disabled', String(!ready));
  analyze.title = ready ? '带着这份规则去选择会话' : '先保存文件，再用它分析';
  analyze.href = ready ? '#/analysis' + (builtin ? '' : '?rules=' + encodeURIComponent(ruleUI.selected)) : '';
  const tag = $('rules-state');
  const [label, tone] = builtin ? ['内置 · 只读', ''] : ruleUI.dirty ? ['未保存', 'warn'] : fresh ? ['新文件', 'warn'] : ['已保存', 'ok'];
  tag.textContent = label;
  tag.className = 'pill ' + tone;
}

function discardRuleEdits() { return !ruleUI.dirty || window.confirm('当前规则修改尚未保存，确定放弃？'); }

function renderRuleFiles() {
  const query = $('rules-search').value.trim().toLowerCase();
  const item = (name, label, sub) => h('a', { href: ruleHash(name), class: 'rule-file', 'aria-current': ruleUI.selected === name ? 'page' : null }, h('span', { class: 'name' }, label), h('small', {}, sub));
  set($('rules-files'),
    !query || '内置规则'.includes(query) ? item('', '内置规则', `${ruleUI.builtins.length} 条 · 只读 · 始终启用`) : null,
    ruleUI.selected === null ? item(NEW_RULE, ($('rules-name').value.trim() || '未命名') + ' *', '新文件 · 尚未保存') : null,
    ruleUI.files.filter((file) => !query || file.name.toLowerCase().includes(query))
      .map((file) => item(file.name, file.name + (ruleUI.dirty && ruleUI.selected === file.name ? ' *' : ''), `${number(file.size)} 字节 · ${relativeTime(file.modified) || formatTime(file.modified)}`)));
  $('rules-summary').textContent = `${ruleUI.files.length} 个文件`;
  $('rules-dir').textContent = ruleUI.dir;
}

async function refreshRuleLibrary() {
  const data = await api('rules');
  ruleUI.files = data.files || [];
  ruleUI.builtins = data.builtin_rules || [];
  ruleUI.dir = data.dir || '';
  ruleUI.loaded = true;
  renderRuleFiles();
  renderRuleOptions();
}

// The preview lists what the engine actually parsed, so a typo in a key or
// severity shows up as a missing or rejected rule before anything is saved.
function renderRulePreview(rules, note) {
  if (rules !== undefined) {
    ruleUI.parsed = rules;
    ruleUI.note = note;
  }
  const list = ruleUI.parsed || [];
  set($('rules-table'), list.map((rule) => h('tr', { 'data-rule': rule.id, title: ruleUI.selected === '' ? null : '定位到编辑器中的这条规则' },
    h('td', {}, rule.id), h('td', {}, h('span', { class: 'sev ' + rule.severity }, SEVERITIES[rule.severity] || rule.severity)),
    h('td', {}, rule.field), h('td', { class: 'wide pattern' }, rule.pattern), hitCells(rule))));
  const empty = $('rules-table-empty');
  empty.hidden = list.length > 0;
  empty.textContent = ruleUI.note || '没有可显示的规则';
  $('rules-count').textContent = ruleUI.parsed ? String(list.length) : '';
  renderHitsMeta();
}

// A hit count only means something if the session was analyzed with this exact rule;
// otherwise the cell says why the number is missing instead of showing a misleading zero.
function hitCells(rule) {
  const data = ruleUI.hits;
  if (!ruleUI.sid || !data || data.sid !== ruleUI.sid || !data.byRule) return [h('td', { class: 'num muted' }, data && data.loading ? '…' : '—'), h('td', {})];
  const hit = data.byRule.get(rule.id);
  const used = data.rules ? data.rules.find((item) => item.id === rule.id) : null;
  if (data.rules && !used) return [h('td', { class: 'num', colspan: 2 }, h('span', { class: 'hit-note', title: '上次分析没有使用这条规则，重新分析后才有命中数据' }, '未参与分析'))];
  if (used && (used.pattern !== rule.pattern || used.field !== rule.field || used.severity !== rule.severity || used.version !== rule.version)) {
    return [h('td', { class: 'num', colspan: 2 }, h('span', { class: 'hit-note warn', title: `分析时：${used.field} · ${used.severity} · ${used.pattern}` }, '已修改，需重新分析'))];
  }
  if (!hit) return [h('td', { class: 'num muted' }, '0'), h('td', {})];
  return [
    h('td', { class: 'num' }, h('a', { class: 'link hit', href: `#/s/${ruleUI.sid}/alerts?rule=${encodeURIComponent(rule.id)}`, title: '查看命中这条规则的请求' }, number(hit.requests))),
    h('td', { class: 'time', title: `首次 ${formatTime(hit.first)}\n最近 ${formatTime(hit.last)}` }, formatTime(hit.last, 'dayclock'))];
}

function renderHitsMeta() {
  const node = $('hits-meta');
  const data = ruleUI.hits;
  if (!ruleUI.sid) return set(node, h('span', { class: 'muted' }, '选择参照会话后显示每条规则的命中数。'));
  if (!data || data.sid !== ruleUI.sid || data.loading) return set(node, h('span', { class: 'muted' }, '正在统计命中…'));
  if (data.error) return set(node, h('span', { class: 'error' }, '无法统计命中：' + data.error));
  const ids = new Set((ruleUI.parsed || []).map((rule) => rule.id));
  const fired = data.hits.filter((hit) => ids.has(hit.rule)).length;
  const reanalyze = '#/analysis?session=' + ruleUI.sid + (ruleUI.selected ? '&rules=' + encodeURIComponent(ruleUI.selected) : '');
  set(node,
    h('span', {}, `${sessionName(ruleUI.sid)} · ${number(data.alerted)} / ${number(data.total)} 条请求有告警 · 本文件 ${fired} / ${ids.size} 条规则有命中`),
    data.completed ? h('span', { class: 'muted' }, ' · 分析于 ' + formatTime(data.completed, 'dayclock')) : null,
    !data.analyzed ? h('span', { class: 'muted' }, ' · 旧版索引，未记录分析规则') : null,
    data.note ? h('span', { class: 'warn' }, ' · ' + data.note) : null,
    h('a', { class: 'link', href: reanalyze }, ' 重新分析'));
}

async function loadRuleHits(force) {
  const sid = ruleUI.sid;
  if (!sid) return renderRulePreview();
  if (!force && ruleUI.hits && ruleUI.hits.sid === sid && !ruleUI.hits.error) return renderRulePreview();
  const seq = ++ruleUI.hitsSeq;
  ruleUI.hits = { sid, loading: true };
  renderRulePreview();
  try {
    const data = await api(`sessions/${sid}/rule-hits`);
    if (seq !== ruleUI.hitsSeq) return;
    ruleUI.hits = { ...data, sid, byRule: new Map((data.hits || []).map((hit) => [hit.rule, hit])) };
  } catch (error) {
    if (seq !== ruleUI.hitsSeq) return;
    ruleUI.hits = { sid, error: error.message, hits: [] };
  }
  renderRulePreview();
}

function renderRuleSessions() {
  const select = $('rules-session');
  const usable = state.sessions.filter((s) => !s.problem);
  if (ruleUI.sid && !usable.some((s) => s.id === ruleUI.sid)) ruleUI.sid = '';
  if (!ruleUI.sid && usable.length) ruleUI.sid = usable[0].id;
  set(select, h('option', { value: '' }, usable.length ? '不选择' : '没有可用会话'), usable.map((s) => h('option', { value: s.id }, `${s.name}${s.host ? ' · ' + s.host : ''}`)));
  select.value = ruleUI.sid;
}

function builtinYAML() {
  return ruleUI.builtins.map((rule) => `- id: ${rule.id}\n  version: ${rule.version}\n  severity: ${rule.severity}\n  field: ${rule.field}\n  pattern: ${JSON.stringify(rule.pattern)}\n`).join('\n');
}

function setEditor(content) {
  $('rules-content').value = content;
  $('rules-content').scrollTop = 0;
  renderGutter();
}

function renderGutter() {
  const area = $('rules-content');
  const lines = area.value.split('\n').length;
  const gutter = $('rules-gutter');
  if (Number(gutter.dataset.lines) !== lines) {
    gutter.dataset.lines = String(lines);
    gutter.textContent = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
  }
  gutter.scrollTop = area.scrollTop;
  const before = area.value.slice(0, area.selectionStart);
  const line = before.split('\n').length;
  $('rules-cursor').textContent = `第 ${line} 行，第 ${before.length - before.lastIndexOf('\n')} 列 · 共 ${lines} 行`;
}

async function openRuleFile(name) {
  const seq = ++ruleUI.seq;
  ruleUI.checkSeq++;
  ruleUI.busy = true;
  updateRuleControls();
  try {
    if (!ruleUI.loaded) await refreshRuleLibrary();
    const file = name ? await api('rules/' + encodeURIComponent(name)) : null;
    if (seq !== ruleUI.seq) return;
    Object.assign(ruleUI, { selected: name, revision: file ? file.revision : '', dirty: false, hash: ruleHash(name) });
    save('rule-file', name);
    $('rules-name').value = name || '内置规则';
    setEditor(file ? file.content : builtinYAML());
    if (!file) {
      renderRulePreview(ruleUI.builtins);
      ruleMessage('内置规则随程序提供，每次分析都会启用。自定义文件在此基础上追加，ID 不能与内置规则重复。');
    } else if (file.valid) {
      renderRulePreview(file.rules || []);
      ruleMessage(`${file.rule_count} 条自定义规则，分析时与 ${ruleUI.builtins.length} 条内置规则一起执行。`);
    } else {
      renderRulePreview(null, '文件当前无法解析，修复后会显示规则列表');
      ruleMessage(file.error, 'error');
    }
    if (testUI.sample) runRuleTest();
  } catch (error) {
    if (seq !== ruleUI.seq) return;
    Object.assign(ruleUI, { selected: name, revision: '', dirty: false, hash: ruleHash(name) });
    $('rules-name').value = name;
    setEditor('');
    renderRulePreview(null, '无法读取文件');
    ruleMessage(error.status === 404 ? `规则目录中没有 ${name}，可能已被删除。` : error.message, 'error');
  } finally {
    if (seq === ruleUI.seq) {
      ruleUI.busy = false;
      renderRuleFiles();
      updateRuleControls();
    }
  }
}

function newRuleFile(name = 'custom.yaml', content = RULE_TEMPLATE) {
  ruleUI.seq++;
  Object.assign(ruleUI, { selected: null, revision: '', dirty: true, hash: ruleHash(NEW_RULE) });
  if (location.hash !== ruleUI.hash) history.replaceState(null, '', ruleUI.hash);
  $('rules-name').value = name;
  setEditor(content);
  renderRuleFiles();
  updateRuleControls();
  checkRules(0);
  $('rules-name').focus();
  $('rules-name').select();
}

// Edits are checked as the user types, like a linter, so saving is rarely the first time an error shows.
function checkRules(delay = 500) {
  clearTimeout(ruleUI.checking);
  const seq = ++ruleUI.checkSeq;
  if (ruleUI.selected === '') return;
  ruleUI.checking = setTimeout(async () => {
    const content = $('rules-content').value;
    if (!content.trim()) {
      renderRulePreview(null, '文件为空');
      return ruleMessage('请输入 YAML 规则列表，可参考右侧字段说明。', 'error');
    }
    try {
      const result = await mutate('rules/validate', 'POST', { content });
      if (seq !== ruleUI.checkSeq) return;
      renderRulePreview(result.rules || []);
      if (testUI.sample) runRuleTest();
      ruleMessage(`校验通过：${result.rule_count} 条自定义规则，加上内置共 ${result.total_rules} 条。` + (ruleUI.dirty ? ' 尚未保存。' : ''), 'success');
    } catch (error) {
      if (seq !== ruleUI.checkSeq) return;
      renderRulePreview(null, '修复错误后会显示解析出的规则');
      ruleMessage(error.message, 'error');
      if (testUI.sample) runRuleTest();
    }
  }, delay);
}

async function saveRuleFile() {
  if ($('rules-save').disabled) return;
  const name = $('rules-name').value.trim();
  ruleUI.busy = true;
  updateRuleControls();
  try {
    const result = await mutate('rules/' + encodeURIComponent(name), 'PUT', { content: $('rules-content').value, revision: ruleUI.revision });
    ruleUI.seq++;
    Object.assign(ruleUI, { selected: result.name, revision: result.revision, dirty: false, hash: ruleHash(result.name) });
    history.replaceState(null, '', ruleUI.hash);
    await refreshRuleLibrary();
    renderRulePreview(result.rules || []);
    ruleMessage(`已保存 ${result.name} · ${result.rule_count} 条自定义规则。重新分析会话后告警才会更新。`, 'success');
    toast('规则文件已保存');
  } catch (error) { ruleMessage(error.message, 'error'); }
  finally { ruleUI.busy = false; renderRuleFiles(); updateRuleControls(); }
}

async function deleteRuleFile() {
  if (!ruleUI.revision || !window.confirm(`删除 ${ruleUI.selected}？已有的分析结果会保留。`)) return;
  ruleUI.busy = true;
  updateRuleControls();
  try {
    await mutate('rules/' + encodeURIComponent(ruleUI.selected), 'DELETE', { revision: ruleUI.revision });
    ruleUI.dirty = false;
    ruleUI.busy = false;
    await refreshRuleLibrary();
    toast('规则文件已删除');
    location.hash = ruleHash('');
  } catch (error) {
    ruleMessage(error.message, 'error');
    ruleUI.busy = false;
    updateRuleControls();
  }
}

function downloadRuleFile() {
  const blob = new Blob([$('rules-content').value], { type: 'application/yaml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = h('a', { href: url, download: ruleUI.selected === '' ? 'builtin-rules.yaml' : $('rules-name').value || 'rules.yaml' });
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function focusRule(id) {
  const area = $('rules-content');
  const found = new RegExp('^\\s*-?\\s*id:\\s*[\'"]?' + id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[\'"]?\\s*$', 'm').exec(area.value);
  if (!found || ruleUI.selected === '') return;
  const at = found.index + found[0].indexOf('id:');
  area.focus();
  area.setSelectionRange(at, found.index + found[0].length);
  const line = area.value.slice(0, at).split('\n').length;
  area.scrollTop = Math.max(0, (line - 4) * parseFloat(getComputedStyle(area).lineHeight || '19'));
  renderGutter();
}

// ---- rule test ----

function setPreviewTab(tab) {
  ruleUI.ptab = tab;
  save('rules-ptab', tab);
  for (const button of document.querySelectorAll('[data-ptab]')) button.setAttribute('aria-selected', String(button.dataset.ptab === tab));
  $('ptab-rules').hidden = tab !== 'rules';
  $('ptab-test').hidden = tab !== 'test';
  if (tab === 'test') renderTestSource();
}

function setTestSource(source) {
  testUI.source = source;
  save('test-source', source);
  renderTestSource();
}

function renderTestSource() {
  for (const button of document.querySelectorAll('[data-src]')) button.setAttribute('aria-pressed', String(button.dataset.src === testUI.source));
  $('test-session-src').hidden = testUI.source !== 'session';
  $('test-manual-src').hidden = testUI.source !== 'manual';
  if (!$('test-request').value) $('test-request').value = TEST_REQUEST;
  if (testUI.source === 'session') loadTestPicks();
}

function loadTestPicks(delay = 0) {
  clearTimeout(testUI.picking);
  testUI.picking = setTimeout(async () => {
    const node = $('test-picks');
    const sid = ruleUI.sid;
    if (!sid) return set(node, h('div', { class: 'blank' }, '先在右上角选择参照会话。'));
    const seq = ++testUI.picksSeq;
    try {
      const data = await api(`sessions/${sid}/requests`, { keyword: $('test-search').value.trim(), alerts: $('test-alerts').checked ? 1 : '', page: 0 });
      if (seq !== testUI.picksSeq) return;
      const rows = (data.rows || []).slice(0, 40);
      if (!rows.length) return set(node, h('div', { class: 'blank' }, data.count === 0 && !$('test-search').value ? '这个会话还没有可查询的请求，可能需要先分析。' : '没有匹配的请求'));
      const current = testUI.sample && testUI.sample.sid === sid ? testUI.sample.rid : '';
      set(node, rows.map((row) => h('button', { type: 'button', class: 'pick', 'data-rid': row.id, 'aria-current': row.id === current ? 'true' : null, title: row.url },
        row.severity ? h('span', { class: 'sev ' + row.severity }, SEVERITIES[row.severity]) : h('span', { class: 'sev none' }, '—'),
        h('span', { class: 'method' }, row.method),
        h('span', { class: 'st' }, row.status ? String(row.status) : '…'),
        h('span', { class: 'url' }, (row.host || '') + row.url),
        h('span', { class: 'when' }, formatTime(row.time, 'clock')))),
        data.count > rows.length ? h('div', { class: 'muted more' }, `显示前 ${rows.length} 条，共 ${number(data.count)} 条，可用搜索缩小范围`) : null);
    } catch (error) {
      if (seq === testUI.picksSeq) set(node, h('div', { class: 'blank error' }, error.message));
    }
  }, delay);
}

async function runRuleTest() {
  const sample = testUI.sample;
  if (!sample) return;
  const seq = ++testUI.seq;
  const content = ruleUI.selected === '' ? '' : $('rules-content').value;
  const body = sample.source === 'session'
    ? { content, session_id: sample.sid, request_id: sample.rid }
    : { content, request: $('test-request').value, response: $('test-response').value };
  testUI.running = true;
  renderTestResult();
  try {
    const result = await mutate('rules/test', 'POST', body);
    if (seq !== testUI.seq) return;
    Object.assign(testUI, { result, error: '', running: false });
  } catch (error) {
    if (seq !== testUI.seq) return;
    Object.assign(testUI, { result: null, error: error.status === 422 ? '规则校验未通过，修复后会自动重新测试：' + error.message : error.message, running: false });
  }
  renderTestResult();
}

function renderTestResult() {
  const node = $('test-result');
  const result = testUI.result;
  $('test-count').textContent = result && !testUI.error ? String(result.alerts.length) : '';
  if (!testUI.sample) return set(node, h('div', { class: 'blank' }, testUI.source === 'session' ? '点击上方一条请求，用当前规则测试它。' : '粘贴请求（可附带响应）后运行测试。'));
  if (testUI.error) return set(node, h('div', { class: 'rules-message error' }, testUI.error));
  if (!result) return set(node, h('div', { class: 'skeleton' }));
  const t = result.transaction;
  const custom = new Set(result.custom_rules);
  const byRule = new Map(result.alerts.map((alert) => [alert.rule, alert]));
  const recorded = new Set(result.recorded.map((alert) => alert.rule));
  const rulesById = new Map((ruleUI.parsed || []).map((rule) => [rule.id, rule]));
  const hitRow = (alert) => h('div', { class: 'test-hit' },
    h('span', { class: 'mark ok' }, '✓'),
    h('b', {}, alert.rule), h('span', { class: 'sev ' + alert.severity }, SEVERITIES[alert.severity]),
    h('span', { class: 'muted' }, alert.field + (alert.view && alert.view !== alert.field ? ' · ' + alert.view : '') + (alert.decoding ? ` · 第 ${alert.decoding} 轮解码后` : '')),
    result.source === 'session' && !recorded.has(alert.rule) ? h('span', { class: 'pill warn', title: '保存的分析结果中没有这条告警' }, '本次新增') : null,
    h('code', { class: 'snippet' }, alert.match));
  const missRow = (id) => {
    const rule = rulesById.get(id);
    return h('div', { class: 'test-hit miss' }, h('span', { class: 'mark' }, '✗'), h('b', {}, id),
      rule ? h('span', { class: 'muted' }, rule.field) : null,
      recorded.has(id) ? h('span', { class: 'pill failed', title: '保存的分析结果命中过，本次未命中' }, '本次未命中') : null);
  };
  const builtinHits = result.alerts.filter((alert) => !custom.has(alert.rule));
  const lost = [...recorded].filter((id) => !byRule.has(id) && !custom.has(id));
  set(node,
    h('div', { class: 'test-target' },
      h('span', { class: 'method' }, t.method), t.status ? h('span', { class: 'st' }, String(t.status)) : null,
      h('span', { class: 'url', title: t.url }, (t.host || '') + t.url),
      result.source === 'session' ? h('a', { class: 'link', href: `#/s/${testUI.sample.sid}/requests?id=${encodeURIComponent(t.id)}` }, '打开请求') : null),
    (result.warnings || []).map((text) => h('div', { class: 'rules-message error' }, text)),
    h('div', { class: 'test-summary' + (result.alerts.length ? ' hot' : '') },
      `共测试 ${result.total_rules} 条规则，命中 ${result.alerts.length} 条`, testUI.running ? h('span', { class: 'muted' }, ' · 正在重新测试…') : null),
    custom.size ? [h('h3', {}, '本文件规则'), result.custom_rules.map((id) => (byRule.has(id) ? hitRow(byRule.get(id)) : missRow(id)))] : null,
    h('h3', {}, '内置规则'), builtinHits.length ? builtinHits.map(hitRow) : h('div', { class: 'muted' }, '没有命中'),
    lost.map(missRow));
}

function chooseTestSample(sample) {
  testUI.sample = sample;
  testUI.result = null;
  testUI.error = '';
  for (const pick of $('test-picks').querySelectorAll('.pick')) {
    if (pick.dataset.rid === sample.rid) pick.setAttribute('aria-current', 'true');
    else pick.removeAttribute('aria-current');
  }
  runRuleTest();
}

async function routeRules(page) {
  const name = page.name;
  renderRuleSessions();
  setPreviewTab(page.rid ? 'test' : ruleUI.ptab);
  // Keep unsaved work when the route already points at it (reload of the same hash, back to it).
  if (ruleUI.dirty && location.hash.split('?')[0] === ruleUI.hash) updateRuleControls();
  else if (name === NEW_RULE) newRuleFile();
  else await openRuleFile(name);
  if (page.sid && page.rid) {
    ruleUI.sid = page.sid;
    save('rules-session', page.sid);
    if (location.hash !== ruleUI.hash) history.replaceState(null, '', ruleUI.hash);
    setTestSource('session');
    chooseTestSample({ source: 'session', sid: page.sid, rid: page.rid });
  }
  if (!state.sessions.length) await loadSessions();
  renderRuleSessions();
  loadRuleHits();
  renderTestResult();
}

function bindRules() {
  $('rules-search').addEventListener('input', renderRuleFiles);
  $('rules-new').addEventListener('click', () => {
    if (ruleUI.selected === null) { if (discardRuleEdits()) newRuleFile(); return; }
    location.hash = ruleHash(NEW_RULE);
  });
  $('rules-upload').addEventListener('click', () => $('rules-upload-input').click());
  $('rules-upload-input').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > 1048576) return ruleMessage('规则文件不能超过 1 MiB', 'error');
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()); }
    catch (_) { return ruleMessage('请选择 UTF-8 编码的 YAML 文件', 'error'); }
    if (!discardRuleEdits()) return;
    const taken = ruleUI.files.some((f) => f.name === file.name);
    newRuleFile(taken ? file.name.replace(/(\.ya?ml)$/i, '-imported$1') : file.name, content);
    if (taken) toast(`已有同名文件，导入为 ${$('rules-name').value}`);
  });
  const area = $('rules-content');
  area.addEventListener('input', () => {
    ruleUI.dirty = true;
    renderGutter();
    updateRuleControls();
    checkRules();
  });
  $('rules-name').addEventListener('input', () => { ruleUI.dirty = true; updateRuleControls(); renderRuleFiles(); });
  area.addEventListener('scroll', () => { $('rules-gutter').scrollTop = area.scrollTop; });
  for (const type of ['click', 'keyup', 'select']) area.addEventListener(type, renderGutter);
  area.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab' || event.ctrlKey || event.metaKey || event.altKey || area.readOnly) return;
    event.preventDefault();
    if (event.shiftKey) return;
    // execCommand keeps the browser's undo history intact.
    if (!document.execCommand('insertText', false, '  ')) area.setRangeText('  ', area.selectionStart, area.selectionEnd, 'end');
  });
  $('view-rules').addEventListener('keydown', (event) => {
    if (!(event.ctrlKey || event.metaKey)) return;
    if (event.key === 's') { event.preventDefault(); saveRuleFile(); }
    else if (event.key === 'Enter' && !$('rules-validate').disabled) { event.preventDefault(); checkRules(0); }
  });
  $('rules-validate').addEventListener('click', () => checkRules(0));
  $('rules-save').addEventListener('click', saveRuleFile);
  $('rules-delete').addEventListener('click', deleteRuleFile);
  $('rules-download').addEventListener('click', downloadRuleFile);
  $('rules-analyze').addEventListener('click', (event) => { if ($('rules-analyze').classList.contains('disabled')) event.preventDefault(); });
  $('rules-table').addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-rule]');
    if (row) focusRule(row.dataset.rule);
  });
  window.addEventListener('beforeunload', (event) => {
    if (ruleUI.dirty) { event.preventDefault(); event.returnValue = ''; }
  });

  for (const button of document.querySelectorAll('[data-ptab]')) button.addEventListener('click', () => setPreviewTab(button.dataset.ptab));
  for (const button of document.querySelectorAll('[data-src]')) button.addEventListener('click', () => setTestSource(button.dataset.src));
  $('rules-session').addEventListener('change', () => {
    ruleUI.sid = $('rules-session').value;
    save('rules-session', ruleUI.sid);
    loadRuleHits();
    if (testUI.source === 'session') loadTestPicks();
  });
  $('test-search').addEventListener('input', () => loadTestPicks(300));
  $('test-alerts').addEventListener('change', () => loadTestPicks());
  $('test-picks').addEventListener('click', (event) => {
    const pick = event.target.closest('.pick[data-rid]');
    if (pick) chooseTestSample({ source: 'session', sid: ruleUI.sid, rid: pick.dataset.rid });
  });
  $('test-run').addEventListener('click', () => chooseTestSample({ source: 'manual' }));
  for (const id of ['test-request', 'test-response']) {
    $(id).addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); chooseTestSample({ source: 'manual' }); }
    });
  }

  $('analysis-search').addEventListener('input', renderAnalysisSessions);
  $('analysis-rule').addEventListener('change', () => { save('analysis-rule', $('analysis-rule').value); renderAnalysisSessions(); });
  $('analysis-sessions').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-analyze]');
    if (button) startRuleAnalysis(button.dataset.analyze);
  });
  $('job-card').addEventListener('click', async (event) => {
    if (!event.target.closest('#job-cancel')) return;
    event.target.disabled = true;
    try { await mutate('analysis', 'DELETE', { id: jobUI.job.id }); toast('正在停止分析，等待当前操作结束'); }
    catch (error) { toast(error.message, true); }
  });
}

// A hash change that would leave unsaved rule edits asks first and otherwise restores the editor's URL.
function guardRuleEdits() {
  if (!ruleUI.dirty || location.hash.split('?')[0] === ruleUI.hash) return true;
  if (window.confirm('当前规则修改尚未保存，确定离开？')) {
    ruleUI.dirty = false;
    return true;
  }
  history.replaceState(null, '', ruleUI.hash);
  return false;
}
