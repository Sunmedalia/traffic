'use strict';

// Captured traffic is attacker-controlled: every value reaches the DOM through
// textContent or attributes set by h(), never through HTML parsing.
const $ = (id) => document.getElementById(id);

function h(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === false || value == null) continue;
    if (key === 'class') node.className = value;
    else if (key === 'onclick') node.addEventListener('click', value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const kid of kids.flat()) {
    if (kid != null && kid !== false) node.append(kid);
  }
  return node;
}

const STATES = { running: '采集中', stopped: '已停止', complete: '已完成', failed: '采集失败', stale: '心跳过期' };
const SEVERITIES = { high: '高', medium: '中', low: '低' };
const FILTER_FIELDS = ['client', 'keyword', 'rule', 'severity', 'service', 'since'];

const state = {
  token: '',
  sessions: [],
  sid: null,
  tab: 'overview',
  page: 0,
  filter: {},
  rows: [],
  rowsKey: '',
  count: 0,
  stats: null,
  warning: '',
  error: '',
  selected: null,
  detail: null,
  detailTab: 'request',
  paused: false,
  refreshMs: 1000,
  seq: 0,
  busy: false,
  timer: 0,
};

const stateLabel = (value) => STATES[value] || '未知';
const number = (value) => Number(value || 0).toLocaleString('zh-CN');
const pad = (value, width = 2) => String(value).padStart(width, '0');

function parseTime(value) {
  if (!value) return null;
  // Index timestamps carry nanoseconds; Date only guarantees milliseconds.
  const date = new Date(String(value).replace(/(\.\d{3})\d+/, '$1'));
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() < 1971 ? null : date;
}

function formatTime(value, millis) {
  const d = parseTime(value);
  if (!d) return '未知';
  const text = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return millis ? `${text}.${pad(d.getMilliseconds(), 3)}` : text;
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, params) {
  const url = new URL('api/' + path, location.origin + '/');
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== '' && value != null) url.searchParams.set(key, value);
  }
  const response = await fetch(url, { headers: { Authorization: 'Bearer ' + state.token }, cache: 'no-store' });
  if (response.status === 401) {
    showGate();
    throw new ApiError('访问令牌无效', 401);
  }
  if (!response.ok) {
    let message = `请求失败（${response.status}）`;
    try {
      message = (await response.json()).error || message;
    } catch (_) { /* keep the generic message */ }
    throw new ApiError(message, response.status);
  }
  return response;
}

const api = async (path, params) => (await request(path, params)).json();

function show(view) {
  for (const name of ['gate', 'sessions', 'session']) $('view-' + name).hidden = name !== view;
  const inSession = view === 'session';
  $('pause').hidden = !inSession;
  $('live').hidden = !inSession;
}

function renderNotice() {
  const node = $('notice');
  const text = state.error ? state.error : state.warning;
  node.hidden = !text;
  node.textContent = text;
  node.className = 'notice' + (state.error ? '' : ' info');
}

function fail(error, prefix) {
  if (error.status === 401) return;
  state.error = (prefix ? prefix + ' · ' : '') + error.message;
  renderNotice();
}

function showGate() {
  sessionStorage.removeItem('traffic-token');
  state.token = '';
  state.error = '';
  renderNotice();
  show('gate');
  $('gate-token').focus();
}

// ---- sessions ----

async function loadSessions() {
  $('rescan').disabled = true;
  try {
    const data = await api('sessions');
    state.sessions = data.sessions || [];
    state.refreshMs = Math.max(500, data.refresh_ms || 1000);
    state.error = '';
    state.warning = data.warning || '';
    $('sessions-meta').textContent = `${state.sessions.length} 个会话 · 按开始时间从新到旧 · 目录 ${(data.roots || []).join(' · ')}`;
    renderSessions();
    renderNotice();
    return true;
  } catch (error) {
    fail(error, '扫描会话失败');
    return false;
  } finally {
    $('rescan').disabled = false;
  }
}

function renderSessions() {
  const body = $('sessions-body');
  body.replaceChildren(...state.sessions.map((s) => {
    const usable = !s.problem;
    const open = () => { if (usable) location.hash = `#/s/${s.id}/overview`; };
    const row = h('tr', { class: usable ? '' : 'unusable', tabindex: usable ? '0' : null, title: s.problem || null, onclick: open },
      h('td', { class: 'mono' }, formatTime(s.started)),
      h('td', {}, s.name),
      h('td', {}, s.host || '—'),
      h('td', { class: usable ? 'state-' + s.state : 'state-failed' }, usable ? stateLabel(s.state) : '索引不可用'),
      h('td', { class: 'num' }, s.counts_known ? number(s.transactions) : '未知'),
      h('td', { class: 'num' }, s.counts_known ? number(s.alerts) : '未知'),
      h('td', { title: s.dir }, s.dir));
    row.addEventListener('keydown', (event) => { if (event.key === 'Enter') open(); });
    return row;
  }));
  $('sessions-empty').hidden = state.sessions.length > 0;
}

// ---- session view ----

function currentSession() {
  return state.sessions.find((s) => s.id === state.sid);
}

function renderChrome() {
  const session = currentSession();
  const crumb = $('crumb');
  if (state.sid) {
    crumb.replaceChildren(h('a', { href: '#/' }, '会话'), ' / ', h('strong', {}, session ? session.name : state.sid));
    crumb.title = session ? session.dir : '';
  } else {
    crumb.replaceChildren();
  }
  for (const button of document.querySelectorAll('[data-tab]')) {
    button.setAttribute('aria-selected', String(button.dataset.tab === state.tab));
  }
  $('tab-overview').hidden = state.tab !== 'overview';
  $('tab-list').hidden = state.tab === 'overview';
  $('pause').textContent = state.paused ? '恢复刷新' : '暂停刷新';
  const live = $('live');
  const value = state.stats ? state.stats.state : '';
  live.className = 'live ' + (value || '');
  live.textContent = stateLabel(value) + (state.paused ? ' · 已暂停刷新' : '');
}

function renderOverview() {
  const s = state.stats || {};
  const tile = (label, value, warn) => h('div', { class: 'tile' + (warn && value > 0 ? ' warn' : '') },
    h('div', { class: 'label' }, label), h('div', { class: 'value' }, number(value)));
  $('tiles').replaceChildren(
    tile('累计请求', s.transactions), tile('累计告警命中', s.alerts), tile('网络包', s.packets),
    tile('网卡丢包', s.dropped, true), tile('用户态队列丢弃', s.queue_dropped, true), tile('TLS 丢失', s.tls_dropped, true));
  const session = currentSession();
  const facts = [['会话目录', state.dir || (session && session.dir) || '—'], ['状态', stateLabel(s.state)], ['开始时间', formatTime(s.started)], ['TLS', s.tls || '—'], ['资源限制', s.resource_limits || '—']];
  $('facts').replaceChildren(...facts.flatMap(([name, value]) => [h('dt', {}, name), h('dd', {}, value)]));
  const targets = s.targets || [];
  $('targets-body').replaceChildren(...targets.map((t) => h('tr', {},
    h('td', {}, t.service), h('td', { class: 'num' }, String(t.pid)), h('td', { class: 'num' }, String(t.uid)),
    h('td', { class: 'mono' }, (t.ports || []).join(', ') || '—'), h('td', { class: 'mono', title: t.library || null }, t.library || '—'), h('td', {}, t.state))));
  $('targets-empty').hidden = targets.length > 0;
  const errors = s.errors || [];
  $('errors').replaceChildren(...(errors.length ? errors.map((e) => h('li', {}, e)) : [h('li', { class: 'none' }, '暂无记录')]));
}

function renderRows() {
  const key = JSON.stringify(state.rows) + '|' + state.selected;
  if (key !== state.rowsKey) {
    state.rowsKey = key;
    $('rows-body').replaceChildren(...state.rows.map((row) => {
      const flags = [row.incomplete && h('span', { class: 'flag' }, '不完整'), row.truncated && h('span', { class: 'flag' }, '截断')];
      const tr = h('tr', { class: row.id === state.selected ? 'selected' : '', tabindex: '0', 'data-id': row.id, onclick: () => openDetail(row.id) },
        h('td', { title: formatTime(row.time, true) }, formatTime(row.time, true).slice(5)),
        h('td', {}, row.method || '—'),
        h('td', { class: 'num st-' + (row.status ? String(row.status)[0] : '0') }, row.status ? String(row.status) : '待响应'),
        h('td', {}, row.severity ? h('span', { class: 'sev ' + row.severity }, SEVERITIES[row.severity]) : ''),
        h('td', { title: row.client }, row.client),
        h('td', { title: row.host }, row.host || '—'),
        h('td', { class: 'wide', title: row.url }, row.url, flags));
      return tr;
    }));
  }
  $('rows-empty').hidden = state.rows.length > 0;
  const pages = Math.max(1, Math.ceil(state.count / 100));
  $('pager-info').textContent = `第 ${state.page + 1}/${pages} 页 · 共 ${number(state.count)} 条`;
  $('page-first').disabled = $('page-prev').disabled = state.page === 0;
  $('page-next').disabled = state.page + 1 >= pages;
}

function renderCounts() {
  const s = state.stats || {};
  $('count-requests').textContent = s.transactions ? number(s.transactions) : '';
  $('count-alerts').textContent = s.alerts ? number(s.alerts) : '';
}

// Historic pages are anchored to their first row so new traffic does not shift them.
async function loadRows(anchored) {
  const seq = ++state.seq;
  const params = { ...state.filter, page: state.page, alerts: state.tab === 'alerts' ? 1 : '' };
  if (state.tab === 'overview') Object.assign(params, { page: 0, alerts: '' });
  if (params.since) params.since = new Date(params.since).toISOString();
  if (anchored && state.page > 0 && state.rows.length) {
    params.anchor_id = state.rows[0].id;
    params.anchor_time = state.rows[0].time;
  }
  state.busy = true;
  try {
    const data = await api(`sessions/${state.sid}/requests`, params);
    if (seq !== state.seq) return;
    state.stats = data.stats;
    state.dir = data.dir;
    state.warning = data.status_warning || '';
    state.error = '';
    if (state.tab !== 'overview') {
      state.rows = data.rows || [];
      state.count = data.count;
      state.page = data.page;
      renderRows();
    }
    renderOverview();
    renderCounts();
    renderChrome();
    renderNotice();
  } catch (error) {
    if (seq === state.seq) fail(error, '刷新失败，保留上次结果');
  } finally {
    if (seq === state.seq) state.busy = false;
  }
}

// ---- detail ----

function closeDetail() {
  state.selected = null;
  state.detail = null;
  $('detail').hidden = true;
  $('split').classList.remove('open');
  renderRows();
}

async function openDetail(id, quiet) {
  if (!quiet) {
    state.selected = id;
    if (!state.detail || state.detail.transaction.id !== id) {
      state.detail = null;
      $('detail-title').textContent = '正在加载详情…';
      $('detail-facts').replaceChildren();
      $('detail-body').replaceChildren();
    }
    $('detail').hidden = false;
    $('split').classList.add('open');
    renderRows();
  }
  try {
    const data = await api(`sessions/${state.sid}/requests/${encodeURIComponent(id)}`);
    if (state.selected !== id) return;
    const before = JSON.stringify(state.detail);
    state.detail = data;
    if (JSON.stringify(data) !== before) renderDetail();
  } catch (error) {
    if (state.selected !== id || quiet) return;
    $('detail-title').textContent = error.status === 404 ? '该记录已被保留期清理' : error.message;
  }
}

function renderDetail() {
  const data = state.detail;
  if (!data) return;
  const t = data.transaction;
  $('detail-title').replaceChildren(h('span', { class: 'method' }, t.method || '—'), t.url || '');
  $('detail-title').title = t.url || '';
  const flags = [t.incomplete && '不完整', t.truncated && '截断'].filter(Boolean).join(' · ');
  const facts = [
    ['时间', formatTime(t.time, true)],
    ['客户端', t.client],
    ['Host', t.host],
    ['响应', (t.status ? String(t.status) : '待响应') + (flags ? ' · ' + flags : '')],
    ['服务', [t.service, t.target_id].filter(Boolean).join(' · ')],
    ['后端', [t.backend, t.local_endpoint].filter(Boolean).join(' · ')],
    ['来源', [t.source, t.pid ? 'PID ' + t.pid : ''].filter(Boolean).join(' · ')],
    ['连接', t.connection],
    ['记录 ID', t.id],
  ].filter(([, value]) => value);
  $('detail-facts').replaceChildren(...facts.flatMap(([name, value]) => [h('dt', {}, name), h('dd', {}, value)]));
  $('detail-alert-count').textContent = (t.alerts || []).length || '';
  for (const button of document.querySelectorAll('[data-detail]')) {
    button.setAttribute('aria-selected', String(button.dataset.detail === state.detailTab));
  }
  const body = $('detail-body');
  const scroll = body.scrollTop;
  const text = (value, empty) => (value ? h('pre', {}, value) : h('p', { class: 'hint' }, empty));
  if (state.detailTab === 'request') {
    body.replaceChildren(text(data.request_text, '暂无请求内容'));
  } else if (state.detailTab === 'response') {
    body.replaceChildren(text(data.response_text, '暂无响应内容'));
  } else if (state.detailTab === 'decoded') {
    body.replaceChildren(data.decoded_view
      ? [h('p', { class: 'hint' }, '解码视图 ' + data.decoded_view), h('pre', {}, data.decoded_body)]
      : h('p', { class: 'hint' }, '暂无可用的 gzip 解码正文，请查看请求标签'));
  } else {
    const alerts = t.alerts || [];
    body.replaceChildren(...(alerts.length ? alerts.map((a) => h('div', { class: 'alert-card' },
      h('header', {}, h('span', { class: 'sev ' + a.severity }, SEVERITIES[a.severity] || '—'), a.rule),
      h('div', { class: 'meta' }, `规则版本 ${a.version} · 字段 ${a.field || '—'} · 视图 ${a.view || '—'} · 解码轮次 ${a.decoding}`),
      h('pre', {}, a.match))) : [h('p', { class: 'hint' }, '暂无告警')]));
  }
  body.scrollTop = scroll;
}

async function exportEvidence() {
  if (!state.detail) return;
  const id = state.detail.transaction.id;
  const button = $('detail-export');
  button.disabled = true;
  button.textContent = '正在导出…';
  try {
    const response = await request(`sessions/${state.sid}/requests/${encodeURIComponent(id)}/export`);
    const blob = await response.blob();
    const name = (/filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') || '') || [])[1] || 'evidence.zip';
    const link = h('a', { href: URL.createObjectURL(blob), download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 10000);
    state.error = '';
    renderNotice();
  } catch (error) {
    fail(error, '导出失败');
  } finally {
    button.disabled = false;
    button.textContent = '导出证据';
  }
}

// ---- routing and refresh ----

function route(event, loaded) {
  const match = /^#\/s\/([0-9a-f]+)(?:\/(overview|requests|alerts))?$/.exec(location.hash);
  if (!state.token) return showGate();
  if (!match) {
    state.sid = null;
    state.seq++;
    show('sessions');
    renderChrome();
    if (!loaded) loadSessions();
    return;
  }
  const [, sid, tab = 'overview'] = match;
  const switched = sid !== state.sid;
  if (switched) {
    Object.assign(state, { sid, stats: null, filter: {}, dir: '' });
    $('filters').reset();
  }
  if (switched || tab !== state.tab || $('view-session').hidden) {
    Object.assign(state, { tab, page: 0, rows: [], rowsKey: '', count: 0 });
    closeDetail();
  }
  show('session');
  renderChrome();
  renderOverview();
  loadRows(false);
  // A deep link can arrive before the session list that supplies the name.
  if (!currentSession()) loadSessions().then(renderChrome);
}

async function tick() {
  if (state.paused || document.hidden || !state.sid || !state.token || state.busy) return;
  await loadRows(true);
  const t = state.detail && state.detail.transaction;
  // A response can arrive after the request was first shown.
  if (t && (!t.status || t.incomplete)) openDetail(t.id, true);
}

function moveSelection(delta) {
  if (!state.rows.length) return;
  const index = state.rows.findIndex((row) => row.id === state.selected);
  const next = state.rows[Math.max(0, Math.min(state.rows.length - 1, index + delta))];
  openDetail(next.id);
  const node = $('rows-body').querySelector(`tr[data-id="${CSS.escape(next.id)}"]`);
  if (node) node.scrollIntoView({ block: 'nearest' });
}

function changePage(page) {
  state.page = Math.max(0, page);
  loadRows(false);
}

function bind() {
  $('gate-form').addEventListener('submit', (event) => {
    event.preventDefault();
    state.token = $('gate-token').value.trim();
    $('gate-token').value = '';
    if (!state.token) return;
    sessionStorage.setItem('traffic-token', state.token);
    route();
  });
  $('rescan').addEventListener('click', loadSessions);
  $('pause').addEventListener('click', () => {
    state.paused = !state.paused;
    renderChrome();
  });
  for (const button of document.querySelectorAll('[data-tab]')) {
    button.addEventListener('click', () => { location.hash = `#/s/${state.sid}/${button.dataset.tab}`; });
  }
  for (const button of document.querySelectorAll('[data-detail]')) {
    button.addEventListener('click', () => {
      state.detailTab = button.dataset.detail;
      $('detail-body').scrollTop = 0;
      renderDetail();
    });
  }
  $('filters').addEventListener('submit', (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    state.filter = Object.fromEntries(FILTER_FIELDS.map((name) => [name, String(form.get(name) || '').trim()]));
    changePage(0);
  });
  $('filters-clear').addEventListener('click', () => {
    $('filters').reset();
    state.filter = {};
    changePage(0);
  });
  $('page-first').addEventListener('click', () => changePage(0));
  $('page-prev').addEventListener('click', () => changePage(state.page - 1));
  $('page-next').addEventListener('click', () => changePage(state.page + 1));
  $('detail-close').addEventListener('click', closeDetail);
  $('detail-export').addEventListener('click', exportEvidence);
  $('rows-body').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && event.target.dataset.id) openDetail(event.target.dataset.id);
  });
  document.addEventListener('keydown', (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey || !state.sid) return;
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(event.target.tagName);
    if (event.key === 'Escape') {
      if (typing) event.target.blur();
      else if (state.selected) closeDetail();
      return;
    }
    if (typing) return;
    const tabs = { 1: 'overview', 2: 'requests', 3: 'alerts' };
    if (tabs[event.key]) location.hash = `#/s/${state.sid}/${tabs[event.key]}`;
    else if (state.tab === 'overview') return;
    else if (event.key === 'j' || event.key === 'ArrowDown') moveSelection(1);
    else if (event.key === 'k' || event.key === 'ArrowUp') moveSelection(-1);
    else if (event.key === 'n' && !$('page-next').disabled) changePage(state.page + 1);
    else if (event.key === 'p' && !$('page-prev').disabled) changePage(state.page - 1);
    else if (event.key === '/') $('filters').elements.client.focus();
    else return;
    event.preventDefault();
  });
  window.addEventListener('hashchange', route);
}

async function boot() {
  bind();
  const offset = -new Date().getTimezoneOffset();
  $('zone').textContent = `本地时间 UTC${offset < 0 ? '-' : '+'}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
  // The launch URL carries the token in the fragment so it never reaches server logs.
  const launch = /^#token=([\w-]+)$/.exec(location.hash);
  if (launch) {
    sessionStorage.setItem('traffic-token', launch[1]);
    history.replaceState(null, '', location.pathname);
  }
  state.token = sessionStorage.getItem('traffic-token') || '';
  (function schedule() {
    state.timer = setTimeout(async () => {
      await tick();
      schedule();
    }, state.refreshMs);
  })();
  if (!state.token) return showGate();
  const loaded = await loadSessions();
  if (!state.token) return;
  const usable = state.sessions.filter((s) => !s.problem);
  if (!location.hash && state.sessions.length === 1 && usable.length === 1) {
    history.replaceState(null, '', `#/s/${usable[0].id}/overview`);
  }
  route(null, loaded);
}

boot();
