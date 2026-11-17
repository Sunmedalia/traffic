'use strict';

// Captured traffic is attacker-controlled: every value reaches the DOM through
// text nodes or attributes set by h(), never through HTML parsing. The page's
// CSP forbids inline styles, so dynamic sizes are set through the CSSOM.
const $ = (id) => document.getElementById(id);

function build(node, props, kids) {
  for (const [key, value] of Object.entries(props || {})) {
    if (value === false || value == null) continue;
    if (key === 'class') node.setAttribute('class', value);
    else if (key === 'onclick') node.addEventListener('click', value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const kid of kids.flat(3)) {
    if (kid != null && kid !== false) node.append(kid);
  }
  return node;
}
const h = (tag, props, ...kids) => build(document.createElement(tag), props, kids);
// Replaces a node's children, accepting the same nested lists and falsy gaps as h().
function set(node, ...kids) {
  node.replaceChildren(...kids.flat(3).filter((kid) => kid != null && kid !== false));
}
const svg = (tag, props, ...kids) => build(document.createElementNS('http://www.w3.org/2000/svg', tag), props, kids);

const STATES = { running: '采集中', stopped: '已停止', complete: '已完成', failed: '采集失败', stale: '心跳过期', interrupted: '采集未正常结束' };
const SEVERITIES = { high: '高', medium: '中', low: '低' };
const STATUS_LABELS = { pending: '待响应', other: '其他' };
const FILTER_KEYS = ['keyword', 'severity', 'status', 'method', 'client', 'rule', 'service', 'since', 'until'];
const MORE_KEYS = ['client', 'rule', 'service', 'since', 'until'];
const DETAIL_TABS = [['request', '请求'], ['response', '响应'], ['decoded', '解码正文'], ['alerts', '检测依据']];

function saved(key, fallback) {
  try {
    return localStorage.getItem('traffic-' + key) || fallback;
  } catch (_) {
    return fallback;
  }
}
function save(key, value) {
  try {
    localStorage.setItem('traffic-' + key, value);
  } catch (_) { /* preferences are optional */ }
}

const state = {
  token: '',
  sessions: [],
  roots: [],
  sid: null,
  tab: 'overview',
  filter: {},
  listKey: '',
  page: 0,
  rows: [],
  rowsKey: '',
  known: null,
  count: 0,
  baseCount: 0,
  pageSize: 100,
  stats: null,
  dir: '',
  coverage: '',
  summary: null,
  recent: [],
  timelines: {},
  auxAt: 0,
  summaryAt: 0,
  warning: '',
  error: '',
  offline: false,
  selected: null,
  detail: null,
  detailError: '',
  detailTab: saved('detail-tab', 'request'),
  pretty: saved('pretty', '1') === '1',
  paused: false,
  utc: saved('tz', 'local') === 'utc',
  theme: saved('theme', 'auto'),
  refreshMs: 1000,
  seq: 0,
  busy: false,
};

// ---- formatting ----

const number = (value) => Number(value || 0).toLocaleString('zh-CN');
const pad = (value, width = 2) => String(value).padStart(width, '0');
const stateLabel = (value) => STATES[value] || '未知';
const stripPort = (client) => String(client || '').replace(/:\d+$/, '');

function parseTime(value) {
  if (!value) return null;
  // Index timestamps carry nanoseconds; Date only guarantees milliseconds.
  const date = value instanceof Date ? value : new Date(String(value).replace(/(\.\d{3})\d+/, '$1'));
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() < 1971 ? null : date;
}

function parts(d) {
  return state.utc
    ? [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds()]
    : [d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds(), d.getMilliseconds()];
}

// style: 'full' date and time, 'ms' adds milliseconds, 'row' is month-day and time with milliseconds,
// 'dayclock' is month-day and time, 'clock' is time only.
function formatTime(value, style = 'full') {
  const d = parseTime(value);
  if (!d) return '未知';
  const [y, mo, day, hh, mi, ss, ms] = parts(d);
  const clock = `${pad(hh)}:${pad(mi)}:${pad(ss)}`;
  if (style === 'clock') return clock;
  if (style === 'dayclock') return `${pad(mo)}-${pad(day)} ${pad(hh)}:${pad(mi)}`;
  if (style === 'row') return `${pad(mo)}-${pad(day)} ${clock}.${pad(ms, 3)}`;
  return `${y}-${pad(mo)}-${pad(day)} ${clock}` + (style === 'ms' ? `.${pad(ms, 3)}` : '');
}

function relativeTime(value) {
  const d = parseTime(value);
  if (!d) return '';
  const seconds = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (seconds < 60) return '刚刚';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

function duration(seconds) {
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3600) return `${seconds / 60} 分钟`;
  if (seconds < 86400) return `${seconds / 3600} 小时`;
  return `${seconds / 86400} 天`;
}

function zoneLabel() {
  if (state.utc) return 'UTC';
  const offset = -new Date().getTimezoneOffset();
  return `本地 UTC${offset < 0 ? '-' : '+'}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
}

function toInputValue(iso) {
  const d = parseTime(iso);
  if (!d) return '';
  const [y, mo, day, hh, mi, ss] = parts(d);
  return `${y}-${pad(mo)}-${pad(day)}T${pad(hh)}:${pad(mi)}:${pad(ss)}`;
}

function fromInputValue(value) {
  if (!value) return '';
  const d = new Date(state.utc ? value + 'Z' : value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

function toast(text, error) {
  const node = h('div', { class: 'toast' + (error ? ' error' : '') }, text);
  $('toasts').append(node);
  setTimeout(() => node.remove(), error ? 5000 : 2200);
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`已复制${label}`);
  } catch (_) {
    toast('浏览器拒绝写入剪贴板', true);
  }
}

// Wraps every literal occurrence of the needles in <mark>, as DOM nodes.
function marked(text, needles) {
  const found = [];
  for (const needle of needles) {
    if (!needle || needle.length < 2) continue;
    for (let at = text.indexOf(needle); at >= 0 && found.length < 200; at = text.indexOf(needle, at + needle.length)) {
      found.push([at, at + needle.length]);
    }
  }
  if (!found.length) return [text];
  found.sort((a, b) => a[0] - b[0]);
  const nodes = [];
  let cursor = 0;
  for (const [from, to] of found) {
    if (to <= cursor) continue;
    const start = Math.max(from, cursor);
    if (start > cursor) nodes.push(text.slice(cursor, start));
    nodes.push(h('mark', {}, text.slice(start, to)));
    cursor = to;
  }
  nodes.push(text.slice(cursor));
  return nodes;
}

// ---- API ----

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, params, options = {}) {
  const url = new URL('api/' + path, location.origin + '/');
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== '' && value != null) url.searchParams.set(key, value);
  }
  let response;
  try {
    response = await fetch(url, { ...options, headers: { Authorization: 'Bearer ' + state.token, ...(options.body ? { 'Content-Type': 'application/json' } : {}) }, cache: 'no-store' });
  } catch (_) {
    setOffline(true);
    throw new ApiError('无法连接分析服务', 0);
  }
  setOffline(false);
  if (response.status === 401) {
    showGate('访问令牌无效或已更换，请重新输入');
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
const mutate = async (path, method, data) => (await request(path, null, { method, body: JSON.stringify(data) })).json();

function setOffline(value) {
  if (state.offline === value) return;
  state.offline = value;
  renderBanner();
}

function renderBanner() {
  const node = $('banner');
  const text = state.offline ? '无法连接分析服务，恢复后会自动重试。请确认 traffic-console web 仍在运行。' : state.error || state.warning;
  node.hidden = !text;
  node.textContent = text;
  node.className = 'banner' + (state.offline || state.error ? ' error' : '');
}

function fail(error, prefix) {
  if (error.status === 401 || error.status === 0) return;
  state.error = (prefix ? prefix + '：' : '') + error.message;
  renderBanner();
}

// ---- routing ----

function parseHash() {
  const match = /^#\/s\/([0-9a-f]+)(?:\/(overview|requests|alerts))?(?:\?(.*))?$/.exec(location.hash);
  if (!match) return null;
  const params = new URLSearchParams(match[3] || '');
  const filter = {};
  for (const key of FILTER_KEYS) {
    const value = (params.get(key) || '').trim();
    if (value) filter[key] = value;
  }
  return { sid: match[1], tab: match[2] || 'overview', filter, id: params.get('id') || null };
}

function buildHash(route) {
  const params = new URLSearchParams();
  if (route.tab !== 'overview') {
    for (const key of FILTER_KEYS) {
      if (route.filter[key]) params.set(key, route.filter[key]);
    }
    if (route.id) params.set('id', route.id);
  }
  const query = params.toString();
  return `#/s/${route.sid}/${route.tab}` + (query ? '?' + query : '');
}

// Every navigation goes through the URL, so reload, back and shared links restore the same view.
function go(patch, replace) {
  const hash = buildHash({ sid: state.sid, tab: state.tab, filter: state.filter, id: state.selected, ...patch });
  if (hash === location.hash) return;
  if (replace) {
    history.replaceState(null, '', hash);
    route();
  } else {
    location.hash = hash;
  }
}

function show(view) {
  for (const name of ['gate', 'sessions', 'session', 'rules', 'analysis']) $('view-' + name).hidden = name !== view;
  $('pause').hidden = $('live').hidden = view !== 'session';
  $('mainnav').hidden = view === 'gate';
  const section = view === 'session' ? 'sessions' : view;
  for (const link of document.querySelectorAll('[data-nav]')) {
    if (link.dataset.nav === section) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

function showGate(message) {
  try {
    sessionStorage.removeItem('traffic-token');
  } catch (_) { /* nothing stored */ }
  state.token = '';
  state.error = message || '';
  state.warning = '';
  renderBanner();
  show('gate');
  renderChrome();
  $('gate-token').focus();
}

function leaveSession() {
  Object.assign(state, { sid: null, selected: null, detail: null, listKey: '', warning: '', error: '', summaryAt: 0 });
  state.seq++;
  closeDetail();
}

function route() {
  if (!state.token) return showGate();
  if (!guardRuleEdits()) return;
  const page = parsePage();
  if (page) {
    if (state.sid) leaveSession();
    show(page.view);
    renderChrome();
    renderBanner();
    if (page.view === 'rules') routeRules(page);
    else routeAnalysis(page);
    schedule();
    return;
  }
  const next = parseHash();
  if (!next) {
    leaveSession();
    show('sessions');
    renderChrome();
    renderBanner();
    loadSessions();
    schedule();
    return;
  }
  if (next.sid !== state.sid) {
    Object.assign(state, { sid: next.sid, stats: null, summary: null, recent: [], timelines: {}, dir: '', warning: '', error: '', auxAt: 0, summaryAt: 0 });
    closeDetail();
    renderBanner();
  }
  const listKey = `${next.sid}|${next.tab}|${JSON.stringify(next.filter)}`;
  const changed = listKey !== state.listKey;
  Object.assign(state, { tab: next.tab, filter: next.filter, listKey });
  if (changed) {
    Object.assign(state, { page: 0, rows: [], rowsKey: '', known: null, count: 0, baseCount: 0, auxAt: 0, summaryAt: 0 });
    state.seq++;
    state.busy = false;
  }
  show('session');
  syncFilters();
  renderChrome();
  renderTimelines();
  if (changed) {
    renderOverview();
    renderRows(true);
    refresh();
  }
  if (next.tab === 'overview' || !next.id) {
    if (state.selected || !$('detail').hidden) hideDetail();
  } else if (next.id !== state.selected) {
    showDetail(next.id);
  }
  if (!currentSession()) loadSessions().then(renderChrome);
  schedule();
}

// ---- chrome ----

const currentSession = () => state.sessions.find((s) => s.id === state.sid);

function renderChrome() {
  const session = currentSession();
  if (state.sid) $('session-analyze').href = `#/analysis?session=${state.sid}`;
  const crumb = $('crumb');
  if (state.sid && state.token) {
    set(crumb,
      h('a', { href: '#/', class: 'root' }, '会话'), h('span', { class: 'sep h' }, '/'),
      session && session.host ? [h('span', { class: 'host' }, session.host), h('span', { class: 'sep h' }, '/')] : null,
      h('strong', { title: session ? session.dir : '' }, session ? session.name : state.sid));
    document.title = `${session ? session.name : '会话'} · Traffic`;
  } else {
    set(crumb);
    const page = !$('view-rules').hidden ? '规则' : !$('view-analysis').hidden ? '分析' : '';
    document.title = page ? `${page} · Traffic` : 'Traffic 流量分析';
  }
  for (const button of document.querySelectorAll('[data-tab]')) {
    button.setAttribute('aria-selected', String(button.dataset.tab === state.tab));
  }
  $('tab-overview').hidden = state.tab !== 'overview';
  $('tab-list').hidden = state.tab === 'overview';
  const s = state.stats || {};
  $('count-requests').textContent = s.transactions ? number(s.transactions) : '';
  $('count-alerts').textContent = s.alerts ? number(s.alerts) : '';
  const running = s.state === 'running';
  const live = $('live');
  live.className = 'live' + (state.paused ? ' paused' : '');
  set(live, h('span', { class: 'dot ' + (s.state || '') }), stateLabel(s.state) + (running ? (state.paused ? ' · 已暂停' : ' · 实时') : ''));
  $('pause').textContent = state.paused ? '恢复刷新' : '暂停';
  $('tz').textContent = zoneLabel();
  $('theme').textContent = { auto: '跟随系统', dark: '深色', light: '浅色' }[state.theme];
}

function applyTheme() {
  if (state.theme === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', state.theme);
}

// ---- sessions ----

async function loadSessions(force) {
  $('rescan').disabled = true;
  try {
    const data = await api('sessions', force ? { rescan: 1 } : null);
    state.sessions = data.sessions || [];
    state.roots = data.roots || [];
    state.refreshMs = Math.max(500, data.refresh_ms || 1000);
    if (!state.sid) {
      state.error = '';
      state.warning = data.warning || '';
      renderBanner();
    }
    renderSessions();
    renderAnalysisSessions();
    return true;
  } catch (error) {
    if (!state.sid) fail(error, '扫描会话失败');
    return false;
  } finally {
    $('rescan').disabled = false;
  }
}

function renderSessions() {
  const query = $('sessions-search').value.trim().toLowerCase();
  const list = state.sessions.filter((s) => !query || [s.name, s.host, s.dir].some((v) => String(v || '').toLowerCase().includes(query)));
  const running = state.sessions.filter((s) => s.state === 'running' && !s.problem).length;
  $('sessions-meta').textContent = `${state.sessions.length} 个会话` + (running ? ` · ${running} 个正在采集` : '') + ` · ${state.roots.join(' · ')}`;
  const nodes = [];
  let day = '';
  for (const s of list) {
    const label = formatTime(s.started).slice(0, 10);
    if (label !== day) {
      day = label;
      nodes.push(h('div', { class: 'day' }, label));
    }
    const usable = !s.problem;
    nodes.push(h('button', { type: 'button', class: 'session-row', disabled: !usable, title: s.problem ? '索引不可用：' + s.problem : null, onclick: () => { location.hash = `#/s/${s.id}/overview`; } },
      h('span', { class: 'dot ' + (usable ? s.state : 'broken') }),
      h('span', {},
        h('div', { class: 'name' }, s.name),
        h('div', { class: 'sub' }, [usable ? stateLabel(s.state) : '索引不可用', s.host, `${formatTime(s.started, 'clock')} 开始`, relativeTime(s.started)].filter(Boolean).join(' · '))),
      h('span', { class: 'path where', title: s.dir }, '‎' + s.dir),
      h('span', { class: 'figure' }, h('b', { title: s.counts_known ? null : '计数未确认' }, s.counts_known ? number(s.transactions) : s.transactions ? '≈ ' + number(s.transactions) : '—'), h('span', {}, '请求')),
      h('span', { class: 'figure' + (s.counts_known && s.alerts ? ' hot' : '') }, h('b', { title: s.counts_known ? null : '计数未确认' }, s.counts_known ? number(s.alerts) : s.alerts ? '≈ ' + number(s.alerts) : '—'), h('span', {}, '告警'))));
  }
  set($('session-list'), ...nodes);
  const empty = $('sessions-empty');
  empty.hidden = list.length > 0;
  if (state.sessions.length === 0) {
    set(empty, h('b', {}, '这个目录下还没有会话'), '用 ', h('code', {}, 'traffic capture'), ' 开始采集，或在启动时通过 ', h('code', {}, '--data-dir'), ' 指定其他采集根目录。');
  } else {
    set(empty, h('b', {}, '没有匹配的会话'), '换一个名称、主机或目录关键词试试。');
  }
}

// ---- data loading ----

function apiFilter(filter) {
  return { ...filter };
}

// Historic pages are anchored to their first row so new traffic does not shift them.
async function loadRows(anchored) {
  const seq = ++state.seq;
  const overview = state.tab === 'overview';
  const params = overview ? { alerts: 1, page: 0, limit: 8 } : { ...apiFilter(state.filter), page: state.page, alerts: state.tab === 'alerts' ? 1 : '' };
  if (!overview && anchored && state.page > 0 && state.rows.length) {
    params.anchor_id = state.rows[0].id;
    params.anchor_time = state.rows[0].time;
  }
  state.busy = true;
  try {
    const data = await api(`sessions/${state.sid}/requests`, params);
    if (seq !== state.seq) return;
    Object.assign(state, { stats: data.stats, dir: data.dir, coverage: data.coverage_warning || '', warning: data.status_warning || '', error: '' });
    if (overview) {
      state.recent = (data.rows || []).slice(0, 8);
    } else {
      state.rows = data.rows || [];
      state.count = data.count;
      state.page = data.page;
      state.pageSize = data.page_size || 100;
      if (state.page === 0) state.baseCount = data.count;
      renderRows();
    }
    renderOverview();
    renderChrome();
    renderBanner();
  } catch (error) {
    if (seq === state.seq) fail(error, '刷新失败，显示的是上次结果');
  } finally {
    if (seq === state.seq) state.busy = false;
  }
}

// Aggregations scan more of the index than a page of rows, so they refresh less often.
async function loadAux() {
  const sid = state.sid;
  const key = state.listKey;
  const overview = state.tab === 'overview';
  const summaryDue = overview && Date.now() - state.summaryAt >= Math.max(15000, state.refreshMs * 10);
  state.auxAt = Date.now();
  const params = overview ? {} : { ...apiFilter(state.filter), alerts: state.tab === 'alerts' ? 1 : '' };
  const jobs = [api(`sessions/${sid}/timeline`, params)];
  if (summaryDue) jobs.push(api(`sessions/${sid}/summary`));
  try {
    const [timeline, summary] = await Promise.all(jobs);
    if (sid !== state.sid || key !== state.listKey) return;
    state.timelines[overview ? 'overview' : 'list'] = timeline;
    if (summary) {
      state.summary = summary;
      state.summaryAt = Date.now();
    }
    renderTimelines();
    if (overview) renderOverview();
  } catch (error) {
    if (sid === state.sid) fail(error, '统计刷新失败');
  }
}

async function refresh(anchored) {
  const due = Date.now() - state.auxAt >= Math.max(5000, state.refreshMs * 5);
  await Promise.all([loadRows(anchored), due || !anchored ? loadAux() : null]);
}

// ---- overview ----

function barList(node, items, render, empty) {
  if (!items) return set(node, h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' }));
  if (!items.length) return set(node, h('div', { class: 'blank' }, empty));
  const peak = Math.max(...items.map((item) => item.count), 1);
  set(node, ...items.map((item) => {
    const { label, title, count, tone, onclick } = render(item);
    const fill = h('span', { class: 'fill ' + (tone || '') });
    fill.style.width = `${Math.max(2, (item.count / peak) * 100)}%`;
    return h('button', { type: 'button', class: 'barrow', title, onclick }, fill, h('span', { class: 'label' }, label), h('span', { class: 'count' }, count));
  }));
}

function stackBar(node, items, order, label, onclick, empty) {
  if (!items) return set(node, h('div', { class: 'skeleton' }));
  const sorted = order.map((name) => items.find((item) => item.name === name)).filter((item) => item && item.count > 0);
  const total = sorted.reduce((sum, item) => sum + item.count, 0);
  if (!total) return set(node, h('div', { class: 'blank' }, empty));
  const bar = h('div', { class: 'stack' }, sorted.map((item) => {
    const part = h('i', { class: 'c-' + item.name, title: `${label(item.name)} ${number(item.count)}` });
    part.style.flex = `${item.count} 1 0`;
    return part;
  }));
  set(node, bar, h('div', { class: 'stack-legend' }, sorted.map((item) => h('button', { type: 'button', title: '查看这些请求', onclick: () => onclick(item.name) },
    h('i', { class: 'c-' + item.name }), label(item.name), h('b', {}, number(item.count)), h('span', { class: 'muted' }, `${Math.round((item.count / total) * 100)}%`)))));
}

function renderHealth() {
  const s = state.stats || {};
  const issues = [];
  if (s.state === 'failed') issues.push('采集以失败状态结束，数据可能不完整。');
  if (s.state === 'interrupted') issues.push('采集未正常结束，尾部数据与探针清理状态未知。');
  if (s.dropped > 0) issues.push(`网卡丢包 ${number(s.dropped)} 个，部分请求可能无法还原。`);
  if (s.queue_dropped > 0) issues.push(`用户态队列丢弃 ${number(s.queue_dropped)} 个。`);
  if (s.probe_failures > 0) issues.push(`探针传输失败 ${number(s.probe_failures)} 次，恢复后仍保留。`);
  if (s.tls_dropped > 0) issues.push(`TLS 已知丢弃 ${number(s.tls_dropped)} 个，这是已观测到的下限。`);
  if (s.alert_delivery_failed > 0 || s.alert_delivery_dropped > 0) issues.push(`告警 Webhook 失败 ${number(s.alert_delivery_failed)} 次，队列丢弃 ${number(s.alert_delivery_dropped)} 次。`);
  if ((s.errors || []).length) issues.push(`采集过程记录了 ${s.errors.length} 条错误，详见“采集状态”。`);
  const bad = s.state === 'failed' || s.state === 'stale' || s.state === 'interrupted';
  set($('health'), issues.length ? h('div', { class: 'health' + (bad ? ' bad' : '') },
    h('div', {}, h('b', {}, '这个会话的数据有缺口'), h('ul', {}, issues.map((text) => h('li', {}, text))))) : '');
}

function renderOverview() {
  if (state.tab !== 'overview') return;
  const s = state.stats || {};
  const sum = state.summary;
  renderHealth();
  const tile = (label, value, note, tone) => h('div', { class: 'tile ' + (tone || '') },
    h('div', { class: 'label' }, label), h('div', { class: 'value' }, state.stats ? number(value) : '—'), h('div', { class: 'note' }, note || ''));
  set($('tiles'),
    tile('累计请求', s.transactions, sum ? `索引内保留 ${number(sum.total)} 条` : ''),
    tile('累计告警命中', s.alerts, sum ? `涉及 ${number(sum.alerted)} 条请求` : '', s.alerts > 0 ? 'alerting' : ''),
    tile('网络包', s.packets, s.tls_wire_records ? `TLS 外层记录 ${number(s.tls_wire_records)}` : ''),
    tile('网卡丢包', s.dropped, '', s.dropped > 0 ? 'warn' : ''),
    tile('用户态队列丢弃', s.queue_dropped, '', s.queue_dropped > 0 ? 'warn' : ''),
    tile('TLS 已知丢弃', s.tls_dropped, '已观测下限', s.tls_dropped > 0 ? 'warn' : ''));

  barList($('ov-rules'), sum && sum.rules, (item) => ({
    label: item.name, tone: item.severity, title: '查看命中这条规则的请求',
    count: [h('span', { class: 'sev ' + item.severity }, SEVERITIES[item.severity] || '—'), ' ', number(item.count)],
    onclick: () => go({ tab: 'alerts', filter: { rule: item.name }, id: null }),
  }), '没有规则命中');
  barList($('ov-clients'), sum && sum.clients, (item) => ({
    label: item.name, title: '查看这个来源的全部请求',
    count: [item.alerts ? [h('b', {}, number(item.alerts)), ' 告警 · '] : null, number(item.count), ' 请求'],
    onclick: () => go({ tab: 'requests', filter: { client: item.name.replace(/^\[|\]$/g, '') }, id: null }),
  }), '暂无请求');
  stackBar($('ov-severity'), sum && sum.severities, ['high', 'medium', 'low'], (name) => SEVERITIES[name] + '危',
    (name) => go({ tab: 'alerts', filter: { severity: name }, id: null }), '没有告警');
  if (sum && !sum.statuses) {
    set($('ov-status'), h('div', { class: 'blank' }, '索引较大，已跳过状态统计。可在请求列表按状态筛选。'));
  } else {
    stackBar($('ov-status'), sum && sum.statuses, ['2xx', '3xx', '4xx', '5xx', '1xx', 'pending', 'other'], (name) => STATUS_LABELS[name] || name,
      (name) => go({ tab: 'requests', filter: name === 'other' || name === '1xx' ? {} : { status: name }, id: null }), '暂无请求');
  }

  const recent = $('ov-recent');
  if (!state.stats) set(recent, h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' }));
  else if (!state.recent.length) set(recent, h('div', { class: 'blank' }, '没有告警。规则命中的请求会出现在这里。'));
  else {
    set(recent, ...state.recent.map((row) => h('button', { type: 'button', title: row.url, onclick: () => go({ tab: 'alerts', filter: {}, id: row.id }) },
      h('span', { class: 'sev ' + row.severity }, SEVERITIES[row.severity] || '—'),
      h('span', { class: 'when', title: formatTime(row.time, 'ms') }, formatTime(row.time, 'clock')),
      h('span', { class: 'who' }, stripPort(row.client)),
      h('span', {}, `${row.method} ${row.url}`))));
  }

  const session = currentSession();
  const started = parseTime(s.started);
  const facts = [
    ['状态', stateLabel(s.state)],
    ['开始时间', started ? `${formatTime(started)}（${relativeTime(started)}）` : '未知'],
    ['会话目录', state.dir || (session && session.dir) || '—', true],
    ['TLS 探针', s.tls || '—', true],
    ['TLS 明文请求', number(s.tls_requests)],
    ['告警 Webhook', `已送达 ${number(s.alert_delivered)} · 失败 ${number(s.alert_delivery_failed)} · 队列丢弃 ${number(s.alert_delivery_dropped)}`],
    ['资源限制', s.resource_limits || '—', true],
    ['采集完整性', state.coverage || '—'],
    ['数据排空', s.drain_state || '未知'],
    ['已知缺口', s.gap_counts ? JSON.stringify(s.gap_counts) : '未知'],
    ['退出确认', s.probe_exits ? JSON.stringify(s.probe_exits) : '未知'],
    ['探针传输', s.probe_transports ? JSON.stringify(s.probe_transports) : '未知'],
    ['探针传输失败', s.probe_failures == null ? '未知' : `${number(s.probe_failures)} 次，恢复后仍保留`],
  ];
  set($('facts'), ...facts.flatMap(([name, value, mono]) => [h('dt', {}, name), h('dd', { class: mono ? 'mono' : '' }, value)]));
  const targets = s.targets || [];
  set($('targets'), targets.length ? h('div', { class: 'targets' }, targets.map((t) => h('div', { class: 'target' },
    h('b', {}, t.service), h('span', { class: 'pill' }, t.state), h('span', {}, `PID ${t.pid}`),
    (t.ports || []).length ? h('span', {}, '端口 ' + t.ports.join(', ')) : null, t.library ? h('span', {}, t.library) : null))) : h('div', { class: 'blank' }, '没有服务探针记录'));
  const errors = s.errors || [];
  set($('errors'), ...(errors.length ? errors.map((e) => h('li', {}, e)) : [h('li', { class: 'none' }, '没有记录到错误')]));
}

// ---- timeline ----

function renderTimelines() {
  const overview = state.timelines.overview;
  if (state.tab === 'overview') {
    drawTimeline($('ov-timeline'), overview, 120);
    $('ov-timeline-meta').textContent = overview && overview.total ? `每格 ${duration(overview.granularity)} · ${formatTime(overview.first)} 起` : '';
  } else {
    drawTimeline($('list-timeline'), state.timelines.list, 44);
  }
}

// Bars are requests per bucket with the alerting share drawn on top; dragging selects a time range.
function drawTimeline(host, data, height) {
  if (!data) return set(host, h('div', { class: 'skeleton' }));
  if (!data.total) return set(host, h('div', { class: 'none' }, '这个范围内没有请求'));
  const step = data.granularity * 1000;
  const byTime = new Map(data.buckets.map((bucket) => [Date.parse(bucket.t), bucket]));
  const start = Date.parse(data.buckets[0].t);
  const count = Math.min(2000, Math.round((Date.parse(data.buckets[data.buckets.length - 1].t) - start) / step) + 1);
  const width = Math.max(200, host.clientWidth);
  const slot = width / count;
  const peak = Math.max(...data.buckets.map((bucket) => bucket.requests), 1);
  const alertsOnly = state.tab === 'alerts';
  const scale = (value) => (value ? Math.max(2, (value / peak) * (height - 4)) : 0);
  const bars = [];
  for (let i = 0; i < count; i++) {
    const bucket = byTime.get(start + i * step);
    if (!bucket) continue;
    const x = i * slot + (slot > 3 ? 0.5 : 0);
    const w = Math.max(1, slot - (slot > 3 ? 1 : 0));
    const total = scale(bucket.requests);
    const hit = alertsOnly ? total : scale(bucket.alerts);
    bars.push(svg('rect', { class: 'bar', x, y: height - total, width: w, height: total, rx: Math.min(1.5, w / 2) }));
    if (hit) bars.push(svg('rect', { class: 'bar hit', x, y: height - hit, width: w, height: hit, rx: Math.min(1.5, w / 2) }));
  }
  const hover = svg('rect', { class: 'hover', y: 0, height, width: Math.max(1, slot), visibility: 'hidden' });
  const brush = svg('rect', { class: 'brush', y: 0.5, height: height - 1, visibility: 'hidden' });
  const chart = svg('svg', { viewBox: `0 0 ${width} ${height}`, height, preserveAspectRatio: 'none', role: 'img', 'aria-label': '请求与告警随时间的分布' },
    bars, svg('line', { class: 'base', x1: 0, x2: width, y1: height - 0.5, y2: height - 0.5 }), hover, brush);
  const tip = h('div', { class: 'tip', hidden: true });
  const firstDay = parts(new Date(start)).slice(0, 3).join('-');
  const lastDay = parts(new Date(start + count * step)).slice(0, 3).join('-');
  const crossesDay = firstDay !== lastDay;
  const axisStyle = data.granularity >= 86400 ? 'full' : crossesDay ? 'dayclock' : 'clock';
  const labels = [0, 0.5, 1].map((at) => formatTime(new Date(start + Math.round((count - 1) * at) * step + (at === 1 ? step : 0)), axisStyle));
  if (data.granularity >= 86400) labels.forEach((text, i) => { labels[i] = text.slice(0, 10); });
  set(host, chart, tip, h('div', { class: 'axis' }, labels.map((text) => h('span', {}, text))));

  const indexAt = (event) => {
    const box = chart.getBoundingClientRect();
    return Math.max(0, Math.min(count - 1, Math.floor(((event.clientX - box.left) / box.width) * count)));
  };
  let anchor = null;
  const paint = (event) => {
    const index = indexAt(event);
    const from = anchor == null ? index : Math.min(anchor, index);
    const to = anchor == null ? index : Math.max(anchor, index);
    hover.setAttribute('x', index * slot);
    hover.setAttribute('visibility', anchor == null ? 'visible' : 'hidden');
    if (anchor != null) {
      brush.setAttribute('x', from * slot);
      brush.setAttribute('width', (to - from + 1) * slot);
      brush.setAttribute('visibility', 'visible');
    }
    let requests = 0;
    let alerts = 0;
    for (let i = from; i <= to; i++) {
      const bucket = byTime.get(start + i * step);
      if (bucket) {
        requests += bucket.requests;
        alerts += bucket.alerts;
      }
    }
    const tipStyle = data.granularity >= 86400 || crossesDay ? 'dayclock' : 'clock';
    const span = formatTime(new Date(start + from * step), tipStyle) + ' – ' + formatTime(new Date(start + (to + 1) * step), tipStyle);
    set(tip, span, ' · ', h('b', {}, number(requests)), ' 请求', alerts ? [' · ', h('b', { class: 'hot' }, number(alerts)), ' 含告警'] : null);
    tip.hidden = false;
    tip.style.left = `${Math.max(90, Math.min(width - 90, ((from + to + 1) / 2) * slot))}px`;
    return [from, to];
  };
  chart.addEventListener('pointermove', paint);
  chart.addEventListener('pointerleave', () => {
    if (anchor != null) return;
    hover.setAttribute('visibility', 'hidden');
    tip.hidden = true;
  });
  chart.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    anchor = indexAt(event);
    chart.setPointerCapture(event.pointerId);
    paint(event);
  });
  chart.addEventListener('pointerup', (event) => {
    if (anchor == null) return;
    const [from, to] = paint(event);
    anchor = null;
    // A plain click on a one-second bucket cannot zoom further.
    if (from === to && count === 1 && data.granularity === 1) return;
    const filter = state.tab === 'overview' ? {} : state.filter;
    go({ tab: state.tab === 'overview' ? 'requests' : state.tab, id: state.tab === 'overview' ? null : state.selected,
      filter: { ...filter, since: new Date(start + from * step).toISOString(), until: new Date(start + (to + 1) * step).toISOString() } });
  });
  chart.addEventListener('pointercancel', () => {
    anchor = null;
    brush.setAttribute('visibility', 'hidden');
  });
}

// ---- filters ----

function setFilter(patch, replace) {
  const filter = { ...state.filter, ...patch };
  for (const key of Object.keys(filter)) {
    if (!filter[key]) delete filter[key];
  }
  go({ filter }, replace);
}

function syncFilters() {
  const form = $('filters');
  const f = state.filter;
  for (const name of ['keyword', 'client', 'rule', 'service', 'method']) {
    const input = form.elements[name];
    if (document.activeElement !== input) input.value = f[name] || '';
  }
  // A method outside the preset list still has to show as selected.
  if (f.method && form.elements.method.value !== f.method) {
    form.elements.method.append(h('option', {}, f.method));
    form.elements.method.value = f.method;
  }
  for (const name of ['since', 'until']) {
    const input = form.elements[name];
    if (document.activeElement !== input) input.value = toInputValue(f[name]);
  }
  for (const button of form.querySelectorAll('[data-filter]')) {
    button.setAttribute('aria-pressed', String(f[button.dataset.filter] === button.dataset.value));
  }
  const active = Object.keys(f).length;
  $('filters-clear').hidden = !active;
  const hiddenActive = MORE_KEYS.filter((key) => f[key]).length;
  $('more-toggle').textContent = hiddenActive ? `更多条件 · ${hiddenActive}` : '更多条件';
  const chip = (label, value, keys) => h('span', { class: 'chip' }, h('span', {}, label), h('b', { title: value }, value),
    h('button', { type: 'button', 'aria-label': `移除${label}条件`, onclick: () => setFilter(Object.fromEntries(keys.map((key) => [key, '']))) }, '✕'));
  const chips = [];
  if (f.since || f.until) {
    chips.push(chip('时间', `${f.since ? formatTime(f.since) : '最早'} – ${f.until ? formatTime(f.until) : '最新'}`, ['since', 'until']));
  }
  if (f.client) chips.push(chip('来源', f.client, ['client']));
  if (f.rule) chips.push(chip('规则', f.rule, ['rule']));
  if (f.service) chips.push(chip('服务', f.service, ['service']));
  if (f.status && !/^(\dxx|pending)$/.test(f.status)) chips.push(chip('状态', f.status, ['status']));
  set($('chips'), ...chips);
}

// ---- rows ----

function renderRows(loading) {
  const key = JSON.stringify(state.rows) + '|' + state.selected + '|' + state.utc;
  if (key !== state.rowsKey) {
    state.rowsKey = key;
    const known = state.known;
    set($('rows-body'), ...state.rows.map((row) => {
      const fresh = known && state.page === 0 && !known.has(row.id);
      return h('tr', { class: [row.id === state.selected ? 'selected' : '', fresh ? 'fresh' : ''].join(' '), 'data-id': row.id },
        h('td', { class: 'time', title: formatTime(row.time, 'ms') + ' ' + zoneLabel() }, h('span', { class: 'date' }, formatTime(row.time, 'row').slice(0, 6)), formatTime(row.time, 'row').slice(6)),
        h('td', {}, row.severity ? h('span', { class: 'sev ' + row.severity }, SEVERITIES[row.severity]) : ''),
        h('td', {}, row.method || '—'),
        h('td', { class: 'num st-' + (row.status ? String(row.status)[0] : '0') }, row.status ? String(row.status) : '待响应'),
        h('td', { class: 'extra', title: row.client }, stripPort(row.client)),
        h('td', { class: 'extra', title: row.host }, row.host || '—'),
        h('td', { class: 'wide url', title: row.url }, row.url, row.incomplete && h('span', { class: 'flag' }, '不完整'), row.truncated && h('span', { class: 'flag' }, '截断')));
    }));
    if (state.rows.length || !loading) state.known = new Set(state.rows.map((row) => row.id));
  }
  const empty = $('rows-empty');
  empty.hidden = state.rows.length > 0;
  if (!state.rows.length) {
    const filtered = Object.keys(state.filter).length > 0;
    if (loading) set(empty, '正在加载…');
    else if (filtered) set(empty, h('b', {}, '没有符合条件的请求'), '放宽条件或清空筛选后再看。', h('br'), h('button', { type: 'button', onclick: () => go({ filter: {} }) }, '清空筛选'));
    else if (state.tab === 'alerts') set(empty, h('b', {}, '没有告警'), '这个会话里还没有请求命中检测规则。');
    else set(empty, h('b', {}, '还没有请求'), '采集到的 HTTP 请求会显示在这里。');
  }
  const pages = Math.max(1, Math.ceil(state.count / (state.pageSize || 100)));
  $('pager-info').textContent = state.count ? `${number(state.count)} 条 · 第 ${state.page + 1} / ${pages} 页` : '';
  $('page-first').disabled = $('page-prev').disabled = state.page === 0;
  $('page-next').disabled = state.page + 1 >= pages;
  const added = state.page > 0 ? state.count - state.baseCount : 0;
  const pill = $('newpill');
  pill.hidden = added <= 0;
  pill.textContent = `↑ 有 ${number(added)} 条新请求`;
  $('detail-prev').disabled = selectedIndex() <= 0;
  $('detail-next').disabled = selectedIndex() < 0 || selectedIndex() >= state.rows.length - 1;
}

const selectedIndex = () => state.rows.findIndex((row) => row.id === state.selected);

function changePage(page) {
  state.page = Math.max(0, page);
  state.known = null;
  $('rows-wrap').scrollTop = 0;
  loadRows(false);
}

function moveSelection(delta, absolute) {
  if (!state.rows.length) return;
  const index = absolute != null ? absolute : selectedIndex() + delta;
  const next = state.rows[Math.max(0, Math.min(state.rows.length - 1, index))];
  go({ id: next.id }, true);
  const node = $('rows-body').querySelector(`tr[data-id="${CSS.escape(next.id)}"]`);
  if (node) node.scrollIntoView({ block: 'nearest' });
}

// ---- detail ----

function closeDetail() {
  state.selected = null;
  state.detail = null;
  $('detail').hidden = $('splitter').hidden = true;
  $('split').classList.remove('open');
  $('tab-list').classList.remove('reading');
}

function hideDetail() {
  closeDetail();
  renderRows();
}

async function showDetail(id, quiet) {
  if (!quiet) {
    state.selected = id;
    state.detailError = '';
    if (state.detail && state.detail.transaction.id !== id) state.detail = null;
    $('detail').hidden = $('splitter').hidden = false;
    $('split').classList.add('open');
    $('tab-list').classList.add('reading');
    renderDetail();
    renderRows();
  }
  const sid = state.sid;
  try {
    const data = await api(`sessions/${sid}/requests/${encodeURIComponent(id)}`);
    if (state.selected !== id || state.sid !== sid) return;
    state.detail = data;
    renderDetail();
  } catch (error) {
    if (state.selected !== id || state.sid !== sid || quiet) return;
    state.detailError = error.status === 404 ? '这条记录已被保留期清理，无法再查看。' : error.message;
    renderDetail();
  }
}

// Pending requests only need a few fields; avoid downloading the full bodies on every tick.
async function showDetailMeta(id) {
  const sid = state.sid;
  try {
    const data = await api(`sessions/${sid}/requests/${encodeURIComponent(id)}/meta`);
    if (state.selected !== id || state.sid !== sid) return;
    const t = state.detail && state.detail.transaction;
    if (!t) return;
    if (t.status !== data.status || Boolean(t.incomplete) !== data.incomplete || Boolean(t.truncated) !== data.truncated || (t.alerts || []).length !== data.alert_count) {
      await showDetail(id, true);
    }
  } catch (_) { /* the next full refresh reports the error */ }
}

function splitHttp(text) {
  const match = /\r?\n\r?\n/.exec(text);
  const head = match ? text.slice(0, match.index) : text;
  const lines = head.split(/\r?\n/);
  const headers = lines.slice(1).map((line) => {
    const at = line.indexOf(':');
    return at > 0 ? [line.slice(0, at), line.slice(at + 1).trim()] : [line, null];
  });
  return { start: lines[0] || '', headers, body: match ? text.slice(match.index + match[0].length) : '' };
}

const headerValue = (message, name) => (message.headers.find(([key]) => key.toLowerCase() === name) || [])[1] || '';

function prettyBody(message) {
  if (!state.pretty || !message.body) return message.body;
  const trimmed = message.body.trim();
  if (!/^[[{]/.test(trimmed)) return message.body;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch (_) {
    return message.body;
  }
}

function httpView(text, needles) {
  const message = splitHttp(text);
  const body = prettyBody(message);
  return h('pre', {},
    h('span', { class: 'sl' }, marked(message.start, needles)), '\n',
    message.headers.map(([name, value]) => [h('span', { class: 'hn' }, name), value == null ? '' : [': ', marked(value, needles)], '\n']),
    body ? ['\n', marked(body, needles)] : null);
}

function pairs(query) {
  try {
    return [...new URLSearchParams(query)];
  } catch (_) {
    return [];
  }
}

function paramsBlock(title, list, needles) {
  if (!list.length) return null;
  return h('div', { class: 'params' }, h('h3', {}, title), h('dl', {}, list.slice(0, 200).map(([name, value]) => [h('dt', {}, name), h('dd', {}, marked(value, needles))])));
}

function decodedUrl(url) {
  let text = url;
  for (let round = 0; round < 2; round++) {
    try {
      const next = decodeURIComponent(text.replace(/\+/g, ' '));
      if (next === text) break;
      text = next;
    } catch (_) {
      break;
    }
  }
  return text;
}

function curlCommand(data) {
  const t = data.transaction;
  const message = splitHttp(data.request_text || '');
  const quote = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;
  const host = headerValue(message, 'host') || t.host || 'HOST';
  const tls = /tls|ssl|https/i.test(`${t.source} ${t.backend}`) || /:443$/.test(t.local_endpoint || '');
  const lines = [`curl -i -X ${t.method || 'GET'} ${quote(`${tls ? 'https' : 'http'}://${host}${t.url || '/'}`)}`];
  for (const [name, value] of message.headers) {
    if (value == null || /^(host|content-length|connection|transfer-encoding)$/i.test(name)) continue;
    lines.push(`  -H ${quote(`${name}: ${value}`)}`);
  }
  if (message.body) lines.push(`  --data-raw ${quote(message.body)}`);
  return lines.join(' \\\n');
}

function availableTabs(data) {
  const alerts = (data.transaction.alerts || []).length;
  return DETAIL_TABS.filter(([key]) => (key !== 'decoded' || data.decoded_view || data.response_decoded_view) && (key !== 'alerts' || alerts));
}

function renderDetail() {
  const data = state.detail;
  const body = $('detail-body');
  const controls = ['detail-curl', 'detail-export', 'detail-copy', 'pretty'];
  if (!data) {
    for (const id of controls) $(id).disabled = true;
    set($('detail-pills'), state.detailError ? '无法显示' : '正在加载…');
    set($('detail-url'));
    $('detail-decoded').hidden = true;
    set($('detail-meta'));
    set($('detail-tabs'));
    set(body, state.detailError ? h('p', { class: 'hint' }, state.detailError) : [h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' })]);
    return;
  }
  for (const id of controls) $(id).disabled = false;
  const t = data.transaction;
  const lastRules = saved('rule-file', '');
  $('detail-test').href = (lastRules && lastRules !== NEW_RULE ? ruleHash(lastRules) : '#/rules') + `?sid=${state.sid}&rid=${encodeURIComponent(t.id)}`;
  const alerts = t.alerts || [];
  const needles = [...new Set(alerts.map((a) => a.match).filter(Boolean))];
  set($('detail-pills'),
    h('span', { class: 'method' }, t.method || '—'),
    h('span', { class: 'status st-' + (t.status ? String(t.status)[0] : '0') }, t.status ? String(t.status) : '待响应'),
    t.incomplete && h('span', { class: 'flag' }, '不完整'), t.truncated && h('span', { class: 'flag' }, '截断'),
    [...new Map(alerts.map((a) => [a.rule, a])).values()].slice(0, 4).map((a) => h('button', { type: 'button', class: 'rule sev ' + a.severity, title: '查看检测依据', onclick: () => setDetailTab('alerts') }, a.rule)));
  set($('detail-url'), h('span', { class: 'host' }, t.host || ''), marked(t.url || '', needles));
  const decoded = decodedUrl(t.url || '');
  $('detail-decoded').hidden = decoded === t.url;
  set($('detail-decoded'), ...marked(decoded, needles));

  const ip = stripPort(t.client).replace(/^\[|\]$/g, '');
  const pick = (label, patch) => h('button', { type: 'button', title: '按这个值筛选', onclick: () => go({ tab: state.tab, filter: { ...state.filter, ...patch } }) }, label);
  const meta = [
    ['时间', formatTime(t.time, 'ms')],
    ['来源', t.client && pick(t.client, { client: ip })],
    ['直连对端', t.peer_client],
    ['来源地址依据', t.client_source],
    ['Host', t.host && pick(t.host, { keyword: t.host })],
    ['服务', t.service && [pick(t.service, { service: t.service }), t.target_id ? ` · ${t.target_id}` : '']],
    ['后端 / 本地端点', [t.backend, t.local_endpoint].filter(Boolean).join(' · ')],
    ['采集来源', [t.source, t.pid ? 'PID ' + t.pid : ''].filter(Boolean).join(' · ')],
    ['连接', t.connection],
    ['协议', t.protocol || '未知'],
    ['HTTP/2 stream ID', t.stream_id ? String(t.stream_id) : ''],
    ['完整性原因', (t.integrity_reasons || []).join(', ')],
    ['记录 ID', t.id],
  ].filter(([, value]) => value);
  set($('detail-meta'), ...meta.map(([name, value]) => h('div', {}, h('dt', {}, name), h('dd', {}, value))));

  const tabs = availableTabs(data);
  const tab = tabs.some(([key]) => key === state.detailTab) ? state.detailTab : 'request';
  set($('detail-tabs'), ...tabs.map(([key, label]) => h('button', { type: 'button', role: 'tab', 'aria-selected': String(key === tab), onclick: () => setDetailTab(key) },
    label, key === 'alerts' ? h('span', { class: 'badge alert' }, String(alerts.length)) : null)));
  $('pretty-wrap').hidden = tab !== 'request' && tab !== 'response';
  $('detail-copy').hidden = tab === 'alerts';

  const scroll = body.scrollTop;
  if (tab === 'request') {
    if (!data.request_text) set(body, h('p', { class: 'hint' }, '没有保存请求内容。'));
    else {
      const message = splitHttp(data.request_text);
      const query = (t.url || '').split('?')[1] || '';
      const form = /x-www-form-urlencoded/i.test(headerValue(message, 'content-type')) ? pairs(message.body) : [];
      set(body, ...[paramsBlock('查询参数（已解码）', pairs(query.split('#')[0]), needles), paramsBlock('表单参数（已解码）', form, needles), httpView(data.request_text, needles)].filter(Boolean));
    }
  } else if (tab === 'response') {
    set(body, data.response_text ? httpView(data.response_text, [])
      : h('p', { class: 'hint' }, t.status ? '没有保存响应内容。' : '还没有采集到响应。会话仍在采集时，响应到达后会自动出现。'));
  } else if (tab === 'decoded') {
    const block = (title, view, text) => view && h('section', {}, h('h3', {}, `${title} · ${view}`), h('pre', {}, marked(text, title === '请求正文' ? needles : [])));
    set(body, ...[block('请求正文', data.decoded_view, data.decoded_body), block('响应正文', data.response_decoded_view, data.response_decoded_body)].filter(Boolean));
  } else {
    set(body, ...alerts.map((a) => h('div', { class: 'alert-card ' + a.severity },
      h('header', {}, h('span', { class: 'sev ' + a.severity }, SEVERITIES[a.severity] || '—'), a.rule, h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'ghost', onclick: () => go({ tab: 'alerts', filter: { rule: a.rule } }) }, '查看同规则请求')),
      h('div', { class: 'info' }, `规则版本 ${a.version} · 命中字段 ${a.field || '—'} · 视图 ${a.view || '原始内容'} · URL 解码 ${a.decoding} 轮`),
      h('pre', {}, a.match))));
  }
  body.scrollTop = scroll;
}

function setDetailTab(key) {
  state.detailTab = key;
  save('detail-tab', key);
  $('detail-body').scrollTop = 0;
  renderDetail();
}

function detailText() {
  const data = state.detail;
  if (!data) return '';
  const tab = availableTabs(data).some(([key]) => key === state.detailTab) ? state.detailTab : 'request';
  if (tab === 'response') return data.response_text;
  if (tab === 'decoded') return [data.decoded_body, data.response_decoded_body].filter(Boolean).join('\n\n');
  return data.request_text;
}

async function exportEvidence() {
  if (!state.detail) return;
  const id = state.detail.transaction.id;
  const button = $('detail-export');
  button.disabled = true;
  button.textContent = '正在打包…';
  try {
    const response = await request(`sessions/${state.sid}/requests/${encodeURIComponent(id)}/export`);
    const blob = await response.blob();
    const name = (/filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') || '') || [])[1] || 'evidence.zip';
    const link = h('a', { href: URL.createObjectURL(blob), download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 10000);
    toast(`已导出 ${name}`);
  } catch (error) {
    if (error.status !== 401) toast('导出失败：' + error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = '导出证据';
  }
}

// ---- refresh loop ----

async function tick() {
  if (!state.token || document.hidden) return;
  if (!state.sid) {
    if (!$('view-sessions').hidden || !$('view-analysis').hidden) await loadSessions();
    return;
  }
  if (state.paused || state.busy) return;
  if (state.stats && state.stats.state !== 'running' && state.stats.state !== 'starting' && state.stats.state !== 'stale') return;
  await refresh(true);
  const t = state.detail && state.detail.transaction;
  // A response can arrive after the request was first shown.
  if (t && (!t.status || t.incomplete)) showDetailMeta(t.id);
}

let refreshTimer = 0;

function schedule() {
  clearTimeout(refreshTimer);
  refreshTimer = 0;
  if (!state.token) return;
  let delay;
  if (state.offline) delay = 3000;
  else if (!state.sid) delay = 10000;
  else if (!state.stats) delay = Math.max(500, state.refreshMs);
  else if ((state.stats.state === 'running' || state.stats.state === 'starting')) delay = state.refreshMs;
  else if (state.stats.state === 'stale') delay = Math.max(5000, state.refreshMs);
  else return; // Stopped and finished sessions only refresh on demand.
  refreshTimer = setTimeout(async () => {
    await tick();
    schedule();
  }, delay);
}

// ---- wiring ----

function bind() {
  $('gate-form').addEventListener('submit', (event) => {
    event.preventDefault();
    state.token = $('gate-token').value.trim();
    $('gate-token').value = '';
    if (!state.token) return;
    try {
      sessionStorage.setItem('traffic-token', state.token);
    } catch (_) { /* the token then lasts until reload */ }
    state.error = '';
    renderBanner();
    route();
  });
  $('rescan').addEventListener('click', () => loadSessions(true));
  $('sessions-search').addEventListener('input', renderSessions);
  $('pause').addEventListener('click', togglePause);
  $('tz').addEventListener('click', () => {
    state.utc = !state.utc;
    save('tz', state.utc ? 'utc' : 'local');
    state.rowsKey = '';
    renderChrome();
    if (state.sid) {
      syncFilters();
      renderRows();
      renderOverview();
      renderTimelines();
      if (state.selected) renderDetail();
    } else {
      renderSessions();
    }
  });
  $('theme').addEventListener('click', () => {
    state.theme = { auto: 'dark', dark: 'light', light: 'auto' }[state.theme];
    save('theme', state.theme);
    applyTheme();
    renderChrome();
  });
  $('help-open').addEventListener('click', () => $('help').showModal());
  $('help-close').addEventListener('click', () => $('help').close());
  $('help').addEventListener('click', (event) => { if (event.target === $('help')) $('help').close(); });
  for (const button of document.querySelectorAll('[data-tab]')) {
    button.addEventListener('click', () => go({ tab: button.dataset.tab, id: null }));
  }
  $('ov-alerts-more').addEventListener('click', () => go({ tab: 'alerts', filter: {}, id: null }));

  const form = $('filters');
  let typing = 0;
  form.addEventListener('submit', (event) => event.preventDefault());
  form.addEventListener('input', (event) => {
    const name = event.target.name;
    if (!name) return;
    const apply = () => {
      const value = name === 'since' || name === 'until' ? fromInputValue(event.target.value) : event.target.value.trim();
      setFilter({ [name]: value }, true);
    };
    clearTimeout(typing);
    if (event.target.tagName === 'SELECT') apply();
    else typing = setTimeout(apply, 300);
  });
  for (const button of form.querySelectorAll('[data-filter]')) {
    button.addEventListener('click', () => {
      const key = button.dataset.filter;
      setFilter({ [key]: state.filter[key] === button.dataset.value ? '' : button.dataset.value });
    });
  }
  $('more-toggle').addEventListener('click', () => {
    const open = $('more').hidden;
    $('more').hidden = !open;
    $('more-toggle').setAttribute('aria-expanded', String(open));
    if (open) form.elements.client.focus();
  });
  $('filters-clear').addEventListener('click', () => go({ filter: {} }));

  $('rows-body').addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-id]');
    if (row) go({ id: row.dataset.id }, Boolean(state.selected));
  });
  $('newpill').addEventListener('click', () => changePage(0));
  $('page-first').addEventListener('click', () => changePage(0));
  $('page-prev').addEventListener('click', () => changePage(state.page - 1));
  $('page-next').addEventListener('click', () => changePage(state.page + 1));
  $('detail-close').addEventListener('click', () => go({ id: null }, true));
  $('detail-prev').addEventListener('click', () => moveSelection(-1));
  $('detail-next').addEventListener('click', () => moveSelection(1));
  $('detail-export').addEventListener('click', exportEvidence);
  $('detail-curl').addEventListener('click', () => state.detail && copyText(curlCommand(state.detail), ' cURL 命令'));
  $('detail-copy').addEventListener('click', () => copyText(detailText() || '', '当前内容'));
  $('pretty').checked = state.pretty;
  $('pretty').addEventListener('change', () => {
    state.pretty = $('pretty').checked;
    save('pretty', state.pretty ? '1' : '0');
    renderDetail();
  });

  // The detail width is a personal layout preference, kept across sessions.
  const split = $('split');
  const splitter = $('splitter');
  const width = Number(saved('detail-width', 0));
  if (width) split.style.setProperty('--detail-w', width + 'px');
  splitter.addEventListener('pointerdown', (event) => {
    splitter.setPointerCapture(event.pointerId);
    splitter.classList.add('dragging');
  });
  splitter.addEventListener('pointermove', (event) => {
    if (!splitter.classList.contains('dragging')) return;
    const box = split.getBoundingClientRect();
    const next = Math.round(Math.max(360, Math.min(box.width - 360, box.right - event.clientX - 14)));
    split.style.setProperty('--detail-w', next + 'px');
    save('detail-width', String(next));
  });
  const release = () => splitter.classList.remove('dragging');
  splitter.addEventListener('pointerup', release);
  splitter.addEventListener('pointercancel', release);
  splitter.addEventListener('dblclick', () => {
    split.style.removeProperty('--detail-w');
    save('detail-width', '');
  });

  let resizing = 0;
  window.addEventListener('resize', () => {
    clearTimeout(resizing);
    resizing = setTimeout(() => state.sid && renderTimelines(), 150);
  });
  window.addEventListener('hashchange', route);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
  document.addEventListener('keydown', onKey);
}

function togglePause() {
  state.paused = !state.paused;
  renderChrome();
  if (!state.paused) refresh(true).then(schedule);
}

function onKey(event) {
  if (event.ctrlKey || event.metaKey || event.altKey || $('help').open) return;
  const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(event.target.tagName);
  if (event.key === 'Escape') {
    if (typing) event.target.blur();
    else if (state.selected) go({ id: null }, true);
    return;
  }
  if (typing) return;
  if (event.key === '?') {
    $('help').showModal();
    return event.preventDefault();
  }
  if (!state.sid) {
    if (event.key === '/') {
      const search = !$('view-rules').hidden ? 'rules-search' : !$('view-analysis').hidden ? 'analysis-search' : 'sessions-search';
      $(search).focus();
      event.preventDefault();
    }
    return;
  }
  const tabs = { 1: 'overview', 2: 'requests', 3: 'alerts' };
  const list = state.tab !== 'overview';
  if (tabs[event.key]) go({ tab: tabs[event.key], id: null });
  else if (event.key === ' ' && event.target.tagName !== 'BUTTON') togglePause();
  else if (event.key === 'r') {
    state.auxAt = 0;
    state.summaryAt = 0;
    refresh(true).then(schedule);
  } else if (!list) return;
  else if (event.key === 'j' || event.key === 'ArrowDown') moveSelection(1);
  else if (event.key === 'k' || event.key === 'ArrowUp') moveSelection(-1);
  else if (event.key === 'g') moveSelection(0, 0);
  else if (event.key === 'G') moveSelection(0, state.rows.length - 1);
  else if (event.key === 'n' && !$('page-next').disabled) changePage(state.page + 1);
  else if (event.key === 'p' && !$('page-prev').disabled) changePage(state.page - 1);
  else if (event.key === '/') $('filters').elements.keyword.focus();
  else if ((event.key === '[' || event.key === ']') && state.detail) {
    const keys = availableTabs(state.detail).map(([key]) => key);
    const at = Math.max(0, keys.indexOf(state.detailTab));
    setDetailTab(keys[(at + (event.key === ']' ? 1 : keys.length - 1)) % keys.length]);
  } else return;
  event.preventDefault();
}

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

// ---- analysis page ----

const sessionName = (id) => { const s = state.sessions.find((item) => item.id === id); return s ? s.name : id.slice(0, 12); };
const jobRunning = () => Boolean(jobUI.job && jobUI.job.state === 'running');
const JOB_STATES = { running: '分析中', succeeded: '已完成', failed: '失败', cancelled: '已停止' };

function elapsed(job) {
  const from = parseTime(job.started);
  const to = job.state === 'running' ? new Date() : parseTime(job.finished);
  if (!from || !to) return '—';
  const seconds = Math.max(0, Math.round((to - from) / 1000));
  return seconds < 60 ? `${seconds} 秒` : `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
}

function renderRuleOptions() {
  const select = $('analysis-rule');
  const wanted = (jobUI.page && jobUI.page.rules) || select.value || saved('analysis-rule', '');
  set(select, h('option', { value: '' }, '仅内置规则'), ruleUI.files.map((file) => h('option', { value: file.name }, '内置 + ' + file.name)));
  select.value = ruleUI.files.some((file) => file.name === wanted) ? wanted : '';
}

function renderJobCard() {
  const job = jobUI.job;
  const card = $('job-card');
  card.className = 'card job ' + (job ? job.state : 'idle');
  if (!job) {
    return set(card, h('div', { class: 'job-line' }, h('b', {}, '没有正在运行的分析'), h('span', { class: 'muted' }, '在下方选择规则和已停止采集的会话开始分析。同一时间只运行一个任务。')));
  }
  const report = job.report;
  set(card,
    h('div', { class: 'job-line' },
      h('span', { class: 'pill ' + job.state }, JOB_STATES[job.state] || job.state),
      h('b', {}, sessionName(job.session_id)),
      h('span', { class: 'muted' }, (job.rules_file ? '内置 + ' + job.rules_file : '仅内置规则') + ' · ' + formatTime(job.started) + ' 开始 · 用时 ' + elapsed(job)),
      h('span', { class: 'spacer' }),
      job.state === 'running' ? h('button', { type: 'button', id: 'job-cancel' }, '停止分析') : null,
      job.state === 'succeeded' ? [h('a', { class: 'button', href: `#/s/${job.session_id}/overview` }, '查看概览'), h('a', { class: 'button primary', href: `#/s/${job.session_id}/alerts` }, '查看告警')] : null),
    job.state === 'running' ? h('div', { class: 'progress', role: 'progressbar', 'aria-label': '分析进行中' }, h('i')) : null,
    job.state === 'succeeded' && report ? h('div', { class: 'job-stats' },
      h('div', {}, h('b', {}, number(report.transactions)), h('span', {}, '事务')),
      h('div', { class: report.alerts ? 'hot' : '' }, h('b', {}, number(report.alerts)), h('span', {}, '告警命中')),
      h('div', {}, h('b', {}, number((report.rules || []).length)), h('span', {}, '规则'))) : null,
    job.state === 'failed' ? h('div', { class: 'rules-message error' }, job.error) : null,
    job.state === 'cancelled' ? h('div', { class: 'rules-message' }, '已停止，会话保留上次完整的分析结果。') : null);
}

function renderAnalysisSessions() {
  if ($('view-analysis').hidden) return;
  const query = $('analysis-search').value.trim().toLowerCase();
  const focus = jobUI.page && jobUI.page.session;
  const list = state.sessions.filter((s) => !query || [s.name, s.host, s.dir].some((v) => String(v || '').toLowerCase().includes(query)));
  const busy = jobRunning();
  set($('analysis-sessions'), list.map((s) => {
    const reason = s.problem ? '会话不可用：' + s.problem : s.state === 'running' ? '采集仍在进行，停止后再分析' : busy ? '已有分析任务在运行' : '';
    const active = busy && jobUI.job.session_id === s.id;
    return h('tr', { class: s.id === focus ? 'selected' : '', 'data-sid': s.id },
      h('td', { title: s.dir }, h('a', { class: 'link', href: `#/s/${s.id}/overview` }, s.name)),
      h('td', { class: 'extra' }, s.host || '—'),
      h('td', {}, h('span', { class: 'state' }, h('span', { class: 'dot ' + (s.problem ? 'broken' : s.state) }), s.problem ? '不可用' : stateLabel(s.state))),
      h('td', { class: 'num' }, s.counts_known ? number(s.transactions) : '—'),
      h('td', { class: 'num' + (s.counts_known && s.alerts ? ' hot' : '') }, s.counts_known ? number(s.alerts) : '—'),
      h('td', { class: 'extra time' }, formatTime(s.started, 'dayclock')),
      h('td', { class: 'act' }, h('button', { type: 'button', class: s.id === focus ? 'primary' : '', 'data-analyze': s.id, disabled: Boolean(reason), title: reason || null }, active ? '分析中…' : '分析')));
  }));
  const empty = $('analysis-sessions-empty');
  empty.hidden = list.length > 0;
  empty.textContent = state.sessions.length ? '没有匹配的会话' : '采集根目录下还没有会话';
  if (focus && !jobUI.scrolled) {
    const row = $('analysis-sessions').querySelector(`tr[data-sid="${focus}"]`);
    if (row) { row.scrollIntoView({ block: 'nearest' }); jobUI.scrolled = true; }
  }
}

function renderAnalysisHistory() {
  const list = jobUI.history || [];
  set($('analysis-history'), list.map((job) => h('tr', {},
    h('td', { class: 'time' }, formatTime(job.started, 'dayclock')),
    h('td', {}, sessionName(job.session_id)),
    h('td', {}, job.rules_file || '仅内置'),
    h('td', {}, h('span', { class: 'pill ' + job.state, title: job.error || null }, JOB_STATES[job.state] || job.state)),
    h('td', { class: 'num' }, job.report ? number(job.report.transactions) : '—'),
    h('td', { class: 'num' + (job.report && job.report.alerts ? ' hot' : '') }, job.report ? number(job.report.alerts) : '—'),
    h('td', { class: 'num' }, elapsed(job)),
    h('td', { class: 'act' }, job.state === 'succeeded' ? h('a', { class: 'link', href: `#/s/${job.session_id}/alerts` }, '告警') : null))));
  $('analysis-history-empty').hidden = list.length > 0;
  $('analysis-history').closest('.table-wrap').hidden = !list.length;
}

function renderAnalysis() {
  $('nav-job').hidden = !jobRunning();
  if ($('view-analysis').hidden) return;
  renderJobCard();
  renderAnalysisSessions();
  renderAnalysisHistory();
}

async function pollAnalysisJob() {
  clearTimeout(jobUI.poll);
  if (!state.token) return;
  try {
    const data = await api('analysis');
    jobUI.job = data.job;
    jobUI.history = data.history || [];
    const job = data.job;
    if (job && job.state === 'running') jobUI.watching = true;
    if (job && job.state !== 'running' && job.id !== jobUI.completed) {
      const first = !jobUI.completed && !jobUI.watching;
      jobUI.completed = job.id;
      jobUI.watching = false;
      if (!first) {
        if (job.state === 'succeeded') toast(`${sessionName(job.session_id)} 分析完成，${number(job.report.alerts)} 条告警`);
        else if (job.state === 'failed') toast('分析失败：' + job.error, true);
        await loadSessions();
        if (ruleUI.hits && ruleUI.hits.sid === job.session_id) {
          ruleUI.hits = null;
          if (!$('view-rules').hidden) loadRuleHits(true);
        }
        if (state.sid === job.session_id) {
          state.auxAt = 0;
          state.summaryAt = 0;
          state.known = null;
          await refresh(false);
          schedule();
          if (state.selected) await showDetail(state.selected, true);
        }
      }
    }
    renderAnalysis();
  } catch (error) {
    if (!$('view-analysis').hidden && error.status) toast('获取分析状态失败：' + error.message, true);
  }
  if (state.token && jobRunning()) jobUI.poll = setTimeout(pollAnalysisJob, 1000);
}

async function startRuleAnalysis(sid) {
  const rules = $('analysis-rule').value;
  try {
    jobUI.job = await mutate(`sessions/${sid}/analyze`, 'POST', { rules_file: rules });
    jobUI.watching = true;
    renderAnalysis();
    pollAnalysisJob();
    window.scrollTo({ top: 0 });
  } catch (error) {
    toast(error.message, true);
  }
}

async function routeAnalysis(page) {
  jobUI.page = page;
  jobUI.scrolled = false;
  renderAnalysis();
  try {
    await Promise.all([ruleUI.loaded ? null : refreshRuleLibrary(), loadSessions()]);
    renderRuleOptions();
  } catch (error) { fail(error, '读取规则目录失败'); }
  await pollAnalysisJob();
}

async function boot() {
  applyTheme();
  bind();
  bindRules();
  // The launch URL carries the token in the fragment so it never reaches server logs.
  const launch = /^#token=([\w-]+)$/.exec(location.hash);
  try {
    if (launch) sessionStorage.setItem('traffic-token', launch[1]);
    state.token = sessionStorage.getItem('traffic-token') || '';
  } catch (_) {
    state.token = launch ? launch[1] : '';
  }
  if (launch) history.replaceState(null, '', location.pathname);
  schedule();
  if (!state.token) return showGate();
  await loadSessions();
  if (!state.token) return;
  const usable = state.sessions.filter((s) => !s.problem);
  if (!location.hash && state.sessions.length === 1 && usable.length === 1) {
    history.replaceState(null, '', `#/s/${usable[0].id}/overview`);
  }
  route();
  if (state.token && $('view-analysis').hidden) pollAnalysisJob();
}

boot();
