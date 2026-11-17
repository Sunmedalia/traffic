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

const STATES = { running: '采集中', stopped: '已停止', complete: '已完成', failed: '采集失败', stale: '心跳过期' };
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
  stats: null,
  dir: '',
  coverage: '',
  summary: null,
  recent: [],
  timelines: {},
  auxAt: 0,
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

// style: 'full' date and time, 'ms' adds milliseconds, 'row' is month-day and time with milliseconds, 'clock' is time only.
function formatTime(value, style = 'full') {
  const d = parseTime(value);
  if (!d) return '未知';
  const [y, mo, day, hh, mi, ss, ms] = parts(d);
  const clock = `${pad(hh)}:${pad(mi)}:${pad(ss)}`;
  if (style === 'clock') return clock;
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
  for (const name of ['gate', 'sessions', 'session']) $('view-' + name).hidden = name !== view;
  $('pause').hidden = $('live').hidden = view !== 'session';
}

function showGate(message) {
  if ($('rules-dialog').open) $('rules-dialog').close();
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

function route() {
  if (!state.token) return showGate();
  const next = parseHash();
  if (!next) {
    Object.assign(state, { sid: null, selected: null, detail: null, listKey: '', warning: '', error: '' });
    state.seq++;
    show('sessions');
    renderChrome();
    renderBanner();
    loadSessions();
    return;
  }
  if (next.sid !== state.sid) {
    Object.assign(state, { sid: next.sid, stats: null, summary: null, recent: [], timelines: {}, dir: '', warning: '', error: '', auxAt: 0 });
    renderBanner();
  }
  const listKey = `${next.sid}|${next.tab}|${JSON.stringify(next.filter)}`;
  const changed = listKey !== state.listKey;
  Object.assign(state, { tab: next.tab, filter: next.filter, listKey });
  if (changed) {
    Object.assign(state, { page: 0, rows: [], rowsKey: '', known: null, count: 0, baseCount: 0, auxAt: 0 });
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
    if (state.selected) hideDetail();
  } else if (next.id !== state.selected) {
    showDetail(next.id);
  }
  if (!currentSession()) loadSessions().then(renderChrome);
}

// ---- chrome ----

const currentSession = () => state.sessions.find((s) => s.id === state.sid);

function renderChrome() {
  $('rules-open').hidden = !state.token;
  const session = currentSession();
  const crumb = $('crumb');
  if (state.sid && state.token) {
    set(crumb,
      h('a', { href: '#/', class: 'root' }, '会话'), h('span', { class: 'sep h' }, '/'),
      session && session.host ? [h('span', { class: 'host' }, session.host), h('span', { class: 'sep h' }, '/')] : null,
      h('strong', { title: session ? session.dir : '' }, session ? session.name : state.sid));
    document.title = `${session ? session.name : '会话'} · Traffic`;
  } else {
    set(crumb);
    document.title = 'Traffic 流量分析';
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

async function loadSessions() {
  $('rescan').disabled = true;
  try {
    const data = await api('sessions');
    state.sessions = data.sessions || [];
    state.roots = data.roots || [];
    state.refreshMs = Math.max(500, data.refresh_ms || 1000);
    if (!state.sid) {
      state.error = '';
      state.warning = data.warning || '';
      renderBanner();
    }
    renderSessions();
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
      h('span', { class: 'figure' }, h('b', {}, s.counts_known ? number(s.transactions) : '—'), h('span', {}, '请求')),
      h('span', { class: 'figure' + (s.counts_known && s.alerts ? ' hot' : '') }, h('b', {}, s.counts_known ? number(s.alerts) : '—'), h('span', {}, '告警'))));
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
  const params = overview ? { alerts: 1, page: 0 } : { ...apiFilter(state.filter), page: state.page, alerts: state.tab === 'alerts' ? 1 : '' };
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
  state.auxAt = Date.now();
  const params = overview ? {} : { ...apiFilter(state.filter), alerts: state.tab === 'alerts' ? 1 : '' };
  const jobs = [api(`sessions/${sid}/timeline`, params)];
  if (overview) jobs.push(api(`sessions/${sid}/summary`));
  try {
    const [timeline, summary] = await Promise.all(jobs);
    if (sid !== state.sid || key !== state.listKey) return;
    state.timelines[overview ? 'overview' : 'list'] = timeline;
    if (summary) state.summary = summary;
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
  if (s.dropped > 0) issues.push(`网卡丢包 ${number(s.dropped)} 个，部分请求可能无法还原。`);
  if (s.queue_dropped > 0) issues.push(`用户态队列丢弃 ${number(s.queue_dropped)} 个。`);
  if (s.probe_failures > 0) issues.push(`探针传输失败 ${number(s.probe_failures)} 次，恢复后仍保留。`);
  if (s.tls_dropped > 0) issues.push(`TLS 已知丢弃 ${number(s.tls_dropped)} 个，这是已观测到的下限。`);
  if (s.alert_delivery_failed > 0 || s.alert_delivery_dropped > 0) issues.push(`告警 Webhook 失败 ${number(s.alert_delivery_failed)} 次，队列丢弃 ${number(s.alert_delivery_dropped)} 次。`);
  if ((s.errors || []).length) issues.push(`采集过程记录了 ${s.errors.length} 条错误，详见“采集状态”。`);
  const bad = s.state === 'failed' || s.state === 'stale';
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
  const labels = [0, 0.5, 1].map((at) => formatTime(new Date(start + Math.round((count - 1) * at) * step + (at === 1 ? step : 0)), data.granularity >= 86400 ? 'full' : 'clock'));
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
    const span = formatTime(new Date(start + from * step), 'clock') + ' – ' + formatTime(new Date(start + (to + 1) * step), 'clock');
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
  const pages = Math.max(1, Math.ceil(state.count / 100));
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

function hideDetail() {
  state.selected = null;
  state.detail = null;
  $('detail').hidden = $('splitter').hidden = true;
  $('split').classList.remove('open');
  $('tab-list').classList.remove('reading');
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
    const before = JSON.stringify(state.detail);
    state.detail = data;
    if (JSON.stringify(data) !== before) renderDetail();
  } catch (error) {
    if (state.selected !== id || quiet) return;
    state.detailError = error.status === 404 ? '这条记录已被保留期清理，无法再查看。' : error.message;
    renderDetail();
  }
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
    if (!$('view-sessions').hidden) await loadSessions();
    return;
  }
  if (state.paused || state.busy) return;
  await refresh(true);
  const t = state.detail && state.detail.transaction;
  // A response can arrive after the request was first shown.
  if (t && (!t.status || t.incomplete)) showDetail(t.id, true);
}

function schedule() {
  // Finished sessions rarely change, and the session list is a directory walk.
  const live = state.sid && state.stats && state.stats.state === 'running';
  const delay = state.offline ? 3000 : live ? state.refreshMs : state.sid ? Math.max(5000, state.refreshMs) : 10000;
  setTimeout(async () => {
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
  $('rescan').addEventListener('click', loadSessions);
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
  if (!state.paused) refresh(true);
}

function onKey(event) {
  if (event.ctrlKey || event.metaKey || event.altKey || $('help').open || $('rules-dialog').open) return;
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
      $('sessions-search').focus();
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
    refresh(true);
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
const ruleUI = { files: [], builtins: [], selected: null, revision: '', dirty: false, busy: false, seq: 0, job: null, poll: 0, completed: '' };
const RULE_TEMPLATE = '- id: CUSTOM-001\n  version: 1\n  severity: medium\n  field: url\n  pattern: \'(?i)/suspicious-endpoint\'\n';

function ruleMessage(text, kind = '') {
  $('rules-validation').textContent = text;
  $('rules-validation').className = 'rules-message ' + kind;
}
function updateRuleControls() {
  const builtin = ruleUI.selected === '';
  for (const id of ['rules-save', 'rules-validate', 'rules-new', 'rules-upload']) $(id).disabled = ruleUI.busy || (builtin && (id === 'rules-save' || id === 'rules-validate'));
  $('rules-delete').disabled = ruleUI.busy || !ruleUI.revision || builtin;
  $('rules-content').readOnly = builtin || ruleUI.busy;
  $('rules-name').readOnly = ruleUI.selected !== null || ruleUI.busy;
  $('rules-editor-note').textContent = builtin ? '· 内置规则只读，分析时始终启用' : ruleUI.dirty ? '· 尚未保存' : ruleUI.revision ? '· 已保存' : '· 新文件';
  const running = ruleUI.job && ruleUI.job.state === 'running';
  $('analysis-start').disabled = running || !$('analysis-session').value || ruleUI.busy || ruleUI.dirty;
  $('analysis-cancel').hidden = !running;
}
function discardRuleEdits() { return !ruleUI.dirty || window.confirm('当前修改尚未保存，确定放弃修改？'); }
function renderRuleFiles() {
  const item = (name, label, size) => h('button', { type: 'button', 'aria-current': String(ruleUI.selected === name), disabled: ruleUI.busy, onclick: () => openRuleFile(name) }, label, h('small', {}, size));
  set($('rules-files'), item('', '内置规则', `${ruleUI.builtins.length} 条 · 只读`), ruleUI.files.map((file) => item(file.name, file.name, `${number(file.size)} 字节`)));
  const previous = $('analysis-rule').value;
  set($('analysis-rule'), h('option', { value: '' }, '仅内置规则'), ruleUI.files.map((file) => h('option', { value: file.name }, '内置 + ' + file.name)));
  $('analysis-rule').value = ruleUI.files.some((file) => file.name === previous) ? previous : '';
}
async function refreshRuleLibrary() {
  const data = await api('rules');
  ruleUI.files = data.files || [];
  ruleUI.builtins = data.builtin_rules || [];
  $('rules-dir').textContent = data.dir;
  renderRuleFiles();
}
async function openRuleFile(name, force = false) {
  if (ruleUI.busy || (!force && !discardRuleEdits())) return;
  const seq = ++ruleUI.seq;
  ruleUI.busy = true;
  updateRuleControls();
  try {
    let file;
    if (name) file = await api('rules/' + encodeURIComponent(name));
    if (seq !== ruleUI.seq) return;
    ruleUI.selected = name;
    ruleUI.revision = file ? file.revision : '';
    ruleUI.dirty = false;
    $('rules-name').value = name || '内置规则（只读）';
    $('rules-content').value = file ? file.content : ruleUI.builtins.map((rule) => `- id: ${rule.id}\n  version: ${rule.version}\n  severity: ${rule.severity}\n  field: ${rule.field}\n  pattern: ${JSON.stringify(rule.pattern)}\n`).join('\n');
    $('analysis-rule').value = name;
    ruleMessage(file && !file.valid ? file.error : file ? `${file.rule_count} 条自定义规则；分析时与内置规则一起执行。` : '内置规则随程序提供。请新建或导入 YAML 文件来追加规则。', file && !file.valid ? 'error' : '');
  } catch (error) {
    ruleMessage(error.message, 'error');
  } finally {
    ruleUI.busy = false;
    renderRuleFiles();
    updateRuleControls();
  }
}
function newRuleFile(name = 'custom.yaml', content = RULE_TEMPLATE) {
  if (ruleUI.busy || !discardRuleEdits()) return;
  ruleUI.seq++;
  ruleUI.selected = null;
  ruleUI.revision = '';
  ruleUI.dirty = true;
  $('rules-name').value = name;
  $('rules-content').value = content;
  ruleMessage('保存前会检查 YAML、规则 ID、字段、级别和正则表达式。');
  renderRuleFiles();
  updateRuleControls();
  $('rules-name').focus();
}
async function validateRuleEditor() {
  ruleUI.busy = true;
  updateRuleControls();
  try {
    const result = await mutate('rules/validate', 'POST', { content: $('rules-content').value });
    ruleMessage(`校验通过：${result.rule_count} 条自定义规则，共 ${result.total_rules} 条规则。`, 'success');
  } catch (error) { ruleMessage(error.message, 'error'); }
  finally { ruleUI.busy = false; updateRuleControls(); }
}
async function saveRuleFile() {
  const name = $('rules-name').value.trim();
  ruleUI.busy = true;
  updateRuleControls();
  try {
    const result = await mutate('rules/' + encodeURIComponent(name), 'PUT', { content: $('rules-content').value, revision: ruleUI.revision });
    ruleUI.selected = result.name;
    ruleUI.revision = result.revision;
    ruleUI.dirty = false;
    await refreshRuleLibrary();
    $('analysis-rule').value = result.name;
    ruleMessage(`已保存 ${result.name} · ${result.rule_count} 条自定义规则。需要重新分析会话才能更新告警。`, 'success');
  } catch (error) { ruleMessage(error.message, 'error'); }
  finally { ruleUI.busy = false; renderRuleFiles(); updateRuleControls(); }
}
async function deleteRuleFile() {
  if (!ruleUI.revision || !window.confirm(`删除 ${ruleUI.selected}？已有分析结果会保留。`)) return;
  ruleUI.busy = true;
  updateRuleControls();
  try {
    await mutate('rules/' + encodeURIComponent(ruleUI.selected), 'DELETE', { revision: ruleUI.revision });
    ruleUI.dirty = false;
    ruleUI.selected = '';
    ruleUI.revision = '';
    await refreshRuleLibrary();
    ruleUI.busy = false;
    await openRuleFile('', true);
    toast('规则文件已删除');
  } catch (error) { ruleMessage(error.message, 'error'); }
  finally { ruleUI.busy = false; renderRuleFiles(); updateRuleControls(); }
}
function downloadRuleFile() {
  const blob = new Blob([$('rules-content').value], { type: 'application/yaml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = h('a', { href: url, download: ruleUI.selected === '' ? 'builtin-rules.yaml' : $('rules-name').value || 'rules.yaml' });
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
function renderAnalysisJob() {
  const job = ruleUI.job;
  if (!job) return updateRuleControls();
  const status = $('analysis-status');
  const session = state.sessions.find((s) => s.id === job.session_id);
  const prefix = (session ? session.name : job.session_id) + ' · ' + (job.rules_file || '仅内置规则') + '：';
  status.className = 'rules-message ' + (job.state === 'failed' ? 'error' : job.state === 'succeeded' ? 'success' : '');
  status.textContent = prefix + (job.state === 'running' ? '正在分析，页面可继续浏览。' : job.state === 'succeeded' ? `分析完成，${number(job.report.transactions)} 条事务，${number(job.report.alerts)} 条告警。` : job.state === 'cancelled' ? '已停止，保留上次完整分析结果。' : '分析失败：' + job.error);
  updateRuleControls();
}
async function pollAnalysisJob() {
  clearTimeout(ruleUI.poll);
  if (!state.token) return;
  try {
    const data = await api('analysis');
    ruleUI.job = data.job;
    renderAnalysisJob();
    if (data.job && data.job.state !== 'running' && data.job.id !== ruleUI.completed) {
      ruleUI.completed = data.job.id;
      await loadSessions();
      if (state.sid === data.job.session_id) {
        state.auxAt = 0;
        state.known = null;
        await refresh(false);
        if (state.selected) await showDetail(state.selected, true);
      }
    }
  } catch (error) { if ($('rules-dialog').open) $('analysis-status').textContent = '获取分析状态失败：' + error.message; }
  if (state.token && ((ruleUI.job && ruleUI.job.state === 'running') || $('rules-dialog').open)) ruleUI.poll = setTimeout(pollAnalysisJob, 1000);
}
async function startRuleAnalysis() {
  $('analysis-start').disabled = true;
  try {
    ruleUI.job = await mutate(`sessions/${$('analysis-session').value}/analyze`, 'POST', { rules_file: $('analysis-rule').value });
    renderAnalysisJob();
    pollAnalysisJob();
  } catch (error) {
    $('analysis-status').textContent = error.message;
    $('analysis-status').className = 'rules-message error';
    updateRuleControls();
  }
}
async function openRuleManager() {
  $('rules-dialog').showModal();
  ruleMessage('正在读取规则目录…');
  try {
    await refreshRuleLibrary();
    await loadSessions();
    const selected = $('analysis-session').value || state.sid || '';
    set($('analysis-session'), h('option', { value: '' }, '请选择会话'), state.sessions.filter((s) => !s.problem).map((s) => h('option', { value: s.id }, `${s.name} · ${stateLabel(s.state)}`)));
    $('analysis-session').value = selected;
    if (ruleUI.selected === null && !ruleUI.dirty) await openRuleFile('', true);
    else if (!ruleUI.dirty) ruleMessage('选择文件编辑，或新建 / 导入规则。');
    updateRuleControls();
    pollAnalysisJob();
  } catch (error) { ruleMessage(error.message, 'error'); }
}
function bindRules() {
  $('rules-open').addEventListener('click', openRuleManager);
  const close = () => { if (discardRuleEdits()) { ruleUI.dirty = false; ruleUI.selected = null; $('rules-dialog').close(); } };
  $('rules-close').addEventListener('click', close);
  $('rules-dialog').addEventListener('cancel', (event) => { event.preventDefault(); close(); });
  $('rules-new').addEventListener('click', () => newRuleFile());
  $('rules-upload').addEventListener('click', () => $('rules-upload-input').click());
  $('rules-upload-input').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > 1048576) return ruleMessage('规则文件不能超过 1 MiB', 'error');
    try { newRuleFile(file.name, new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer())); }
    catch (_) { ruleMessage('请选择 UTF-8 编码的 YAML 文件', 'error'); }
  });
  for (const id of ['rules-name', 'rules-content']) $(id).addEventListener('input', () => { ruleUI.dirty = true; ruleMessage('修改尚未保存。'); updateRuleControls(); });
  $('rules-validate').addEventListener('click', validateRuleEditor);
  $('rules-save').addEventListener('click', saveRuleFile);
  $('rules-delete').addEventListener('click', deleteRuleFile);
  $('rules-download').addEventListener('click', downloadRuleFile);
  $('analysis-session').addEventListener('change', updateRuleControls);
  $('analysis-start').addEventListener('click', startRuleAnalysis);
  $('analysis-cancel').addEventListener('click', async () => {
    try { await mutate('analysis', 'DELETE', { id: ruleUI.job.id }); $('analysis-status').textContent = '正在停止分析，等待当前操作结束…'; }
    catch (error) { $('analysis-status').textContent = error.message; }
  });
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
}

boot();
