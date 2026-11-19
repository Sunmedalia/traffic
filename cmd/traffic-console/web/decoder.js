'use strict';

// Manual decoding tools for the request detail pane. Loaded after app.js;
// classic scripts share one global scope, so helpers from app.js are in scope.

// ---- decoder ----
// Nothing is decoded automatically: values are shown as captured, and each
// decoding step is an explicit choice that can be chained (decode, then decode
// the result again) and rolled back. Steps work on bytes so binary results
// (gzip, raw Base64 payloads) survive until they are shown.

const utf8Out = new TextDecoder('utf-8');
const utf8In = new TextEncoder();
const latin1 = (bytes) => Array.from(bytes, (b) => String.fromCharCode(b)).join('');
const MAX_DECODE_INPUT = 1 << 20;
const MAX_DECODE_OUTPUT = 16 << 20;

function percentBytes(text, plus) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '%' && /^[0-9a-fA-F]{2}$/.test(text.slice(i + 1, i + 3))) {
      out.push(parseInt(text.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (plus && c === '+') {
      out.push(0x20);
    } else {
      // Collect the run of literal characters so multi-byte UTF-8 stays intact.
      let j = i;
      while (j < text.length && text[j] !== '%' && !(plus && text[j] === '+')) j++;
      if (j === i) j = i + 1;
      for (const byte of utf8In.encode(text.slice(i, j))) out.push(byte);
      i = j - 1;
    }
  }
  return new Uint8Array(out);
}

function base64Bytes(text) {
  let clean = text.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!clean || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.replace(/=+$/, '').length % 4 === 1) throw new Error('不是有效的 Base64');
  clean = clean.replace(/=+$/, '');
  clean += '='.repeat((4 - (clean.length % 4)) % 4);
  return Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
}

function hexBytes(text) {
  const clean = text.replace(/0x|\\x|%|[\s:,-]/gi, '');
  if (!clean || clean.length % 2 || !/^[0-9a-fA-F]+$/.test(clean)) throw new Error('不是有效的十六进制');
  return Uint8Array.from(clean.match(/../g), (pair) => parseInt(pair, 16));
}

const HTML_NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', sol: '/', colon: ':', lpar: '(', rpar: ')', equals: '=', semi: ';', comma: ',', period: '.', excl: '!', num: '#', percnt: '%', plus: '+', lsqb: '[', rsqb: ']', lcub: '{', rcub: '}', bsol: '\\', grave: '`', Tab: '\t', NewLine: '\n' };
function codePoint(value) {
  return value > 0 && value <= 0x10ffff ? String.fromCodePoint(value) : '�';
}

const DECODERS = [
  { key: 'url', label: 'URL', title: '百分号解码，+ 视为空格', run: (bytes, text) => percentBytes(text, true) },
  { key: 'url-raw', label: 'URL（保留 +）', title: '百分号解码，+ 保持原样（路径、Cookie 常用）', run: (bytes, text) => percentBytes(text, false) },
  { key: 'base64', label: 'Base64', title: '标准或 URL 安全 Base64，自动补齐 =', run: (bytes, text) => base64Bytes(text) },
  { key: 'hex', label: 'Hex', title: '十六进制，可带 0x、\\x、% 或空格分隔', run: (bytes, text) => hexBytes(text) },
  { key: 'html', label: 'HTML 实体', title: '&lt; &#60; &#x3c; 等', run: (bytes, text) => utf8In.encode(text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (all, body) => {
    if (body[0] === '#') return codePoint(body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10));
    return Object.hasOwn(HTML_NAMED, body) ? HTML_NAMED[body] : all;
  })) },
  { key: 'unicode', label: 'Unicode / JS 转义', title: '\\uXXXX、\\u{…}、%uXXXX、\\xHH、\\n 等', run: (bytes, text) => utf8In.encode(text
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (_, hex) => codePoint(parseInt(hex, 16)))
    .replace(/(?:\\|%)u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\([nrtbf0'"\\/])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', 0: '\0' })[c] ?? c)) },
  { key: 'jwt', label: 'JWT', title: '解出 JWT 的头部与载荷（不校验签名）', run: (bytes, text) => {
    const parts = text.trim().split('.');
    if (parts.length < 2 || parts.length > 3) throw new Error('不是 JWT');
    const json = (part) => JSON.stringify(JSON.parse(utf8Out.decode(base64Bytes(part))), null, 2);
    return utf8In.encode(`// 头部\n${json(parts[0])}\n// 载荷\n${json(parts[1])}` + (parts[2] ? `\n// 签名（未校验）\n${parts[2]}` : ''));
  } },
  { key: 'gzip', label: 'Gzip / Deflate', title: '解压 gzip、zlib 或原始 deflate 字节', async: true, run: async (bytes) => {
    const formats = bytes[0] === 0x1f && bytes[1] === 0x8b ? ['gzip'] : bytes[0] === 0x78 ? ['deflate', 'deflate-raw'] : ['deflate-raw'];
    if (typeof DecompressionStream === 'undefined') throw new Error('浏览器不支持解压');
    for (const format of formats) {
      try {
        const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
        const reader = stream.getReader();
        const chunks = [];
        let length = 0;
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            length += value.byteLength;
            if (length > MAX_DECODE_OUTPUT) throw new RangeError('解压结果不能超过 16 MiB');
            chunks.push(value);
          }
        } finally {
          await reader.cancel().catch(() => {});
          reader.releaseLock();
        }
        const result = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
        return result;
      } catch (error) {
        if (error instanceof RangeError) throw error;
        // Try the next container only for a format mismatch.
      }
    }
    throw new Error('不是可解压的数据');
  } },
];

// Cheap synchronous check used to dim decoders that would fail or change nothing.
function decoderApplies(decoder, bytes, text) {
  if (decoder.async) return (bytes[0] === 0x1f && bytes[1] === 0x8b) || (bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1]));
  try {
    const out = decoder.run(bytes, text);
    return out.length !== bytes.length || out.some((b, i) => b !== bytes[i]);
  } catch (_) {
    return false;
  }
}

function looksBinary(bytes) {
  if (!bytes.length) return false;
  const text = utf8Out.decode(bytes);
  let odd = 0;
  for (const c of text) {
    const code = c.codePointAt(0);
    if (code === 0xfffd || (code < 32 && code !== 9 && code !== 10 && code !== 13)) odd++;
  }
  return odd / Math.max(1, text.length) > 0.1;
}

function hexDump(bytes) {
  const lines = [];
  for (let at = 0; at < Math.min(bytes.length, 65536); at += 16) {
    const row = bytes.slice(at, at + 16);
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    lines.push(`${at.toString(16).padStart(8, '0')}  ${hex}  ${Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('')}`);
  }
  if (bytes.length > 65536) lines.push(`… 共 ${number(bytes.length)} 字节，仅显示前 64 KiB`);
  return lines.join('\n');
}

// Values a user may want to decode, read from the captured request as typed.
function rawPairs(text, separator) {
  if (!text) return [];
  return text.split(separator).filter(Boolean).slice(0, 500).map((part) => {
    const at = part.indexOf('=');
    return at < 0 ? [part, ''] : [part.slice(0, at), part.slice(at + 1)];
  });
}

function decodeSources(data) {
  const t = data.transaction;
  const url = t.url || '';
  const [pathPart, query = ''] = url.split('#')[0].split(/\?(.*)/s);
  const sources = [{ label: '完整 URL', value: url }];
  if (query) sources.push({ label: '路径', value: pathPart }, { label: '查询字符串', value: query });
  for (const [name, value] of rawPairs(query, '&')) sources.push({ label: `查询参数 ${name}`, value });
  const message = data.request_text ? splitHttp(data.request_text) : null;
  if (message) {
    for (const [name, value] of rawPairs(headerValue(message, 'cookie') || '', /;\s*/)) sources.push({ label: `Cookie ${name}`, value });
    if (/x-www-form-urlencoded/i.test(headerValue(message, 'content-type'))) {
      for (const [name, value] of rawPairs(message.body, '&')) sources.push({ label: `表单参数 ${name}`, value });
    }
    if (message.body) sources.push({ label: '请求正文', value: message.body });
    for (const name of ['authorization', 'referer', 'user-agent', 'x-forwarded-for']) {
      const value = headerValue(message, name);
      if (value) sources.push({ label: `请求头 ${name}`, value });
    }
  }
  return sources.filter((source) => source.value);
}

function openDecoder(label, value) {
  const text = String(value || '').slice(0, MAX_DECODE_INPUT);
  state.decoder = { id: state.selected, label, input: text, steps: [{ label: '原文', bytes: utf8In.encode(text) }], hex: false, error: '' };
  setDetailTab('decoder');
  $('detail-body').querySelector('.decoder-input')?.focus();
}

function currentDecoder() {
  const data = state.detail;
  if (!data) return null;
  if (!state.decoder || state.decoder.id !== state.selected) {
    const first = decodeSources(data).find((source) => source.label.startsWith('查询参数')) || { label: '完整 URL', value: data.transaction.url || '' };
    state.decoder = { id: state.selected, label: first.label, input: first.value, steps: [{ label: '原文', bytes: utf8In.encode(first.value) }], hex: false, error: '' };
  }
  return state.decoder;
}

async function applyDecoder(key) {
  const decoder = DECODERS.find((item) => item.key === key);
  const d = currentDecoder();
  const last = d.steps[d.steps.length - 1];
  try {
    const bytes = await decoder.run(last.bytes, utf8Out.decode(last.bytes));
    if (bytes.length === last.bytes.length && bytes.every((b, i) => b === last.bytes[i])) throw new Error('解码后内容没有变化');
    d.steps.push({ label: decoder.label, bytes });
    d.error = '';
    d.hex = looksBinary(bytes);
  } catch (error) {
    d.error = `${decoder.label}：${error.message}`;
  }
  renderDetail();
}

function decoderOutput(d) {
  return utf8Out.decode(d.steps[d.steps.length - 1].bytes);
}

function renderDecoder(data, needles) {
  const d = currentDecoder();
  const last = d.steps[d.steps.length - 1];
  const text = utf8Out.decode(last.bytes);
  const sources = decodeSources(data);
  const sourceSelect = h('select', { class: 'decoder-source', 'aria-label': '选择要解码的内容' },
    sources.some((s) => s.label === d.label) ? null : h('option', { value: '' }, d.label),
    sources.map((s, i) => h('option', { value: String(i), selected: s.label === d.label ? true : null }, s.label)));
  sourceSelect.addEventListener('change', () => {
    const source = sources[Number(sourceSelect.value)];
    if (source) openDecoder(source.label, source.value);
  });
  const input = h('textarea', { class: 'decoder-input', spellcheck: 'false', rows: 3, 'aria-label': '待解码内容' });
  input.value = d.input;
  input.addEventListener('change', () => {
    d.input = input.value.slice(0, MAX_DECODE_INPUT);
    d.label = '手动输入';
    d.steps = [{ label: '原文', bytes: utf8In.encode(d.input) }];
    d.error = '';
    renderDetail();
  });
  const binary = looksBinary(last.bytes);
  return h('div', { class: 'decoder' },
    h('div', { class: 'decoder-row' }, h('span', { class: 'muted' }, '来源'), sourceSelect,
      h('span', { class: 'muted' }, `${number(utf8In.encode(d.input).length)} 字节`)),
    input,
    h('div', { class: 'decoder-chain', 'aria-label': '解码步骤' }, d.steps.map((step, i) => [
      i ? h('span', { class: 'arrow' }, '→') : null,
      h('button', { type: 'button', class: 'step', 'aria-current': i === d.steps.length - 1 ? 'step' : null, title: i === d.steps.length - 1 ? '当前结果' : '回到这一步', onclick: () => { d.steps = d.steps.slice(0, i + 1); d.error = ''; d.hex = looksBinary(d.steps[i].bytes); renderDetail(); } }, step.label)])),
    h('div', { class: 'decoder-actions' },
      h('span', { class: 'muted' }, d.steps.length > 1 ? '继续解码：' : '解码为：'),
      DECODERS.map((item) => h('button', { type: 'button', class: decoderApplies(item, last.bytes, text) ? 'fits' : '', title: item.title, onclick: () => applyDecoder(item.key) }, item.label)),
      h('span', { class: 'spacer' }),
      d.steps.length > 1 ? h('button', { type: 'button', class: 'ghost', title: '撤销最后一步', onclick: () => { d.steps.pop(); d.error = ''; renderDetail(); } }, '撤销') : null),
    d.error ? h('div', { class: 'decoder-error' }, d.error) : null,
    h('div', { class: 'decoder-out-head' },
      h('h3', {}, d.steps.length > 1 ? `结果 · ${d.steps.length - 1} 步` : '原文'),
      h('span', { class: 'muted' }, `${number(last.bytes.length)} 字节`),
      binary ? h('span', { class: 'pill warn' }, '含二进制') : null,
      h('span', { class: 'spacer' }),
      h('label', { class: 'check' }, (() => { const box = h('input', { type: 'checkbox', checked: d.hex ? true : null }); box.addEventListener('change', () => { d.hex = box.checked; renderDetail(); }); return box; })(), '十六进制')),
    h('pre', { class: 'decoder-out' }, d.hex ? hexDump(last.bytes) : marked(text, needles)),
    h('p', { class: 'hint' }, '高亮的按钮表示当前结果可以用这种方式解码。解码只在浏览器中进行，不改动采集数据。'));
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
    $('detail-test').removeAttribute('href');
    $('decode-selection').hidden = $('pretty-wrap').hidden = $('detail-copy').hidden = true;
    for (const id of controls) $(id).disabled = true;
    set($('detail-pills'), state.detailError ? '无法显示' : '正在加载…');
    set($('detail-url'));
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
  set($('detail-url'), h('span', { class: 'host' }, t.host || ''), marked(t.url || '', needles),
    h('button', { type: 'button', class: 'mini', title: '在解码工具中打开 URL（d）', onclick: () => openDecoder('完整 URL', t.url || '') }, '解码'));

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
  $('decode-selection').hidden = tab === 'decoder' || tab === 'alerts';
  $('detail-copy').hidden = tab === 'alerts';

  const showMessages = tab === 'request' || tab === 'response';
  $('detail-copy').textContent = showMessages ? (tab === 'request' ? '复制请求' : '复制响应') : '复制';
  const scroll = body.scrollTop;
  const messageScroll = Array.from(body.querySelectorAll('.message-pane'), (pane) => pane.scrollTop);
  if (showMessages) {
    const request = data.request_text ? splitHttp(data.request_text) : null;
    const form = request && /x-www-form-urlencoded/i.test(headerValue(request, 'content-type')) ? rawPairs(request.body, '&') : [];
    const cookies = request ? rawPairs(headerValue(request, 'cookie'), /;\s*/) : [];
    const pane = (key, title, ...content) => h('section', { class: 'message-pane', 'data-active': String(tab === key), 'aria-label': title },
      h('h3', { class: 'message-label' }, title), content);
    set(body, h('div', { class: 'message-pair' },
      pane('request', '请求',
        request ? [httpView(data.request_text, needles), paramsBlock('表单参数（原文）', form, needles, '表单参数'),
          paramsBlock('Cookie（原文）', cookies, needles, 'Cookie')] : h('p', { class: 'hint' }, '没有保存请求内容。')),
      pane('response', '响应', data.response_text ? httpView(data.response_text, [])
        : h('p', { class: 'hint' }, t.status ? '没有保存响应内容。' : '还没有采集到响应。会话仍在采集时，响应到达后会自动出现。'))));
    body.querySelectorAll('.message-pane').forEach((pane, i) => { pane.scrollTop = messageScroll[i] || 0; });
  } else if (tab === 'decoder') {
    set(body, renderDecoder(data, needles));
  } else if (tab === 'decoded') {
    const block = (title, view, text) => view && h('section', {}, h('h3', {}, `${title} · ${view}`), h('pre', {}, marked(text, title === '请求正文' ? needles : [])));
    set(body, ...[block('请求正文', data.decoded_view, data.decoded_body), block('响应正文', data.response_decoded_view, data.response_decoded_body)].filter(Boolean));
  } else {
    set(body, ...alerts.map((a) => h('div', { class: 'alert-card ' + a.severity },
      h('header', {}, h('span', { class: 'sev ' + a.severity }, SEVERITIES[a.severity] || '—'), a.rule, h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'ghost', onclick: () => go({ tab: 'alerts', filter: { rule: a.rule } }) }, '查看同规则请求')),
      h('div', { class: 'info' }, `规则版本 ${a.version} · 命中字段 ${a.field || '—'} · 视图 ${a.view || '原始内容'} · URL 解码 ${a.decoding} 轮`),
      h('pre', {}, a.match),
      h('button', { type: 'button', class: 'mini', onclick: () => openDecoder(`命中片段 ${a.rule}`, a.match) }, '解码片段'))));
  }
  body.scrollTop = scroll;
}

// The last text selected inside the detail body; a button click can clear the live selection.
let detailSelection = '';
function decodeSelection() {
  const text = detailSelection || String(window.getSelection() || '');
  if (text.trim()) openDecoder('选中内容', text);
  else if (state.detail) openDecoder('完整 URL', state.detail.transaction.url || '');
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
  if (tab === 'decoder') return state.decoder ? decoderOutput(state.decoder) : '';
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
