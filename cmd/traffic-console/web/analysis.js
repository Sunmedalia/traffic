'use strict';

// Local analysis jobs (#/analysis).

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
