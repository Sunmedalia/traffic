'use strict';

// Analysis is scoped to the open session. Jobs continue when the dialog closes.
const jobUI = { job: null, history: [], poll: 0, inflight: null, completed: '', watching: false, starting: false, cancelling: '', ruleLoad: null };
const sessionName = (id) => { const s = state.sessions.find((item) => item.id === id); return s ? s.name : id.slice(0, 12); };
const analysisHref = (sid, rules) => `#/s/${sid}/overview?analysis=${encodeURIComponent(rules)}`;
const jobRunning = () => jobUI.job?.state === 'running';
const JOB_STATES = { running: '分析中', succeeded: '已完成', failed: '失败', cancelled: '已停止' };

function elapsed(job) {
  const from = parseTime(job.started);
  const to = job.state === 'running' ? new Date() : parseTime(job.finished);
  if (!from || !to) return '—';
  const seconds = Math.max(0, Math.round((to - from) / 1000));
  return seconds < 60 ? `${seconds} 秒` : `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
}

function renderRuleOptions(wanted = $('analysis-rule').value) {
  const select = $('analysis-rule');
  set(select, h('option', { value: '' }, '仅内置规则'), ruleUI.files.map((file) => h('option', { value: file.name }, '内置 + ' + file.name)));
  select.value = ruleUI.files.some((file) => file.name === wanted) ? wanted : '';
}

function renderJobCard(job) {
  const card = $('job-card');
  card.hidden = !job;
  if (!job) return;
  card.className = 'card job ' + job.state;
  const report = job.report;
  set(card,
    h('div', { class: 'job-line' },
      h('span', { class: 'pill ' + job.state }, JOB_STATES[job.state] || job.state),
      h('span', { class: 'muted' }, (job.rules_file ? '内置 + ' + job.rules_file : '仅内置规则') + ' · ' + formatTime(job.started) + ' 开始 · 用时 ' + elapsed(job)),
      h('span', { class: 'spacer' }),
      job.state === 'running' ? h('button', { type: 'button', id: 'job-cancel', disabled: jobUI.cancelling === job.id }, jobUI.cancelling === job.id ? '正在停止…' : '停止分析') : null,
      job.state === 'succeeded' ? h('a', { class: 'button primary', href: `#/s/${job.session_id}/alerts`, onclick: () => $('session-analysis').close() }, '查看告警') : null),
    job.state === 'running' ? h('div', { class: 'progress', role: 'progressbar', 'aria-label': '分析进行中' }, h('i')) : null,
    job.state === 'succeeded' && report ? h('div', { class: 'job-stats' },
      h('div', {}, h('b', {}, number(report.transactions)), h('span', {}, '事务')),
      h('div', { class: report.alerts ? 'hot' : '' }, h('b', {}, number(report.alerts)), h('span', {}, '告警命中')),
      h('div', {}, h('b', {}, number((report.rules || []).length)), h('span', {}, '规则'))) : null,
    job.state === 'succeeded' && report && report.scan_skipped ? h('div', { class: 'rules-message' }, scanSkippedText(report.scan_skipped)) : null,
    job.state === 'failed' ? h('div', { class: 'rules-message error' }, job.error) : null,
    job.state === 'cancelled' ? h('div', { class: 'rules-message' }, '已停止，会话保留上次完整的分析结果。') : null);
}

// SCAN-001 tracks a bounded number of clients and paths; the rest go uncounted.
function scanSkippedText(skipped) {
  const total = (skipped.clients || 0) + (skipped.paths || 0);
  return `扫描检测达到跟踪上限：${number(total)} 条事务未参与 SCAN-001 统计，其中的扫描可能未报出。`;
}

function renderAnalysisHistory(list) {
  $('analysis-history-card').hidden = !list.length;
  set($('analysis-history'), list.map((job) => h('tr', {},
    h('td', { class: 'time' }, formatTime(job.started, 'dayclock')),
    h('td', {}, job.rules_file || '仅内置'),
    h('td', {}, h('span', { class: 'pill ' + job.state, title: job.error || null }, JOB_STATES[job.state] || job.state)),
    h('td', { class: 'num' }, job.report ? number(job.report.transactions) : '—'),
    h('td', { class: 'num' + (job.report && job.report.alerts ? ' hot' : '') }, job.report ? number(job.report.alerts) : '—'),
    h('td', { class: 'num' }, elapsed(job)))));
}

function renderAnalysis() {
  const running = jobRunning();
  const currentJob = jobUI.job?.session_id === state.sid ? jobUI.job : null;
  $('nav-job').hidden = !(running && currentJob);
  if (!$('session-analysis').open) return;
  const session = currentSession();
  $('analysis-session').textContent = [sessionName(state.sid), session?.host, session?.started && formatTime(session.started)].filter(Boolean).join(' · ');
  const status = $('analysis-status');
  const capture = state.stats?.state || session?.state;
  const otherJob = running && !currentJob;
  const reason = jobUI.ruleLoad ? '正在读取规则…' : session?.problem ? '会话不可用：' + session.problem
    : capture === 'running' || capture === 'starting' ? '采集仍在进行，停止采集后即可分析。'
    : otherJob ? `${sessionName(jobUI.job.session_id)} 正在分析，同一时间只能运行一个任务。` : '';
  status.hidden = !reason;
  set(status, reason, otherJob ? [' ', h('a', { class: 'link', href: analysisHref(jobUI.job.session_id, jobUI.job.rules_file) }, '查看任务')] : null);
  $('analysis-start').disabled = Boolean(reason || running || jobUI.starting);
  $('analysis-rule').disabled = Boolean(jobUI.ruleLoad || jobUI.starting);
  const history = jobUI.history.filter((job) => job.session_id === state.sid);
  const latest = currentJob || history[0];
  renderJobCard(latest);
  renderAnalysisHistory(history.filter((job) => job.id !== latest?.id));
}

function pollAnalysisJob() {
  if (!state.token || jobUI.inflight) return jobUI.inflight;
  clearTimeout(jobUI.poll);
  jobUI.inflight = updateAnalysisJob().finally(() => {
    jobUI.inflight = null;
    if (state.token && jobRunning()) jobUI.poll = setTimeout(pollAnalysisJob, 1000);
  });
  return jobUI.inflight;
}

async function updateAnalysisJob() {
  try {
    const data = await api('analysis');
    // A status request can finish while the server is still accepting a new job.
    if (jobUI.starting) return;
    const job = jobUI.job = data.job;
    jobUI.history = data.history || [];
    if (job?.state === 'running') jobUI.watching = true;
    else if (job && job.id !== jobUI.completed) {
      const first = !jobUI.completed && !jobUI.watching;
      jobUI.completed = job.id;
      jobUI.watching = false;
      jobUI.cancelling = '';
      if (!first) {
        if (job.state === 'succeeded') toast(`${sessionName(job.session_id)} 分析完成，${number(job.report.alerts)} 条告警`);
        else if (job.state === 'failed') toast('分析失败：' + job.error, true);
        if (ruleUI.hits?.sid === job.session_id) {
          ruleUI.hits = null;
          if (!$('view-rules').hidden) loadRuleHits(true);
        }
        if (state.sid === job.session_id && job.state === 'succeeded') {
          state.auxAt = 0;
          state.summaryAt = 0;
          state.known = null;
          await refresh(false);
          schedule();
          if (state.sid === job.session_id && state.selected) await showDetail(state.selected, true);
        }
        await loadSessions();
      }
    }
    renderAnalysis();
  } catch (error) {
    if ($('session-analysis').open && error.status && error.status !== 401) toast('获取分析状态失败：' + error.message, true);
  }
}

async function openAnalysis(wanted = saved('analysis-rule', '')) {
  const dialog = $('session-analysis');
  if (!state.sid || dialog.open) return;
  const load = jobUI.ruleLoad = Symbol();
  showAnalysisError('');
  renderRuleOptions(wanted);
  dialog.showModal();
  renderAnalysis();
  pollAnalysisJob();
  try {
    await refreshRuleLibrary();
    if (jobUI.ruleLoad === load && dialog.open) {
      renderRuleOptions(wanted);
      if (wanted && !$('analysis-rule').value) showAnalysisError(`规则文件「${wanted}」已不可用，请重新选择。`);
    }
  } catch (error) {
    if (jobUI.ruleLoad === load && dialog.open) showAnalysisError('读取规则目录失败：' + error.message);
  } finally {
    if (jobUI.ruleLoad === load) {
      jobUI.ruleLoad = null;
      renderAnalysis();
    }
  }
}

function showAnalysisError(message) {
  const error = $('analysis-error');
  error.hidden = !message;
  error.textContent = message;
}

async function startRuleAnalysis() {
  if ($('analysis-start').disabled) return;
  const sid = state.sid;
  const rules = $('analysis-rule').value;
  showAnalysisError('');
  jobUI.starting = true;
  renderAnalysis();
  try {
    await jobUI.inflight;
    jobUI.job = await mutate(`sessions/${sid}/analyze`, 'POST', { rules_file: rules });
    jobUI.watching = true;
    save('analysis-rule', rules);
  } catch (error) {
    if (state.sid === sid && $('session-analysis').open) showAnalysisError(error.message);
    else toast(error.message, true);
  } finally {
    jobUI.starting = false;
    renderAnalysis();
    pollAnalysisJob();
  }
}

function bindAnalysis() {
  const dialog = $('session-analysis');
  $('session-analyze').addEventListener('click', () => openAnalysis());
  $('analysis-close').addEventListener('click', () => dialog.close());
  $('analysis-start').addEventListener('click', startRuleAnalysis);
  $('analysis-rule').addEventListener('change', () => showAnalysisError(''));
  $('job-card').addEventListener('click', async (event) => {
    if (!event.target.closest('#job-cancel')) return;
    const id = jobUI.job.id;
    jobUI.cancelling = id;
    renderAnalysis();
    try {
      await mutate('analysis', 'DELETE', { id });
    } catch (error) {
      if (jobUI.cancelling === id) jobUI.cancelling = '';
      toast(error.message, true);
      renderAnalysis();
    }
  });
}
