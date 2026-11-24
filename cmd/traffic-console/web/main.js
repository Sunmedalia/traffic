'use strict';

// Refresh loop, event wiring and startup. Loaded last so every module's
// declarations exist before boot() runs.

// ---- refresh loop ----

async function tick() {
  if (!state.token || document.hidden) return;
  if (!state.sid) {
    if (!$('view-sessions').hidden) await loadSessions();
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
    pollAnalysisJob();
  });
  $('sidebar-toggle').addEventListener('click', () => {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    save('sidebar-collapsed', state.sidebarCollapsed ? '1' : '0');
    renderSidebar();
    if (state.sid) renderTimelines();
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
  $('detail-meta-toggle').addEventListener('click', () => setDetailMetaExpanded($('detail-record').hidden));
  $('detail-close').addEventListener('click', () => go({ id: null }, true));
  $('detail-prev').addEventListener('click', () => moveSelection(-1));
  $('detail-next').addEventListener('click', () => moveSelection(1));
  $('detail-export').addEventListener('click', exportEvidence);
  $('detail-copy').addEventListener('click', () => copyText(detailText() || '', '当前内容'));
  $('decode-selection').addEventListener('mousedown', (event) => event.preventDefault());
  $('decode-selection').addEventListener('click', decodeSelection);
  document.addEventListener('selectionchange', () => {
    const selection = window.getSelection();
    const inside = selection && selection.anchorNode && $('detail-body').contains(selection.anchorNode) && !$('detail-body').querySelector('.decoder');
    detailSelection = inside ? String(selection) : '';
    $('decode-selection').textContent = detailSelection.trim() ? '解码选中内容' : '解码 URL';
  });
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

  // List column widths are a layout preference too. A dragged column keeps
  // its width in a --col-<name> property on the table; the URL takes the rest.
  const table = document.querySelector('.rows-table');
  let columns = {};
  try {
    columns = JSON.parse(saved('column-widths', '{}')) || {};
  } catch (_) { /* a damaged preference falls back to automatic widths */ }
  const applyColumn = (name) => {
    if (columns[name]) table.style.setProperty('--col-' + name, columns[name] + 'px');
    else table.style.removeProperty('--col-' + name);
  };
  for (const name of Object.keys(columns)) applyColumn(name);
  // A column is at least 40px and always leaves the URL 120px.
  const columnLimit = (grip) => {
    let others = 0;
    for (const th of table.querySelectorAll('thead th:not(.wide)')) {
      if (th !== grip.parentElement && th.offsetWidth) others += th.getBoundingClientRect().width;
    }
    return Math.max(40, $('rows-wrap').clientWidth - others - 120);
  };
  const setColumn = (grip, width) => {
    const name = grip.dataset.col;
    columns[name] = Math.round(Math.max(40, Math.min(columnLimit(grip), width)));
    applyColumn(name);
  };
  const saveColumns = () => save('column-widths', JSON.stringify(columns));
  for (const grip of table.querySelectorAll('.col-grip')) {
    let start = 0, startWidth = 0;
    grip.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      grip.setPointerCapture(event.pointerId);
      grip.classList.add('dragging');
      document.body.classList.add('col-resizing');
      start = event.clientX;
      startWidth = grip.parentElement.getBoundingClientRect().width;
    });
    grip.addEventListener('pointermove', (event) => {
      if (grip.classList.contains('dragging')) setColumn(grip, startWidth + event.clientX - start);
    });
    const release = () => {
      if (!grip.classList.contains('dragging')) return;
      grip.classList.remove('dragging');
      document.body.classList.remove('col-resizing');
      saveColumns();
    };
    grip.addEventListener('pointerup', release);
    grip.addEventListener('pointercancel', release);
    grip.addEventListener('dblclick', () => {
      delete columns[grip.dataset.col];
      applyColumn(grip.dataset.col);
      saveColumns();
    });
    grip.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      event.stopPropagation(); // the list's own arrow keys move the selection
      const step = event.shiftKey ? 40 : 10;
      setColumn(grip, grip.parentElement.getBoundingClientRect().width + (event.key === 'ArrowLeft' ? -step : step));
      saveColumns();
    });
  }

  // Keep the selected view and copy action in sync when the panes become a pair.
  let showingMessagePair = false;
  new ResizeObserver(() => {
    const pair = detailShowsMessagePair();
    if (pair === showingMessagePair) return;
    showingMessagePair = pair;
    if (!$('detail').hidden && state.detail) renderDetail();
  }).observe($('detail'));

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
  if (!state.paused && (state.stats || {}).state !== 'running') return;
  state.paused = !state.paused;
  renderChrome();
  if (!state.paused) refresh(true).then(schedule);
}

function onKey(event) {
  if (event.ctrlKey || event.metaKey || event.altKey || $('help').open || $('session-analysis').open) return;
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
      const search = !$('view-rules').hidden ? 'rules-search' : 'sessions-search';
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
  else if (event.key === 'd' && state.detail) decodeSelection();
  else if ((event.key === '[' || event.key === ']') && state.detail) {
    const keys = availableTabs(state.detail).map(([key]) => key);
    const at = Math.max(0, keys.indexOf(state.detailTab));
    setDetailTab(keys[(at + (event.key === ']' ? 1 : keys.length - 1)) % keys.length]);
  } else return;
  event.preventDefault();
}

async function boot() {
  applyTheme();
  bind();
  bindRules();
  bindAnalysis();
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
  pollAnalysisJob();
}

boot();
