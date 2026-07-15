(function () {
  'use strict';

  const runtime = window.AssessmentRuntime;
  const terminalStates = new Set(['COMPLETED', 'PARTIAL_COMPLETED', 'FAILED', 'CANCELLED', 'WAITING_CONSENT']);
  const state = {
    busy: false,
    startedAt: 0,
    timer: null,
    agents: [],
    latestScan: null,
    latestFindings: [],
  };

  const byId = id => document.getElementById(id);
  const sleep = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));
  const escapeHtml = value => String(value == null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  function request(path, options) {
    if (!runtime) return Promise.reject(new Error('前端运行时未加载'));
    return runtime.request(path, options);
  }

  function post(path, body) {
    return request(path, {method: 'POST', body: JSON.stringify(body || {})});
  }

  function setBusy(value) {
    state.busy = value;
    byId('start-scan').disabled = value;
    byId('discover-only').disabled = value;
    byId('rescan-assets').disabled = value;
  }

  function clearError() {
    byId('error-message').hidden = true;
    byId('error-message').textContent = '';
  }

  function showError(error) {
    const message = runtime ? runtime.describeError(error) : String(error && error.message || error);
    byId('error-message').textContent = message;
    byId('error-message').hidden = false;
  }

  function startClock() {
    state.startedAt = Date.now();
    window.clearInterval(state.timer);
    const render = () => {
      const seconds = Math.max(0, Math.floor((Date.now() - state.startedAt) / 1000));
      byId('elapsed-time').textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
    };
    render();
    state.timer = window.setInterval(render, 1000);
  }

  function stopClock() {
    window.clearInterval(state.timer);
    state.timer = null;
  }

  function setPhase(phase, message, progress) {
    const order = {discover: 0, discovered: 0, scan: 1, result: 2};
    const currentIndex = order[phase] == null ? 0 : order[phase];
    document.querySelectorAll('.step').forEach((element, index) => {
      element.classList.toggle('active', phase !== 'discovered' && index === currentIndex);
      element.classList.toggle('done', index < currentIndex || phase === 'result' && index === currentIndex || phase === 'discovered' && index === 0);
    });
    const headings = {discover: '正在发现本机 Agent', discovered: '资产发现完成', scan: '正在执行只读扫描', result: '检查完成'};
    byId('workflow-heading').textContent = headings[phase] || '准备就绪';
    byId('status-message').textContent = message || '';
    byId('progress-bar').style.width = `${Math.max(4, Math.min(100, progress || 4))}%`;
  }

  function countHits(hits, terms) {
    return (hits || []).filter(hit => {
      const type = String(hit.type || hit.asset_type || hit.kind || '').toLowerCase();
      return terms.some(term => type.includes(term));
    }).length;
  }

  function agentPath(agent) {
    return agent.path || agent.install_path || agent.executable || agent.config_path || '-';
  }

  function renderAssets(payload) {
    const hits = payload.hits || [];
    state.agents = payload.agents || [];
    byId('agent-count').textContent = state.agents.length;
    byId('config-count').textContent = countHits(hits, ['config', '配置']);
    byId('mcp-count').textContent = (payload.mcp_servers || []).length || countHits(hits, ['mcp']);
    byId('skill-count').textContent = (payload.skills || []).length || countHits(hits, ['skill']);
    byId('asset-section').hidden = false;

    const list = byId('agent-list');
    if (!state.agents.length) {
      list.innerHTML = '<p class="empty-state">没有发现受支持的本机 Agent。</p>';
      return;
    }
    list.innerHTML = state.agents.slice(0, 12).map(agent => `
      <article class="agent-item">
        <div class="agent-title">
          <strong>${escapeHtml(agent.name || agent.adapter || agent.id || 'Agent')}</strong>
          <span class="agent-type">${escapeHtml(agent.adapter || agent.type || '本机')}</span>
        </div>
        <dl class="agent-detail">
          <dt>版本</dt><dd title="${escapeHtml(agent.version || '-')}">${escapeHtml(agent.version || '-')}</dd>
          <dt>路径</dt><dd title="${escapeHtml(agentPath(agent))}">${escapeHtml(agentPath(agent))}</dd>
          <dt>状态</dt><dd>${escapeHtml(agent.status || agent.probe_status || '已发现')}</dd>
        </dl>
      </article>`).join('');
  }

  async function discover() {
    setPhase('discover', '正在读取当前用户的 Agent 配置、MCP 和 Skill...', 15);
    const payload = await post('/api/v1/discovery-runs', {
      scope: 'current-user',
      include_agent_configs: true,
      include_skills: true,
      include_mcp: true,
      changes_only: false,
      mutates_installed_agents: false,
    });
    renderAssets(payload);
    setPhase('discovered', `已发现 ${state.agents.length} 个 Agent，未启动任何 Agent 或 stdio MCP。`, 32);
    return payload;
  }

  function taskProgress(task) {
    const direct = Number(task.progress);
    if (Number.isFinite(direct) && direct > 0) return Math.min(92, 35 + direct * .57);
    const stage = String(task.stage || task.state_code || '').toUpperCase();
    if (stage.includes('DISCOVER')) return 45;
    if (stage.includes('SCAN') || stage.includes('RUNNING')) return 68;
    if (stage.includes('PERSIST')) return 82;
    if (stage.includes('REPORT')) return 90;
    return 40;
  }

  async function waitForTask(taskId) {
    for (let attempt = 0; attempt < 360; attempt += 1) {
      const response = await request(`/api/v1/tasks/${encodeURIComponent(taskId)}`);
      const task = response.item || response.task || {};
      const stateCode = String(task.state_code || task.stage || '').toUpperCase();
      setPhase('scan', task.status || task.stage || '正在扫描本机 Agent...', taskProgress(task));
      if (terminalStates.has(stateCode)) return task;
      await sleep(1000);
    }
    throw new Error('扫描等待超时，请在专业模式的任务中心查看状态。');
  }

  function severityClass(severity) {
    const value = String(severity || '').toLowerCase();
    if (value.includes('p0') || value.includes('critical') || value.includes('严重')) return 'critical';
    if (value.includes('p1') || value.includes('high') || value.includes('高危')) return 'high';
    if (value.includes('p2') || value.includes('medium') || value.includes('中危')) return 'medium';
    return '';
  }

  function displayScanStatus(scan) {
    const raw = String(scan && (scan.status || scan.stage) || '');
    if (raw.includes('等待审批') || raw.toUpperCase() === 'WAITING_CONSENT') return '静态检查完成';
    return raw || '已完成';
  }

  async function loadScanResults(scanId, scanResponse) {
    const [historyPayload, findingsPayload] = await Promise.all([
      request('/api/v1/quick-scans/recent?page_size=20'),
      request('/api/v1/findings?page_size=200'),
    ]);
    const history = historyPayload.items || [];
    const scan = history.find(item => String(item.id) === String(scanId)) || history[0] || {};
    const responseFindings = scanResponse && scanResponse.findings || [];
    const persistedFindings = (findingsPayload.items || []).filter(item => String(item.assessment_id || '') === String(scanId));
    let reportFindings = [];
    if (!persistedFindings.length && !responseFindings.length && scan.report && scan.report.id) {
      const reportPayload = await request(`/api/v1/reports/${encodeURIComponent(scan.report.id)}`);
      reportFindings = reportPayload.preview && reportPayload.preview.findings || [];
    }
    state.latestScan = scan;
    state.latestFindings = persistedFindings.length ? persistedFindings : responseFindings.length ? responseFindings : reportFindings;
    renderResult();
    renderHistory(history);
  }

  function renderResult() {
    const scan = state.latestScan || {};
    const severity = scan.severity || {};
    byId('p0-count').textContent = severity.p0 || 0;
    byId('p1-count').textContent = severity.p1 || 0;
    byId('p2-count').textContent = severity.p2 || 0;
    byId('other-count').textContent = severity.other || 0;
    byId('result-status').textContent = displayScanStatus(scan);
    byId('files-scanned').textContent = `${scan.files_scanned || 0} 个文件`;
    byId('evidence-count').textContent = `${scan.evidence_count || 0} 份证据`;
    byId('result-section').hidden = false;

    const reportLink = byId('report-link');
    if (scan.report_download) {
      reportLink.href = scan.report_download;
      reportLink.hidden = false;
    } else {
      reportLink.hidden = true;
    }

    const list = byId('finding-list');
    if (!state.latestFindings.length) {
      list.innerHTML = '<p class="empty-state">本次检查没有生成风险记录。</p>';
      return;
    }
    list.innerHTML = state.latestFindings.slice(0, 10).map(finding => {
      const severityText = finding.severity || finding.priority || '未分级';
      const target = finding.component || finding.agent || finding.path || finding.rule || finding.rule_id || '-';
      return `<article class="finding-item">
        <span class="finding-severity ${severityClass(severityText)}">${escapeHtml(severityText)}</span>
        <div class="finding-main"><strong>${escapeHtml(finding.title || finding.name || finding.id || '安全风险')}</strong><small>${escapeHtml(target)}</small></div>
        <a class="finding-link" href="/assessment/findings/${encodeURIComponent(finding.id || '')}">查看详情</a>
      </article>`;
    }).join('');
  }

  function renderHistory(rows) {
    const list = byId('history-list');
    if (!rows.length) {
      list.innerHTML = '<p class="empty-state">暂无检查记录。</p>';
      return;
    }
    list.innerHTML = rows.slice(0, 5).map(row => {
      const report = row.report_download ? `<a class="finding-link" href="${escapeHtml(row.report_download)}" target="_blank" rel="noopener">报告</a>` : '<span></span>';
      return `<article class="history-row">
        <div class="history-main"><strong>${escapeHtml(row.name || row.id || '本机安全检查')}</strong><small>${escapeHtml(row.finished_at || row.started_at || '-')}</small></div>
        <span class="history-count">${Number(row.finding_count || 0)} 项风险</span>
        <span class="history-status">${escapeHtml(displayScanStatus(row))}</span>
        ${report}
      </article>`;
    }).join('');
  }

  async function refreshHistory() {
    try {
      const payload = await request('/api/v1/quick-scans/recent?page_size=5');
      renderHistory(payload.items || []);
    } catch (error) {
      byId('history-list').innerHTML = '<p class="empty-state">检查历史暂不可用。</p>';
    }
  }

  async function runDiscoveryOnly() {
    if (state.busy) return;
    clearError();
    setBusy(true);
    startClock();
    try {
      await discover();
    } catch (error) {
      showError(error);
      setPhase('discover', '资产发现未完成。', 8);
    } finally {
      stopClock();
      setBusy(false);
    }
  }

  async function runFullCheck() {
    if (state.busy) return;
    clearError();
    setBusy(true);
    startClock();
    byId('result-section').hidden = true;
    try {
      await discover();
      setPhase('scan', '正在创建本机只读扫描任务...', 36);
      const response = await post('/api/v1/quick-scans', {
        mode: 'machine',
        adapter: '自动识别',
        max_files: 150,
        user_scope: 'current-user',
        execution_mode: 'readonly',
        remote_analysis: false,
      });
      const task = response.task || response.assessment || {};
      const taskId = task.id;
      if (!taskId) throw new Error('扫描服务未返回任务 ID。');
      if (response.status_code === 202 || response.status === 'QUEUED') await waitForTask(taskId);
      await loadScanResults(taskId, response);
      setPhase('result', `检查完成，共发现 ${state.latestScan && state.latestScan.finding_count || state.latestFindings.length} 项风险。`, 100);
    } catch (error) {
      showError(error);
      setPhase('scan', '检查未完成，可进入专业模式查看任务状态。', 40);
    } finally {
      stopClock();
      setBusy(false);
    }
  }

  async function initialize() {
    byId('start-scan').addEventListener('click', runFullCheck);
    byId('discover-only').addEventListener('click', runDiscoveryOnly);
    byId('rescan-assets').addEventListener('click', runDiscoveryOnly);
    byId('refresh-history').addEventListener('click', refreshHistory);
    try {
      const version = await request('/api/v1/version');
      byId('version-text').textContent = `V${version.app || '4.2.10'} · 本机版`;
    } catch (error) {
      showError(error);
    }
    await refreshHistory();
  }

  initialize();
}());
