const input = document.getElementById('zipInput');
const browse = document.getElementById('browseButton');
const dropZone = document.getElementById('dropZone');
const statusBox = document.getElementById('status');
const results = document.getElementById('results');
const historyGrid = document.getElementById('historyGrid');
const historySummary = document.getElementById('historySummary');
const clearHistoryButton = document.getElementById('clearHistoryButton');
const modeHint = document.getElementById('modeHint');

let sessionReady = false;
let sessionToken = '';
let activeMode = 'safety';

const MODE_DEFINITIONS = {
  safety: {
    label: 'Safety Scan',
    axes: ['Risk Surface', 'Credential Exposure', 'Binary Surface', 'Filesystem Surface', 'Install Observations'],
    categories: ['credential', 'binary', 'install_hook', 'filesystem', 'process', 'archive_safety', 'obfuscation'],
    prompt: 'Credentials, binaries, install hooks, filesystem and process risk. Is this safe to run?',
  },
  phishing: {
    label: 'Phishing / Impersonation',
    axes: ['Phishing Surface', 'Risk Surface', 'Network Surface'],
    categories: ['phishing', 'network', 'intrusiveness'],
    prompt: 'Shortlinks, lookalike domains, scam tracking stacks, harvest wording. Is this a scam?',
  },
  'supply-chain': {
    label: 'Dependency & Supply Chain',
    axes: ['Dependency Risk', 'Install Observations', 'Risk Surface'],
    categories: ['dependency', 'install_hook', 'credential'],
    prompt: 'Dependencies, lockfiles, install hooks, version drift. What does this pull in?',
  },
  'ai-surface': {
    label: 'AI / Agent Surface',
    axes: ['Risk Surface'],
    categories: [],
    prompt: 'MCP servers, agent instructions, prompts, workflows. Does this drive agents?',
  },
  exfil: {
    label: 'Exfil & Telemetry',
    axes: ['Phishing Surface', 'Intrusiveness', 'Network Surface'],
    categories: ['phishing', 'intrusiveness', 'network'],
    prompt: 'Webhook endpoints, tracking stacks, data collection. Does this phone home?',
  },
  archive: {
    label: 'Archive Safety',
    axes: ['Archive Safety', 'Storage Footprint', 'Binary Surface'],
    categories: ['archive_safety', 'binary'],
    prompt: 'Traversal, bombs, symlinks, path tricks. Is the ZIP itself hostile?',
  },
};

function setActiveMode(mode) {
  if (!MODE_DEFINITIONS[mode]) return;
  activeMode = mode;
  document.querySelectorAll('.mode-card').forEach(button => {
    const isActive = button.dataset.mode === mode;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-selected', String(isActive));
  });
  if (modeHint) {
    const def = MODE_DEFINITIONS[mode];
    modeHint.textContent = `${def.label} is active. ${def.prompt}`;
  }
}

function findingsForMode(findings = []) {
  const def = MODE_DEFINITIONS[activeMode];
  if (!def || activeMode === 'safety') return findings;
  return findings.filter(finding => def.categories.includes(finding.category));
}

function axesForMode(axes = {}) {
  const def = MODE_DEFINITIONS[activeMode];
  if (!def || activeMode === 'safety') return Object.entries(axes);
  const preferred = def.axes;
  const entries = Object.entries(axes);
  const ordered = preferred.map(name => entries.find(([key]) => key === name)).filter(Boolean);
  const rest = entries.filter(([name]) => !preferred.includes(name));
  return [...ordered, ...rest];
}

const PUBLIC_STATES = new Set(['No signal detected by this scan', 'Review', 'Risk', 'Blocked']);
const UI_STATES = new Set([...PUBLIC_STATES, 'Scanning', 'Error']);
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
}

function normalizeState(value, fallback = 'Review') {
  const text = String(value || '').trim();
  if (PUBLIC_STATES.has(text)) return text;
  return fallback;
}

function stateTone(state) {
  if (state === 'Blocked') return 'blocked';
  if (state === 'Risk') return 'risk';
  if (state === 'No signal detected by this scan') return 'no-signal';
  if (state === 'Scanning') return 'scanning';
  if (state === 'Error') return 'error';
  return 'review';
}

function setStatus(message, tone = 'review') {
  statusBox.classList.remove('hidden', 'status-scanning', 'status-error', 'status-blocked', 'status-risk', 'status-review', 'status-no-signal');
  statusBox.classList.add(`status-${tone}`);
  statusBox.textContent = message;
}

function announceUiState(state, detail) {
  const normalized = UI_STATES.has(state) ? state : 'Error';
  setStatus(`${normalized}: ${detail}`, stateTone(normalized));
}

function focusElement(element) {
  if (!element) return;
  element.setAttribute('tabindex', '-1');
  element.focus({ preventScroll: false });
}

async function ensureSession() {
  if (sessionReady && sessionToken) return true;
  const response = await fetch('/api/session', { cache: 'no-store' });
  const payload = await response.json();
  sessionToken = response.ok && payload.ok && typeof payload.token === 'string' ? payload.token : '';
  sessionReady = Boolean(sessionToken);
  return sessionReady;
}

function sessionHeaders() {
  return { 'X-MAYA-Session-Token': sessionToken };
}

function formatStamp(value) {
  if (!value) return 'recent';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function formatScanIdForDisplay(value, maxLength = 28) {
  const text = String(value || 'retained scan');
  if (text.length <= maxLength) return text;
  const headLength = Math.ceil((maxLength - 1) / 2);
  const tailLength = maxLength - 1 - headLength;
  return `${text.slice(0, headLength)}…${text.slice(-tailLength)}`;
}

function publicReviewLabel(value, fallback = 'Sentinel review') {
  return String(value || fallback);
}

function firstValue(...values) {
  return values.find(value => value !== null && value !== undefined && value !== '') ?? '';
}

function renderInlineMeta(items = []) {
  const entries = items.filter(([, value]) => value !== null && value !== undefined && value !== '');
  if (!entries.length) return '';
  return `<p class="inline-meta-row">${entries.map(([label, value]) => `<span class="inline-meta"><strong>${escapeHtml(label)}:</strong> <span>${escapeHtml(value)}</span></span>`).join('')}</p>`;
}

function renderInlineSignals(items = [], emptyText = 'No extra signals emitted.') {
  const entries = (Array.isArray(items) ? items : []).filter(value => value !== null && value !== undefined && value !== '');
  if (!entries.length) return `<p class="inline-signal-row"><span class="inline-signal">${escapeHtml(emptyText)}</span></p>`;
  return `<p class="inline-signal-row">${entries.map(item => {
    if (typeof item === 'string') return `<span class="inline-signal">${escapeHtml(item)}</span>`;
    const label = firstValue(item.label, item.check, item.surface, item.summary, item.path, item.recommended_action, 'signal');
    const count = item.count || item.evidence_count;
    return `<span class="inline-signal">${escapeHtml(label)}${count ? ` (${escapeHtml(count)})` : ''}</span>`;
  }).join('')}</p>`;
}

function renderLooseList(items, emptyText) {
  if (!Array.isArray(items) || !items.length) return `<li>${escapeHtml(emptyText)}</li>`;
  return items.map(item => {
    if (typeof item === 'string') return `<li>${escapeHtml(publicReviewLabel(item, item))}</li>`;
    if (item && typeof item === 'object') {
      const lead = firstValue(item.label, item.check, item.name, item.type, item.surface, item.signal, item.path, item.category, 'detail');
      const tail = firstValue(item.recommended_action, item.summary, item.reason, item.note, item.status, item.value, item.count, item.target);
      return `<li>${escapeHtml(lead)}${tail ? ` - ${escapeHtml(publicReviewLabel(tail, tail))}` : ''}</li>`;
    }
    return `<li>${escapeHtml(String(item))}</li>`;
  }).join('');
}

function objectChipRow(record = {}, emptyText = 'No surface details emitted.') {
  const entries = Object.entries(record || {}).filter(([, value]) => value !== null && value !== undefined && value !== '' && value !== 0);
  if (!entries.length) return `<p class="inline-signal-row"><span class="inline-signal">${escapeHtml(emptyText)}</span></p>`;
  return renderInlineMeta(entries.map(([key, value]) => [key.replaceAll('_', ' '), value]));
}

function renderPanel(title, body, options = {}) {
  const open = options.open ? ' open' : '';
  const meta = options.meta ? `<span class="panel-meta">${escapeHtml(options.meta)}</span>` : '';
  return `<details class="panel collapsible"${open}><summary><span>${escapeHtml(title)}</span>${meta}</summary><div class="panel-body">${body}</div></details>`;
}

function renderReportLinks(reports = {}) {
  return `
    ${reports.html ? `<a class="link-button" href="/reports/${encodeURIComponent(reports.html)}" target="_blank" rel="noopener">Open HTML Report</a>` : ''}
    ${reports.markdown ? `<a class="link-button" href="/reports/${encodeURIComponent(reports.markdown)}" target="_blank" rel="noopener">Open Markdown Report</a>` : ''}
    ${reports.json ? `<a class="link-button" href="/reports/${encodeURIComponent(reports.json)}" target="_blank" rel="noopener">Open JSON Receipt</a>` : ''}
  `;
}

function recommendedActions(result = {}) {
  const receipt = result.public_receipt || {};
  const boundary = result.action_boundary_review || {};
  const triage = result.advisory_triage || {};
  return [
    ...(receipt.recommended_actions || []),
    ...(boundary.recommended_actions || []),
    ...(triage.recommended_actions || []),
  ].filter(Boolean);
}

function artifactMetaRows(receipt, publicReceipt, result) {
  const rows = [
    ['Receipt version', receipt.version || 'n/a'],
    ['Completed', firstValue(publicReceipt.completed_at, result.completed_at, 'n/a')],
    ['Source ZIP', firstValue(publicReceipt.source_zip, receipt.input_name, result.source_zip, 'n/a')],
    ['SHA-256', firstValue(publicReceipt.source_sha256, receipt.sha256, result.source_sha256, 'n/a')],
    ['Archive safety', firstValue(publicReceipt.archive_safety, receipt.archive_safety?.status, 'n/a')],
    ['Review decision', normalizeState(firstValue(result.status, publicReceipt.status, publicReceipt.review_decision, 'Review'))],
    ['Fence', firstValue(publicReceipt.fence, result.fence, 'n/a')],
  ];
  return rows.map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`).join('');
}

function renderStateSummary(result, finalState) {
  const receipt = result.public_receipt || {};
  const routing = result.security_routing || {};
  const boundary = result.action_boundary_review || {};
  const archiveSafety = firstValue(receipt.archive_safety, result.artifact_receipt?.archive_safety?.status, 'not emitted');
  const reasons = [
    result.summary?.headline,
    routing.recommended_lane,
    ...(Array.isArray(routing.why) ? routing.why : []),
    boundary.manual_approval_required ? 'Manual approval is required before authority-sensitive action.' : '',
  ].filter(Boolean);
  return `
    <div class="state-stack">
      <div class="state-pill state-${stateTone(finalState)}"><strong>${escapeHtml(finalState)}</strong><span>final bounded state</span></div>
      <div>
        <h3>Why this state</h3>
        <ul>${renderLooseList(reasons.slice(0, 5), 'No state rationale was emitted by the scanner.')}</ul>
      </div>
      <div>
        <h3>What was not inspected</h3>
        <ul>${renderLooseList(result.summary?.not_checked, 'No additional non-guarantee notes were emitted.')}</ul>
      </div>
      ${renderInlineMeta([['Archive safety', normalizeState(archiveSafety, archiveSafety)], ['Human gate', receipt.human_gate_required || boundary.manual_approval_required ? 'required' : 'not required'], ['Static only', receipt.static_only ?? true]])}
    </div>
  `;
}

function renderResult(result, options = {}) {
  const axes = axesForMode(result.axes || {});
  const findings = findingsForMode(result.findings || []);
  const bom = result.ai_bom || {};
  const groups = result.finding_groups || [];
  const remediation = result.remediation_plan || [];
  const receipt = result.artifact_receipt || {};
  const triage = result.advisory_triage || {};
  const agentic = result.agentic_surface || {};
  const publicReceipt = result.public_receipt || {};
  const boundary = result.action_boundary_review || {};
  const securityTool = result.security_tool_surface || {};
  const governance = result.governance_surface || {};
  const componentCounts = agentic.component_counts || {};
  const finalState = normalizeState(firstValue(publicReceipt.status, result.status, options.state, 'Review'));
  const stateClass = stateTone(finalState);
  const topFindings = findings.slice(0, 8);
  const actions = recommendedActions(result);

  results.classList.remove('hidden');
  const modeDef = MODE_DEFINITIONS[activeMode];
  results.innerHTML = `
    <section class="summary result-state-${stateClass}" aria-labelledby="resultTitle">
      <p class="eyebrow">MAYA static decision brief</p>
      <h2 id="resultTitle">${escapeHtml(result.tool || 'MAYA Sentinel')}</h2>
      ${modeDef && activeMode !== 'safety' ? `<p class="mode-active-note">Scan focus: <strong>${escapeHtml(modeDef.label)}</strong>. ${escapeHtml(modeDef.prompt)}</p>` : ''}
      ${renderStateSummary(result, finalState)}
      <div class="priority-block">
        <h3>Highest-impact findings</h3>
        <ul>${topFindings.length ? renderLooseList(topFindings.map(item => ({
          label: `${item.severity || 'signal'} ${item.category || 'finding'}`,
          summary: `${item.path || 'unknown path'}${item.signal ? ` - ${item.signal}` : ''}`,
        })), 'No static findings were emitted.') : '<li>No static findings were detected by this scan. This does not prove the repository is safe.</li>'}</ul>
      </div>
      <div class="priority-block">
        <h3>Recommended next action</h3>
        <ol>${actions.length ? renderLooseList(actions.slice(0, 5), 'No public follow-up action was emitted.') : `<li>${escapeHtml(result.summary?.next_step || 'Review the public receipt before trusting or running this repository.')}</li>`}</ol>
      </div>
      <div class="actions">
        ${renderReportLinks(result.reports)}
        <button type="button" id="dropAnotherButton">Drop Another Repo</button>
      </div>
    </section>
    ${renderPanel('Evidence and Public Receipt', `
      ${renderInlineMeta([['Receipt', publicReceipt.version || 'n/a'], ['Source ZIP', publicReceipt.source_zip || result.source_zip || receipt.input_name || 'n/a'], ['Completed', publicReceipt.completed_at || result.completed_at || 'n/a'], ['Status', finalState]])}
      ${renderInlineMeta([['Executed repo code', publicReceipt.executed_repo_code ?? false], ['Installed dependencies', publicReceipt.installed_dependencies ?? false], ['Network calls', publicReceipt.network_calls ?? false]])}
      <table class="kv-table"><tbody>${artifactMetaRows(receipt, publicReceipt, result)}</tbody></table>
      ${renderInlineSignals(publicReceipt.action_boundaries, 'No authority-sensitive action boundaries detected.')}
      <ol>${renderLooseList(publicReceipt.recommended_actions, 'No public follow-up actions were emitted.')}</ol>
    `, { open: true, meta: publicReceipt.version || 'receipt' })}
    ${renderPanel('Action Boundary Review', `
      ${renderInlineMeta([['Decision', normalizeState(boundary.decision, boundary.decision || 'Review')], ['Manual approval', boundary.manual_approval_required ?? false], ['Instruction surface', normalizeState(boundary.instruction_surface_integrity?.status, boundary.instruction_surface_integrity?.status || 'not available')]])}
      ${renderInlineMeta([['Agent instructions', boundary.instruction_surface_integrity?.agent_instruction_count || 0], ['MCP servers', boundary.instruction_surface_integrity?.mcp_server_count || 0], ['Workflows', boundary.instruction_surface_integrity?.workflow_automation_count || 0], ['Approval docs', boundary.instruction_surface_integrity?.approval_doc_count || 0]])}
      <table>
        <thead><tr><th>Authority class</th><th>Signals</th><th>Recommended action</th></tr></thead>
        <tbody>${Array.isArray(boundary.authority_classes) && boundary.authority_classes.length ? boundary.authority_classes.slice(0, 12).map(item => `<tr><td>${escapeHtml(item.label || item.id || 'Authority class')}</td><td>${escapeHtml(item.evidence_count || item.count || 0)}</td><td>${escapeHtml(publicReviewLabel(item.recommended_action, 'Review before action.'))}</td></tr>`).join('') : '<tr><td colspan="3">No authority-sensitive action classes detected.</td></tr>'}</tbody>
      </table>
      <ul>${renderLooseList(boundary.instruction_surface_integrity?.checks, 'No extra instruction-surface checks were emitted.')}</ul>
    `, { open: true, meta: boundary.manual_approval_required ? 'approval gate visible' : 'static review' })}
    ${renderPanel('Agentic / MCP Surface', `
      ${renderInlineMeta([['Posture', normalizeState(agentic.posture, agentic.posture || 'Review')], ['Review route', publicReviewLabel(agentic.owner, 'Sentinel review')]])}
      ${objectChipRow(componentCounts, 'No agentic component counts emitted.')}
      <table>
        <thead><tr><th>Surface</th><th>Count</th><th>Summary</th></tr></thead>
        <tbody>${Array.isArray(agentic.surfaces) && agentic.surfaces.length ? agentic.surfaces.map(surface => `<tr><td>${escapeHtml(surface.label || surface.surface || 'surface')}</td><td>${escapeHtml(surface.count || 0)}</td><td>${escapeHtml(surface.summary || surface.path || surface.recommended_action || surface.surface || '')}</td></tr>`).join('') : Object.entries(componentCounts).map(([key, count]) => `<tr><td>${escapeHtml(key.replaceAll('_', ' '))}</td><td>${escapeHtml(count)}</td><td>Component count from scanner schema.</td></tr>`).join('') || '<tr><td colspan="3">No agentic surfaces detected.</td></tr>'}</tbody>
      </table>
      <ul>${renderLooseList(agentic.policy_checks, 'No extra policy checks were emitted.')}</ul>
    `, { meta: agentic.version || 'component counts' })}
    ${renderPanel('Security Tool Surface', `
      ${renderInlineMeta([['Posture', normalizeState(securityTool.posture, securityTool.posture || 'not available')], ['Human scope', securityTool.human_scope_required ? 'required' : 'not required']])}
      ${objectChipRow(securityTool.counts, 'No scanner/API/MCP security-tool surface detected.')}
      <table>
        <thead><tr><th>Surface</th><th>Path</th><th>Recommended action</th></tr></thead>
        <tbody>${Array.isArray(securityTool.signals) && securityTool.signals.length ? securityTool.signals.slice(0, 18).map(item => `<tr><td>${escapeHtml(item.label || item.id || 'surface')}</td><td><code>${escapeHtml(item.path || '')}</code></td><td>${escapeHtml(publicReviewLabel(item.recommended_action, 'Review before promotion.'))}</td></tr>`).join('') : '<tr><td colspan="3">No security-tool surface signals detected.</td></tr>'}</tbody>
      </table>
      <ul>${renderLooseList(securityTool.recommended_review_actions, 'No security-tool review actions were emitted.')}</ul>
    `, { open: Boolean(securityTool.human_scope_required), meta: securityTool.posture || 'review' })}
    ${renderPanel('Install-Related Static Signals and Reuse Indicators', `
      ${renderInlineMeta([['BOM', bom.version || 'n/a'], ['Components', bom.component_count || 0], ['Dependencies', bom.dependency_direct_count || 0]])}
      ${objectChipRow(bom.component_type_counts, 'No component-type mix detected.')}
      ${objectChipRow(bom.dependency_ecosystems, 'No dependency ecosystems detected.')}
      ${objectChipRow(governance.counts, 'No governance or maintenance counters emitted.')}
      <table>
        <thead><tr><th>Type</th><th>Path</th><th>Reason</th></tr></thead>
        <tbody>${(bom.components || []).slice(0, 60).map(c => `<tr><td>${escapeHtml(c.type)}</td><td><code>${escapeHtml(c.path)}</code></td><td>${escapeHtml(c.reason)}</td></tr>`).join('') || '<tr><td colspan="3">No AI/component BOM entries detected.</td></tr>'}</tbody>
      </table>
    `, { meta: `${bom.component_count || 0} components` })}
    ${renderPanel('Finding Groups', `
      <table>
        <thead><tr><th>Count</th><th>Max Severity</th><th>Category</th><th>Signal</th><th>Sample Paths</th></tr></thead>
        <tbody>${groups.length ? groups.slice(0, 60).map(g => `<tr><td>${escapeHtml(g.count)}</td><td>${escapeHtml(g.max_severity)}</td><td>${escapeHtml(g.category)}</td><td>${escapeHtml(g.signal)}</td><td><code>${escapeHtml((g.sample_paths || []).slice(0, 3).join(', '))}</code></td></tr>`).join('') : '<tr><td colspan="5">No finding groups produced.</td></tr>'}</tbody>
      </table>
    `, { meta: `${groups.length} groups` })}
    ${renderPanel('Remediation Plan', `
      <ol>${remediation.length ? remediation.slice(0, 20).map(item => `<li><strong>${escapeHtml(item.category)}</strong> - ${escapeHtml(item.action)}</li>`).join('') : '<li>No deterministic remediation steps were generated from static findings.</li>'}</ol>
    `, { meta: `${remediation.length} steps` })}
    <section class="metric-grid" aria-label="Lower-priority architecture detail">
      ${axes.map(([name, axis]) => {
        const axisState = normalizeState(axis.status_label || axis.color);
        return `
        <article class="metric-card ${escapeHtml(axis.color || 'blue')}">
          <div class="metric-top"><h3>${escapeHtml(name)}</h3><span>${escapeHtml(axisState)}</span></div>
          <div class="bar"><i></i><span>${escapeHtml(axisState)}</span></div>
          <p>${escapeHtml(axis.interpretation || '')}</p>
          ${axis.reward_note ? `<p class="maya-note"><strong>MAYA</strong> ${escapeHtml(axis.reward_note)}</p>` : ''}
          ${Array.isArray(axis.review_options) && axis.review_options.length ? `<div class="suggested-checks"><strong>Suggested checks</strong>${renderInlineSignals(axis.review_options)}</div>` : ''}
        </article>`;
      }).join('')}
    </section>
    ${renderPanel('Raw Static Findings', `
      <table>
        <thead><tr><th>Severity</th><th>Category</th><th>Path</th><th>Line</th><th>Signal</th><th>Evidence</th></tr></thead>
        <tbody>${findings.length ? findings.slice(0, 80).map(f => `<tr><td>${escapeHtml(f.severity)}</td><td>${escapeHtml(f.category)}</td><td><code>${escapeHtml(f.path)}</code></td><td>${escapeHtml(f.line || '')}</td><td>${escapeHtml(f.signal)}</td><td><code>${escapeHtml(f.snippet || '')}</code></td></tr>`).join('') : '<tr><td colspan="6">No static findings were detected by this scan. This does not prove the repository is safe.</td></tr>'}</tbody>
      </table>
    `, { meta: `${findings.length} findings` })}
  `;

  document.getElementById('dropAnotherButton')?.addEventListener('click', () => window.location.reload());
  focusElement(results.querySelector('.summary'));
}

function renderHistory(items = []) {
  if (!historyGrid) return;
  const count = Array.isArray(items) ? items.length : 0;
  if (historySummary) {
    historySummary.textContent = `${count} retained scan${count === 1 ? '' : 's'} shown. Reports are stored locally until deleted.`;
  }
  if (clearHistoryButton) clearHistoryButton.disabled = count === 0;
  if (!count) {
    historyGrid.innerHTML = `<article class="history-card empty"><strong>No local scans retained</strong><span>Run a repo ZIP and public receipt links will appear here.</span></article>`;
    return;
  }
  historyGrid.innerHTML = items.map(item => {
    const state = normalizeState(item.approved_final_state || item.status, 'Review');
    return `
    <article class="history-card">
      <strong title="${escapeHtml(item.scan_id || 'retained scan')}">${escapeHtml(formatScanIdForDisplay(item.scan_id || 'retained scan'))}</strong>
      <span>${escapeHtml(formatStamp(item.completed_at))}</span>
      ${renderInlineMeta([['State', state], ['Receipt', item.public_receipt_version || 'n/a'], ['SHA-256', item.input_sha256 ? `${item.input_sha256.slice(0, 12)}...` : 'n/a']])}
      <div class="history-links">
        ${item.reports?.html ? `<a class="link-button" href="/reports/${encodeURIComponent(item.reports.html)}" target="_blank" rel="noopener">HTML</a>` : ''}
        ${item.reports?.markdown ? `<a class="link-button" href="/reports/${encodeURIComponent(item.reports.markdown)}" target="_blank" rel="noopener">MD</a>` : ''}
        ${item.reports?.json ? `<a class="link-button" href="/reports/${encodeURIComponent(item.reports.json)}" target="_blank" rel="noopener">JSON</a>` : ''}
        <button type="button" class="delete-history-button" data-scan-id="${escapeHtml(item.scan_id || '')}" aria-label="Delete retained scan ${escapeHtml(item.scan_id || '')}">Delete</button>
      </div>
    </article>`;
  }).join('');
}

async function fetchHistory() {
  try {
    const response = await fetch('/api/history', { cache: 'no-store', credentials: 'same-origin' });
    const payload = await response.json();
    if (response.ok && payload.ok) renderHistory(payload.items || []);
  } catch {
    renderHistory([]);
  }
}

async function deleteHistory(scanId) {
  if (!scanId) return;
  if (!window.confirm('Delete this retained scan and its local report files?')) return;
  try {
    await ensureSession();
    const response = await fetch(`/api/history/${encodeURIComponent(scanId)}`, {
      method: 'DELETE',
      cache: 'no-store',
      headers: sessionHeaders(),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error?.message || 'Delete failed.');
    setStatus('Retained scan deleted locally.', 'review');
    await fetchHistory();
    focusElement(historyGrid);
  } catch (err) {
    setStatus(`Delete failed: ${err.message}`, 'error');
    focusElement(statusBox);
  }
}

async function clearHistory() {
  if (!window.confirm('Delete all retained scans and local report files?')) return;
  try {
    await ensureSession();
    const response = await fetch('/api/history', {
      method: 'DELETE',
      cache: 'no-store',
      headers: sessionHeaders(),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error?.message || 'Clear failed.');
    setStatus('All retained scan history was deleted locally.', 'review');
    await fetchHistory();
    focusElement(historyGrid);
  } catch (err) {
    setStatus(`Clear failed: ${err.message}`, 'error');
    focusElement(statusBox);
  }
}

async function scanFile(file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.zip')) {
    announceUiState('Error', 'MAYA Sentinel v1.0 only accepts repo ZIP files.');
    focusElement(statusBox);
    return;
  }
  announceUiState('Scanning', 'MAYA is reading static structure, dependency signals, action boundaries, and receipt surfaces.');
  results.classList.add('hidden');
  const body = new FormData();
  body.append('zipfile', file);
  try {
    await ensureSession();
    const response = await fetch('/api/scan', { method: 'POST', body, cache: 'no-store', headers: sessionHeaders() });
    const payload = await response.json();
    if (payload.blocked && payload.result) {
      announceUiState('Blocked', 'ZIP intake stopped during guarded intake before static analysis. Review the blocked receipt.');
      renderResult(payload.result, { state: 'Blocked' });
      await fetchHistory();
      return;
    }
    if (!response.ok || !payload.ok) {
      const message = typeof payload.error === 'string' ? payload.error : payload.error?.message;
      announceUiState('Error', message || 'Scan failed before a public receipt could be completed.');
      focusElement(statusBox);
      return;
    }
    const finalState = normalizeState(payload.result?.public_receipt?.status || payload.result?.status);
    announceUiState(finalState, 'static scan finished with local receipt output. Review before trust.');
    renderResult(payload.result, { state: finalState });
    await fetchHistory();
  } catch (err) {
    announceUiState('Error', err.message);
    focusElement(statusBox);
  }
}

if (browse) {
  browse.addEventListener('click', () => input.click());
}

input.addEventListener('change', () => scanFile(input.files[0]));

dropZone.addEventListener('click', event => {
  if (event.target.closest('#browseButton') || event.target === input) return;
  input.click();
});
['dragenter', 'dragover'].forEach(name => dropZone.addEventListener(name, event => {
  event.preventDefault();
  dropZone.classList.add('dragging');
}));
['dragleave', 'drop'].forEach(name => dropZone.addEventListener(name, event => {
  event.preventDefault();
  dropZone.classList.remove('dragging');
}));
dropZone.addEventListener('drop', event => scanFile(event.dataTransfer.files[0]));
historyGrid?.addEventListener('click', event => {
  const button = event.target.closest('.delete-history-button');
  if (button) deleteHistory(button.dataset.scanId);
});
clearHistoryButton?.addEventListener('click', clearHistory);

document.querySelectorAll('.mode-card').forEach(button => {
  button.addEventListener('click', () => setActiveMode(button.dataset.mode));
});

ensureSession().catch(() => {
  setStatus('Error: local session could not be initialized.', 'error');
});
fetchHistory();
