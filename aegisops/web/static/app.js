/* AegisOps client controls — presentation never authorizes an action. */
'use strict';
const $ = (selector) => document.querySelector(selector);
const feedback = (message, error = false) => {
  const node = $('#feedback');
  if (!node) return;
  node.hidden = false;
  node.textContent = message;
  node.classList.toggle('error', error);
  clearTimeout(feedback.timer);
  feedback.timer = setTimeout(() => { node.hidden = true; }, 5200);
};
async function api(path, data) {
  const token = sessionStorage.getItem('aegisops-token') || '';
  const response = await window.aegisAuth.request(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
    body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
async function perform(path, data, refresh = false) {
  const actionButtons = [...document.querySelectorAll('button')];
  try {
    const result = await api(path, data);
    if ($('#result')) $('#result').textContent = JSON.stringify(result, null, 2);
    feedback(result.outcome || (result.kill_switch !== undefined ? (result.kill_switch ? 'Kill switch engaged' : 'Kill switch released') : 'Control recorded'));
    if (refresh) { location.reload(); return; }
    await poll();
  } catch (error) {
    feedback(error.message, true);
  } finally {
    actionButtons.forEach(button => { button.disabled = false; });
  }
}
if (document.body.dataset.authMode === 'token') $('#credentials')?.addEventListener('click', () => $('#token-dialog').showModal());
$('#save-token')?.addEventListener('click', () => {
  const value = $('#operator-token').value.trim();
  if (!value) { feedback('Enter the operator token to unlock controls.', true); return; }
  sessionStorage.setItem('aegisops-token', value);
  $('#operator-token').value = '';
  feedback('Token stored for this browser tab. Server authorization will be checked on the next action.');
});
$('#inject')?.addEventListener('click', () => perform('/api/inject', {fault: $('#fault').value}));
$('#run')?.addEventListener('click', () => perform('/api/run', {}));
$('#dry-run')?.addEventListener('click', () => perform('/api/run', {dry_run: true}));
$('#kill-toggle')?.addEventListener('click', () => {
  const button = $('#kill-toggle');
  const enabling = button.dataset.enabled === 'true';
  button.disabled = true;
  perform('/api/killswitch', {enabled: enabling});
});
document.querySelectorAll('[data-approval]').forEach(button => button.addEventListener('click', () => {
  const id = button.dataset.approval;
  const reason = document.getElementById('reason-' + id)?.value || '';
  if (!reason.trim()) { feedback('A reason is required for this decision.', true); return; }
  button.disabled = true;
  perform('/api/' + button.dataset.operation + '/' + id, {reason}, true);
}));
document.querySelectorAll('[data-epoch]').forEach(node => {
  const epoch = Number(node.dataset.epoch);
  if (Number.isFinite(epoch)) node.textContent = new Date(epoch * 1000).toLocaleString();
});
$('#mobile-menu')?.addEventListener('click', () => $('.sidebar')?.classList.toggle('nav-open'));
async function poll() {
  if (!$('#observations')) return;
  try {
    const response = await fetch('/api/status', {cache: 'no-store'});
    if (!response.ok) throw new Error('Status unavailable');
    const s = await response.json();
    $('#observations').replaceChildren(...Object.entries(s.state || {}).map(([key, value]) => {
      const item = document.createElement('div');
      item.className = 'observation-item';
      const label = document.createElement('span');
      const current = document.createElement('strong');
      const note = document.createElement('small');
      label.textContent = key.replaceAll('_', ' ');
      current.textContent = value === null ? 'UNKNOWN' : String(value);
      note.textContent = 'OBSERVED VALUE';
      item.append(label, current, note);
      return item;
    }));
    const limit = Number(s.rate_limit?.max_actions || 0);
    const used = Number(s.actions_in_window || 0);
    $('#action-count').textContent = String(used);
    const actionCard = $('#action-count')?.closest('.stat-card');
    if (actionCard) {
      const total = actionCard.querySelector('.stat-total');
      if (total) total.textContent = '/ ' + limit;
      const fill = $('#budget-fill');
      if (fill) { fill.className = 'width-' + Math.round(Math.min(100, limit ? used / limit * 100 : 0)); }
    }
    $('#pending-count').textContent = s.approvals?.length ?? 0;
    $('#audit-count').textContent = s.audit_events ?? 0;
    if ($('#sidebar-pending')) $('#sidebar-pending').textContent = s.approvals?.length ?? 0;
    $('#circuit-state').textContent = s.circuit_open ? 'OPEN' : 'CLOSED';
    const circuitTag = $('#circuit-tag');
    if (circuitTag) {
      circuitTag.textContent = s.circuit_open ? 'TRIPPED' : 'STANDBY';
      circuitTag.classList.toggle('tag-danger', Boolean(s.circuit_open));
    }
    const state = $('#system-state');
    if (state) {
      state.textContent = s.kill_switch ? 'AUTOMATION HALTED' : 'POLICY GUARD ACTIVE';
      state.classList.toggle('danger-text', Boolean(s.kill_switch));
    }
    if ($('#hero-state-caption')) $('#hero-state-caption').textContent = s.kill_switch ? 'Operator kill switch engaged' : 'No live infrastructure connected';
    const kill = $('#kill-toggle');
    if (kill) {
      kill.dataset.enabled = String(!s.dashboard_kill);
      kill.textContent = '';
      kill.append(document.createTextNode(s.dashboard_kill ? 'Release dashboard switch ' : 'HALT AUTOMATION '));
      const arrow = document.createElement('span'); arrow.textContent = '↗'; kill.append(arrow);
      kill.classList.toggle('button-danger', !s.dashboard_kill);
      kill.classList.toggle('button-quiet', Boolean(s.dashboard_kill));
    }
  } catch (error) {
    feedback(error.message, true);
  }
}
poll();
setInterval(poll, 3000);
