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
  const response = await fetch(path, {
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
$('#credentials')?.addEventListener('click', () => $('#token-dialog').showModal());
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


/* =========================================================================
   AegisOps Copilot — Chat Interface Controller
   ========================================================================= */
(function initCopilot() {
  const form = $('#copilot-form');
  const input = $('#copilot-input');
  const stream = $('#chat-stream');
  const loading = $('#copilot-loading');
  const errorBox = $('#copilot-error-box');
  const retryBtn = $('#copilot-retry');
  const clearBtn = $('#copilot-clear');

  if (!form || !input || !stream) return;

  let lastQuery = '';

  // Setup suggestion chips
  document.querySelectorAll('.suggestion-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const prompt = chip.dataset.prompt;
      if (prompt) {
        input.value = prompt;
        input.focus();
      }
    });
  });

  // Clear chat history
  clearBtn?.addEventListener('click', () => {
    stream.replaceChildren();
    const welcome = document.createElement('div');
    welcome.className = 'chat-message assistant-message welcome-message';
    welcome.innerHTML = `
      <div class="message-header">
        <span class="message-author">◈ AEGISOPS COPILOT</span>
        <span class="message-badge">HYBRID RETRIEVAL</span>
      </div>
      <div class="message-body">
        <p>Conversation history cleared. Ready for your operational questions.</p>
      </div>
    `;
    stream.appendChild(welcome);
  });

  function appendUserMessage(text) {
    const msg = document.createElement('div');
    msg.className = 'chat-message user-message';
    const body = document.createElement('div');
    body.className = 'message-body';
    const p = document.createElement('p');
    p.textContent = text;
    body.appendChild(p);
    msg.appendChild(body);
    stream.appendChild(msg);
    stream.scrollTop = stream.scrollHeight;
  }

  function appendAssistantMessage(data) {
    const msg = document.createElement('div');
    msg.className = 'chat-message assistant-message';

    const header = document.createElement('div');
    header.className = 'message-header';
    const author = document.createElement('span');
    author.className = 'message-author';
    author.textContent = '◈ AEGISOPS COPILOT';
    const badge = document.createElement('span');
    badge.className = 'message-badge';
    badge.textContent = data.abstained ? 'ABSTAINED' : (data.execution_time_seconds ? `${data.execution_time_seconds}s` : 'GROUNDED');
    header.append(author, badge);
    msg.appendChild(header);

    const body = document.createElement('div');
    body.className = 'message-body';

    // Direct answer paragraph
    const p = document.createElement('p');
    p.textContent = data.answer || 'No response generated.';
    body.appendChild(p);

    // Abstention alert if applicable
    if (data.abstained && data.abstain_reason) {
      const abstainBox = document.createElement('div');
      abstainBox.className = 'abstain-box';
      abstainBox.innerHTML = `<strong>Insufficient evidence:</strong> ${data.abstain_reason}`;
      body.appendChild(abstainBox);
    }

    // Citations
    if (data.citations && data.citations.length > 0) {
      const citWrap = document.createElement('div');
      citWrap.className = 'citations-wrap';
      const citLabel = document.createElement('span');
      citLabel.className = 'citations-label';
      citLabel.textContent = 'VERIFIED CITATIONS & SOURCE RECORDS:';
      citWrap.appendChild(citLabel);

      data.citations.forEach(cit => {
        const link = document.createElement('a');
        link.className = 'citation-pill';
        let targetHref = '#';
        if (cit.type === 'runbook') targetHref = '/runbooks';
        else if (cit.type === 'policy') targetHref = '/runbooks';
        else if (cit.type === 'incident' || cit.type === 'metric' || cit.type === 'approval' || cit.type === 'execution_action') targetHref = '/audit';
        
        link.href = targetHref;
        link.innerHTML = `<span class="citation-type">[${cit.type}]</span> <strong>${cit.id}</strong> (${cit.source})`;
        citWrap.appendChild(link);
      });
      body.appendChild(citWrap);
    }

    // Facts and interpretations accordion
    if ((data.facts && data.facts.length > 0) || (data.interpretations && data.interpretations.length > 0)) {
      const details = document.createElement('details');
      details.className = 'evidence-accordion';
      const summary = document.createElement('summary');
      summary.textContent = 'Inspect verified facts & interpretations ＋';
      details.appendChild(summary);

      if (data.facts && data.facts.length > 0) {
        const factsTitle = document.createElement('strong');
        factsTitle.textContent = 'Verified Facts:';
        details.appendChild(factsTitle);
        const ul = document.createElement('ul');
        data.facts.forEach(f => {
          const li = document.createElement('li');
          li.textContent = f;
          ul.appendChild(li);
        });
        details.appendChild(ul);
      }

      if (data.interpretations && data.interpretations.length > 0) {
        const interpTitle = document.createElement('strong');
        interpTitle.textContent = 'Analysis & Policy Constraints:';
        details.appendChild(interpTitle);
        const ul = document.createElement('ul');
        data.interpretations.forEach(it => {
          const li = document.createElement('li');
          li.textContent = it;
          ul.appendChild(li);
        });
        details.appendChild(ul);
      }
      body.appendChild(details);
    }

    msg.appendChild(body);
    stream.appendChild(msg);
    stream.scrollTop = stream.scrollHeight;
  }

  async function sendQuery(queryText) {
    const q = queryText.trim();
    if (!q) return;

    lastQuery = q;
    appendUserMessage(q);
    input.value = '';

    if (loading) {
      loading.hidden = false;
      loading.style.display = 'flex';
    }
    if (errorBox) {
      errorBox.hidden = true;
      errorBox.style.display = 'none';
    }

    try {
      const token = sessionStorage.getItem('aegisops-token') || '';
      const headers = { 'Content-Type': 'application/json' };
      if (token) {
        headers['Authorization'] = 'Bearer ' + token;
      }
      const response = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({query: q})
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || `Server responded with status ${response.status}`);
      }

      appendAssistantMessage(result);
    } catch (err) {
      if (errorBox) {
        errorBox.hidden = false;
        errorBox.style.display = 'flex';
        $('#error-details').textContent = err.message || 'Network request failed';
      }
    } finally {
      if (loading) {
        loading.hidden = true;
        loading.style.display = 'none';
      }
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    sendQuery(input.value);
  });

  retryBtn?.addEventListener('click', () => {
    if (lastQuery) {
      sendQuery(lastQuery);
    }
  });
})();
