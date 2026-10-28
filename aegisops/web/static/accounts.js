/* Individual account sessions. All network requests stay on this origin. */
'use strict';
(() => {
  const mode = document.body.dataset.authMode;
  let user = null;
  let refreshing = null;
  const permissions = {viewer: [], operator: ['inject', 'run', 'dry-run', 'kill-toggle'], approver: ['approve', 'deny'], admin: ['inject', 'run', 'dry-run', 'kill-toggle', 'approve', 'deny']};
  const dialog = document.getElementById('account-dialog');
  const message = (text) => {
    const node = document.getElementById('account-message');
    if (node) node.textContent = text;
  };
  function render(next) {
    user = next;
    const identity = document.getElementById('account-identity');
    if (identity) identity.textContent = user ? user.email + ' · ' + user.role : 'Guest · view only';
    const login = document.getElementById('credentials');
    if (login && mode === 'supabase') login.textContent = user ? 'Account' : 'Sign in';
    const logout = document.getElementById('signout');
    if (logout) logout.hidden = !user;
    const admin = document.getElementById('accounts-nav');
    if (admin) admin.hidden = user?.role !== 'admin';
    const note = document.getElementById('account-access');
    if (note) note.textContent = !user ? 'Sign in to use controls. Visitors can view this simulation.' : user.email + ' · ' + (user.role === 'viewer' ? 'Viewer: ask an admin for control access.' : user.role + ' · Policy checks still apply.');
    for (const button of document.querySelectorAll('#inject, #run, #dry-run, #kill-toggle, [data-approval]')) {
      const action = button.dataset.operation || button.id;
      button.classList.toggle('account-locked', !user || !permissions[user.role].includes(action));
      button.setAttribute('aria-disabled', String(!user || !permissions[user.role].includes(action)));
    }
  }
  function clear() { sessionStorage.removeItem('aegisops-access'); render(null); }
  function accept(data) {
    if (typeof data.access_token !== 'string' || !data.user) throw new Error('Invalid session response');
    sessionStorage.setItem('aegisops-access', data.access_token);
    render(data.user);
  }
  async function exchange(path, data) {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Sign-in unavailable');
    return result;
  }
  async function refresh() {
    if (!refreshing) refreshing = exchange('/api/auth/refresh', {}).then(accept).finally(() => { refreshing = null; });
    return refreshing;
  }
  async function authorized(path, options = {}) {
    if (mode === 'token') return fetch(path, {...options, headers: {...options.headers, Authorization: 'Bearer ' + (sessionStorage.getItem('aegisops-token') || '')}});
    const send = () => fetch(path, {...options, headers: {...options.headers, Authorization: 'Bearer ' + (sessionStorage.getItem('aegisops-access') || '')}});
    let response = await send();
    if (response.status === 401) {
      try { await refresh(); response = await send(); }
      catch (_) { clear(); dialog?.showModal(); throw new Error('Please sign in to continue.'); }
    }
    return response;
  }
  async function loadUsers() {
    const target = document.getElementById('account-users');
    if (!target) return;
    if (user?.role !== 'admin') { target.textContent = 'Admin sign-in is required to manage access.'; return; }
    const response = await authorized('/api/auth/users');
    const data = await response.json();
    if (!response.ok) { target.textContent = data.error || 'Unable to load accounts.'; return; }
    target.replaceChildren();
    for (const account of data.users) {
      const row = document.createElement('form'); row.className = 'account-user';
      const label = document.createElement('label'); label.textContent = account.email;
      const select = document.createElement('select'); select.setAttribute('aria-label', 'Role for ' + account.email);
      for (const role of ['viewer', 'operator', 'approver', 'admin']) {
        const option = document.createElement('option'); option.value = role; option.textContent = role; option.selected = account.role === role; select.append(option);
      }
      const save = document.createElement('button'); save.className = 'button button-primary'; save.textContent = 'Save role';
      save.disabled = account.user_id === user.id;
      row.append(label, select, save);
      row.addEventListener('submit', async event => {
        event.preventDefault(); save.disabled = true;
        try {
          const response = await authorized('/api/auth/role', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({user_id: account.user_id, role: select.value})});
          const result = await response.json();
          document.getElementById('role-message').textContent = result.message || result.error;
        } catch (error) { document.getElementById('role-message').textContent = error.message; }
        finally { save.disabled = account.user_id === user?.id; }
      });
      target.append(row);
    }
    if (!data.users.length) target.textContent = 'No accounts yet. Users appear after signing up.';
  }
  const ready = (async () => {
    if (mode === 'token') return;
    sessionStorage.removeItem('aegisops-token');
    if (location.hash.includes('access_token=') || location.hash.includes('error=')) {
      history.replaceState(null, '', location.pathname + location.search);
      message('Please sign in after confirming your email.');
    }
    try {
      if (!sessionStorage.getItem('aegisops-access')) await refresh();
      const response = await authorized('/api/auth/session');
      const data = await response.json();
      render(response.ok ? data.user : null);
    } catch (_) { clear(); }
    try { await loadUsers(); } catch (error) { const target = document.getElementById('account-users'); if (target) target.textContent = error.message; }
  })();
  window.aegisAuth = {ready, request: async (path, options) => { await ready; return authorized(path, options); }};
  if (mode === 'token') return;
  document.getElementById('credentials')?.addEventListener('click', () => dialog?.showModal());
  document.getElementById('account-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const buttons = [...dialog.querySelectorAll('button[type="submit"]')]; buttons.forEach(b => { b.disabled = true; });
    const password = document.getElementById('account-password');
    try {
      const operation = event.submitter?.value === 'signup' ? 'signup' : 'signin';
      const result = await exchange('/api/auth/' + operation, {email: document.getElementById('account-email').value.trim(), password: password.value});
      password.value = '';
      if (operation === 'signup') message(result.message);
      else { accept(result); dialog.close(); message(''); await loadUsers(); }
    } catch (error) { message(error.message); }
    finally { password.value = ''; buttons.forEach(b => { b.disabled = false; }); }
  });
  document.getElementById('close-account')?.addEventListener('click', () => dialog.close());
  document.getElementById('signout')?.addEventListener('click', async () => {
    try {
      const response = await authorized('/api/auth/signout', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
      if (!response.ok) throw new Error('Sign-out could not be confirmed. Please try again.');
      clear(); await loadUsers();
    } catch (error) { message(error.message); dialog.showModal(); }
  });
})();
