document.addEventListener('DOMContentLoaded', async () => {
  const gate = document.getElementById('auth-gate');
  const shell = document.getElementById('workspace-shell');
  const signIn = document.getElementById('google-sign-in');
  const authMessage = document.getElementById('auth-message');
  const accountDialog = document.getElementById('account-dialog');
  const commandDialog = document.getElementById('command-dialog');
  let session = { required: false, enabled: false, user: null };

  signIn?.addEventListener('click', () => { location.href = '/auth/google'; });

  const authErrors = {
    not_configured: 'Google sign-in is not configured on this server yet.',
    access_denied: 'This Google account cannot access the workspace.',
    sign_in_failed: 'Google sign-in could not be completed. Please try again.'
  };
  const params = new URLSearchParams(location.search);
  if (params.get('auth_error')) {
    authMessage.textContent = authErrors[params.get('auth_error')] || 'Sign-in failed.';
    history.replaceState({}, '', location.pathname);
  }

  try {
    const response = await fetch('/auth/session', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Session check failed');
    session = await response.json();
  } catch {
    authMessage.textContent = 'The workspace server is unavailable.';
    gate.classList.remove('hidden');
    return;
  }

  if (session.required && !session.user) {
    gate.classList.remove('hidden');
    if (!session.configured) {
      signIn.disabled = true;
      authMessage.textContent = 'Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and APP_URL to enable sign-in.';
    }
    return;
  }

  shell.hidden = false;
  gate.classList.add('hidden');
  const user = session.user;
  const accountName = document.getElementById('account-name');
  const accountEmail = document.getElementById('account-email');
  const accountAvatar = document.getElementById('account-avatar');
  accountName.textContent = user?.name || 'Local workspace';
  accountEmail.textContent = user?.email || 'On this device';
  accountAvatar.textContent = (user?.name || user?.email || 'L').slice(0, 1).toUpperCase();
  document.querySelectorAll('[data-admin-only]').forEach(element => element.hidden = Boolean(user && !user.isAdmin));

  document.getElementById('workspace-date').textContent = new Intl.DateTimeFormat(undefined, { weekday: 'short', day: '2-digit', month: 'short' }).format(new Date()).toUpperCase();

  const setActiveNav = (button, locationName) => {
    document.querySelectorAll('.site-nav button').forEach(item => item.classList.toggle('active', item === button));
    document.getElementById('workspace-location').textContent = locationName;
  };
  const navTargets = [
    ['nav-overview-btn', 'Overview', 'hero-section'], ['nav-history-btn', 'Scan history', 'history-section'],
    ['nav-report-btn', 'Reports', null], ['nav-cicd-btn', 'Integrations', null],
    ['nav-waf-btn', 'Hardening rules', null], ['nav-threat-btn', 'Threat library', 'ai-matrix-section'],
    ['nav-settings-btn', 'Settings', null]
  ];
  navTargets.forEach(([id, label, target]) => document.getElementById(id)?.addEventListener('click', event => {
    setActiveNav(event.currentTarget, label);
    if (target) document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    document.querySelector('.site-header')?.classList.remove('mobile-open');
  }));

  const focusAudit = () => {
    document.getElementById('hero-section')?.scrollIntoView({ behavior: 'smooth' });
    setTimeout(() => document.getElementById('target-url')?.focus(), 350);
  };
  document.getElementById('new-audit-btn')?.addEventListener('click', focusAudit);
  document.querySelectorAll('.guide-steps details').forEach(detail => detail.addEventListener('toggle', () => {
    if (detail.open) document.querySelectorAll('.guide-steps details').forEach(other => { if (other !== detail) other.open = false; });
  }));

  const updateScope = () => {
    const count = document.querySelectorAll('.module-check.checked').length;
    const page = document.getElementById('max-pages')?.selectedOptions[0]?.textContent.split('—')[0].trim() || 'Standard';
    const mode = document.getElementById('safety-mode')?.selectedOptions[0]?.textContent.split(' ')[0] || 'Safe-active';
    document.getElementById('scan-scope-summary').textContent = `${count} module${count === 1 ? '' : 's'} · ${page} · ${mode}`;
  };
  document.getElementById('module-checks')?.addEventListener('click', () => setTimeout(updateScope));
  document.getElementById('max-pages')?.addEventListener('change', updateScope);
  document.getElementById('safety-mode')?.addEventListener('change', updateScope);
  updateScope();

  const commands = [
    { name: 'Start a new audit', hint: 'N', run: focusAudit },
    { name: 'Open scan history', hint: 'Workspace', run: () => document.getElementById('nav-history-btn')?.click() },
    { name: 'Open latest report', hint: 'Report', run: () => document.getElementById('nav-report-btn')?.click() },
    { name: 'Review threat library', hint: 'Tool', run: () => document.getElementById('nav-threat-btn')?.click() },
    { name: 'Open integrations', hint: 'Tool', run: () => document.getElementById('nav-cicd-btn')?.click() }
  ];
  const commandInput = document.getElementById('command-input');
  const commandResults = document.getElementById('command-results');
  const renderCommands = () => {
    const query = commandInput.value.trim().toLowerCase();
    const matches = commands.filter(command => command.name.toLowerCase().includes(query));
    commandResults.replaceChildren(...matches.map((command, index) => {
      const button = document.createElement('button'); button.type = 'button'; button.className = `command-item${index === 0 ? ' active' : ''}`;
      button.innerHTML = `<span>${command.name}</span><small>${command.hint}</small>`;
      button.addEventListener('click', () => { commandDialog.close(); command.run(); }); return button;
    }));
  };
  const openCommands = () => { renderCommands(); commandDialog.showModal(); setTimeout(() => commandInput.focus()); };
  document.getElementById('command-open')?.addEventListener('click', openCommands);
  commandInput?.addEventListener('input', renderCommands);
  commandInput?.addEventListener('keydown', event => {
    const items = [...commandResults.querySelectorAll('.command-item')]; let active = Math.max(0, items.findIndex(item => item.classList.contains('active')));
    if (items.length && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) { event.preventDefault(); items[active]?.classList.remove('active'); active = (active + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length; items[active]?.classList.add('active'); }
    if (event.key === 'Enter') { event.preventDefault(); items[active]?.click(); }
  });
  document.addEventListener('keydown', event => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openCommands(); }
    if (!event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'n' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)) focusAudit();
    if (event.key === 'Escape') { if (commandDialog.open) commandDialog.close(); if (accountDialog.open) accountDialog.close(); }
  });
  document.querySelectorAll('[data-close-dialog]').forEach(button => button.addEventListener('click', () => button.closest('dialog')?.close()));

  document.getElementById('account-button')?.addEventListener('click', () => {
    document.getElementById('account-dialog-title').textContent = user ? user.name : 'Make it yours.';
    document.getElementById('account-dialog-copy').textContent = user ? `Signed in as ${user.email}. Your audit history is private to this account.` : 'Google sign-in is optional in this local workspace.';
    const primary = document.getElementById('account-primary'); primary.textContent = user ? 'Sign out' : 'Continue with Google'; primary.hidden = !user && !session.enabled;
    document.getElementById('account-dialog-note').textContent = user?.isAdmin ? 'Workspace administrator' : user ? 'Workspace member' : 'Local mode';
    accountDialog.showModal();
  });
  document.getElementById('account-primary')?.addEventListener('click', async () => {
    if (!user) { location.href = '/auth/google'; return; }
    const response = await fetch('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' });
    if (response.ok) location.reload();
  });
  document.getElementById('mobile-nav-toggle')?.addEventListener('click', event => {
    const rail = document.querySelector('.site-header'); const open = rail.classList.toggle('mobile-open'); event.currentTarget.setAttribute('aria-expanded', String(open));
  });
});
