const state = {
  csrf: '',
  permissions: [],
  timer: null,
  capability: '',
  previewGrant: '',
  refreshing: false,
  sessionExpiresAt: null,
};
const $ = (selector) => document.querySelector(selector);

class PortalRequestError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

const formatBytes = (bytes) => {
  if (!Number.isFinite(bytes)) return 'Unavailable';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
};
const formatDuration = (seconds) => {
  if (!Number.isFinite(seconds)) return 'Not running';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
};
const formatRate = (bytesPerSecond) => Number.isFinite(bytesPerSecond)
  ? `${formatBytes(bytesPerSecond)}/s`
  : 'Calculating…';
const setMessage = (message, kind = 'status') => {
  const node = $('#message');
  node.textContent = message;
  node.dataset.kind = kind;
};
const setAuthMessage = (message) => { $('#auth-message').textContent = message; };

function showAuth(message, showPasscode = false) {
  $('#loading').hidden = true;
  $('#dashboard').hidden = true;
  $('#auth').hidden = false;
  $('#passcode-wrap').hidden = !showPasscode;
  setAuthMessage(message);
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: 'same-origin',
    signal: options.signal ?? AbortSignal.timeout(15_000),
    headers: { 'content-type': 'application/json', ...(options.headers ?? {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new PortalRequestError(body.error || 'Request failed', response.status);
  return body;
}

function renderBranding(data) {
  const branding = data.branding && typeof data.branding === 'object' ? data.branding : {};
  const brandName = typeof branding.name === 'string' && branding.name.trim()
    ? branding.name.trim()
    : data.clientLabel;
  const primaryColor = typeof branding.primaryColor === 'string' && /^#[0-9A-Fa-f]{6}$/.test(branding.primaryColor)
    ? branding.primaryColor
    : '#2563EB';
  document.documentElement?.style?.setProperty?.('--accent', primaryColor);
  $('#brand-name').textContent = brandName.toUpperCase();
  $('#footer-brand').textContent = `${brandName} client portal`;
  document.title = `${data.clientLabel} · ${brandName}`;

  const logo = $('#brand-logo');
  const logoDataUrl = typeof branding.logoDataUrl === 'string' ? branding.logoDataUrl : '';
  if (/^data:image\/(?:png|jpeg|webp);base64,/.test(logoDataUrl)) {
    logo.src = logoDataUrl;
    logo.alt = `${brandName} logo`;
    logo.hidden = false;
    $('#brand-fallback').hidden = true;
  } else {
    logo.removeAttribute('src');
    logo.alt = '';
    logo.hidden = true;
    $('#brand-fallback').hidden = false;
  }
}

function render(data) {
  $('#loading').hidden = true;
  $('#auth').hidden = true;
  $('#dashboard').hidden = false;
  renderBranding(data);
  $('#client-label').textContent = data.clientLabel;
  $('#health').textContent = data.snapshot.health;
  $('#health').dataset.state = data.snapshot.health;
  $('#health-indicator').dataset.state = data.snapshot.health;
  $('#containers').textContent = `${data.snapshot.running} of ${data.snapshot.total} components running`;
  $('#uptime').textContent = formatDuration(data.snapshot.uptimeSeconds);
  $('#cpu').textContent = `${data.metrics.cpuPercent.toFixed(1)}%`;
  $('#memory').textContent = `${formatBytes(data.metrics.memoryBytes)} / ${formatBytes(data.metrics.memoryLimit)}`;
  $('#network-rate').textContent = `↓ ${formatRate(data.metrics.rxBytesPerSecond)}  ↑ ${formatRate(data.metrics.txBytesPerSecond)}`;
  $('#network-total').textContent = `Total received ${formatBytes(data.metrics.rxBytes)} · sent ${formatBytes(data.metrics.txBytes)}`;
  $('#storage').textContent = formatBytes(data.metrics.storageBytes);
  $('#storage-io').textContent = `Block read ${formatBytes(data.metrics.blockReadBytes)} · write ${formatBytes(data.metrics.blockWriteBytes)}. Named-volume capacity is not included.`;
  $('#backup-status').textContent = data.backup?.status === 'owner_managed' ? 'Owner-managed' : 'Unavailable';
  $('#backup-reason').textContent = data.backup?.reason || 'Backup status is controlled by the application owner.';
  const lastSuccessfulAt = data.source?.lastSuccessfulAt ?? data.snapshot.updatedAt;
  $('#updated').textContent = `Updated ${new Date(lastSuccessfulAt).toLocaleTimeString()}`;
  const sessionExpiry = Number(state.sessionExpiresAt ?? data.expiresAt);
  $('#session-expiry').textContent = Number.isFinite(sessionExpiry)
    ? `Access remembered until ${new Date(sessionExpiry).toLocaleDateString()}`
    : '';
  $('#services').replaceChildren(...data.snapshot.services.map((service) => {
    const row = document.createElement('li');
    const name = document.createElement('span');
    const status = document.createElement('span');
    name.textContent = service.name;
    status.textContent = service.state;
    status.className = 'pill';
    status.dataset.state = service.state;
    row.append(name, status);
    return row;
  }));
  $('#http-metrics-reason').textContent = data.httpMetrics?.reason
    || 'HTTP request metrics are unavailable. Resource metrics continue to update.';

  const history = Array.isArray(data.history) ? data.history : [];
  const chartPoints = (selector) => history.map((point, index) => {
    const x = history.length <= 1 ? 0 : (index / (history.length - 1)) * 600;
    const value = selector(point);
    return `${x.toFixed(1)},${(180 - Math.max(0, Math.min(100, value)) * 1.8).toFixed(1)}`;
  }).join(' ');
  $('#cpu-line').setAttribute('points', chartPoints((point) => point.cpuPercent));
  $('#memory-line').setAttribute('points', chartPoints((point) => point.memoryLimit > 0 ? point.memoryBytes / point.memoryLimit * 100 : 0));
  $('#history-rows').replaceChildren(...history.slice(-10).reverse().map((point) => {
    const row = document.createElement('tr');
    const network = Number.isFinite(point.rxBytesPerSecond) && Number.isFinite(point.txBytesPerSecond)
      ? `↓ ${formatRate(point.rxBytesPerSecond)} ↑ ${formatRate(point.txBytesPerSecond)}`
      : '—';
    const values = [
      new Date(point.at).toLocaleTimeString(),
      `${point.cpuPercent.toFixed(1)}%`,
      point.memoryLimit > 0 ? `${(point.memoryBytes / point.memoryLimit * 100).toFixed(1)}%` : '—',
      network,
      formatBytes(point.storageBytes),
      `${point.running}/${point.total}`,
    ];
    for (const value of values) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    return row;
  }));

  state.permissions = data.permissions;
  $('#start').hidden = !data.permissions.includes('start');
  $('#restart').hidden = !data.permissions.includes('restart');
  $('#suspend').hidden = !data.permissions.includes('suspend');
  $('#actions-card').hidden = !data.permissions.some((permission) => ['start', 'restart', 'suspend'].includes(permission));
  $('#start').disabled = data.snapshot.running === data.snapshot.total;
  $('#restart').disabled = data.snapshot.running === 0;
  $('#suspend').disabled = data.snapshot.running === 0;
  $('#logs-card').hidden = !data.permissions.includes('view_logs');
  setMessage(
    data.source?.stale ? 'Status is stale — the last successful sample is shown' : 'Live status',
    data.source?.stale ? 'warning' : 'success'
  );
}

async function refresh() {
  if (state.refreshing) return false;
  state.refreshing = true;
  $('#refresh').disabled = true;
  $('#refresh').setAttribute('aria-busy', 'true');
  try {
    render(await request('/api/dashboard'));
    return true;
  } catch (error) {
    if (error instanceof PortalRequestError && error.status === 401) {
      if (state.timer) window.clearInterval(state.timer);
      showAuth('Your saved access is no longer active. Reopen the private link from the application owner.');
    } else {
      setMessage(error.message, 'error');
    }
    return false;
  } finally {
    state.refreshing = false;
    $('#refresh').disabled = false;
    $('#refresh').removeAttribute('aria-busy');
  }
}

function startRefreshTimer() {
  if (state.timer) window.clearInterval(state.timer);
  state.timer = window.setInterval(refresh, 30_000);
}

async function activateSession(result) {
  state.csrf = result.csrf;
  state.sessionExpiresAt = result.expiresAt;
  const refreshed = await refresh();
  if (refreshed) startRefreshTimer();
  return refreshed;
}

async function resumeSession() {
  try {
    const result = await request('/api/session/restore', { method: 'POST', body: '{}' });
    return activateSession(result);
  } catch {
    return false;
  }
}

async function attemptExchange(passcode = '') {
  if (!state.capability && !state.previewGrant) return false;
  const previewing = Boolean(state.previewGrant);
  try {
    const result = previewing
      ? await request('/api/session/preview', { method: 'POST', body: JSON.stringify({ grant: state.previewGrant }) })
      : await request('/api/session/exchange', { method: 'POST', body: JSON.stringify({ capability: state.capability, passcode }) });
    state.capability = '';
    state.previewGrant = '';
    return activateSession(result);
  } catch {
    $('#loading').hidden = true;
    if (previewing) {
      state.previewGrant = '';
      showAuth('This preview is invalid or unavailable.');
    } else {
      showAuth('This link is invalid or unavailable. Enter the passcode if one was provided.', true);
    }
    return false;
  }
}

async function exchange() {
  const rawFragment = location.hash.slice(1);
  const params = new URLSearchParams(rawFragment);
  state.capability = params.get('token') || (rawFragment.startsWith('scp_') ? rawFragment : '');
  state.previewGrant = params.get('preview') || '';
  history.replaceState(null, '', `${location.pathname}${location.search}`);

  if (state.capability || state.previewGrant) {
    await attemptExchange();
    return;
  }
  if (await resumeSession()) return;
  showAuth('No active access was found on this browser. Open the private link shared by the application owner.');
}

$('#refresh').addEventListener('click', refresh);

async function performAction(action, confirmation, pendingMessage, successMessage) {
  if (!window.confirm(confirmation)) return;
  const buttons = [$('#start'), $('#restart'), $('#suspend')];
  const actionButton = $(`#${action}`);
  const originalLabel = actionButton.textContent;
  buttons.forEach((item) => { item.disabled = true; });
  actionButton.textContent = pendingMessage.replace('…', '');
  actionButton.setAttribute('aria-busy', 'true');
  let statusRefreshed = false;
  try {
    setMessage(pendingMessage);
    const result = await request(`/api/${action}`, {
      method: 'POST',
      body: '{}',
      headers: { 'x-csrf-token': state.csrf, 'x-idempotency-key': crypto.randomUUID() },
    });
    const refreshed = await refresh();
    statusRefreshed = refreshed;
    const failures = Array.isArray(result.outcomes)
      ? result.outcomes.filter((outcome) => !outcome.success).length
      : 0;
    setMessage(
      failures > 0
        ? `${action} completed with ${failures} component failure${failures === 1 ? '' : 's'}. Contact the application owner.`
        : refreshed
          ? successMessage
          : 'The action completed, but current status could not be refreshed. Wait a moment, then use Refresh.',
      failures > 0 ? 'error' : refreshed ? 'success' : 'warning'
    );
  } catch (error) {
    setMessage(error.message, 'error');
  } finally {
    actionButton.textContent = originalLabel;
    actionButton.removeAttribute('aria-busy');
    if (!statusRefreshed && !state.refreshing) buttons.forEach((item) => { item.disabled = false; });
  }
}

$('#start').addEventListener('click', () => performAction('start', 'Start this application now?', 'Starting application…', 'Application started successfully.'));
$('#restart').addEventListener('click', () => performAction('restart', 'Restart this application now? Clients may see a brief interruption.', 'Restarting application…', 'Application restarted successfully.'));
$('#suspend').addEventListener('click', () => performAction('suspend', 'Suspend this application now? It will remain unavailable until it is started again.', 'Suspending application…', 'Application suspended successfully.'));
$('#show-logs').addEventListener('click', async () => {
  const output = $('#logs');
  output.textContent = 'Loading…';
  try { output.textContent = (await request('/api/logs')).logs || 'No recent logs.'; }
  catch (error) { output.textContent = error.message; }
});
$('#passcode-submit').addEventListener('click', () => attemptExchange($('#passcode').value));
$('#passcode').addEventListener('keydown', (event) => { if (event.key === 'Enter') attemptExchange(event.currentTarget.value); });
$('#sign-out').addEventListener('click', async () => {
  try { await request('/api/session/logout', { method: 'POST', body: '{}' }); } catch { /* local UI still forgets the session */ }
  if (state.timer) window.clearInterval(state.timer);
  state.csrf = '';
  state.sessionExpiresAt = null;
  showAuth('This browser has been forgotten. Reopen the private link to connect again.');
});

exchange();
