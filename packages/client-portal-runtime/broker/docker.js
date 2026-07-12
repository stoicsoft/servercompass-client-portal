import http from 'node:http';

const socketPath = process.env.DOCKER_SOCKET ?? '/var/run/docker.sock';
const MAX_DOCKER_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_DOCKER_LOG_BYTES = 4 * 1024 * 1024;

function dockerRequest(path, method = 'GET') {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path, method }, (response) => {
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_DOCKER_RESPONSE_BYTES) {
          response.destroy(new Error('Docker API response too large'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if ((response.statusCode ?? 500) >= 400) return reject(new Error(`Docker API ${response.statusCode}`));
        try {
          resolve(body ? JSON.parse(body) : null);
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on('error', reject);
    request.setTimeout(5000, () => request.destroy(new Error('Docker API timeout')));
    request.end();
  });
}

export function scopedContainers(containers, stackRef, expectedProjectName) {
  const matched = containers.filter(
    (container) =>
      container.Labels?.['servercompass.stack_id'] === stackRef &&
      String(container.Labels?.['com.docker.compose.oneoff'] ?? '').toLowerCase() !== 'true'
  );
  if (matched.length === 0) {
    throw new Error('No containers matched the authorized stack');
  }
  const hasScopeMismatch = matched.some(
    (container) =>
      container.Labels?.['com.docker.compose.project'] !== expectedProjectName
  );
  if (hasScopeMismatch) {
    throw new Error('Authorized stack labels do not match the expected Compose project');
  }
  return matched;
}

export function redactLogText(raw, knownSecrets = [], tail = 500) {
  let redacted = String(raw);
  for (const secret of [...knownSecrets].filter((value) => typeof value === 'string' && value.length >= 4 && value.length <= 16 * 1024).sort((left, right) => right.length - left.length)) {
    redacted = redacted.split(secret).join('[REDACTED]');
  }
  return redacted
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^@\s/]+@/gi, '$1[REDACTED]@')
    .replace(/\b(Bearer\s+|(?:token|password|secret|api[_-]?key)[=:]\s*)\S+/gi, '$1[REDACTED]')
    .split('\n')
    .slice(-Math.min(tail, 500))
    .map((line) => line.slice(0, 4096))
    .join('\n')
    .slice(0, 512 * 1024);
}

export function addCounterRates(points) {
  return points.map((point, index) => {
    const previous = points[index - 1];
    if (!previous) return { ...point, rxBytesPerSecond: null, txBytesPerSecond: null };
    const elapsedSeconds = (point.at - previous.at) / 1000;
    const rxDelta = point.rxBytes - previous.rxBytes;
    const txDelta = point.txBytes - previous.txBytes;
    return {
      ...point,
      rxBytesPerSecond: elapsedSeconds > 0 && rxDelta >= 0 ? rxDelta / elapsedSeconds : null,
      txBytesPerSecond: elapsedSeconds > 0 && txDelta >= 0 ? txDelta / elapsedSeconds : null,
    };
  });
}

export function orderedPowerContainers(containers, action) {
  const appFirst = action === 'stop';
  return [...containers].sort((left, right) => {
    const leftApp = left.Labels?.['servercompass.role'] === 'app' ? 1 : 0;
    const rightApp = right.Labels?.['servercompass.role'] === 'app' ? 1 : 0;
    return appFirst ? rightApp - leftApp : leftApp - rightApp;
  });
}

export async function getStackSnapshot(stackRef, expectedProjectName) {
  const containers = scopedContainers(
    await dockerRequest('/containers/json?all=1'),
    stackRef,
    expectedProjectName
  );
  const running = containers.filter((container) => container.State === 'running').length;
  const runningContainers = containers.filter((container) => container.State === 'running');
  const startedAtValues = await Promise.all(
    runningContainers.map(async (container) => {
      const inspect = await dockerRequest(`/containers/${encodeURIComponent(container.Id)}/json`);
      return Date.parse(inspect.State?.StartedAt ?? '');
    })
  );
  const fullyRunningSince = running === containers.length
    ? Math.max(...startedAtValues.filter(Number.isFinite))
    : Number.NaN;
  const health = containers.map((container) => container.Status).find((status) => status.includes('unhealthy'))
    ? 'unhealthy'
    : running === containers.length
      ? 'healthy'
      : running > 0
        ? 'degraded'
        : 'stopped';
  return {
    health,
    running,
    total: containers.length,
    uptimeSeconds: Number.isFinite(fullyRunningSince)
      ? Math.max(0, Math.floor((Date.now() - fullyRunningSince) / 1000))
      : null,
    services: containers.map((container, index) => ({
      // Never expose a Compose service or container name to the client portal.
      name: `Component ${index + 1}`,
      state: container.State,
      health: String(container.Status ?? '').includes('unhealthy')
        ? 'unhealthy'
        : container.State === 'running'
          ? 'healthy'
          : 'stopped',
    })),
    updatedAt: Date.now(),
  };
}

export async function getStackMetrics(stackRef, expectedProjectName) {
  const allContainers = scopedContainers(
    await dockerRequest('/containers/json?all=1&size=1'),
    stackRef,
    expectedProjectName
  );
  const containers = allContainers.filter((container) => container.State === 'running');
  const samples = await Promise.all(
    containers.map((container) =>
      dockerRequest(`/containers/${encodeURIComponent(container.Id)}/stats?stream=false`)
    )
  );
  let cpuPercent = 0;
  let memoryBytes = 0;
  let memoryLimit = 0;
  let rxBytes = 0;
  let txBytes = 0;
  let blockReadBytes = 0;
  let blockWriteBytes = 0;
  const storageBytes = allContainers.reduce(
    (total, container) => total + Math.max(0, Number(container.SizeRw ?? 0)),
    0
  );
  for (const stats of samples) {
    const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
    const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
    const cores = stats.cpu_stats.online_cpus || stats.cpu_stats.cpu_usage.percpu_usage?.length || 1;
    if (systemDelta > 0) cpuPercent += (cpuDelta / systemDelta) * cores * 100;
    memoryBytes += Math.max(0, stats.memory_stats.usage - (stats.memory_stats.stats?.cache ?? 0));
    memoryLimit += stats.memory_stats.limit ?? 0;
    for (const network of Object.values(stats.networks ?? {})) {
      rxBytes += network.rx_bytes ?? 0;
      txBytes += network.tx_bytes ?? 0;
    }
    for (const item of stats.blkio_stats?.io_service_bytes_recursive ?? []) {
      const operation = String(item.op ?? '').toLowerCase();
      if (operation === 'read') blockReadBytes += Number(item.value ?? 0);
      if (operation === 'write') blockWriteBytes += Number(item.value ?? 0);
    }
  }
  return {
    cpuPercent,
    memoryBytes,
    memoryLimit,
    rxBytes,
    txBytes,
    storageBytes,
    blockReadBytes,
    blockWriteBytes,
    updatedAt: Date.now(),
  };
}

export async function restartStack(stackRef, expectedProjectName) {
  const containers = scopedContainers(
    await dockerRequest('/containers/json?all=1'),
    stackRef,
    expectedProjectName
  );
  const outcomes = [];
  for (const container of containers) {
    try {
      await dockerRequest(`/containers/${encodeURIComponent(container.Id)}/restart?t=10`, 'POST');
      outcomes.push({ component: outcomes.length + 1, success: true });
    } catch {
      outcomes.push({ component: outcomes.length + 1, success: false });
    }
  }
  return outcomes;
}

async function changeStackPower(stackRef, expectedProjectName, action) {
  const containers = orderedPowerContainers(scopedContainers(
    await dockerRequest('/containers/json?all=1'),
    stackRef,
    expectedProjectName
  ), action);
  const outcomes = [];
  for (const container of containers) {
    const shouldChange = action === 'start'
      ? container.State !== 'running'
      : container.State === 'running';
    if (!shouldChange) {
      outcomes.push({ component: outcomes.length + 1, success: true, changed: false });
      continue;
    }
    try {
      const suffix = action === 'stop' ? '?t=10' : '';
      await dockerRequest(`/containers/${encodeURIComponent(container.Id)}/${action}${suffix}`, 'POST');
      outcomes.push({ component: outcomes.length + 1, success: true, changed: true });
    } catch {
      outcomes.push({ component: outcomes.length + 1, success: false, changed: false });
    }
  }
  return outcomes;
}

export async function startStack(stackRef, expectedProjectName) {
  return changeStackPower(stackRef, expectedProjectName, 'start');
}

export async function suspendStack(stackRef, expectedProjectName) {
  return changeStackPower(stackRef, expectedProjectName, 'stop');
}

export async function getStackLogs(stackRef, expectedProjectName, tail = 200) {
  const containers = scopedContainers(
    await dockerRequest('/containers/json?all=1'),
    stackRef,
    expectedProjectName
  ).filter(
    (container) => container.Labels?.['servercompass.role'] === 'app'
  );
  const lines = [];
  for (const container of containers) {
    const inspect = await dockerRequest(`/containers/${encodeURIComponent(container.Id)}/json`);
    const knownSecrets = (inspect.Config?.Env ?? [])
      .map((entry) => {
        const separator = entry.indexOf('=');
        return separator >= 0 ? entry.slice(separator + 1) : '';
      })
      // Exact-match every non-trivial environment value. Restricting this to
      // secret-looking variable names misses credentials embedded in values
      // such as DATABASE_URL.
      .filter((value) => value.length >= 4 && value.length <= 16 * 1024)
      .sort((left, right) => right.length - left.length);
    const rawBuffer = await new Promise((resolve, reject) => {
      const request = http.request(
        { socketPath, path: `/containers/${encodeURIComponent(container.Id)}/logs?stdout=1&stderr=1&tail=${tail}`, method: 'GET' },
        (response) => {
          const chunks = [];
          let total = 0;
          if ((response.statusCode ?? 500) >= 400) {
            response.resume();
            reject(new Error(`Docker API ${response.statusCode}`));
            return;
          }
          response.on('data', (chunk) => {
            total += chunk.length;
            if (total > MAX_DOCKER_LOG_BYTES) {
              response.destroy(new Error('Docker log response too large'));
              return;
            }
            chunks.push(chunk);
          });
          response.on('error', reject);
          response.on('end', () => resolve(Buffer.concat(chunks)));
        }
      );
      request.on('error', reject);
      request.setTimeout(5000, () => request.destroy(new Error('Docker API timeout')));
      request.end();
    });
    const chunks = [];
    let offset = 0;
    while (offset + 8 <= rawBuffer.length && (rawBuffer[offset] === 1 || rawBuffer[offset] === 2)) {
      const length = rawBuffer.readUInt32BE(offset + 4);
      if (offset + 8 + length > rawBuffer.length) throw new Error('Malformed Docker log frame');
      chunks.push(rawBuffer.subarray(offset + 8, offset + 8 + length));
      offset += 8 + length;
    }
    lines.push(redactLogText((chunks.length > 0 ? Buffer.concat(chunks) : rawBuffer).toString('utf8'), knownSecrets, tail));
  }
  return redactLogText(lines.join('\n'), [], 500);
}
