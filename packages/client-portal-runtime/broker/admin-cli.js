import http from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';

const [command, requestPath, outputPath] = process.argv.slice(2);
const tokenPath = process.env.PORTAL_ADMIN_TOKEN_FILE ?? '/run/secrets/admin_token';
const token = readFileSync(tokenPath, 'utf8').trim();
const requestBody = requestPath ? readFileSync(requestPath) : Buffer.from('{}');
const linkId = process.env.PORTAL_LINK_ID ?? '';
const routes = {
  apply: { method: 'POST', path: '/admin/links/apply' },
  revoke: { method: 'POST', path: `/admin/links/${encodeURIComponent(linkId)}/revoke` },
  remove: { method: 'DELETE', path: `/admin/links/${encodeURIComponent(linkId)}` },
  activity: { method: 'GET', path: `/admin/links/${encodeURIComponent(linkId)}/activity` },
  preview: { method: 'POST', path: `/admin/links/${encodeURIComponent(linkId)}/preview` },
  health: { method: 'GET', path: '/admin/health' },
  actions: { method: 'POST', path: '/admin/actions' },
  acquire: { method: 'POST', path: '/admin/leases/acquire' },
  release: { method: 'POST', path: '/admin/leases/release' },
  backup: { method: 'POST', path: '/admin/backup' },
};
const route = routes[command];
if (!route) throw new Error('Unknown admin command');

const request = http.request({
  hostname: '127.0.0.1',
  port: Number(process.env.PORT ?? 4101),
  path: route.path,
  method: route.method,
  headers: {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
    'content-length': requestBody.length,
  },
}, (response) => {
  const chunks = [];
  response.on('data', (chunk) => chunks.push(chunk));
  response.on('end', () => {
    const output = Buffer.concat(chunks);
    if (outputPath) {
      writeFileSync(outputPath, output, { mode: 0o600 });
    } else {
      process.stdout.write(output);
    }
    process.exitCode = (response.statusCode ?? 500) >= 400 ? 1 : 0;
  });
});
request.on('error', (error) => { console.error(error.message); process.exitCode = 1; });
request.end(route.method === 'GET' ? undefined : requestBody);
