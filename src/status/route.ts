import { Hono } from 'hono';
import type { ProbeItem, ProbeState } from '../../cli/output.js';

export interface StatusRouteOpts {
  version: string;
  buildSha: string;
  probes: () => Promise<ProbeItem[]>;
}

const RANK: Record<ProbeState, number> = { green: 0, yellow: 1, red: 2 };
const COLOR: Record<ProbeState, string> = {
  green: '#1a7f37',
  yellow: '#bf8700',
  red: '#cf222e',
};

function worstOf(items: ProbeItem[]): ProbeState {
  let s: ProbeState = 'green';
  for (const i of items) if (RANK[i.state] > RANK[s]) s = i.state;
  return s;
}

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}

function renderHtml(opts: {
  version: string;
  buildSha: string;
  status: ProbeState;
  items: ProbeItem[];
}): string {
  const rows = opts.items
    .map(
      (i) => `
    <tr>
      <td>${escapeHtml(i.name)}</td>
      <td><span style="color:${COLOR[i.state]};font-weight:600">${i.state}</span></td>
      <td>${escapeHtml(i.detail)}</td>
    </tr>`,
    )
    .join('');
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>oidc-bridge status</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 720px; margin: 2em auto; }
  h1 { color: ${COLOR[opts.status]}; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 0.4em 0.8em; border-bottom: 1px solid #ddd; text-align: left; }
  code { background: #f6f8fa; padding: 0.1em 0.3em; border-radius: 3px; }
</style></head>
<body>
  <h1>oidc-bridge: ${opts.status}</h1>
  <p>version <code>${escapeHtml(opts.version)}</code> · build <code>${escapeHtml(opts.buildSha)}</code></p>
  <table>
    <thead><tr><th>probe</th><th>state</th><th>detail</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p style="color:#666;font-size:0.9em">Refreshed ${new Date().toISOString()}.</p>
</body>
</html>`;
}

export function mountStatusRoute(opts: StatusRouteOpts): Hono {
  const app = new Hono();
  app.get('/status', async (c) => {
    const items = await opts.probes();
    const status = worstOf(items);
    c.header('cache-control', 'no-store');
    const wantsJson =
      c.req.query('format') === 'json' ||
      (c.req.header('accept') ?? '').includes('application/json');
    if (wantsJson) {
      return c.json({ status, version: opts.version, build_sha: opts.buildSha, items });
    }
    c.header('content-type', 'text/html; charset=utf-8');
    return c.body(renderHtml({ version: opts.version, buildSha: opts.buildSha, status, items }));
  });
  return app;
}
