export interface RestOpts {
  bridge: string;
  adminToken: string;
}

async function call<T>(opts: RestOpts, path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${opts.bridge}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${opts.adminToken}`,
      ...((init.headers as Record<string, string>) ?? {}),
    },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status}: ${text}`);
  return text ? (JSON.parse(text) as T) : (undefined as unknown as T);
}

export const rest = {
  createTenant: (o: RestOpts, body: unknown) =>
    call(o, '/admin/tenants', { method: 'POST', body: JSON.stringify(body) }),
  listTenants: (o: RestOpts) => call<{ tenants: unknown[] }>(o, '/admin/tenants'),
  getTenant: (o: RestOpts, id: string) => call(o, `/admin/tenants/${id}`),
  rotateSecret: (o: RestOpts, id: string) =>
    call(o, `/admin/tenants/${id}/secrets/rotate`, { method: 'POST' }),
  deleteTenant: (o: RestOpts, id: string) => call(o, `/admin/tenants/${id}`, { method: 'DELETE' }),
};
