export interface ApiClient {
  request<T>(method: string, path: string, body?: unknown): Promise<T>;
}

export interface ApiClientOptions {
  baseUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  return {
    async request(method, path, body) {
      const init: RequestInit = {
        method,
        headers: {
          authorization: `Bearer ${opts.token}`,
          'content-type': 'application/json',
        },
      };
      if (body !== undefined) init.body = JSON.stringify(body);
      const res = await fetchImpl(`${opts.baseUrl.replace(/\/$/, '')}${path}`, init);
      if (!res.ok && res.status !== 204) {
        const text = await res.text().catch(() => '');
        throw new Error(`api ${method} ${path} → ${res.status}: ${text}`);
      }
      if (res.status === 204) return undefined as never;
      return (await res.json()) as never;
    },
  };
}
