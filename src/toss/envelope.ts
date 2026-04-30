export type ParsedEnvelope<T> =
  | { ok: true; value: T }
  | { ok: false; reason: string; description?: string };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function parseTossEnvelope<T>(raw: unknown): ParsedEnvelope<T> {
  if (!isObject(raw)) throw new Error('toss response is not an object');
  if (raw.resultType === 'SUCCESS') {
    if (!isObject(raw.success)) throw new Error('SUCCESS envelope missing `success` body');
    return { ok: true, value: raw.success as T };
  }
  if (raw.resultType === 'FAIL') {
    if (!isObject(raw.error)) throw new Error('FAIL envelope missing `error` body');
    const reason = typeof raw.error.reason === 'string' ? raw.error.reason : 'unknown';
    const description =
      typeof raw.error.description === 'string' ? raw.error.description : undefined;
    return { ok: false, reason, description };
  }
  throw new Error(`unknown resultType ${String(raw.resultType)}`);
}
