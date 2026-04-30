/** Returns true if `x` is a plain, non-null, non-array object. */
export function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
