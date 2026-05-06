export type DoctorState = 'green' | 'yellow' | 'red';

export function extractDoctorState(input: string): DoctorState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    throw new Error(`failed to parse doctor JSON: ${(e as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('doctor output is not an object');
  }
  const status = (parsed as { status?: unknown }).status;
  if (typeof status !== 'string') {
    throw new Error('doctor output is missing "status" field');
  }
  if (status !== 'green' && status !== 'yellow' && status !== 'red') {
    throw new Error(`unknown doctor status value: ${status}`);
  }
  return status;
}
