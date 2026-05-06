import { type DbProbeOpts, runDbProbe } from '../../cli/commands/doctor-probes/db-probe.js';
import { type JwksProbeOpts, runJwksProbe } from '../../cli/commands/doctor-probes/jwks-probe.js';
import {
  type MasterKeyProbeOpts,
  runMasterKeyProbe,
} from '../../cli/commands/doctor-probes/master-key-probe.js';
import type { ProbeItem } from '../../cli/output.js';
import { getLastHealthz } from './last-healthz.js';

export interface StatusProbeOpts {
  db: DbProbeOpts;
  masterKey: MasterKeyProbeOpts;
  jwks: JwksProbeOpts;
}

const HEALTHZ_STALE_MS = 5 * 60_000;

export async function runStatusProbes(opts: StatusProbeOpts): Promise<ProbeItem[]> {
  const [db, masterKey, jwks] = await Promise.all([
    runDbProbe(opts.db),
    runMasterKeyProbe(opts.masterKey),
    runJwksProbe(opts.jwks),
  ]);
  return [db, masterKey, jwks, probeLastHealthz()];
}

function probeLastHealthz(): ProbeItem {
  const last = getLastHealthz();
  if (!last) {
    return { name: 'last-healthz', state: 'yellow', detail: 'never received a /healthz hit' };
  }
  const ageMs = Date.now() - last.getTime();
  if (ageMs > HEALTHZ_STALE_MS) {
    return {
      name: 'last-healthz',
      state: 'red',
      detail: `stale: ${Math.round(ageMs / 1000)}s ago`,
    };
  }
  return { name: 'last-healthz', state: 'green', detail: `ok: ${Math.round(ageMs / 1000)}s ago` };
}
