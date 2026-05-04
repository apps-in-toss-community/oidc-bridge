export type ProbeState = 'green' | 'yellow' | 'red';

export interface ProbeItem {
  name: string;
  state: ProbeState;
  detail: string;
}

export interface ProbeReport {
  status: ProbeState;
  items: ProbeItem[];
}

export interface ReporterOpts {
  stdout: NodeJS.WriteStream;
  forceJson?: boolean;
}

export interface Reporter {
  report(rep: ProbeReport): void;
}

const COLOR: Record<ProbeState, string> = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
};
const RESET = '\x1b[0m';

export function createReporter(opts: ReporterOpts): Reporter {
  const useJson = opts.forceJson === true || !opts.stdout.isTTY;
  return {
    report(rep) {
      if (useJson) {
        opts.stdout.write(`${JSON.stringify(rep)}\n`);
        return;
      }
      const w = (s: string) => opts.stdout.write(s);
      const nameWidth = Math.max(4, ...rep.items.map((i) => i.name.length));
      w(`Overall: ${COLOR[rep.status]}${rep.status}${RESET}\n`);
      for (const item of rep.items) {
        w(
          `  ${item.name.padEnd(nameWidth)}  ${COLOR[item.state]}${item.state.padEnd(6)}${RESET}  ${item.detail}\n`,
        );
      }
    },
  };
}
