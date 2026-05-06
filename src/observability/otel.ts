export type OtelStartResult =
  | { kind: 'disabled' }
  | { kind: 'missing'; reason: string }
  | { kind: 'started' };

export async function maybeStartOtel(): Promise<OtelStartResult> {
  if (process.env.OTEL_ENABLED !== '1') {
    return { kind: 'disabled' };
  }
  try {
    const sdkMod = (await import('@opentelemetry/sdk-node' as string)) as {
      NodeSDK: new (cfg: {
        instrumentations: unknown[];
      }) => {
        start(): Promise<void> | void;
        shutdown(): Promise<void>;
      };
    };
    const autoMod = (await import('@opentelemetry/auto-instrumentations-node' as string)) as {
      getNodeAutoInstrumentations: () => unknown;
    };
    const sdk = new sdkMod.NodeSDK({
      instrumentations: [autoMod.getNodeAutoInstrumentations()],
    });
    await sdk.start();
    for (const sig of ['SIGTERM', 'SIGINT'] as const) {
      process.once(sig, () => {
        sdk.shutdown().catch(() => {});
      });
    }
    return { kind: 'started' };
  } catch (err) {
    return { kind: 'missing', reason: (err as Error).message };
  }
}
