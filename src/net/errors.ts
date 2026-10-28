/** A network-level failure (DNS, connect, timeout, TLS). The check runner turns these into "unverifiable". */
export class NetError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'NetError';
  }
}

export function toNetError(e: unknown, fallbackCode = 'NET_ERROR'): NetError {
  if (e instanceof NetError) return e;
  const err = e as NodeJS.ErrnoException | undefined;
  return new NetError(err?.code ?? fallbackCode, err?.message ?? String(e));
}
