/** A check could not observe what it needs (no snapshot, tool missing, advisory source down, unsupported distro). Reported as unverifiable. */
export class ObservationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ObservationError';
  }
}
