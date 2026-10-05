/**
 * Google's attestation revocation list (developer.android.com, "Certificate revocation status
 * list"), fetched in the background and kept in memory.
 *
 * Registration fails closed: when no list has been fetched successfully in the last 24 hours, no
 * phone can register (SPEC.md §5.2 step 5). A failed refresh keeps the previous list until then,
 * so a short outage at Google or on our side doesn't stop registrations.
 */

/** Statuses that make a certificate unacceptable. Google's verifier refuses only REVOKED; a key
 * Google suspended for a "software flaw" isn't one to start trusting either. */
const REFUSED_STATUSES = new Set(['REVOKED', 'SUSPENDED']);
/** The published list is about 180 KB; anything past this is not the list. */
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

export interface RevocationListOptions {
  readonly url: string;
  /** How old the last good list may get before registration stops. */
  readonly maxAgeMillis?: number;
  /** How often to refresh. The list is served with `max-age=86400`; hourly keeps it well inside that. */
  readonly refreshMillis?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly onError?: (error: unknown) => void;
}

export class RevocationList {
  private serials = new Set<string>();
  private fetchedAt: number | null = null;
  private timer: NodeJS.Timeout | null = null;
  private readonly options: Required<Omit<RevocationListOptions, 'onError'>> & Pick<RevocationListOptions, 'onError'>;

  constructor(options: RevocationListOptions) {
    this.options = {
      maxAgeMillis: 24 * 60 * 60 * 1000,
      refreshMillis: 60 * 60 * 1000,
      fetch: globalThis.fetch,
      now: Date.now,
      ...options,
    };
  }

  /** Fetches the list once, replacing the current one only if the whole response is valid. */
  async refresh(): Promise<void> {
    const response = await this.options.fetch(this.options.url, {
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
      headers: { accept: 'application/json' },
    });
    if (!response.ok) throw new Error(`revocation list: HTTP ${response.status}`);
    const length = Number(response.headers.get('content-length') ?? '0');
    if (length > MAX_RESPONSE_BYTES) throw new Error('revocation list: response too large');
    const body = await response.text();
    if (body.length > MAX_RESPONSE_BYTES) throw new Error('revocation list: response too large');
    this.serials = parseStatusList(body);
    this.fetchedAt = this.options.now();
  }

  /** Refreshes now and then periodically, reporting failures without throwing. */
  start(): void {
    const tick = (): void => {
      this.refresh().catch((error: unknown) => this.options.onError?.(error));
    };
    tick();
    this.timer = setInterval(tick, this.options.refreshMillis);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
  }

  /** True when the list is recent enough to register phones against. */
  isFresh(): boolean {
    return this.fetchedAt !== null && this.options.now() - this.fetchedAt <= this.options.maxAgeMillis;
  }

  /**
   * True when a certificate serial number is listed.
   *
   * @param serialHex the serial as hex, in any case and with or without leading zeros.
   */
  isRevoked(serialHex: string): boolean {
    const hex = serialHex.toLowerCase().replace(/^0+(?=.)/, '');
    if (this.serials.has(hex)) return true;
    // More than half of the published entries are decimal, not the documented hex.
    return /^[0-9a-f]+$/.test(hex) && this.serials.has(BigInt(`0x${hex}`).toString(10));
  }
}

/**
 * Parses the status list. Every entry must have the documented shape; one that doesn't makes the
 * whole response unusable rather than silently shorter.
 */
export function parseStatusList(body: string): Set<string> {
  const parsed: unknown = JSON.parse(body);
  if (parsed === null || typeof parsed !== 'object' || !('entries' in parsed)) throw new Error('revocation list: no entries');
  const entries = (parsed as { entries: unknown }).entries;
  if (entries === null || typeof entries !== 'object' || Array.isArray(entries)) throw new Error('revocation list: bad entries');
  const serials = new Set<string>();
  for (const [serial, entry] of Object.entries(entries)) {
    if (!/^[0-9a-f]{1,64}$/.test(serial)) throw new Error('revocation list: bad serial');
    const status = (entry as { status?: unknown } | null)?.status;
    if (typeof status !== 'string') throw new Error('revocation list: entry without a status');
    if (REFUSED_STATUSES.has(status)) serials.add(serial);
  }
  return serials;
}
