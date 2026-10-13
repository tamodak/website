/**
 * The two paged message kinds, APP_LIST and MOVE_STATE (SPEC.md §11.10, §11.14): packing a long
 * list into pages that each fit one envelope, and putting the pages back together with the rules
 * that span more than one page.
 *
 * A decoder sees one page at a time, so it can only check what a single page says. Whether the
 * pages agree with each other, whether one is missing, and whether a package turns up on two of
 * them is decided here, once every page has arrived.
 *
 * End-to-end code: the server never imports it.
 */
import { equalBytes, toHex } from './bytes.ts';
import { MAX_BODY_BYTES } from './envelope.ts';
import { fingerprint, verifyBundle } from './identity.ts';
import {
  Kind,
  MAX_LISTED_APPS,
  MAX_MOVED_APPS,
  MAX_MOVED_PAIRINGS,
  Role,
  encodeBody,
  type AppList,
  type ListedApp,
  type MoveState,
  type MovedApp,
  type MovedPairing,
} from './messages.ts';

/** Where putting the pages together stands. */
export type Assembly<T> =
  | { readonly state: 'complete'; readonly value: T }
  | { readonly state: 'incomplete'; readonly missing: number }
  | { readonly state: 'invalid'; readonly error: string };

/** Fills pages in order, each with as many items as fit (SPEC.md §11.10). */
function pack<T>(items: readonly T[], emptyPageBytes: number, itemBytes: (item: T) => number): T[][] {
  const pages: T[][] = [];
  let page: T[] = [];
  let size = emptyPageBytes;
  for (const item of items) {
    const bytes = itemBytes(item);
    if (emptyPageBytes + bytes > MAX_BODY_BYTES) throw new RangeError('an item is too large for a page');
    if (size + bytes > MAX_BODY_BYTES) {
      pages.push(page);
      page = [];
      size = emptyPageBytes;
    }
    page.push(item);
    size += bytes;
  }
  pages.push(page);
  return pages;
}

const NO_ID = new Uint8Array(16);

/**
 * Splits an app list into APP_LIST pages: sorted by package name, cut at 1000 apps.
 *
 * @throws RangeError when the list would need more than 255 pages, which 1000 apps never do.
 */
export function pageAppList(listId: Uint8Array, apps: readonly ListedApp[]): AppList[] {
  const sorted = [...apps].sort((a, b) => (a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0)).slice(0, MAX_LISTED_APPS);
  const empty = encodeBody({ kind: Kind.APP_LIST, listId: NO_ID, page: 0, pageCount: 1, apps: [] }).length;
  const groups = pack(sorted, empty, (app) => encodeBody({ kind: Kind.APP_LIST, listId: NO_ID, page: 0, pageCount: 1, apps: [app] }).length - empty);
  if (groups.length > 255) throw new RangeError('too many pages');
  return groups.map((group, page) => ({ kind: Kind.APP_LIST, listId, page, pageCount: groups.length, apps: group }));
}

/** Puts an app list back together: same list id and page count everywhere, each package once. */
export function assembleAppList(pages: readonly AppList[]): Assembly<ListedApp[]> {
  if (pages.length === 0) return { state: 'incomplete', missing: 1 };
  const first = pages[0]!;
  const byPage = new Map<number, AppList>();
  for (const page of pages) {
    if (!equalBytes(page.listId, first.listId) || page.pageCount !== first.pageCount) return { state: 'invalid', error: 'pages of different lists' };
    if (byPage.has(page.page)) return { state: 'invalid', error: 'a page arrived twice' };
    byPage.set(page.page, page);
  }
  if (byPage.size < first.pageCount) return { state: 'incomplete', missing: first.pageCount - byPage.size };
  const apps: ListedApp[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < first.pageCount; i++) {
    for (const app of byPage.get(i)!.apps) {
      if (seen.has(app.packageName)) return { state: 'invalid', error: 'a package appears twice' };
      seen.add(app.packageName);
      apps.push(app);
    }
  }
  if (apps.length > MAX_LISTED_APPS) return { state: 'invalid', error: 'too many apps' };
  return { state: 'complete', value: apps };
}

/** What a move hands over, once its pages are put together. */
export interface MovedState {
  readonly moveId: Uint8Array;
  readonly appManagement: boolean;
  readonly protection: number;
  readonly pairings: readonly MovedPairing[];
  readonly apps: readonly MovedApp[];
}

type MoveItem = { readonly pairing: MovedPairing } | { readonly app: MovedApp };

/**
 * Splits a move's state into MOVE_STATE pages: pairings first, then apps, each page as full as
 * it fits.
 */
export function pageMoveState(state: MovedState): MoveState[] {
  const header = { kind: Kind.MOVE_STATE, moveId: state.moveId, page: 0, pageCount: 1, appManagement: state.appManagement, protection: state.protection } as const;
  const empty = encodeBody({ ...header, pairings: [], apps: [] }).length;
  const items: MoveItem[] = [...state.pairings.map((pairing) => ({ pairing })), ...state.apps.map((app) => ({ app }))];
  const groups = pack(items, empty, (item) =>
    encodeBody('pairing' in item ? { ...header, pairings: [item.pairing], apps: [] } : { ...header, pairings: [], apps: [item.app] }).length - empty,
  );
  if (groups.length > 255) throw new RangeError('too many pages');
  return groups.map((group, page) => ({
    ...header,
    page,
    pageCount: groups.length,
    pairings: group.flatMap((item) => ('pairing' in item ? [item.pairing] : [])),
    apps: group.flatMap((item) => ('app' in item ? [item.app] : [])),
  }));
}

/**
 * Puts a move's state back together, with every check SPEC.md §11.14 step 3 lists.
 *
 * @param newFp the new phone: the one receiving the state.
 * @param oldFp the old phone, which sent it.
 */
export function assembleMoveState(pages: readonly MoveState[], newFp: Uint8Array, oldFp: Uint8Array): Assembly<MovedState> {
  if (pages.length === 0) return { state: 'incomplete', missing: 1 };
  const first = pages[0]!;
  const byPage = new Map<number, MoveState>();
  for (const page of pages) {
    const same =
      equalBytes(page.moveId, first.moveId) &&
      page.pageCount === first.pageCount &&
      page.appManagement === first.appManagement &&
      page.protection === first.protection;
    if (!same) return { state: 'invalid', error: 'pages of different moves' };
    if (byPage.has(page.page)) return { state: 'invalid', error: 'a page arrived twice' };
    byPage.set(page.page, page);
  }
  if (byPage.size < first.pageCount) return { state: 'incomplete', missing: first.pageCount - byPage.size };

  const pairings: MovedPairing[] = [];
  const apps: MovedApp[] = [];
  const pairIds = new Set<string>();
  const packages = new Set<string>();
  for (let i = 0; i < first.pageCount; i++) {
    const page = byPage.get(i)!;
    for (const pairing of page.pairings) {
      if (pairIds.has(toHex(pairing.pairId))) return { state: 'invalid', error: 'a pairing appears twice' };
      pairIds.add(toHex(pairing.pairId));
      if (!verifyBundle(pairing.peer)) return { state: 'invalid', error: "a peer's bundle doesn't verify" };
      const peerFp = fingerprint(pairing.peer.signPk);
      if (equalBytes(peerFp, newFp) || equalBytes(peerFp, oldFp)) return { state: 'invalid', error: 'a peer is one of the two phones' };
      pairings.push(pairing);
    }
    for (const app of page.apps) {
      if (packages.has(app.packageName)) return { state: 'invalid', error: 'a package appears twice' };
      packages.add(app.packageName);
      apps.push(app);
    }
  }
  if (pairings.length > MAX_MOVED_PAIRINGS || apps.length > MAX_MOVED_APPS) return { state: 'invalid', error: 'too much state' };
  // The setting, the protection options and the decisions about apps belong to a phone that has
  // guardians, and to no other.
  const guarded = pairings.some((pairing) => pairing.role === Role.PROTECTED);
  if (!guarded && (first.appManagement || first.protection !== 0 || apps.length > 0)) {
    return { state: 'invalid', error: 'protection state without guardians' };
  }
  return { state: 'complete', value: { moveId: first.moveId, appManagement: first.appManagement, protection: first.protection, pairings, apps } };
}
