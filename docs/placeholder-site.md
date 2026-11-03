# Placeholder site

What does tamodak.org serve until the real site exists, and which promises do Hisar's privacy pages
make?

Static files in `deploy/placeholder/`, served by Caddy from the server's checkout, so updating them
is a `git pull` on the server, with no rebuild.

## The pages

| Path | Content |
|---|---|
| `/` | "tamodak is a two-person organisation working on digital wellbeing and a safer internet. Our new website is on its way." (English and Turkish), one line each for Killit, Hisar and the Desktop Authenticator, and the contact `info@tamodak.org` |
| `/hisar/privacy/` | **Hisar's privacy policy**, linked from Google Play |
| `/hisar/data-safety/` | **Hisar's data-safety explanation**: why the Play listing says no data collected, no data shared, and the Families policy, type by type |
| `/.well-known/security.txt` | contact `info@tamodak.org`, preferred languages en and tr, expires 2027-10-13 |

- **No scripts** and one stylesheet, so the strict CSP holds (`default-src 'none'; style-src 'self';
  base-uri 'none'; form-action 'none'; frame-ancestors 'none'`), plus `nosniff` and `no-referrer`.
  Keep it that way when editing.
- Hisar's pages are in English only.
- The real site must keep Hisar's URLs (`/hisar/privacy/`, `/hisar/data-safety/`), because Google
  Play links to them.

## Hisar's privacy claims

The policy promises: no accounts, ads, analytics or crash reporting from the app; no tamodak server
for Hisar; filtering and the picture models run on the phone; data stays in private storage that's
excluded from backups.

It lists what does leave the phone: the websites visited (with strict SafeSearch asked of Google,
Bing, DuckDuckGo, Yahoo and Brave); searches, and what's typed for suggestions (which can be turned
off; suggestions with blocked words aren't shown); Google Lens image search, only when the user
starts it; voice recognition by the phone's own service; Google Translate when asked; GeckoView's
Safe Browsing and Mozilla's downloads; the one-time model download from GitHub; uBlock Origin's
filter-list updates (GitHub, Cloudflare, jsDelivr, GitLab, pgl.yoyo.org, publicsuffix.org, and a
regional list's publisher such as AdGuard); and Google Play itself. Permissions: internet, plus
storage on Android 9 and older. Since 0.4 it also names the media playback service (playback
controls while the screen is off), which sends nothing anywhere.

Since 2026-10-21 it no longer claims that searches with blocked words never leave the phone, nor that
YouTube is asked for Restricted Mode (off since 2026-10-03).

**If a Hisar change would send anything not listed, this page is updated before that version ships**,
with a new date (the page says so). Hisar's side of that rule:
[`../hisar-android/CLAUDE.md`](../../hisar-android/CLAUDE.md).

History: first published 2026-10-13; updated for Hisar 0.2 (2026-10-21) and for the media playback
service in 0.4 (2026-10-23).
