# Authentication Security Note

**Scope:** a small local Flask + SQLite service (`/register`, `/login`, `/logout`, `/me`) built and tested on my own machine with synthetic accounts only.

## Threat model

| Threat | Attacker goal | Control |
|---|---|---|
| Database leak | Recover passwords / reuse sessions | scrypt with per-password random salt; session tokens stored only as SHA-256 |
| Brute force | Guess one account's password | 5 failures / 15 min per account, throttled before any password work |
| Password spraying | Few guesses against many accounts | 20 failures / 15 min per IP |
| Account enumeration | Learn which usernames exist | One generic login error, dummy-hash verify for unknown users, lockout keyed on submitted name |
| Session theft via XSS | Read the cookie | `HttpOnly`, strict CSP, JSON-only responses |
| Network sniffing | Capture cookie | `Secure`, HSTS header, `__Host-` prefix |
| CSRF | Cross-site state change | `SameSite=Lax`, JSON-only POSTs (forces CORS preflight) |
| Session fixation | Plant a known session ID | Server issues a fresh random token on every login and drops older sessions |
| Stolen/forgotten session | Long-lived access | 15 min idle + 8 h absolute expiry; logout deletes the server-side record |
| Malformed input / DoS | Crash or slow the service | Type + format validation, 4 KB body cap, 128-char password cap, bad hash parameters rejected |

## Design choices

- **scrypt (stdlib)** is memory-hard and keeps the lab dependency-free. Argon2id is the usual first choice in production; swapping is a change to `hashing.py`. Parameters are stored inside each hash, and `needs_rehash` upgrades hashes at the next login.
- **Server-side sessions** (not signed cookies) so logout and expiry take effect immediately.
- **Passwords:** 12-128 characters, NFKC-normalized, no composition rules (length matters more), blocklist of common values, must not contain the username.
- **Injectable clock** makes expiry and lockout tests deterministic.

## Evidence

`TEST_OUTPUT.txt` holds the full run: 39 tests, all passing. Mapping to the task steps:

1. **Hashing + validation:** `TestPasswordHashing`, `TestValidation`, `TestRegistration`
2. **Cookies, logout, expiry:** `TestSessions`
3. **Rate limits + generic errors:** `TestGenericErrors`, `TestRateLimiting`

## Known limitations (honest list)

- Rate-limit state is in memory: it resets on restart and isn't shared across processes. Production needs Redis or similar.
- Registration returns "Username unavailable" (409), which reveals existing usernames; fixing it needs email-based signup.
- No MFA, password reset, or breached-password (HIBP) check.
- Client IP uses `remote_addr`; behind a reverse proxy, configure trusted proxy headers properly or all users share one IP bucket.
- Per-account lockout lets an attacker deliberately lock a victim out (a denial-of-service trade-off); throttling with Retry-After limits the damage.
- Timing equalization is approximate, not proven constant-time end to end.
- Flask's dev server is for local use only; deploy behind HTTPS.
