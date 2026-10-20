# Changelog

All notable changes to `objectiveweb/auth` are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions and [Semantic Versioning](https://semver.org/); releases prior to 1.0 may include breaking changes in minor versions.

## [0.2.0] — Unreleased

**Breaking release.** This is a rewrite of the 0.1.x public API and storage model, not a drop-in upgrade. Read the [0.2.0 upgrade guide](docs/UPGRADING-0.2.0.md) before updating an existing application.

### Added

- Abstract `Objectiveweb\Auth` provider contract, `Objectiveweb\Auth\DBAuth` backed by `objectiveweb/db ^0.8`, and an in-memory `BasicAuth` provider.
- Separate user and `(provider, uid)` credential records, provider-specific profiles, UUIDs, configurable login/recovery providers, credential lifecycle (create, rename, delete) and per-credential verification status.
- Bundled Phinx migrations for `user`, `user_credentials`, `role`, `user_roles`, and `delegations`, including credential verification/expiry columns.
- Role-based authorization, `RequireRole` middleware, relational permissions/delegations, configurable eager loading, and `user_context_callback` for refreshing application-owned context in sessions.
- `Controller\AuthController`, `Controller\OAuthController`, and admin-only `Controller\UserController` with paginated, filterable `Collection` results, credential management, invitations, password resets, lifecycle management and CSRF-protected writes.
- Optional OAuth client login with Google/Facebook provider support, PKCE S256, provider/session-bound single-use state, and explicit, CSRF-protected account linking.
- A **first-time OAuth account-choice flow**: an unknown provider identity remains pending for up to ten minutes. The user explicitly chooses to create a new account or sign into an existing password account to link; the provider callback creates no account by itself. Includes an example frontend.
- Configurable callbacks for registration, token delivery, invitation/reset, audit events, deletion guards and application context.
- PHP 8.2–8.5 tests, SQLite unit tests, PostgreSQL 16 migration/integration checks, MySQL 8.0/8.4 schema and authentication integration checks, real Google/Facebook provider-class tests with mocked HTTP, and pre-merge production/consumer Composer installation tests.

### Changed

- **Minimum PHP version raised from 5.3 to 8.2.** Runtime dependency: `objectiveweb/db ^0.8.0`. Router/Phinx/PHPUnit packages are development dependencies; applications using router middleware or OAuth providers must install the relevant integration packages themselves.
- Database access moved from direct PDO/MySQL-specific SQL in `Objectiveweb\Auth` to the portable `DBAuth` abstraction. Queries now return `Objectiveweb\DB\Collection`, rather than the 0.1.x HAL-style `_embedded`/pagination array.
- Local identifiers are represented as credentials (`provider = local`, `uid`); the user table no longer contains the legacy `username` identity column by default.
- Password login failures return the same `AuthException` HTTP 401 for unknown identifiers, bad passwords and suspended accounts.
- Password reset tokens are cryptographically random, stored only as SHA-256 digests, expire and are consumed atomically; previously issued plaintext legacy tokens do **not** carry forward.
- Session IDs regenerate upon authentication, protected requests can revalidate account status and roles, and public user payloads are sanitized.
- User-facing password changes require the existing password, a session-bound `X-CSRF-Token`, and a JSON request; public registration is restricted to local credentials and safe profile fields.
- OAuth callbacks require a **configured, trusted `redirectUri`** (HTTPS, or explicitly configured HTTP loopback for local development), no longer inferred from Host/proxy request headers.
- OAuth provider-resource-owner display names, emails and avatars are optional hints with safe fallbacks; matching email addresses do **not** link accounts.
- User-managed application associations (`managed_relations`) now belong to application services. Use `user_context_callback` to expose current assignments to the authenticated session. User deletion cleans only explicitly `auth_owned` authorization relation tables; application-owned relation tables are never implicitly modified.
- Project testing/release verification moved from Travis to GitHub Actions; Composer metadata and support URL updated.

### Security fixes

- Prevent account enumeration through password-login errors and anonymous password-recovery responses.
- Consume password reset and credential-verification tokens at most once; separate proof for each provider credential.
- Prevent OAuth login CSRF, state replay, cross-provider state confusion, unconsented linking, email-based account takeover and cross-account credential reassignment.
- Restrict logout redirects to safe same-origin absolute paths and reject attacker-controlled OAuth callback URLs.
- Enforce management CSRF checks, prevent removal of the last active admin and protect the caller from self-deletion/suspension.
- Avoid returning passwords, reset tokens or other internal secrets in normal user/session/management payloads.

### Removed / incompatible

- Direct construction of `new Objectiveweb\Auth($pdo, ...)`; instantiate `DBAuth` or `BasicAuth` instead.
- `Objectiveweb\Auth\AuthController` (old class path), `PasswordMismatchException`, legacy `src/password.php`, and the 0.1.x MySQL-only query format.
- Implicit ownership of application-managed relations and implicit OAuth account linking based on email.
- Legacy plaintext password-reset token storage/consumption.

### Deferred / not included

- Built-in rate limiting is intentionally excluded. Deployments **must** configure throttling at the reverse proxy, gateway, WAF or application middleware. Planned non-SQL pluggable throttling: [#2](https://github.com/objectiveweb/auth/issues/2).
- Acting as an OAuth2/OIDC identity provider, JWT signing/JWKS: [#3](https://github.com/objectiveweb/auth/issues/3).
- WebAuthn/passkeys, TOTP and MFA: [#4](https://github.com/objectiveweb/auth/issues/4).
- Refresh-token rotation, device/session management and advanced audit sinks: [#5](https://github.com/objectiveweb/auth/issues/5).

See [release notes](docs/RELEASE-0.2.0.md) for a concise announcement and the [upgrade guide](docs/UPGRADING-0.2.0.md) for required migration steps. This entry is **unreleased** until the PR is merged and a release tag is published.

## 0.1.x — Legacy series

The previous public API used a concrete, PDO-backed `Objectiveweb\Auth`, a single `ow_auth` user table with a `username` column, `Objectiveweb\Auth\AuthController` and PHP 5.3-era dependencies. This entry describes the legacy series for comparison; its individual release dates and tag history are not reconstructed here.
