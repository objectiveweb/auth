# Upgrading objectiveweb/auth from 0.1.x to 0.2.0

> **Breaking rewrite — manual migration required.** There is no automatic schema/data converter or compatibility adapter from 0.1.x. Do not deploy v0.2.0 against the old `ow_auth` table and assume that existing users will work. Migrate a copy of your application first, and plan a coordinated code + schema rollout.

## Before you start

- Confirm the new runtime can run **PHP 8.2+** and install `objectiveweb/db ^0.8.0`.
- Review every caller of `Objectiveweb\Auth`, the old `Objectiveweb\Auth\AuthController`, the old HAL-style `query()` response and legacy exception classes.
- Inventory existing `ow_auth` columns, password hashes, primary IDs, external foreign keys, username/email semantics, sessions, outstanding password reset links and application permission tables.
- Prepare a current **restorable backup** of both the database and application configuration. Use a staging clone and run the migration with writes paused or with a proven incremental catch-up strategy.
- Decide which legacy user IDs must be retained to preserve external FK references. Verify there are no duplicate login identifiers in the new `(uid, provider)` namespace.
- Plan a rollback point. The old and new user models are not schema-compatible; rolling back code alone after new writes is unsafe.

## 1. Change application code and dependencies

| In 0.1.x | In 0.2.0 | Required action |
| --- | --- | --- |
| PHP >=5.3, concrete `Objectiveweb\Auth` | PHP >=8.2, abstract `Objectiveweb\Auth` | Update PHP/dependencies, instantiate an implementation |
| `new Auth($pdo, $params)` | `new DBAuth(new DB($dsn, ...), $params)` | Replace direct PDO construction with `objectiveweb/db` |
| One `ow_auth` table, `username` stored on user row | `user` + `user_credentials`, `(provider, uid)` identity | Create schema and import old identities |
| `Auth::get($username)` / `update($username, ...)` by inferred username | `DBAuth::get($id)`, `update($id, ...)` by user ID (or explicit alternate key where supported) | Resolve the credential first or use retained user IDs |
| `Auth::query()` returns `_embedded` + page arrays | Returns `Objectiveweb\DB\Collection` | Rewrite list controllers and pagination rendering |
| `Objectiveweb\Auth\AuthController` (old class) | `Objectiveweb\Auth\Controller\AuthController` and `UserController` | Update imports, routes, authorization and write payloads |
| `PasswordMismatchException` / distinct unknown-user response | `AuthException('Invalid credentials', 401)` for password login | Update exception handling without leaking which condition failed |
| 0.1.x plaintext password-reset tokens | Expiring, one-use SHA-256 token digests | Invalidate old links and issue new ones |
| Legacy session principal format | Sanitized principal with credentials, roles and optional context | Expire old sessions and require a fresh login |
| Implicit application assignments in Auth-managed relations | Application-owned relationships and `user_context_callback` | Move write/validation logic to application services |

Minimal setup for a new application database:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Objectiveweb\DB;
use Objectiveweb\Auth\DBAuth;

$db = new DB('mysql:host=127.0.0.1;dbname=app;charset=utf8mb4', 'app_user', 'secret');
$auth = new DBAuth($db, [
    'token' => 'token',
    'disabled_at' => 'disabled_at',
]);
```

Install/upgrade the package when the migrated schema is ready:

```sh
composer require 'objectiveweb/auth:^0.2'
```

Until v0.2.0 is published, the package cannot be installed from a public release tag; use PR/test environments rather than changing production prematurely. If your application uses the packaged router controllers, add the compatible `objectiveweb/router` integration explicitly. The bundled Phinx package and OAuth provider implementations are optional; include them in the **application** deployment/build environment if used.

## 2. Provision and inspect the new schema

The bundled Phinx migrations in `db/` create the **default logical tables**:

| Table | Meaning |
| --- | --- |
| `user` | User IDs, unique UUID, optional bcrypt password, name/image, password reset token digest/expiry, suspension timestamp, created timestamp |
| `user_credentials` | Unique `(uid, provider)`, `user_id` foreign key, provider profile, last login, token digest, `token_expires_at`, `verified_at` |
| `role` / `user_roles` | Global roles and membership |
| `delegations` | Optional application-configured authorization relationship |

Apply all bundled migrations **in timestamp order**, including
`20261019210000_auth_credential_verification_migration.php`. The last migration adds credential-level `token_expires_at` and `verified_at`; it does **not** migrate legacy users.

Point your application's Phinx configuration to the installed package's `db/` directory (or copy those migrations into your application's migration plan). The repository's `test/phinx.php` is for integration tests, **not** a production deployment configuration.

If the application already has conflicting table names or uses prefixes, configure explicit table mappings in `DBAuth` and migrate into a compatible schema. Check foreign keys, collations and column sizes on your target engine; CI covers SQLite, PostgreSQL 16, MySQL 8.0 and MySQL 8.4 but cannot validate an arbitrary application's existing schema.

## 3. Migrate legacy user data explicitly

The 0.1.x default table was `ow_auth`, with fields such as `id`, `username`, `password`, `created`, `last_login` and optionally `token`, plus any application-specific fields.

A **migration script that you write and test** should apply the following mapping. These are mapping rules, not an executable generic migration: actual schemas and data constraints vary.

| Old value | New value | Rule |
| --- | --- | --- |
| `ow_auth.id` | `user.id` | Preserve the numeric ID if other tables reference it, otherwise build and persist an old-to-new ID map |
| `ow_auth.password` | `user.password` | Retain valid bcrypt hash **as-is**; do not double-hash it, decrypt it or replace it with a plaintext password |
| `ow_auth.username` | `user_credentials.uid` | Use `provider = 'local'`; do not assume that the username is necessarily an email address |
| Old username/password identity | `user_credentials.user_id` | Link to exactly one migrated user; enforce uniqueness of `(uid, provider)` |
| Existing display name/image | `user.name` / `user.image` | Map approved application-specific columns explicitly |
| `ow_auth.created` | `user.created` | Preserve if valid; otherwise select a documented import value |
| New UUID | `user.uuid` | Generate a **unique, valid UUID v4** for each migrated user; the old model did not have this column by default |
| `ow_auth.last_login` | `user_credentials.last_login` | Map only if it represents that credential's login; otherwise leave nullable |
| `ow_auth.token` | **do not migrate** | Revoke outstanding legacy password-reset links; set `user.token` and `token_expires_at` to `NULL` |
| `user_credentials.verified_at` | Initially `NULL` unless independently proven | Never mark legacy email/phone/OAuth ownership verified solely because a matching address was stored |
| Existing roles and relations | `role`, `user_roles` or application tables | Review grants and target IDs; do not silently grant `admin` to a legacy user |

**Data migration order:** import user rows; verify ID/UUID uniqueness; import linked `local` credentials; migrate or remap application foreign keys; import the intended role memberships; migrate any Auth-owned delegations; then run validation queries. Do this in a controlled transaction where the database/schema permits it, and stop deployment on conflicts.

Preserving an existing bcrypt hash allows a password user to sign in without knowing the plaintext. But a legacy username like `jdoe` will not automatically work with the new public registration endpoint, which requires an email-formatted UID. Choose and document your application's identity/registration strategy before launch. Password login itself checks configured `login_providers` (default `['local', 'email']`).

If you preserve numeric `id` values, also reset the auto-increment/identity sequence for the migrated user table above the maximum imported ID before any new registration. Migrate and verify application-side FKs before enabling deletes, and confirm the DBAuth default table names or configured aliases resolve to the intended physical tables.

## 4. Update requests, controllers and authorization

- Replace old `Objectiveweb\Auth\AuthController` routes with `Objectiveweb\Auth\Controller\AuthController` for authentication and `UserController` for admin user management.
- Public registration accepts an email UID, an optional password and safe `name`/`image` profile fields, not arbitrary `provider` or role grants.
- Privileged management operations require the **admin** role. Seed valid roles before accepting role assignments; the management API rejects unknown roles.
- Management writes and authenticated password changes use **JSON**, the authenticated PHP session and `X-CSRF-Token` from `AuthController::index()` (`_csrf`). Authenticated password changes also require `current_password`.
- Replace HAL queries such as `$result['_embedded']['ow_auth']` with iteration over a `Collection` and `$collection->total()` / `$collection->contentRange()`.
- Replace old `PasswordMismatchException` handlers with `AuthException` and a generic 401 response for invalid password login.
- Update any direct password/credential/token calls to use **numeric user IDs** and the new `(provider, uid)` credential APIs. `passwd()` is a trusted service/admin operation; use `postPassword()` for end-user password changes.
- If using `managed_relations` in earlier development builds, migrate their reads/writes/validation to application services and use `user_context_callback` for refreshed session context. Auth does not automatically persist or remove application-owned association rows. A configured `relations` entry opts into deletion cleanup only when explicitly marked `auth_owned => true` (for genuinely Auth-owned tables such as bundled `delegations`); do not enable it for application tables.

## 5. Deploy OAuth changes deliberately

- Install each optional League OAuth client implementation you use, e.g. `league/oauth2-google` or `league/oauth2-facebook`, in the application; they are suggestions, not mandatory runtime dependencies.
- Configure an exact registered `redirectUri` for every provider. It must use HTTPS, except explicitly configured HTTP on `localhost` / loopback for development. Request-derived Host/proxy callback URLs are no longer accepted.
- OAuth uses PKCE S256 and expiring single-use provider/session-bound state. Maintain secure, HttpOnly, SameSite browser sessions.
- A provider identity that has never been seen before does **not** create a local account automatically. Your application must serve the pending-choice page and wire `getPendingAccount()`, `postCreateAccount()`, `postExistingAccount()`, `postCancelPendingAccount()`. See [account-choice example](../examples/oauth-account-choice.html).
- Existing signed-in users link OAuth identities only via an authenticated, CSRF-protected `postLink($provider)` POST; the frontend navigates to its returned `authorization_url`. Normal OAuth login never silently links by email.
- Provider display profile/email values are **hints**, never proof that two accounts belong together.

## 6. Configure production security and callback delivery

- **Enable external rate limiting** for login, registration, recovery, reset redemption and credential verification at the gateway/WAF/reverse proxy or middleware. There is intentionally no application-DB rate-limit counter in 0.2.0; see [#2](https://github.com/objectiveweb/auth/issues/2).
- Set `register_scope`, `token`, `token_ttl`, `token_callback`, `invitation_callback`, `reset_callback`, and `disabled_at` appropriately. The package cannot deliver email/SMS itself.
- Back up data, expire old auth sessions and clear legacy password-reset links during cutover. Require fresh login; the legacy session payload and credentials cannot be trusted as a v0.2.0 principal.
- Keep user secrets, credential profiles and tokens out of logs, analytics, public APIs and generic error pages.
- Validate application-specific roles, relationships and callbacks on staging before allowing privileged operations.

## 7. Verify the rollout

Before merging/upgrading, check:

- [ ] PHP >=8.2 and correct Composer runtime/integration dependencies; `composer validate --strict` passes.
- [ ] A clean install with `--no-dev` and the standalone production smoke test passes; PR checks cover this.
- [ ] The target migration schema includes both credential verification columns; indexes and foreign keys validate.
- [ ] Old/new user counts match; preserved IDs and all application foreign keys resolve correctly.
- [ ] Every old password identity maps to exactly one `local` credential and bcrypt login works.
- [ ] Old password-reset tokens are invalid; new reset and credential-specific verification tokens are one-time and expire.
- [ ] List/search pagination, role assignment and active-admin safeguards behave as expected.
- [ ] Existing sessions are invalidated; password changes require current password and CSRF.
- [ ] OAuth registered redirect URIs, first-time account choice, existing-account linking, returning-login and link-conflict cases work with **your** providers.
- [ ] External rate limits and secure session cookies are configured and tested.
- [ ] Backups, restore procedure, cutover maintenance window and rollback criteria are agreed.

**Rollback:** Restore a consistent snapshot of the original 0.1.x database and code together, including application tables and session strategy. Do not simply point 0.1.x code at the 0.2.0 schema, and do not expect new accounts/credentials to survive a rollback unless you build a separate reverse-conversion process.

For complete API documentation, see [README](../README.md); for the feature summary, see [CHANGELOG](../CHANGELOG.md).
