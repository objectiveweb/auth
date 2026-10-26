# objectiveweb/auth v0.2.0 — Release notes

<small>**Status: release candidate — not published.** Prepared for [PR #1](https://github.com/objectiveweb/auth/pull/1). These notes may be used as the GitHub release description **after** the PR is merged, the release checks pass on the intended commit, and the `v0.2.0` tag is created.</small>

## Summary

v0.2.0 is a **breaking rewrite** of `objectiveweb/auth`. It introduces a provider-based authentication core, a portable `objectiveweb/db` backend, an in-memory reference/test provider, secure OAuth login/linking flows, role-based authorization, reusable management controllers and stronger session/token handling.

**Do not upgrade an existing 0.1.x application in place without a migration plan.** The former PDO-backed class, tables and controller paths are incompatible with v0.2.0.

Read the [upgrade guide](UPGRADING-0.2.0.md) and [full changelog](../CHANGELOG.md) before upgrading.

## Highlights

- **Provider architecture:** abstract `Objectiveweb\Auth`, database-backed `Objectiveweb\Auth\DBAuth` and `BasicAuth` exclusively for tests, examples and custom-provider development (not production).
- **Portable data model:** independent user and provider-credential records; UUID, roles, user-role memberships, optional delegations, session context callbacks and normalized `Collection` queries.
- **Password and credential protection:** generic invalid-login responses, sanitized public users, expiring SHA-256 reset/verification token digests, atomic single-use redemption, CSRF-protected authenticated password changes and account suspension checks.
- **OAuth hardening:** configured HTTPS callback URLs, PKCE S256, bound one-time state, safe provider-profile handling and **explicit account linking** without email-based account takeover.
- **First-time OAuth choice:** unknown OAuth users choose to create an account or sign in with an existing email/password before any local account is created or linked; example frontend included.
- **Admin API:** user lifecycle and credential management, role constraints, safe sorting/pagination and protection of the last active administrator.
- **Validation:** PHP 8.2–8.5; SQLite; PostgreSQL 16 migrations; MySQL 8.0/8.4 migrations and DBAuth scenarios; real League Google/Facebook provider implementations with mocked network; Composer `--no-dev` and isolated consumer installation.

## Required changes for existing applications

1. Upgrade to **PHP 8.2+** and `objectiveweb/db ^0.8.0`. The 0.1.x concrete `new Auth($pdo, ...)` API is removed; use `DBAuth(new DB(...))` for production; `BasicAuth` is a reference/test implementation only.
2. Provision the **new user/credentials schema** and manually map legacy `ow_auth` users and their login IDs. There is **no automatic 0.1.x data migration**.
3. Replace legacy `Objectiveweb\Auth\AuthController` routes with `Objectiveweb\Auth\Controller\AuthController` and `UserController`; update role enforcement, JSON/CSRF requirements, and `Collection` response handling.
4. Invalidate legacy plaintext password-reset links and old sessions, then confirm new reset, registration and login flows in staging.
5. Explicitly configure an OAuth `redirectUri` for each provider and integrate the OAuth account-choice and consent-based linking routes if OAuth is enabled.
6. Configure **external authentication rate limiting** at the reverse proxy, WAF, gateway or middleware before making endpoints public.

### New application installation

```sh
composer require 'objectiveweb/auth:^0.2'
```

> The above command is for **after v0.2.0 is published**. The pre-release CI verifies the candidate through a separate Composer path-based consumer project without falsely assuming Packagist publication.

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Objectiveweb\DB;
use Objectiveweb\Auth\DBAuth;

$db = new DB('mysql:host=127.0.0.1;dbname=app;charset=utf8mb4', 'app_user', 'secret');
$auth = new DBAuth($db, ['token' => 'token', 'disabled_at' => 'disabled_at']);
```

Apply the bundled **Phinx migrations** or an equivalent checked schema before constructing an application with persistent users. Provider implementations and the router integration must be included by consuming applications that use those features.

## Security and deployment notes

- A matching OAuth email does **not** imply ownership of an existing account; use explicit, authenticated linking. The pending-account choice expires after ten minutes.
- Runtime PHP sessions and secure cookie settings are the consuming application's responsibility; use HttpOnly, Secure and SameSite where appropriate.
- Reset/verification tokens are one-time and should be delivered only out-of-band; provide the application's delivery callbacks.
- `managed_relations` is not part of the generic Auth-owned persistence model; application services own business-specific authorization assignments.
- `register_scope`, protected admin routes, CSRF, gateway throttling and deployed OAuth callback URLs must be reviewed per application.

## Deferred to later versions

Rate limiting ([#2](https://github.com/objectiveweb/auth/issues/2)), OAuth2/OIDC server and JWT/JWKS ([#3](https://github.com/objectiveweb/auth/issues/3)), passkeys/TOTP/MFA ([#4](https://github.com/objectiveweb/auth/issues/4)), and refresh-token/device-session management ([#5](https://github.com/objectiveweb/auth/issues/5)) are **not** delivered by v0.2.0.

## Release operator checklist

- [ ] Review and approve [PR #1](https://github.com/objectiveweb/auth/pull/1), including this changelog and upgrade guide.
- [ ] Confirm all mandatory CI and release-verification checks pass for the **final** PR head/merge commit: PHP 8.2–8.5, MySQL 8.0/8.4, PostgreSQL 16, OAuth and production installation.
- [ ] Verify package metadata and `composer validate --strict`, and check that the chosen tag points to the exact merged commit.
- [ ] Confirm production applications have migration, backup/rollback, session, callback, OAuth redirect and rate-limit plans.
- [ ] Merge the PR, create the `v0.2.0` tag and publish release notes **only after** those checks; do not imply this document itself performs a release.
- [ ] Confirm Composer/Packagist can resolve the newly published tag (if using Packagist), and validate a clean consumer installation.

Full reference: [README](../README.md) · [Changelog](../CHANGELOG.md) · [Upgrade guide](UPGRADING-0.2.0.md).
