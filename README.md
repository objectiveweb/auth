# objectiveweb/auth [![CI](https://github.com/objectiveweb/auth/actions/workflows/ci.yml/badge.svg)](https://github.com/objectiveweb/auth/actions/workflows/ci.yml)

Authentication library with pluggable providers.

## Install

```bash
composer require objectiveweb/auth
```

This package requires:
- PHP `>=8.2`
- `objectiveweb/db`

## Providers

### `DBAuth`

`DBAuth` uses `Objectiveweb\DB` and supports:
- local login with hashed password
- external credentials (`provider` + `uid`)
- password reset tokens
- immutable UUID generation on user creation (default field name: `uuid`)

#### Example setup

Apply the bundled Phinx migrations (or an equivalent schema) before using `DBAuth`. The example uses the default **logical** table names created by those migrations: `user`, `user_credentials`, `role`, `user_roles` and `delegations`.

```php
use Objectiveweb\DB;
use Objectiveweb\Auth\DBAuth;

$db = new DB('sqlite:/tmp/app.sqlite'); // MySQL and PostgreSQL also supported

$auth = new DBAuth($db, [
    'token' => 'token',             // Enable password resets
    'disabled_at' => 'disabled_at', // Enable account suspension
    'invitation_callback' => function (array $user, array $credentials, string $token): void {
        // Deliver invitations out of band; never return a token over HTTP.
    },
    'reset_callback' => function (array $user, array $credentials, string $token): void {
        // Deliver admin-initiated resets out of band.
    },
    'token_callback' => function (array $credential): void {
        // Anonymous forgot-password delivery; token is in $credential['token'].
    },
]);
```

The table names are defaults; they do **not** need to be repeated in the constructor. `DBAuth` initializes a `$db->table('user')` object for user CRUD and pagination.

To use physical table prefixes, configure `DB` and your Phinx installation consistently, leaving `DBAuth` table names logical:

```php
$db = new DB('sqlite:/tmp/app.sqlite', null, '', ['prefix' => 'app_']);
$auth = new DBAuth($db, ['token' => 'token', 'disabled_at' => 'disabled_at']);
// Logical table "user" resolves to physical table "app_user".
```

#### DBAuth parameters

These options come from both the shared `Auth` contract and `DBAuth`. Set only the options your application needs.

| Parameter | Default | Purpose |
| --- | --- | --- |
| `table` | `user` | Logical user table (DB applies any configured prefix) |
| `id` / `password` | `id` / `password` | User primary key and password-hash columns |
| `uuid` | `uuid` | Generates UUIDs on registration; `null` disables |
| `created` / `last_login` | `created` / `null` | User-table creation and optional last-login columns |
| `credentials_table` | `user_credentials` | Logical provider-credential table |
| `credentials_last_login` / `credentials_created` | `last_login` / `created` | Credential timestamp columns; `null` disables updates |
| `login_providers` | `['local', 'email']` | Ordered provider identities considered for password login |
| `recovery_providers` | `['local', 'email', 'phone']` | Provider identities checked for anonymous recovery |
| `token` | `null` | User-table reset-token field; use `'token'` to enable |
| `token_expires_field` / `token_ttl` | `token_expires_at` / `3600` | Reset-token expiry column and lifetime in seconds |
| `disabled_at` | `null` | Nullable suspension column; use `'disabled_at'` to enable lifecycle checks |
| `roles` | `roles` | Name of the calculated user roles array (not a database column) |
| `roles_table` / `user_roles_table` | `role` / `user_roles` | Global roles and memberships; both required or both `null` |
| `role_id` / `role_name` | `id` / `name` | Role table's ID/name fields |
| `user_roles_user_id` / `user_roles_role_id` | `user_id` / `role_id` | Membership foreign-key fields |
| `relations` | `[]` | Resource abilities and user-to-user delegations; see Relations |
| `user_context_callback` | `null` | Application callback `(sanitizedUser): array` to populate the authenticated session's `context` |
| `session_key` | `ow_auth` | Authenticated principal's session key |
| `register_scope` / `register_allow_grants` | `Auth::ANONYMOUS` / `false` | Registration access and whether callers may supply roles |
| `management_csrf` / `management_csrf_session_key` | `true` / `ow_auth_management_csrf` | Management write protection and CSRF session key |
| `register_callback` / `token_callback` | `null` / `null` | Registration callback / anonymous recovery delivery callback |
| `invitation_callback` / `reset_callback` | `null` / `null` | Delivery callbacks for invitation/admin reset: `(user, credentials, plaintextToken)` |
| `audit_callback` | `null` | Management events: `(actorId, targetId, action, metadata)` |
| `deletion_guard_callback` | `null` | Return `false` or a conflict string to reject user deletion |

The anonymous `token_callback` receives a **single** credential array containing the one-time token. `Auth::invite()` instead invokes `invitation_callback` or `reset_callback` with **three** arguments; without dedicated callbacks it falls back to `register_callback`/`token_callback`, respectively. Prefer dedicated callbacks when supporting both flows.

#### Database tables and migrations

The bundled migrations in `db/` use the following **default logical names**:

| Table | Fields and purpose |
| --- | --- |
| `user` | `id`, unique `uuid`, nullable `password`, `name`, `image`, `created`, nullable `token`, `token_expires_at` and `disabled_at` |
| `user_credentials` | Unique (`uid`, `provider`) credential identity, `user_id` FK, `profile`, `token`, `last_login`, `created` |
| `role` | `id` and unique role `name` |
| `user_roles` | (`user_id`, `role_id`) memberships with both foreign keys |
| `delegations` | Optional (`user_id`, `target_user_id`, `ability`) relation table |

Use your application's Phinx configuration to run the package's migrations; Phinx is a development/migration dependency, not a runtime dependency of this package. The reset-token column is indexed in the bundled user migration and stores only a SHA-256 digest of the generated one-time token.


For a standalone SQLite setup, the following is an equivalent schema using **default table names**. Prefer the bundled migrations for a production application and adapt column types/constraints to your database:

```sql
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid VARCHAR(36) NOT NULL UNIQUE,
    password VARCHAR(60),
    name VARCHAR(255),
    image VARCHAR(255),
    token VARCHAR(255),
    token_expires_at DATETIME,
    disabled_at DATETIME,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX user_token_idx ON user(token);

CREATE TABLE user_credentials (
    uid VARCHAR(255) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    user_id INTEGER NOT NULL,
    profile TEXT,
    token VARCHAR(255),
    last_login DATETIME,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid, provider),
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE
);
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (role_id) REFERENCES role(id)
);
CREATE INDEX user_roles_role_id_idx ON user_roles(role_id);

-- Optional, used only when explicitly configured under "relations":
CREATE TABLE delegations (
    user_id INTEGER NOT NULL,
    target_user_id INTEGER NOT NULL,
    ability VARCHAR(64) NOT NULL,
    PRIMARY KEY (user_id, target_user_id, ability)
);
CREATE INDEX delegations_target_idx ON delegations(target_user_id);
```

**Custom schemas:** Override `table`, `credentials_table`, `roles_table` and `user_roles_table` when integrating existing tables. For instance, the following maps to *logical* custom tables; these physical tables must already exist because the bundled migrations use the default names:

```php
$auth = new DBAuth($db, [
    'table' => 'auth_user',
    'credentials_table' => 'auth_credentials',
    'roles_table' => 'auth_role',
    'user_roles_table' => 'auth_user_role',
    'token' => 'token',
    'disabled_at' => 'disabled_at',
]);
```

Configure a prefix only on `DB` rather than manually including it in these table names. With the default configuration, **both** role tables are expected. To disable database roles, set **both** `roles_table` and `user_roles_table` to `null`; no role columns belong in the user table.

#### Public registration

`AuthController::postRegister()` accepts only `uid` (email), `password`,
and optional `name` and `image`. It always creates a `local` credential.
Role requests are ignored; provider names, OAuth profiles, IDs, suspension
state, tokens, and other fields are rejected with HTTP 400.

This prevents clients from claiming external provider identities, but **does
not verify ownership of the submitted email address**. Applications must
complete email verification before treating an email as verified. Explicit
provider registration using `DBAuth::register()` is reserved for trusted
application code after authenticating the provider's identity.

#### Users

`register()` creates the user and its initial credential transactionally. It returns a **sanitized** user. `get()` returns the provider's **raw** user record, including sensitive fields; sanitize it before exposing it to clients.

```php
$user = $auth->register('alice@example.com', 'secret', ['name' => 'Alice']);
$userId = $user['id'];

$rawUser = $auth->get($userId);
$publicUser = $auth->sanitize_user($rawUser);

$auth->update($userId, ['name' => 'Alice Smith']);
```

`query()` returns `Objectiveweb\DB\Collection`, not HAL-formatted data:

```php
$users = $auth->query([
    'q' => 'alice',      // Search name, numeric ID or credential UID
    'page' => 0,
    'size' => 20,
    'sort' => 'name ASC',
    'status' => 'active',
]);

foreach ($users as $user) {
    // Sanitized user, with roles and credentials
}
$total = $users->total();
$range = $users->contentRange(); // e.g. "items 0-19/137"
```

For password-based login and session management:

```php
use Objectiveweb\Auth\AuthException;

try {
    $current = $auth->login('alice@example.com', 'secret');
} catch (AuthException $e) {
    // 401 "Invalid credentials" for unknown users, wrong passwords, or
    // suspended accounts. Do not reveal which case applies.
}

if ($auth->check()) {
    $current = $auth->user(); // Sanitized session principal
}
$auth->logout();
```

`passwd($userId, $newPassword)` performs a **direct** password replacement and must only be called by trusted admin/service code. For an authenticated user's own change, the included `AuthController::postPassword()` verifies the old password and session CSRF token; see below.

#### User credentials

A user can have multiple identities, each uniquely identified by `(provider, uid)` and linked through `user_id`. The default `login_providers` are `local` and `email`; adding an OAuth/phone/email credential does not verify ownership automatically.

```php
$auth->get_credential('local', 'alice@example.com'); // Raw provider credential or false
$credentials = $auth->get_credentials($userId); // Normalized public-safe list

$auth->create_credential($userId, 'phone', '+5511999999999', ['country' => 'BR']);
$auth->rename_credential($userId, 'phone', '+5511999999999', 'phone', '+5511888888888');
$auth->delete_credential($userId, 'phone', '+5511888888888');
```

`create_credential()` rejects duplicates; `update_credential()` inserts or updates a provider identity and updates its last-login field when configured. `delete_credential()` refuses to remove the user's last credential. Treat raw provider profiles as potentially sensitive; send normalized/sanitized credentials to clients.

##### Independent credential verification

Each `(provider, uid)` credential has its own verification state: `token`
(SHA-256 digest only), `token_expires_at`, and `verified_at`. A new
credential is unverified until its specific identity has been proven.
The `user.token` field remains for **password reset/invitation**, and is
not interchangeable with credential verification tokens.

For contact methods (`local`, `email`, `phone` by default), trusted
application code can issue an out-of-band token and deliver it **only**
through that credential's address or channel:

```php
$auth->create_credential($userId, 'email', 'alice@example.com');
$token = $auth->issue_credential_token($userId, 'email', 'alice@example.com');
// Email the secret to alice@example.com; do not expose it via an API response.
// The caller redeems it with AuthController::postVerifyCredential():
$result = $auth->verify_credential_token('email', 'alice@example.com', $token);
// true on first valid redemption; false for wrong, expired, or reused tokens.
```

Each token is independent; validating one credential does **not** validate
any other. Issuing a new token replaces an earlier pending one. Tokens
expire after `credential_token_ttl` seconds (default 3600; minimum 60),
and are consumed once. Credentials lists include `verified_at`, but never
return verification token digests or expirations. Renaming a credential's
provider or UID clears its prior verification state.

An OAuth provider identity is **not** verified by a locally issued email or
SMS token. OAuth credentials are proven using the validated provider callback,
including code/token exchange and provider-specific user ID; the trusted
OAuth integration marks exactly that credential verified. OAuth sign-in never
links accounts by email equality and never automatically creates a separate
`email` credential. An existing unverified OAuth credential cannot authorize
an anonymous login; its owning user must authenticate separately and confirm
the provider link. External providers are deliberately excluded from
`credential_token_providers` unless explicitly configured by the application;
do not enable arbitrary OAuth provider names.

The public `postVerifyCredential()` endpoint accepts `provider`, `uid`, and
`token`, marks the matching credential verified, and returns
`{"verified":true}`. It does not establish a login session. Applications
must rate-limit verification attempts and token issuance. Local password login
continues to prove knowledge of the password; it does not imply that the
credential's email address is verified.

#### Roles

**Global roles** are attached to users and stored in `role` and `user_roles`. `roles` in returned user data is a computed array, not a SQL column. They are independent of resource-specific relations.

```php
// Trusted bootstrap/service code:
$admin = $auth->register('admin@example.com', 'secret', [
    'name' => 'Admin',
    'roles' => ['admin'],
]);

$auth->get_roles();                // ['admin', ...]
$auth->get_users_by_role('admin'); // Sanitized user arrays
$auth->update($admin['id'], ['roles' => ['admin', 'editor']]);

// With the appropriate user already logged in:
$auth->user_can('admin'); // bool
```

Direct `DBAuth::register()` / `update()` can create role definitions when syncing names that do not exist. The **admin UserController API** is intentionally stricter and accepts only *existing* role names: seed the allowed roles before using its role-management endpoints. The public registration controller always ignores role grants, regardless of `register_allow_grants`. Both `roles_table` and `user_roles_table` must be disabled together if roles are not wanted.

#### Relations and authorization

`relations` provides **resource permissions and user-to-user delegations**, separate from global roles. The bundled `delegations` table is optional until you map it; any other permission tables are owned by your application and must be created in your migrations.

```php
$auth = new DBAuth($db, [
    'relations' => [
        'user' => [
            'table' => 'delegations', // Bundled table
            'subject_key' => 'user_id',
            'target_key' => 'target_user_id',
            'ability_key' => 'ability',
            'target_is_user' => true, // Also clean target-user rows on deletion
        ],
        'item' => [
            'table' => 'item_users',  // Application-owned relation table
            'subject_key' => 'user_id',
            'target_key' => 'item_id',
            'ability_key' => 'ability',
            'eager' => true,         // Eagerly load matching rows with get()/query()
        ],
    ],
]);

// With a user logged in:
$auth->user_can('delegate', 42);       // "user" relation for target user 42
$auth->user_can('manage', 'item', 10);  // Ability on item 10
$itemIds = $auth->user_can('manage', 'item'); // Accessible item IDs
```

Each permission relation requires `table`, `subject_key`, `target_key` and either `ability_key` or `role_key` together with `role_abilities` (a role-to-ability map). `eager` may be `true` or a `DB::select()` options array such as `['order' => 'item_id DESC']`. Eager relation rows remain scoped to the current subject user.

#### Application-owned user context

Use `user_context_callback` for application authorization context that must be available on the authenticated principal (for example, the venue IDs assigned to the current user). It receives a **sanitized** user and must return an array. Auth stores that array under `$auth->user()['context']` at login (including OAuth) and **rebuilds** it from the latest user record whenever `reload()` or `revalidate()` is called.

The application owns the underlying relationships, validation, and writes. Auth does not read or modify the application association table itself:

```php
use Breakfastweekend\App\Service\UserService;

$auth = new DBAuth($db, [
    'user_context_callback' => function (array $user) use ($app): array {
        $service = $app->create(UserService::class);
        return [
            'venues' => $service->getVenueIds($user['id']),
        ];
    },
]);

$auth->login('alice@example.com', 'secret');
$venueIds = $auth->user()['context']['venues']; // e.g. [12, 34]

// Once the application updates venue assignments, refresh session context:
$auth->revalidate();
$venueIds = $auth->user()['context']['venues'];
```

`getVenueIds()` is an **application method to implement**; it is not supplied by Auth. Keep the existing application's `validateVenueIds()` in its own service, alongside an application-owned assignment method such as `syncVenueIds($userId, $ids)`. The latter should validate IDs and authorization before changing `venue_users` transactionally. For users whose assignments change in another session, call `revalidate()` on the next protected request or otherwise invalidate/refresh that session according to your application's needs.

Session context is not implicitly added to `get()` or `query()` results; those remain user-record APIs. `AuthController::index()` returns the authenticated session principal, including its context. If the callback is omitted, Auth does not add a context field.

**Migration from `managed_relations` (breaking change for 0.2.0):** remove that parameter; move `get_managed_relations()` and `sync_managed_relations()` callers into your application's user service; expose venue assignments through application-specific endpoints rather than generic `UserController` create/update. The generic Auth controller now rejects `managed_relations` request fields instead of silently losing assignments, and it no longer includes them in user-detail responses. `DBAuth::delete()` no longer cleans application association tables: arrange cleanup using application transactions/foreign-key cascades and, where necessary, `deletion_guard_callback`.

### `BasicAuth`

In-memory provider for tests/dev/small setups.

`BasicAuth` fully implements the provider contract:
- `query`, `get`, `register`, `login`
- `passwd`, `passwd_reset`
- `update`, `delete`
- `update_token`
- `get_credential`, `update_credential`

#### BasicAuth setup

```php
use Objectiveweb\Auth\BasicAuth;

$auth = new BasicAuth(
    [
        'admin@example.com' => 'secret',
    ],
    [
        'token' => 'token',
    ]
);
```

Passwords passed to the constructor/register are hashed internally unless already hashed.

## Authenticated password changes

`AuthController::postPassword()` requires proof of the existing password for
authenticated sessions. Retrieve the session-bound CSRF token from the
authenticated `AuthController::index()` response (`_csrf`) and send it as
`X-CSRF-Token` with `Content-Type: application/json`:

```http
POST /auth/password
Content-Type: application/json
X-CSRF-Token: <token from authenticated current-user response>

{"current_password":"old-password","password":"new-password","confirm":"new-password"}
```

The authenticated change is refused when the current password is missing or
incorrect, or when the user has no usable local password (for example, an
OAuth-only account). Passwordless users must complete an independently verified
password-reset or reauthentication flow instead; a session alone cannot set a
password. The CSRF token is required even for direct controller invocations.

## Password reset flow

When `token` is configured:

```php
$credential = $auth->get_credential('local', 'alice@example.com');
$token = $auth->update_token($credential['user_id']);

// Send token, then later:
$auth->passwd_reset($token, 'new-password');
```

`DBAuth` stores only a SHA-256 digest of the high-entropy reset token and looks it up through the indexed token column. The plaintext token is returned only once for delivery.

Anonymous password-recovery requests intentionally return the same empty success payload whether or not the supplied UID exists. Recovery callbacks are delivery-only: their return value is not exposed, and delivery failures do not change the anonymous response. **There is no built-in rate limiting in v0.2.0.** Applications must enforce external rate limits at their web server, reverse proxy, gateway, or middleware for login, public registration, recovery, reset-token redemption, and credential verification. Future non-database throttling is tracked in [issue #2](https://github.com/objectiveweb/auth/issues/2).

## OAuth controller

Configure OAuth providers by provider name. Set an explicit `redirectUri` in production so callback URLs do not depend on request/proxy headers:

```php
use Objectiveweb\Auth\Controller\OAuthController;

$oauth = new OAuthController($auth, [
    'google' => [
        'clientId' => getenv('GOOGLE_CLIENT_ID'),
        'clientSecret' => getenv('GOOGLE_CLIENT_SECRET'),
        'redirectUri' => 'https://app.example/auth/oauth/google',
    ],
]);
```

If `redirectUri` is omitted, the controller derives it from the current request for development/legacy setups. **Use an explicit trusted redirect URI in production:** request-derived host and proxy headers are not an authorization boundary.

OAuth authorization includes a fresh **PKCE S256** challenge and stores a per-provider authorization flow in the PHP session (`oauth2flows`). The callback requires the matching provider's state, the original initiating session principal, and a state created within the past 10 minutes. The state is consumed before exchanging the code, and the matching PKCE verifier is supplied to the token endpoint. Providers must support PKCE S256. OAuth accounts are linked by the provider's stable subject identifier only; matching email addresses never establishes or links identities.

### First-time OAuth account choice (no automatic duplicate accounts)

After the OAuth authorization-code/PKCE exchange, if no `(provider, uid)` credential exists, the user is **not logged in** and no local user is created. A short-lived `oauth2pending` entry remains in their PHP session; it contains the provider's verified subject, profile, safe display hints, and creation timestamp, and expires after 10 minutes. The OAuth state is already consumed.

The callback redirects to **`/?oauth=choose-account`** by default. The application must render an account-choice page at that URL (or configure a different same-origin path in the controller constructor):

```php
$oauth = new OAuthController($auth, $providers, '/account/choose');
```

A ready-to-adapt frontend is included as [`examples/oauth-account-choice.html`](examples/oauth-account-choice.html). The library does not manage application UI routes, so mount the page at the configured redirect path and map the following methods to your application router:

| Example route | OAuthController method | Function |
| --- | --- | --- |
| `GET /auth/oauth/pending` | `getPendingAccount()` | Safe choice metadata, email/name hints and session `_csrf` |
| `POST /auth/oauth/pending/create` | `postCreateAccount(array $form)` | Explicitly create a new **OAuth-only** local account |
| `POST /auth/oauth/pending/existing` | `postExistingAccount(array $form)` | Authenticate existing `uid` and `password`, then link the provider identity |
| `POST /auth/oauth/pending/cancel` | `postCancelPendingAccount()` | Discard the pending identity |

All three POST actions require JSON, the `X-CSRF-Token` from `getPendingAccount()`, and the same browser session. Creation permits only optional `name` and respects `register_scope`; arbitrary provider, user ID, role and profile fields are rejected. Existing-account linking requires the actual password for that existing account. Wrong passwords do not consume the pending proof, so users can retry before expiry. Neither option treats the provider email as an automatically verified local email credential.

On successful creation, the library creates an external-provider credential and establishes a new local session. On successful existing-account login, it attaches **that same provider identity to the password-authenticated local user**, marks the provider credential verified, and keeps that existing account. Both actions consume the pending proof; it cannot be reused. Concurrent ownership conflicts return HTTP 409; expired/cancelled/consumed choices return HTTP 410. For security, do not store the pending proof in the browser or return OAuth tokens/provider subject IDs as client data. The application must maintain secure, HttpOnly, SameSite session cookies; enforce external rate limits (see issue #2); and avoid caching the pending-account API response.

```js
const pending = await fetch('/auth/oauth/pending', { credentials: 'same-origin' }).then(r => r.json());
// Render two user-selected actions: "Create new account" and "Use existing account".
const response = await fetch('/auth/oauth/pending/existing', {
  method: 'POST',
  credentials: 'same-origin',
  headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': pending._csrf },
  body: JSON.stringify({ uid: email, password }),
});
// Do not navigate to the signed-in area unless response.ok.
```

If the OAuth credential already belongs to a verified local user, normal OAuth login still signs that user in immediately. If the local user is already signed in and wants another OAuth credential, use the explicit account-linking flow below instead.

### Explicit OAuth account linking

**OAuth login and account linking are separate operations.** A normal `OAuthController::get($provider, $query)` authorization/callback authenticates an already verified external identity. If an anonymous user's provider identity has no local credential yet, the callback **does not create an account**: it stores a ten-minute, session-bound pending identity and redirects to a configurable account-choice page. It never attaches a new provider credential to an existing authenticated account, even when email addresses match. A signed-in user attempting to sign in through an unassociated provider receives HTTP 409 and must explicitly link the account first. Existing unverified OAuth identities cannot sign in anonymously or be silently confirmed.

To link a provider, the application must expose `OAuthController::postLink($provider)` on an authenticated **POST** route (for example, `POST /auth/oauth/link/google` using the application's router). The request requires `Content-Type: application/json` and a valid session-bound `X-CSRF-Token` from `Auth::management_csrf_token()` (also available in the logged-in `AuthController::index()` response as `_csrf`). Do not allow GET links or unprotected forms to initiate linking.

The action returns JSON containing an `authorization_url`. **The frontend must navigate to that URL** rather than relying on an AJAX redirect:

```js
const response = await fetch('/auth/oauth/link/google', {
  method: 'POST',
  credentials: 'same-origin',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken,
  },
  body: '{}',
});
if (!response.ok) throw new Error('Could not start account linking');
const { authorization_url } = await response.json();
window.location.assign(authorization_url);
```

The provider's usual OAuth callback still uses `get()`. The session flow records an explicit `link` intent, the initiating user ID, provider, PKCE verifier, expiring one-time state and login session. Only a valid callback for the same active user may create/verify that user's provider credential. Identities already associated with a different user are rejected with HTTP 409; unverified mappings owned by the current user require this explicit flow to be confirmed. State is consumed even when linking fails.

Applications should make the action visible only after the user chooses **Link account**, and may require additional recent-authentication or step-up checks as local policy dictates. All existing authorization, CSRF, and provider-account security checks continue to apply.

The explicit authenticated `postLink()` flow remains distinct from the *anonymous first-time* account choice above. Never interpret an OAuth callback, query-string `intent`, or matching email as permission to link accounts.

## User-management API

Register `Objectiveweb\Auth\Controller\UserController` at an application-owned
prefix such as `/api/users`. It requires the `admin` role and supports:

- searchable, filtered and paginated `GET /api/users` (`q`, `role`,
  `status`, `page`, `size`, whitelisted `sort`), returned directly as an
  `Objectiveweb\DB\Collection`;
- role and user detail reads;
- create/invite and profile/global-role updates;
- credential create, rename and delete;
- suspend, activate, invitation and password-reset actions;
- guarded deletion with relation cleanup.

User detail and role-list responses include a session CSRF token. Send it as
`X-CSRF-Token` with `Content-Type: application/json` on every write. The user
list itself is a plain `Collection`; use `total()` and `contentRange()` for
pagination metadata. Setup and reset tokens are passed only to delivery
callbacks and are never serialized in HTTP responses.

Role names accepted by the management API must already exist in the configured
roles table. Use migrations/seeds for role definitions. Application-owned assignments
(e.g. venues) belong in application-specific endpoints; `managed_relations` is not
accepted by the generic management API.

## Controllers and middleware

Included:
- `AuthController`
- `OAuthController`
- `UserController`
- `RequireRole` middleware
