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

```php
use Objectiveweb\Auth\DBAuth;
use Objectiveweb\DB;

$db = new DB('sqlite:/tmp/app.sqlite'); // or mysql:..., pgsql:...

$auth = new DBAuth($db, [
    'table' => 'auth_user',
    'credentials_table' => 'auth_credentials',
    'id' => 'id',
    'password' => 'password',
    'roles' => 'roles',
    'login_providers' => ['local', 'email', 'phone'],
    'token' => 'token',
    'created' => 'created',
    'uuid' => 'uuid',
    'credentials_last_login' => 'last_login',
    'roles_table' => 'auth_role',
    'user_roles_table' => 'auth_user_role',
    'relations' => [
        'user' => [
            'table' => 'user_delegations',
            'subject_key' => 'user_id',
            'target_key' => 'target_user_id',
            'ability_key' => 'ability',
        ],
        'item' => [
            'table' => 'item_users',
            'subject_key' => 'user_id',
            'target_key' => 'item_id',
            'ability_key' => 'ability',
            'eager' => true // or array of parameters passed to select 
                            // ['order' => 'item_id DESC', 'fields' => ['a', 'b']]

        ],
    ],
]);
```

#### Required tables

`DBAuth` expects:
- users table (`table`)
- credentials table (`credentials_table`)

Example schema (SQLite-compatible):

```sql
CREATE TABLE auth_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT,
    image TEXT,
    created TEXT,
    password TEXT,
    token TEXT
);

CREATE TABLE auth_credentials (
    uid TEXT NOT NULL,
    provider TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    profile TEXT NULL,
    last_login TEXT NULL,
    PRIMARY KEY(uid, provider)
);

CREATE TABLE auth_role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE auth_user_role (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, role_id)
);
```

#### DBAuth params

- `session_key`: session storage key (default `ow_auth`)
- `id`: user PK field (default `id`)
- `password`: password field (default `password`)
- `roles`: roles field attached to the user payload (default `roles`)
- `login_providers`: ordered providers used by `login()` (default `['local', 'email']`)
- `token`: optional password-reset token field
- `table`: users table name (default `user`)
- `credentials_table`: credentials table name (default `user_credentials`)
- `roles_table`: optional roles table name (default `null`)
- `user_roles_table`: optional user-role mapping table name (default `null`)
- `user_roles_user_id`: user FK column in mapping table (default `user_id`)
- `user_roles_role_id`: role FK column in mapping table (default `role_id`)
- `role_id`: role PK column in `roles_table` (default `id`)
- `role_name`: role name column in `roles_table` (default `name`)
- `relations`: relationship auth mapping by resource type (default `[]`)
- `relations.<name>.eager`: eager load related rows into user payload (`true` => `[]`, `array` => select params)
- `created`: optional created-at field
- `last_login`: optional user last-login field
- `credentials_last_login`: optional credentials last-login field
- `uuid`: UUID field created on register and protected from updates (default `uuid`)

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

## Common usage

```php
use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\UserException;

// Register
$user = $auth->register('alice@example.com', 'secret', ['name' => 'Alice']);

// Login
try {
    $user = $auth->login('alice@example.com', 'secret');
} catch (AuthException $e) {
    // invalid password
} catch (UserException $e) {
    // user not found
}

// Session
if ($auth->check()) {
    $current = $auth->user();
}

// Logout
$auth->logout();
```

## Password reset flow

When `token` is configured:

```php
$credential = $auth->get_credential('local', 'alice@example.com');
$token = $auth->update_token($credential['user_id']);

// Send token, then later:
$auth->passwd_reset($token, 'new-password');
```

## Credential strategy (`local`, `email`, `phone`, social)

Recommended model:
- `local`: password-based login identity
- `email`: email identities for verification/login/magic-link
- `phone`: phone identities for SMS verification/login
- `google`, `facebook`, ...: external OAuth providers

Store each identity in `credentials_table` as `(provider, uid)`, linked to one `user_id`.

## Query and update

```php
// List users (paginated response)
$result = $auth->query(['page' => 0, 'size' => 20]);

// Update user profile data
$auth->update($userId, ['name' => 'Alice Updated']);

// Update password
$auth->passwd($userId, 'new-password');

// List all credentials for a user
$credentials = $auth->get_credentials($userId);
```

## Authorization checks (`user_can`)

```php
// Global grants (roles)
$auth->user_can('admin'); // bool

// Delegation to a target user (relation type "user")
$auth->user_can('delegate', 42); // bool

// Permission for a single resource
$auth->user_can('manage', 'item', 10); // bool

// List resource IDs accessible for an ability
$auth->user_can('manage', 'item'); // int[]
```

## Controllers and middleware

Included:
- `AuthController`
- `OAuthController`
- `UserController`
- `RequireRole` middleware
