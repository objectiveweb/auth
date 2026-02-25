# objectiveweb/auth

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
- optional related data inserts (`with`)
- immutable UUID generation on user creation (default field name: `uuid`)

#### Minimal setup

```php
use Objectiveweb\Auth\DBAuth;
use Objectiveweb\DB;

$db = new DB('sqlite:/tmp/app.sqlite'); // or mysql:..., pgsql:...

$auth = new DBAuth($db, [
    'table' => 'auth_user',
    'credentials_table' => 'auth_credentials',
    'id' => 'id',
    'password' => 'password',
    'scopes' => 'scopes',
    'token' => 'token',
    'created' => 'created',
    'uuid' => 'uuid',
    'credentials_last_login' => 'last_login',
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
    scopes TEXT,
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
```

#### DBAuth params

- `session_key`: session storage key (default `ow_auth`)
- `id`: user PK field (default `id`)
- `password`: password field (default `password`)
- `scopes`: scopes field (default `scopes`)
- `token`: optional password-reset token field
- `table`: users table name (default `user`)
- `credentials_table`: credentials table name (default `user_credentials`)
- `created`: optional created-at field
- `last_login`: optional user last-login field
- `credentials_last_login`: optional credentials last-login field
- `uuid`: UUID field created on register and protected from updates (default `uuid`)
- `with`: associative array for extra related inserts, format: `['table_name' => 'foreign_key']`

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

## Query and update

```php
// List users (paginated response)
$result = $auth->query(['page' => 0, 'size' => 20]);

// Update user profile data
$auth->update($userId, ['name' => 'Alice Updated']);

// Update password
$auth->passwd($userId, 'new-password');
```

## Controllers and middleware

Included:
- `AuthController`
- `OAuthController`
- `UserController`
- `RequireScope` middleware
