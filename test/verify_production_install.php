<?php

declare(strict_types=1);

// Production smoke test: runs WITHOUT Composer's require-dev dependencies.
// Usage: php test/verify_production_install.php /path/to/vendor/autoload.php
//
// Can validate the repository's own --no-dev install, or a separate
// consumer project's vendor/autoload.php after requiring objectiveweb/auth.
$autoload = $argv[1] ?? null;
if (!is_string($autoload) || !is_file($autoload)) {
    fwrite(STDERR, "Usage: php verify_production_install.php /path/to/vendor/autoload.php\n");
    exit(1);
}
require $autoload;

$assert = static function (bool $value, string $message): void {
    if (!$value) {
        throw new RuntimeException($message);
    }
};

$required = [
    \Objectiveweb\Auth::class,
    \Objectiveweb\Auth\BasicAuth::class,
    \Objectiveweb\Auth\DBAuth::class,
    \Objectiveweb\Auth\AuthException::class,
    \Objectiveweb\Auth\UserException::class,
    \Objectiveweb\Auth\Controller\AuthController::class,
    \Objectiveweb\Auth\Controller\OAuthController::class,
    \Objectiveweb\Auth\Controller\UserController::class,
    \Objectiveweb\DB::class,
    \Objectiveweb\DB\Collection::class,
];
foreach ($required as $class) {
    $assert(class_exists($class), "Production autoload is missing {$class}");
}

// PHPunit/Phinx are development-only. OAuth provider packages and the
// router are optional integrations, not required for the core library.
$assert(!class_exists(\PHPUnit\Framework\TestCase::class), 'PHPUnit was installed in production');
$assert(!class_exists(\Phinx\Migration\AbstractMigration::class), 'Phinx was installed in production');

// Exercise the production DB-backed provider with only runtime dependencies.
// This deliberately does not rely on Phinx (a development dependency).
$db = new \Objectiveweb\DB('sqlite::memory:');
$db->query(
    'CREATE TABLE auth_user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT NOT NULL UNIQUE,
        name TEXT,
        created TEXT,
        password TEXT,
        token TEXT,
        token_expires_at TEXT,
        disabled_at TEXT
    )'
)->exec();
$db->query(
    'CREATE TABLE auth_credentials (
        uid TEXT NOT NULL,
        provider TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        profile TEXT,
        token TEXT,
        token_expires_at TEXT,
        verified_at TEXT,
        last_login TEXT,
        created TEXT,
        PRIMARY KEY(uid, provider)
    )'
)->exec();

$_SESSION = [];
$auth = new \Objectiveweb\Auth\DBAuth($db, [
    'table' => 'auth_user',
    'credentials_table' => 'auth_credentials',
    'roles_table' => null,
    'user_roles_table' => null,
    'token' => 'token',
    'disabled_at' => 'disabled_at',
]);

$new = $auth->register('production@example.com', 'production-password', ['name' => 'Production User']);
$assert(!empty($new['id']), 'DBAuth registration failed without dev dependencies');
$assert(!array_key_exists('password', $new), 'Registration response exposed password');
$assert(
    password_verify('production-password', $auth->get($new['id'])['password']),
    'DBAuth did not store a valid password hash'
);
$logged = $auth->login('production@example.com', 'production-password');
$assert($logged['id'] === $new['id'] && $auth->check(), 'DBAuth login failed');
$assert($auth->user()['name'] === 'Production User', 'DBAuth session context failed');
$assert($auth->revalidate(), 'DBAuth session revalidation failed');

$auth->passwd($new['id'], 'changed-password');
$auth->logout();
$assert(!$auth->check(), 'DBAuth logout failed');
$logged = $auth->login('production@example.com', 'changed-password');
$assert($logged['id'] === $new['id'], 'DBAuth password change failed');
$auth->logout();
$assert(!$auth->check(), 'DBAuth final logout failed');

echo "Production Composer autoload, runtime dependencies and DBAuth authentication smoke test passed.\n";
