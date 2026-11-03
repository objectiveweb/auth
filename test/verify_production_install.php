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

$_SESSION = [];
$auth = new \Objectiveweb\Auth\BasicAuth();
$new = $auth->register('production@example.com', 'production-password', ['name' => 'Production User']);
$assert(!empty($new['id']), 'BasicAuth registration failed without dev dependencies');
$assert(!array_key_exists('password', $new), 'Registration response exposed password');
$logged = $auth->login('production@example.com', 'production-password');
$assert($logged['id'] === $new['id'] && $auth->check(), 'BasicAuth login failed');
$assert($auth->user()['name'] === 'Production User', 'BasicAuth session context failed');
$auth->logout();
$assert(!$auth->check(), 'BasicAuth logout failed');

// The DB abstraction must resolve from require, not require-dev. Instantiate
// DBAuth against SQLite without relying on Phinx or PHPUnit to create schema.
$db = new \Objectiveweb\DB('sqlite::memory:');
$dbAuth = new \Objectiveweb\Auth\DBAuth($db, ['roles_table' => null, 'user_roles_table' => null]);
$assert(!$dbAuth->check(), 'DBAuth did not initialize in production');

echo "Production Composer autoload, runtime dependencies and authentication smoke test passed.\n";
