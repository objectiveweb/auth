<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\DBAuth;
use Objectiveweb\DB;

$db = new DB(
    sprintf(
        'pgsql:host=%s;port=%s;dbname=%s',
        getenv('PGHOST') ?: '127.0.0.1',
        getenv('PGPORT') ?: '5432',
        getenv('PGDATABASE') ?: 'auth_test'
    ),
    getenv('PGUSER') ?: 'postgres',
    getenv('PGPASSWORD') ?: 'postgres'
);

$auth = new DBAuth($db, [
    'token' => 'token',
    'disabled_at' => 'disabled_at',
]);

$db->insert('role', ['name' => 'admin']);
$db->insert('role', ['name' => 'operator']);

$admin = $auth->register('postgres-admin@example.com', 'secret', [
    'roles' => ['admin', 'operator'],
]);
$auth->register('postgres-viewer@example.com', 'secret', [
    'roles' => ['viewer'],
]);

$admins = $auth->get_users_by_role('admin');

if (count($admins) !== 1) {
    fwrite(STDERR, "Expected exactly one admin\n");
    exit(1);
}

if ((int) $admins[0]['id'] !== (int) $admin['id']) {
    fwrite(STDERR, "Role lookup returned the wrong user\n");
    exit(1);
}

if (($admins[0]['roles'] ?? []) !== ['admin', 'operator']) {
    fwrite(STDERR, "Role hydration did not preserve all user roles\n");
    exit(1);
}

foreach (['password', 'token', 'token_expires_at'] as $secret) {
    if (array_key_exists($secret, $admins[0])) {
        fwrite(STDERR, "Role lookup exposed {$secret}\n");
        exit(1);
    }
}

if ($auth->get_users_by_role('missing') !== []) {
    fwrite(STDERR, "Unknown role should return an empty list\n");
    exit(1);
}

echo "PostgreSQL role lookup passed.\n";
