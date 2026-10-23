<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\DBAuth;
use Objectiveweb\Auth\UserException;
use Objectiveweb\DB;
use Objectiveweb\DB\Collection;

// Exercise DBAuth's actual CRUD, role joins, credentials and token workflows
// on the schema created by Phinx, not on a hand-crafted SQLite test schema.
$_SESSION = [];
$db = new DB(
    sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        getenv('MYSQL_HOST') ?: '127.0.0.1',
        getenv('MYSQL_PORT') ?: '3306',
        getenv('MYSQL_DATABASE') ?: 'auth_test'
    ),
    getenv('MYSQL_USER') ?: 'auth_user',
    getenv('MYSQL_PASSWORD') ?: ''
);

$auth = new DBAuth($db, [
    'token' => 'token',
    'disabled_at' => 'disabled_at',
]);

$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

$expectFailure = static function (
    callable $callback, string $expectedClass, int $expectedCode
) use ($assert): void {
    try {
        $callback();
    } catch (Throwable $exception) {
        $assert($exception instanceof $expectedClass, 'Unexpected error type: ' . get_class($exception));
        $assert($exception->getCode() === $expectedCode, 'Unexpected error code: ' . $exception->getCode());
        return;
    }
    throw new RuntimeException("Expected {$expectedClass} ({$expectedCode})");
};

// Real MySQL INSERTs and foreign-key-backed role assignment.
$admin = $auth->register('mysql-admin@example.com', 'original-secret', [
    'name' => 'MySQL Admin',
    'roles' => ['admin', 'operator'],
]);
$viewer = $auth->register('mysql-viewer@example.com', 'viewer-secret', [
    'name' => 'MySQL Viewer',
    'roles' => ['viewer'],
]);

$assert(!empty($admin['uuid']) && $admin['id'] !== $viewer['id'], 'Missing distinct user IDs or UUID');
$assert(!array_key_exists('password', $admin), 'Registration exposed password hash');
$assert($auth->get_users_by_role('admin')[0]['id'] == $admin['id'], 'Role join returned wrong user');
$assert($auth->get_users_by_role('admin')[0]['roles'] === ['admin', 'operator'], 'Role join lost other roles');
$assert($auth->get_users_by_role('nonexistent') === [], 'Unknown role returned users');

$listing = $auth->query(['page' => 0, 'size' => 1, 'sort' => 'name ASC']);
$assert($listing instanceof Collection, 'Query must return a Collection');
$assert($listing->total() === 2 && count($listing) === 1, 'Query pagination totals are wrong');
$assert($listing->contentRange() === 'items 0-0/2', 'Query content range is wrong');
$assert($listing[0]['name'] === 'MySQL Admin', 'Query returned wrong sorted user');
$search = $auth->query(['q' => 'mysql-viewer@example.com', 'size' => 10]);
$assert($search->total() === 1, 'Credential UID search on MySQL failed');

$expectFailure(
    static fn () => $auth->login('missing@example.com', 'invalid'),
    AuthException::class,
    401
);
$expectFailure(
    static fn () => $auth->login('mysql-admin@example.com', 'invalid'),
    AuthException::class,
    401
);
$logged = $auth->login('mysql-admin@example.com', 'original-secret');
$assert($logged['id'] == $admin['id'] && $auth->check(), 'MySQL login/session failed');
$assert($auth->user()['roles'] === ['admin', 'operator'], 'Session did not hydrate roles');
$auth->logout();

// Reset tokens must be hashed at rest, expired on consumption and usable once.
$reset = $auth->update_token($admin['id']);
$stored = $db->select('user', ['id' => $admin['id']], ['limit' => 1])->fetch();
$assert($stored['token'] === hash('sha256', $reset), 'Reset token not stored as digest');
$assert(!empty($stored['token_expires_at']), 'Reset token expiry missing');
$auth->passwd_reset($reset, 'replacement-secret');
$expectFailure(
    static fn () => $auth->passwd_reset($reset, 'replay-secret'),
    UserException::class,
    404
);
$expectFailure(
    static fn () => $auth->login('mysql-admin@example.com', 'original-secret'),
    AuthException::class,
    401
);
$auth->login('mysql-admin@example.com', 'replacement-secret');
$auth->logout();

// Direct password updates must invalidate any previously issued reset link
// in the same SQL statement, without leaving a usable stale token.
$pendingReset = $auth->update_token($admin['id']);
$auth->passwd($admin['id'], 'changed-by-user-secret');
$stored = $db->select('user', ['id' => $admin['id']], ['limit' => 1])->fetch();
$assert($stored['token'] === null && $stored['token_expires_at'] === null,
    'Password change did not revoke the outstanding reset token');
$expectFailure(
    static fn () => $auth->passwd_reset($pendingReset, 'stale-reset-secret'),
    UserException::class,
    404
);
$auth->login('mysql-admin@example.com', 'changed-by-user-secret');
$auth->logout();

// Each credential has its own token, expiration and verification state.
$credential = $auth->create_credential($admin['id'], 'email', 'admin-contact@example.com');
$assert(empty($credential['verified_at']), 'New email credential should be unverified');
$verification = $auth->issue_credential_token($admin['id'], 'email', 'admin-contact@example.com');
$storedCredential = $auth->get_credential('email', 'admin-contact@example.com');
$assert(
    $storedCredential['token'] === hash('sha256', $verification),
    'Credential verification token not stored as digest'
);
$assert(
    !$auth->verify_credential_token('email', 'admin-contact@example.com', 'bad-token'),
    'Bad credential token was accepted'
);
$assert(
    $auth->verify_credential_token('email', 'admin-contact@example.com', $verification),
    'Valid credential token failed'
);
$assert(
    !$auth->verify_credential_token('email', 'admin-contact@example.com', $verification),
    'Credential verification token was reused'
);
$assert(
    !empty($auth->get_credential('email', 'admin-contact@example.com')['verified_at']),
    'Verified credential is missing verified_at'
);

// Roles are synced portably with MySQL's SQL dialect. Preserve another
// active admin while demoting the account under test.
$backupAdmin = $auth->register('mysql-backup-admin@example.com', 'backup-secret', [
    'roles' => ['admin'],
]);
$auth->update($admin['id'], ['roles' => ['operator']]);
$assert($auth->get($admin['id'])['roles'] === ['operator'], 'Role replacement failed');
$remainingAdmins = $auth->get_users_by_role('admin');
$assert(count($remainingAdmins) === 1 && $remainingAdmins[0]['id'] == $backupAdmin['id'],
    'Removed role still grants access or backup admin was lost');
$auth->delete($viewer['id']);
$assert($auth->get_users_by_role('viewer') === [], 'Deleted user still appears in role lookup');
$assert(count($auth->query()) === 2, 'Deleted user still appears in MySQL query');

// Provider identity comparisons must remain exact even when the database's
// default collation is case-insensitive. These are distinct OAuth subjects.
$subjects = [
    ['google', 'OAuthSubjectAbC'],
    ['google', 'oauthsubjectabc'],
    ['google', 'OAuthSubjectAbC '],
    ['Google', 'OAuthSubjectAbC'],
];
$identityUserIds = [];
foreach ($subjects as [$provider, $uid]) {
    $user = $auth->register($uid, null, ['provider' => $provider]);
    $identityUserIds[] = $user['id'];
    $credential = $auth->get_credential($provider, $uid);
    $assert(
        $credential !== false && $credential['user_id'] == $user['id'],
        "MySQL returned another account for {$provider}/{$uid}"
    );
}
$assert(
    count(array_unique($identityUserIds)) === count($subjects),
    'Distinct OAuth subjects must never resolve to the same user'
);
$assert(
    $auth->get_credential('google', 'OAUTHSUBJECTABC') === false,
    'MySQL incorrectly resolved an OAuth subject using case-insensitive lookup'
);

echo "MySQL 8 DBAuth registration, roles, login, pagination, password reset, credential verification and deletion passed.\n";
