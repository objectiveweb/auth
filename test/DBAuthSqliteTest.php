<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\DBAuth;
use Objectiveweb\Auth\UserException;
use Objectiveweb\DB;
use PHPUnit\Framework\TestCase;

class DBAuthSqliteTest extends TestCase
{
    private static DB $db;
    private static DBAuth $auth;

    public static function setUpBeforeClass(): void
    {
        self::$db = new DB('sqlite::memory:');

        self::$db->query(
            'CREATE TABLE auth_user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL UNIQUE,
                name TEXT,
                image TEXT,
                created TEXT,
                password TEXT,
                token TEXT,
                token_expires_at TEXT
            )'
        )->exec();

        self::$db->query(
            'CREATE TABLE auth_credentials (
                uid TEXT NOT NULL,
                provider TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                profile TEXT NULL,
                token TEXT NULL,
                verified_at TEXT NULL,
                last_login TEXT NULL,
                created TEXT NULL,
                PRIMARY KEY(uid, provider)
            )'
        )->exec();

        self::$db->query(
            'CREATE TABLE auth_role (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )'
        )->exec();

        self::$db->query(
            'CREATE TABLE auth_user_role (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                PRIMARY KEY(user_id, role_id)
            )'
        )->exec();

        self::$db->query(
            'CREATE TABLE user_delegations (
                user_id INTEGER NOT NULL,
                target_user_id INTEGER NOT NULL,
                ability TEXT NOT NULL
            )'
        )->exec();

        self::$db->query(
            'CREATE TABLE item_users (
                user_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                ability TEXT NOT NULL
            )'
        )->exec();

        self::$auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'credentials_created' => 'created',
            'roles' => 'roles',
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
                ],
            ],
        ]);
    }

    protected function setUp(): void
    {
        $_SESSION = [];
        self::$db->query('DELETE FROM auth_credentials')->exec();
        self::$db->query('DELETE FROM auth_user_role')->exec();
        self::$db->query('DELETE FROM auth_role')->exec();
        self::$db->query('DELETE FROM user_delegations')->exec();
        self::$db->query('DELETE FROM item_users')->exec();
        self::$db->query('DELETE FROM auth_user')->exec();
    }

    public function testRegistration(): void
    {
        $user = self::$auth->register('alice@example.com', 'secret', ['name' => 'Alice']);
        $this->assertArrayHasKey('id', $user);
        $this->assertSame(1, (int) $user['id']);
        $this->assertArrayHasKey('uuid', $user);
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $user['uuid']
        );
        $this->assertSame('Alice', $user['name']);

        $logged = self::$auth->login('alice@example.com', 'secret');
        $this->assertSame($user['id'], $logged['id']);
        $this->assertMatchesRegularExpression(
            '/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/',
            $logged['created']
        );
        $this->assertTrue(self::$auth->check());

        $sessionUser = self::$auth->user();
        $this->assertSame($user['id'], $sessionUser['id']);

        self::$auth->logout();
        $this->assertFalse(self::$auth->check());
    }

    public function testInvalidLogin(): void
    {
        $this->expectException(UserException::class);
        self::$auth->login('nouser@example.com', 'pass');
    }

    public function testInvalidPassword(): void
    {
        self::$auth->register('alice@example.com', 'secret');
        $this->expectException(AuthException::class);
        self::$auth->login('alice@example.com', 'wrong');
    }

    public function testLoginWithPhoneProviderWhenConfiguredInLoginProviders(): void
    {
        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'token' => 'token',
            'created' => 'created',
            'login_providers' => ['phone', 'email', 'local'],
        ]);

        $auth->register('+5511999999999', 'secret', ['provider' => 'phone', 'name' => 'Phone User']);
        $logged = $auth->login('+5511999999999', 'secret');

        $this->assertSame('Phone User', $logged['name']);
    }

    public function testUsesCredentialLastLoginDefaultWithConfiguredRoleTables(): void
    {
        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'token' => 'token',
            'created' => 'created',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
        ]);

        $user = $auth->register('autodetect@example.com', 'secret', [
            'roles' => ['admin'],
        ]);

        self::$db->update('auth_credentials', ['last_login' => null], [
            'provider' => 'local',
            'uid' => 'autodetect@example.com',
        ]);

        $logged = $auth->login('autodetect@example.com', 'secret');
        $credential = $auth->get_credential('local', 'autodetect@example.com');

        $this->assertSame($user['id'], $logged['id']);
        $this->assertSame(['admin'], $logged['roles']);
        $this->assertNotNull($credential['last_login'] ?? null);
    }

    public function testLoginHydratesRolesWhenRoleIsAssignedInDatabase(): void
    {
        $user = self::$auth->register('dbrole@example.com', 'secret', ['name' => 'DB Role User']);

        $roleId = self::$db->insert('auth_role', ['name' => 'manager']);
        self::$db->insert('auth_user_role', [
            'user_id' => $user['id'],
            'role_id' => $roleId,
        ]);

        $logged = self::$auth->login('dbrole@example.com', 'secret');
        $this->assertArrayHasKey('roles', $logged);
        $this->assertSame(['manager'], $logged['roles']);

        $sessionUser = self::$auth->user();
        $this->assertArrayHasKey('roles', $sessionUser);
        $this->assertSame(['manager'], $sessionUser['roles']);
    }

    public function testLoginHydratesRolesWhenRoleTablesAreConfiguredAtInstantiation(): void
    {
        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'token' => 'token',
            'created' => 'created',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
        ]);

        $user = $auth->register('autorole@example.com', 'secret');
        $roleId = self::$db->insert('auth_role', ['name' => 'viewer']);
        self::$db->insert('auth_user_role', [
            'user_id' => $user['id'],
            'role_id' => $roleId,
        ]);

        $logged = $auth->login('autorole@example.com', 'secret');
        $this->assertArrayHasKey('roles', $logged);
        $this->assertSame(['viewer'], $logged['roles']);
    }

    public function testPasswd(): void
    {
        $user = self::$auth->register('alice@example.com', 'secret');
        $account = self::$auth->get_credential('local', 'alice@example.com');

        $this->assertNotFalse($account);

        $updated = self::$auth->passwd($account['user_id'], 'new-secret');
        $this->assertTrue($updated);

        $logged = self::$auth->login('alice@example.com', 'new-secret');
        $this->assertSame($user['id'], $logged['id']);
    }

    public function testUpdate(): void
    {
        $user = self::$auth->register('alice@example.com', 'secret', ['name' => 'Alice']);
        $account = self::$auth->get_credential('local', 'alice@example.com');

        $current = self::$auth->get($account['user_id']);
        $this->assertSame('Alice', $current['name']);
        $this->assertSame($user['uuid'], $current['uuid']);

        self::$auth->update($user['id'], ['name' => 'Alice Updated', 'uuid' => 'manual-value']);
        $updated = self::$auth->get($user['id']);

        $this->assertSame('Alice Updated', $updated['name']);
        $this->assertSame($user['uuid'], $updated['uuid']);
    }

    public function testQuery(): void
    {
        self::$auth->register('alice@example.com', 'secret', ['name' => 'Alice']);
        $list = self::$auth->query();

        $this->assertSame(1, count($list['_embedded']['auth_user']));
        $this->assertSame('Alice', $list['_embedded']['auth_user'][0]['name']);
        $this->assertSame(1, $list['page']['totalElements']);
        $this->assertSame(1, $list['page']['totalPages']);
        $this->assertSame(0, $list['page']['number']);
    }

    public function testRequestToken(): void
    {
        $user = self::$auth->register('alice@example.com', 'secret');
        $account = self::$auth->get_credential('local', 'alice@example.com');
        $this->assertSame($user['id'], $account['user_id']);

        $token = self::$auth->update_token($account['user_id']);
        $stored = self::$db->select('auth_user', ['id' => $account['user_id']], ['limit' => 1])->fetch();
        $this->assertIsString($stored['token']);
        $this->assertTrue(password_verify($token, $stored['token']));
        $this->assertNotNull($stored['token_expires_at']);
        self::$auth->passwd_reset($token, 'final-secret');

        $logged = self::$auth->login('alice@example.com', 'final-secret');
        $this->assertSame($user['id'], $logged['id']);
    }

    public function testPasswdResetRejectsExpiredToken(): void
    {
        $user = self::$auth->register('expired@example.com', 'secret');
        $token = self::$auth->update_token($user['id']);
        self::$db->update('auth_user', ['token_expires_at' => '2000-01-01 00:00:00'], ['id' => $user['id']]);

        $this->expectException(UserException::class);
        self::$auth->passwd_reset($token, 'new-secret');
    }

    public function testDelete(): void
    {
        $this->expectException(UserException::class);

        self::$auth->register('alice@example.com', 'secret');
        $account = self::$auth->get_credential('local', 'alice@example.com');
        self::$auth->logout();

        self::$auth->delete($account['user_id']);
        self::$auth->login('alice@example.com', 'secret');
    }

    public function testGetCredentialsReturnsOnlyExpectedFields(): void
    {
        $user = self::$auth->register('alice@example.com', 'secret');
        self::$auth->update_credential($user['id'], 'phone', '+5511999999999', ['carrier' => 'test']);

        $credentials = self::$auth->get_credentials($user['id']);

        $this->assertCount(2, $credentials);
        foreach ($credentials as $credential) {
            $this->assertSame(
                ['uid', 'provider', 'profile', 'last_login', 'created'],
                array_keys($credential)
            );
            $this->assertNotNull($credential['last_login']);
            $this->assertNotNull($credential['created']);
        }
    }

    public function testUserCanChecksRoles(): void
    {
        self::$auth->register('scoped@example.com', 'secret', [
            'roles' => ['admin'],
        ]);

        self::$auth->login('scoped@example.com', 'secret');

        $this->assertTrue(self::$auth->user_can('admin'));
        $this->assertFalse(self::$auth->user_can('operator'));

        $current = self::$auth->user();
        $this->assertSame(['admin'], $current['roles']);
    }

    public function testUpdateRolesReplacesAssignments(): void
    {
        $user = self::$auth->register('roles@example.com', 'secret', [
            'roles' => ['partner'],
        ]);

        self::$auth->update($user['id'], ['roles' => ['operator', 'admin']]);
        $reloaded = self::$auth->get($user['id']);

        $this->assertSame(['admin', 'operator'], $reloaded['roles']);
    }

    public function testUserCanChecksDelegationForSpecificUser(): void
    {
        $actor = self::$auth->register('owner@example.com', 'secret');
        $target = self::$auth->register('target@example.com', 'secret');
        self::$auth->login('owner@example.com', 'secret');

        self::$db->insert('user_delegations', [
            'user_id' => $actor['id'],
            'target_user_id' => $target['id'],
            'ability' => 'admin',
        ]);

        $this->assertTrue(self::$auth->user_can('admin', (int) $target['id']));
        $this->assertFalse(self::$auth->user_can('manage', (int) $target['id']));
    }

    public function testUserCanChecksResourceAndListsResourceIds(): void
    {
        $actor = self::$auth->register('manager@example.com', 'secret');
        self::$auth->login('manager@example.com', 'secret');

        self::$db->insert('item_users', [
            'user_id' => $actor['id'],
            'item_id' => 10,
            'ability' => 'manage',
        ]);
        self::$db->insert('item_users', [
            'user_id' => $actor['id'],
            'item_id' => 3,
            'ability' => 'manage',
        ]);
        self::$db->insert('item_users', [
            'user_id' => $actor['id'],
            'item_id' => 3,
            'ability' => 'manage',
        ]);
        self::$db->insert('item_users', [
            'user_id' => $actor['id'],
            'item_id' => 12,
            'ability' => 'view',
        ]);

        $this->assertTrue(self::$auth->user_can('manage', 'item', 10));
        $this->assertFalse(self::$auth->user_can('manage', 'item', 12));
        $this->assertSame([3, 10], self::$auth->user_can('manage', 'item'));
        $this->assertSame([12], self::$auth->user_can('view', 'item'));
    }

    public function testUserCanReturnsFalseOrEmptyWhenUnauthenticatedForRelationModes(): void
    {
        self::$auth->register('anon@example.com', 'secret');
        $this->assertFalse(self::$auth->user_can('manage'));
        $this->assertFalse(self::$auth->user_can('manage', 1));
        $this->assertFalse(self::$auth->user_can('manage', 'item', 1));
        $this->assertSame([], self::$auth->user_can('manage', 'item'));
    }

    public function testUserCanGlobalCheckDoesNotReadRelationshipRows(): void
    {
        $actor = self::$auth->register('owner@example.com', 'secret');
        self::$auth->login('owner@example.com', 'secret');

        self::$db->insert('item_users', [
            'user_id' => $actor['id'],
            'item_id' => 10,
            'ability' => 'admin',
        ]);

        $this->assertFalse(self::$auth->user_can('admin'));
        $this->assertTrue(self::$auth->user_can('admin', 'item', 10));
    }

    public function testUserCanSupportsRoleBasedRelationshipMapping(): void
    {
        self::$db->query(
            'CREATE TABLE IF NOT EXISTS item_members (
                user_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                role TEXT NOT NULL
            )'
        )->exec();
        self::$db->query('DELETE FROM item_members')->exec();

        $roleAuth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'roles' => 'roles',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
            'relations' => [
                'item' => [
                    'table' => 'item_members',
                    'subject_key' => 'user_id',
                    'target_key' => 'item_id',
                    'role_key' => 'role',
                    'role_abilities' => [
                        'owner' => ['manage', 'view'],
                        'staff' => ['view'],
                    ],
                ],
            ],
        ]);

        $actor = $roleAuth->register('rolemap@example.com', 'secret');
        $roleAuth->login('rolemap@example.com', 'secret');

        self::$db->insert('item_members', [
            'user_id' => $actor['id'],
            'item_id' => 20,
            'role' => 'owner',
        ]);
        self::$db->insert('item_members', [
            'user_id' => $actor['id'],
            'item_id' => 22,
            'role' => 'staff',
        ]);

        $this->assertTrue($roleAuth->user_can('manage', 'item', 20));
        $this->assertFalse($roleAuth->user_can('manage', 'item', 22));
        $this->assertSame([20, 22], $roleAuth->user_can('view', 'item'));
    }

    public function testGetHydratesRelationWithEagerTrue(): void
    {
        $eagerAuth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'roles' => 'roles',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
            'relations' => [
                'item' => [
                    'table' => 'item_users',
                    'subject_key' => 'user_id',
                    'target_key' => 'item_id',
                    'ability_key' => 'ability',
                    'eager' => true,
                ],
            ],
        ]);

        $user = $eagerAuth->register('eager1@example.com', 'secret');
        self::$db->insert('item_users', ['user_id' => $user['id'], 'item_id' => 4, 'ability' => 'view']);
        self::$db->insert('item_users', ['user_id' => $user['id'], 'item_id' => 8, 'ability' => 'manage']);

        $loaded = $eagerAuth->get($user['id']);
        $this->assertArrayHasKey('item', $loaded);
        $ids = array_values(array_map(fn (array $item): int => (int) $item['item_id'], $loaded['item']));
        sort($ids);
        $this->assertSame([4, 8], $ids);
    }

    public function testGetHydratesRelationWithEagerArrayAsSelectParams(): void
    {
        $eagerAuth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'roles' => 'roles',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
            'relations' => [
                'item' => [
                    'table' => 'item_users',
                    'subject_key' => 'user_id',
                    'target_key' => 'item_id',
                    'ability_key' => 'ability',
                    'eager' => ['order' => 'item_id DESC'],
                ],
            ],
        ]);

        $user = $eagerAuth->register('eager2@example.com', 'secret');
        self::$db->insert('item_users', ['user_id' => $user['id'], 'item_id' => 3, 'ability' => 'view']);
        self::$db->insert('item_users', ['user_id' => $user['id'], 'item_id' => 9, 'ability' => 'view']);

        $loaded = $eagerAuth->get($user['id']);
        $ids = array_values(array_map(fn (array $item): int => (int) $item['item_id'], $loaded['item']));
        $this->assertSame([9, 3], $ids);
    }

    public function testUserCanThrowsForInvalidSignatureAndUnknownRelation(): void
    {
        self::$auth->register('owner@example.com', 'secret');
        self::$auth->login('owner@example.com', 'secret');

        $this->expectException(\InvalidArgumentException::class);
        self::$auth->user_can('manage', 'item', '1');
    }

    public function testUserCanThrowsForUnknownRelationType(): void
    {
        self::$auth->register('owner@example.com', 'secret');
        self::$auth->login('owner@example.com', 'secret');

        $this->expectException(\InvalidArgumentException::class);
        self::$auth->user_can('manage', 'invoice', 1);
    }

    public function testRoleTablesMustBeConfiguredTogether(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'roles_table' => 'auth_role',
            'user_roles_table' => null,
        ]);
    }
}
