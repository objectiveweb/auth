<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\DBAuth;
use Objectiveweb\Auth\Controller\AuthController;
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
                token_expires_at TEXT,
                disabled_at TEXT
            )'
        )->exec();

        self::$db->query('CREATE INDEX auth_user_token_idx ON auth_user(token)')->exec();

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

        self::$db->query(
            'CREATE TABLE managed_items (
                user_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                PRIMARY KEY(user_id, item_id)
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
            'disabled_at' => 'disabled_at',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
            'relations' => [
                'user' => [
                    'table' => 'user_delegations',
                    'subject_key' => 'user_id',
                    'target_key' => 'target_user_id',
                    'ability_key' => 'ability',
                    'target_is_user' => true,
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
        self::$db->query('DELETE FROM managed_items')->exec();
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
        $this->assertArrayNotHasKey('password', $user);
        $this->assertArrayNotHasKey('token', $user);
        $this->assertArrayNotHasKey('token_expires_at', $user);

        $stored = self::$auth->get($user['id']);
        $this->assertArrayHasKey('password', $stored);

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
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
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

        $this->assertInstanceOf(\Objectiveweb\DB\Collection::class, $list);
        $this->assertCount(1, $list);
        $this->assertSame(1, $list->total());
        $this->assertSame('items 0-0/1', $list->contentRange());
        $this->assertSame('Alice', $list[0]['name']);
        $this->assertArrayNotHasKey('password', $list[0]);
        $this->assertArrayNotHasKey('token', $list[0]);
        $this->assertArrayNotHasKey('token_expires_at', $list[0]);
    }

    public function testQueryPaginatesAndSortsBeforeHydration(): void
    {
        self::$auth->register('charlie@example.com', 'secret', ['name' => 'Charlie']);
        self::$auth->register('alice@example.com', 'secret', ['name' => 'Alice']);
        self::$auth->register('bob@example.com', 'secret', ['name' => 'Bob']);

        $first = self::$auth->query([
            'page' => 0,
            'size' => 2,
            'sort' => 'name ASC',
        ]);
        $second = self::$auth->query([
            'page' => 1,
            'size' => 2,
            'sort' => 'name ASC',
        ]);

        $this->assertSame(3, $first->total());
        $this->assertSame('items 0-1/3', $first->contentRange());
        $this->assertSame('items 2-2/3', $second->contentRange());
        $this->assertSame(['Alice', 'Bob'], array_column($first->data(), 'name'));
        $this->assertSame(['Charlie'], array_column($second->data(), 'name'));

        foreach ($first as $user) {
            $this->assertArrayHasKey('credentials', $user);
            $this->assertCount(1, $user['credentials']);
        }
    }

    public function testQueryCombinesSearchRoleAndLifecycleFilters(): void
    {
        self::$auth->register('active-admin@example.com', 'secret', [
            'name' => 'Active Admin',
            'roles' => ['admin'],
        ]);
        self::$auth->register('suspended-admin@example.com', 'secret', [
            'name' => 'Suspended Admin',
            'roles' => ['admin'],
            'disabled_at' => '2026-09-30 12:00:00',
        ]);
        self::$auth->register('active-viewer@example.com', 'secret', [
            'name' => 'Active Viewer',
            'roles' => ['viewer'],
        ]);

        $result = self::$auth->query([
            'q' => 'admin@example.com',
            'role' => 'admin',
            'status' => 'active',
            'size' => 10,
        ]);

        $this->assertSame(1, $result->total());
        $this->assertSame('Active Admin', $result[0]['name']);
        $this->assertSame(['admin'], $result[0]['roles']);
        $this->assertSame(
            'active-admin@example.com',
            $result[0]['credentials'][0]['uid']
        );
    }

    public function testQueryUnassignedWorksWithAndWithoutRoleTables(): void
    {
        self::$auth->register('assigned@example.com', 'secret', ['roles' => ['admin']]);
        self::$auth->register('unassigned@example.com', 'secret');

        $withRoles = self::$auth->query(['role' => 'unassigned', 'size' => 10]);
        $this->assertSame(1, $withRoles->total());
        $this->assertSame('unassigned', $withRoles[0]['name']);

        $withoutRoles = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'credentials_created' => 'created',
            'roles_table' => null,
            'user_roles_table' => null,
        ]);
        $result = $withoutRoles->query(['role' => 'unassigned', 'size' => 10]);
        $this->assertSame(2, $result->total());
    }

    public function testRequestToken(): void
    {
        $user = self::$auth->register('alice@example.com', 'secret');
        $account = self::$auth->get_credential('local', 'alice@example.com');
        $this->assertSame($user['id'], $account['user_id']);

        $token = self::$auth->update_token($account['user_id']);
        $stored = self::$db->select('auth_user', ['id' => $account['user_id']], ['limit' => 1])->fetch();
        $this->assertIsString($stored['token']);
        $this->assertSame(hash('sha256', $token), $stored['token']);
        $this->assertSame(64, strlen($stored['token']));
        $this->assertNotNull($stored['token_expires_at']);
        $reset = self::$auth->passwd_reset($token, 'final-secret');
        $this->assertArrayNotHasKey('password', $reset);
        $this->assertArrayNotHasKey('token', $reset);
        $this->assertArrayNotHasKey('token_expires_at', $reset);

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

    public function testGetByConfiguredUuidUsesUserTable(): void
    {
        $user = self::$auth->register('uuid-lookup@example.com', 'secret');

        $loaded = self::$auth->get($user['uuid'], 'uuid');

        $this->assertSame((int) $user['id'], (int) $loaded['id']);
        $this->assertSame($user['uuid'], $loaded['uuid']);
    }

    public function testPasswdResetUsesConfiguredDatabasePrefix(): void
    {
        $db = new DB('sqlite::memory:', null, '', ['prefix' => 'app_']);
        $db->query(
            'CREATE TABLE app_user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password TEXT,
                token TEXT,
                token_expires_at TEXT
            )'
        )->exec();

        $auth = new DBAuth($db, [
            'table' => 'user',
            'created' => null,
            'uuid' => null,
            'token' => 'token',
            'roles_table' => null,
            'user_roles_table' => null,
        ]);

        $userId = $db->insert('user', ['password' => null, 'token' => null, 'token_expires_at' => null]);
        $token = $auth->update_token($userId);
        $user = $auth->passwd_reset($token, 'new-secret');

        $this->assertSame((int) $userId, (int) $user['id']);
        $stored = $db->select('user', ['id' => $userId], ['limit' => 1])->fetch();
        $this->assertTrue(password_verify('new-secret', $stored['password']));
        $this->assertNull($stored['token']);
        $this->assertNull($stored['token_expires_at']);
    }

    public function testDbAuthAuthenticatedPasswordChangeVerifiesCurrentPassword(): void
    {
        $user = self::$auth->register('db-password-change@example.com', 'old-secret');
        self::$auth->login('db-password-change@example.com', 'old-secret');
        $controller = new AuthController(self::$auth);

        $originalHeader = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $controller->index()['_csrf'];

        try {
            try {
                $controller->postPassword([
                    'current_password' => 'invalid',
                    'password' => 'new-secret',
                    'confirm' => 'new-secret',
                ]);
                $this->fail('Incorrect current password was accepted');
            } catch (AuthException $exception) {
                $this->assertSame(403, $exception->getCode());
            }

            $this->assertTrue(password_verify('old-secret', self::$auth->get($user['id'])['password']));
            $this->assertTrue($controller->postPassword([
                'current_password' => 'old-secret',
                'password' => 'new-secret',
                'confirm' => 'new-secret',
            ]));
            $this->assertTrue(password_verify('new-secret', self::$auth->get($user['id'])['password']));

            self::$auth->logout();
            $this->assertSame($user['id'], self::$auth->login('db-password-change@example.com', 'new-secret')['id']);
        } finally {
            if ($originalHeader === null) {
                unset($_SERVER['HTTP_X_CSRF_TOKEN']);
            } else {
                $_SERVER['HTTP_X_CSRF_TOKEN'] = $originalHeader;
            }
        }
    }

    public function testAuthControllerResponsesDoNotExposeUserSecrets(): void
    {
        $controller = new AuthController(self::$auth);

        $registered = $controller->postRegister([
            'uid' => 'controller@example.com',
            'password' => 'secret',
        ]);
        $this->assertArrayNotHasKey('password', $registered);
        $this->assertArrayNotHasKey('token', $registered);
        $this->assertArrayNotHasKey('token_expires_at', $registered);

        $token = self::$auth->update_token($registered['id']);
        $reset = $controller->postToken([
            'token' => $token,
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]);
        $this->assertArrayNotHasKey('password', $reset);
        $this->assertArrayNotHasKey('token', $reset);
        $this->assertArrayNotHasKey('token_expires_at', $reset);
    }

    public function testInvitationCallbackReceivesSanitizedUser(): void
    {
        $captured = null;
        self::$auth->params['invitation_callback'] = function (array $user) use (&$captured): void {
            $captured = $user;
        };

        try {
            $user = self::$auth->register('invite@example.com', 'secret');
            self::$auth->invite($user['id']);

            $this->assertIsArray($captured);
            $this->assertArrayNotHasKey('password', $captured);
            $this->assertArrayNotHasKey('token', $captured);
            $this->assertArrayNotHasKey('token_expires_at', $captured);
        } finally {
            self::$auth->params['invitation_callback'] = null;
        }
    }

    public function testDuplicateCredentialExceptionDoesNotExposeUserSecrets(): void
    {
        self::$auth->register('duplicate@example.com', 'secret');

        try {
            self::$auth->register('duplicate@example.com', 'another-secret');
            $this->fail('Expected duplicate credential exception');
        } catch (UserException $exception) {
            $user = $exception->getUser();
            $this->assertIsArray($user);
            $this->assertArrayNotHasKey('password', $user);
            $this->assertArrayNotHasKey('token', $user);
            $this->assertArrayNotHasKey('token_expires_at', $user);
        }
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
            $this->assertArrayHasKey('last_login', $credential);
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

    public function testGetUsersByRoleReturnsOnlyUsersWithMatchingRole(): void
    {
        $admin = self::$auth->register('admin@example.com', 'secret', [
            'name' => 'Admin',
            'roles' => ['admin', 'operator'],
        ]);
        self::$auth->register('viewer@example.com', 'secret', [
            'name' => 'Viewer',
            'roles' => ['viewer'],
        ]);

        $admins = self::$auth->get_users_by_role('admin');

        $this->assertCount(1, $admins);
        $this->assertSame($admin['id'], $admins[0]['id']);
        $this->assertSame(['admin', 'operator'], $admins[0]['roles']);
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

    public function testEagerRelationHydrationDoesNotIncludeOtherUsersRowsForSharedTarget(): void
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

        $alice = $eagerAuth->register('eager-alice@example.com', 'secret');
        $bob = $eagerAuth->register('eager-bob@example.com', 'secret');

        self::$db->insert('item_users', [
            'user_id' => $alice['id'],
            'item_id' => 42,
            'ability' => 'view',
        ]);
        self::$db->insert('item_users', [
            'user_id' => $bob['id'],
            'item_id' => 42,
            'ability' => 'manage',
        ]);

        $loaded = $eagerAuth->get($alice['id']);

        $this->assertCount(1, $loaded['item']);
        $this->assertSame((int) $alice['id'], (int) $loaded['item'][0]['user_id']);
        $this->assertSame(42, (int) $loaded['item'][0]['item_id']);
        $this->assertSame('view', $loaded['item'][0]['ability']);
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

    public function testSuspendedUserCannotLoginAndExistingSessionIsInvalidated(): void
    {
        $user = self::$auth->register('suspended@example.com', 'secret');
        self::$auth->login('suspended@example.com', 'secret');
        self::$auth->update($user['id'], ['disabled_at' => '2026-07-25 12:00:00']);

        $this->assertFalse(self::$auth->revalidate());
        $this->assertFalse(self::$auth->check());

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(403);
        self::$auth->login('suspended@example.com', 'secret');
    }

    public function testCredentialLifecycleEnforcesOwnershipUniquenessAndLastCredential(): void
    {
        $alice = self::$auth->register('alice@example.com', 'secret');
        $bob = self::$auth->register('bob@example.com', 'secret');
        self::$auth->create_credential($alice['id'], 'local', 'alice.secondary@example.com');
        $renamed = self::$auth->rename_credential(
            $alice['id'],
            'local',
            'alice.secondary@example.com',
            'local',
            'alice.renamed@example.com'
        );
        $this->assertSame('alice.renamed@example.com', $renamed['uid']);
        self::$auth->delete_credential($alice['id'], 'local', 'alice.renamed@example.com');

        try {
            self::$auth->create_credential($bob['id'], 'local', 'alice@example.com');
            $this->fail('Expected duplicate credential rejection');
        } catch (UserException $exception) {
            $this->assertSame(409, $exception->getCode());
        }

        $this->expectException(UserException::class);
        $this->expectExceptionCode(409);
        self::$auth->delete_credential($alice['id'], 'local', 'alice@example.com');
    }

    public function testUserDeletionCleansDelegationsButLeavesApplicationAssociationsToApplication(): void
    {
        $actor = self::$auth->register('actor@example.com', 'secret');
        $target = self::$auth->register('target@example.com', 'secret');
        self::$db->insert('managed_items', ['user_id' => $target['id'], 'item_id' => 3]);

        self::$db->insert('user_delegations', [
            'user_id' => $actor['id'],
            'target_user_id' => $target['id'],
            'ability' => 'manage',
        ]);
        self::$auth->delete($target['id']);
        $this->assertSame(0, self::$db->count('user_delegations', []));
        $this->assertSame(1, self::$db->count('managed_items', []));
    }

    public function testDbAuthSessionContextReloadsApplicationAssignments(): void
    {
        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
            'user_context_callback' => function (array $user): array {
                $rows = self::$db->select(
                    'managed_items',
                    ['user_id' => $user['id']],
                    ['order' => 'item_id']
                )->all();
                return ['venues' => array_map(
                    fn (array $row): int => (int) $row['item_id'],
                    $rows
                )];
            },
        ]);

        $user = $auth->register('app-context@example.com', 'secret');
        self::$db->insert('managed_items', ['user_id' => $user['id'], 'item_id' => 4]);
        $login = $auth->login('app-context@example.com', 'secret');
        $this->assertSame(['venues' => [4]], $login['context']);

        self::$db->insert('managed_items', ['user_id' => $user['id'], 'item_id' => 9]);
        $this->assertSame(['venues' => [4]], $auth->user()['context']);
        $this->assertTrue($auth->revalidate());
        $this->assertSame(['venues' => [4, 9]], $auth->user()['context']);
        $controller = new AuthController($auth);
        $this->assertSame(['venues' => [4, 9]], $controller->index()['context']);
    }

    public function testRoleNamesAndCredentialUidSearchAreNormalized(): void
    {
        self::$auth->register('searchable@example.com', 'secret', ['roles' => ['partner']]);
        $this->assertSame(['partner'], self::$auth->get_roles());

        $result = self::$auth->query(['q' => 'searchable@example.com', 'size' => 10]);
        $this->assertSame(1, $result->total());
        $this->assertSame('searchable@example.com', $result[0]['credentials'][0]['uid']);
    }
}
