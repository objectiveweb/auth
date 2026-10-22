<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\Controller\UserController;
use Objectiveweb\Auth\DBAuth;
use Objectiveweb\DB;
use PHPUnit\Framework\TestCase;

class UserControllerTest extends TestCase
{
    private static DB $db;
    private static DBAuth $auth;
    private static UserController $controller;

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

        self::$db->query(
            'CREATE TABLE auth_credentials (
                uid TEXT NOT NULL,
                provider TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                profile TEXT NULL,
                token TEXT NULL,
                token_expires_at TEXT NULL,
                verified_at TEXT NULL,
                last_login TEXT NULL,
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

        self::$auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'credentials_created' => null,
            'roles_table' => null,
            'user_roles_table' => null,
        ]);
        self::$controller = new UserController(self::$auth);
    }

    protected function setUp(): void
    {
        $_SESSION = [];
        self::$db->query('DELETE FROM auth_credentials')->exec();
        self::$db->query('DELETE FROM auth_user_role')->exec();
        self::$db->query('DELETE FROM auth_role')->exec();
        self::$db->query('DELETE FROM auth_user')->exec();
    }

    public function testManagedRelationsAreRejectedByAuthAdminCreate(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(400);

        self::$controller->post([
            'uid' => 'venue-create@example.com',
            'password' => 'test',
            'managed_relations' => ['venues' => [1, 2]],
        ]);
    }

    public function testManagedRelationsAreRejectedByAuthAdminUpdate(): void
    {
        $user = self::$controller->post([
            'uid' => 'venue-update@example.com',
            'password' => 'test',
        ]);
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(400);

        self::$controller->put((int) $user['id'], [
            'managed_relations' => ['venues' => [1, 2]],
        ]);
    }

    public function testAdminUserDetailNoLongerOwnsApplicationAssociations(): void
    {
        $user = self::$controller->post([
            'uid' => 'detail@example.com',
            'password' => 'test',
        ]);
        $detail = self::$controller->get((int) $user['id']);
        $this->assertArrayNotHasKey('managed_relations', $detail);
    }

    public function testPost(): void
    {
        $user = self::$controller->post([
            'uid' => 'vagrant@localhost',
            'password' => 'test',
            'name' => 'Test User',
        ]);

        $this->assertGreaterThan(0, (int) $user['id']);
    }

    public function testPostMissingUid(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        self::$controller->post([
            'name' => 'Invalid User',
        ]);
    }

    public function testGet(): void
    {
        $user = self::$controller->post([
            'uid' => 'vagrant@localhost',
            'password' => 'test',
            'name' => 'Test User',
        ]);

        $loaded = self::$controller->get((int) $user['id']);
        $this->assertSame((int) $user['id'], (int) $loaded['id']);
    }

    public function testQuery(): void
    {
        self::$controller->post([
            'uid' => 'vagrant@localhost',
            'password' => 'test',
            'name' => 'Test User',
        ]);

        $all = self::$controller->get();

        $this->assertInstanceOf(\Objectiveweb\DB\Collection::class, $all);
        $this->assertCount(1, $all);
        $this->assertSame(1, $all->total());
        $this->assertSame('items 0-0/1', $all->contentRange());
        $this->assertSame('Test User', $all[0]['name']);
    }

    public function testQueryInvalidFilterField(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        self::$controller->get(['unknown_field' => 'x']);
    }

    public function testPostRejectsNonArrayRoles(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(400);

        self::$controller->post([
            'uid' => 'roles-string@example.com',
            'password' => 'test',
            'roles' => 'admin',
        ]);
    }

    public function testPostAllowsCredentialMetadata(): void
    {
        $user = self::$controller->post([
            'uid' => 'oauth@example.com',
            'password' => 'test',
            'provider' => 'email',
            'profile' => ['source' => 'test'],
        ]);

        $this->assertCount(1, $user['credentials']);
        $this->assertSame('email', $user['credentials'][0]['provider']);
        $this->assertSame(['source' => 'test'], $user['credentials'][0]['profile']);
    }

    public function testPutRejectsNonArrayRoles(): void
    {
        $user = self::$controller->post([
            'uid' => 'roles-update@example.com',
            'password' => 'test',
        ]);

        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(400);

        self::$controller->put((int) $user['id'], ['roles' => 'admin']);
    }

    public function testPutRejectsCredentialOnlyFields(): void
    {
        $user = self::$controller->post([
            'uid' => 'credential-fields@example.com',
            'password' => 'test',
        ]);

        foreach (['provider', 'profile'] as $field) {
            try {
                self::$controller->put((int) $user['id'], [$field => 'invalid']);
                $this->fail("Expected {$field} to be rejected");
            } catch (\Objectiveweb\Auth\UserException $exception) {
                $this->assertSame(400, $exception->getCode());
                $this->assertSame("Invalid field `{$field}`", $exception->getMessage());
            }
        }
    }

    public function testPut(): void
    {
        $user = self::$controller->post([
            'uid' => 'vagrant@localhost',
            'password' => 'test',
            'name' => 'Test User',
        ]);

        self::$controller->put((int) $user['id'], ['name' => 'Updated name']);
        $updated = self::$controller->get((int) $user['id']);

        $this->assertSame('Updated name', $updated['name']);
    }

    public function testCannotSuspendOnlyActiveAdminWhenAnotherAdminIsSuspended(): void
    {
        self::$db->insert('auth_role', ['name' => 'admin']);

        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'credentials_created' => null,
            'disabled_at' => 'disabled_at',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
        ]);
        $controller = new UserController($auth);

        $actor = $auth->register('actor@example.com', 'secret');
        $activeAdmin = $auth->register('active-admin@example.com', 'secret', [
            'roles' => ['admin'],
        ]);
        $suspendedAdmin = $auth->register('suspended-admin@example.com', 'secret', [
            'roles' => ['admin'],
            'disabled_at' => '2026-09-27 12:00:00',
        ]);

        $auth->login('actor@example.com', 'secret');

        $admins = $auth->get_users_by_role('admin');
        $this->assertCount(2, $admins);
        $suspended = array_values(array_filter(
            $admins,
            fn (array $user): bool => (int) $user['id'] === (int) $suspendedAdmin['id']
        ));
        $this->assertCount(1, $suspended);
        $this->assertSame('2026-09-27 12:00:00', $suspended[0]['disabled_at']);

        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(409);
        $controller->post((int) $activeAdmin['id'], 'suspend');
    }

    public function testFinalAdminGuardCoversSuspendDemoteDeleteAndDirectDisable(): void
    {
        self::$db->insert('auth_role', ['name' => 'admin']);
        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'credentials_created' => null,
            'disabled_at' => 'disabled_at',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
        ]);
        $controller = new UserController($auth);
        $admin = $auth->register('sole-admin@example.com', 'secret', ['roles' => ['admin']]);
        $id = (int) $admin['id'];

        $mutations = [
            static fn () => $controller->post($id, 'suspend'),
            static fn () => $controller->put($id, ['roles' => []]),
            static fn () => $controller->put($id, ['disabled_at' => '2026-01-01 00:00:00']),
            static fn () => $controller->put($id, ['roles' => [], 'disabled_at' => '2026-01-01 00:00:00']),
            static fn () => $controller->delete($id),
        ];
        foreach ($mutations as $mutate) {
            try {
                $mutate();
                $this->fail('A mutation removed the final active administrator');
            } catch (\Objectiveweb\Auth\UserException $exception) {
                $this->assertSame(409, $exception->getCode());
            }
            $stillAdmin = $auth->get($id);
            $this->assertTrue($auth->is_active($stillAdmin));
            $this->assertContains('admin', $stillAdmin['roles']);
        }
    }

    public function testReducingTwoActiveAdminsToOnePreventsFurtherRemoval(): void
    {
        self::$db->insert('auth_role', ['name' => 'admin']);
        $auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
            'credentials_created' => null,
            'disabled_at' => 'disabled_at',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
        ]);
        $controller = new UserController($auth);
        $first = $auth->register('first-admin@example.com', 'secret', ['roles' => ['admin']]);
        $second = $auth->register('second-admin@example.com', 'secret', ['roles' => ['admin']]);

        $this->assertSame(['ok' => true], $controller->delete((int) $first['id']));
        $this->assertCount(1, array_filter(
            $auth->get_users_by_role('admin'),
            static fn (array $user): bool => $auth->is_active($user)
        ));
        try {
            $controller->post((int) $second['id'], 'suspend');
            $this->fail('A second operation removed the last active admin');
        } catch (\Objectiveweb\Auth\UserException $exception) {
            $this->assertSame(409, $exception->getCode());
        }
        $this->assertTrue($auth->is_active($auth->get($second['id'])));
    }

    /**
     * Model a competing transaction committed before the role lock is
     * acquired. The count must not be read or cached outside the lock.
     */
    public function testAdminGuardReloadsActiveCountAfterAcquiringLock(): void
    {
        $db = new class('sqlite::memory:') extends DB {
            public ?\Closure $beforeRoleLock = null;
            public function update(string $table, array $data, ?array $where = null): int
            {
                if ($table === 'role' && $this->beforeRoleLock !== null) {
                    $callback = $this->beforeRoleLock;
                    $this->beforeRoleLock = null;
                    $callback();
                }
                return parent::update($table, $data, $where);
            }
        };
        $db->query('CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT NOT NULL UNIQUE, name TEXT, password TEXT, disabled_at TEXT)')->exec();
        $db->query('CREATE TABLE user_credentials (uid TEXT NOT NULL, provider TEXT NOT NULL, user_id INTEGER NOT NULL, profile TEXT, token TEXT, token_expires_at TEXT, verified_at TEXT, last_login TEXT, created TEXT, PRIMARY KEY(uid, provider))')->exec();
        $db->query('CREATE TABLE role (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)')->exec();
        $db->query('CREATE TABLE user_roles (user_id INTEGER NOT NULL, role_id INTEGER NOT NULL, PRIMARY KEY(user_id, role_id))')->exec();
        $db->insert('role', ['id' => 1, 'name' => 'admin']);

        $auth = new DBAuth($db, ['disabled_at' => 'disabled_at', 'created' => null]);
        $controller = new UserController($auth);
        $first = $auth->register('race-first@example.com', 'secret', ['roles' => ['admin']]);
        $second = $auth->register('race-second@example.com', 'secret', ['roles' => ['admin']]);

        $db->beforeRoleLock = static function () use ($db, $first): void {
            $db->delete('user_roles', ['user_id' => $first['id']]);
        };
        try {
            $controller->put((int) $second['id'], ['roles' => []]);
            $this->fail('Stale admin count bypassed serialization guard');
        } catch (\Objectiveweb\Auth\UserException $exception) {
            $this->assertSame(409, $exception->getCode());
        }

        // The simulated concurrent mutation must roll back with the guard.
        $this->assertCount(2, $auth->get_users_by_role('admin'));
        $this->assertContains('admin', $auth->get($second['id'])['roles']);
    }

    public function testDeleteRejectsUnknownSubresourcesWithoutDeletingUser(): void
    {
        self::$controller->post([
            'uid' => 'actor@example.com',
            'password' => 'test',
        ]);
        $target = self::$controller->post([
            'uid' => 'target@example.com',
            'password' => 'test',
        ]);
        self::$auth->login('actor@example.com', 'test');

        foreach (['unknown', '', 'suspend', 'roles'] as $resource) {
            try {
                self::$controller->delete((int) $target['id'], $resource);
                $this->fail('Expected invalid delete subresource to be rejected');
            } catch (\Objectiveweb\Auth\UserException $exception) {
                $this->assertSame(404, $exception->getCode());
            }
            $this->assertSame(
                (int) $target['id'],
                (int) self::$controller->get((int) $target['id'])['id']
            );
            $this->assertNotFalse(self::$auth->get_credential('local', 'target@example.com'));
        }

        // Stray nested path parameters without a resource are also invalid.
        try {
            self::$controller->delete((int) $target['id'], null, 'local', 'target@example.com');
            $this->fail('Expected incomplete subresource path to be rejected');
        } catch (\Objectiveweb\Auth\UserException $exception) {
            $this->assertSame(404, $exception->getCode());
        }
        $this->assertSame(
            (int) $target['id'],
            (int) self::$controller->get((int) $target['id'])['id']
        );
    }

    public function testDeleteUserOnlyAtBaseResource(): void
    {
        self::$controller->post([
            'uid' => 'actor@example.com',
            'password' => 'test',
        ]);
        $target = self::$controller->post([
            'uid' => 'target@example.com',
            'password' => 'test',
            'name' => 'Test User',
        ]);
        self::$auth->login('actor@example.com', 'test');

        $this->assertSame(['ok' => true], self::$controller->delete((int) $target['id']));
        $this->assertFalse(self::$auth->get_credential('local', 'target@example.com'));

        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(404);
        self::$controller->get((int) $target['id']);
    }

    public function testDeleteCredentialDoesNotDeleteUser(): void
    {
        self::$controller->post([
            'uid' => 'actor@example.com',
            'password' => 'test',
        ]);
        $target = self::$controller->post([
            'uid' => 'target@example.com',
            'password' => 'test',
        ]);
        self::$auth->create_credential((int) $target['id'], 'phone', '+5511999999999');
        self::$auth->login('actor@example.com', 'test');

        $this->assertSame(
            ['ok' => true],
            self::$controller->delete((int) $target['id'], 'credentials', 'phone', '%2B5511999999999')
        );
        $this->assertFalse(self::$auth->get_credential('phone', '+5511999999999'));
        $this->assertNotFalse(self::$auth->get_credential('local', 'target@example.com'));
        $this->assertSame(
            (int) $target['id'],
            (int) self::$controller->get((int) $target['id'])['id']
        );
    }
}
