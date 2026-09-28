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
                disabled_at TEXT
            )'
        )->exec();

        self::$db->query(
            'CREATE TABLE auth_credentials (
                uid TEXT NOT NULL,
                provider TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                profile TEXT NULL,
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

    public function testPost(): void
    {
        $user = self::$controller->post([
            'uid' => 'vagrant@localhost',
            'password' => 'test',
            'name' => 'Test User',
        ]);

        $this->assertSame(1, (int) $user['id']);
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

        $this->assertSame(1, count($all['_embedded']['auth_user']));
        $this->assertSame('Test User', $all['_embedded']['auth_user'][0]['name']);
        $this->assertSame(1, $all['page']['totalElements']);
        $this->assertSame(1, $all['page']['totalPages']);
        $this->assertSame(0, $all['page']['number']);
    }

    public function testQueryInvalidFilterField(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        self::$controller->get(['unknown_field' => 'x']);
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

    public function testDelete(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);

        $user = self::$controller->post([
            'uid' => 'vagrant@localhost',
            'password' => 'test',
            'name' => 'Test User',
        ]);

        $deleted = self::$controller->delete((int) $user['id']);
        $this->assertTrue($deleted);

        self::$controller->get((int) $user['id']);
    }
}
