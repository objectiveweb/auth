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
                scopes TEXT,
                created TEXT,
                password TEXT,
                token TEXT
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
            'roles' => 'roles',
            'roles_table' => 'auth_role',
            'user_roles_table' => 'auth_user_role',
        ]);
    }

    protected function setUp(): void
    {
        $_SESSION = [];
        self::$db->query('DELETE FROM auth_credentials')->exec();
        self::$db->query('DELETE FROM auth_user_role')->exec();
        self::$db->query('DELETE FROM auth_role')->exec();
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
        self::$auth->passwd_reset($token, 'final-secret');

        $logged = self::$auth->login('alice@example.com', 'final-secret');
        $this->assertSame($user['id'], $logged['id']);
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

    public function testUserCanChecksScopesAndRoles(): void
    {
        self::$auth->register('scoped@example.com', 'secret', [
            'scopes' => ['profile:read'],
            'roles' => ['admin'],
        ]);

        self::$auth->login('scoped@example.com', 'secret');

        $this->assertTrue(self::$auth->user_can('profile:read'));
        $this->assertTrue(self::$auth->user_can('admin'));
        $this->assertFalse(self::$auth->user_can('operator'));

        $current = self::$auth->user();
        $this->assertSame(['admin'], $current['roles']);
        $this->assertSame(['profile:read'], $current['scopes']);
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
}
