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

        self::$auth = new DBAuth(self::$db, [
            'table' => 'auth_user',
            'credentials_table' => 'auth_credentials',
            'created' => 'created',
            'token' => 'token',
            'credentials_last_login' => 'last_login',
        ]);
        self::$controller = new UserController(self::$auth);
    }

    protected function setUp(): void
    {
        $_SESSION = [];
        self::$db->query('DELETE FROM auth_credentials')->exec();
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
