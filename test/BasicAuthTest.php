<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\UserException;
use PHPUnit\Framework\TestCase;

class BasicAuthTest extends TestCase
{
    private BasicAuth $auth;

    protected function setUp(): void
    {
        $_SESSION = [];

        $this->auth = new BasicAuth(
            [
                'alice@example.com' => 'secret',
            ],
            [
                'token' => 'token',
            ]
        );
    }

    public function testLoginSuccessAndSessionData(): void
    {
        $user = $this->auth->login('alice@example.com', 'secret');

        $this->assertSame(1, $user['id']);
        $this->assertSame('alice@example.com', $user['uid']);
        $this->assertTrue($this->auth->check());
        $this->assertArrayNotHasKey('password', $user);
    }

    public function testLoginInvalidPassword(): void
    {
        $this->expectException(AuthException::class);
        $this->auth->login('alice@example.com', 'wrong');
    }

    public function testRegisterAndGetCredential(): void
    {
        $user = $this->auth->register('bob@example.com', 'pass123', ['name' => 'Bob']);
        $credential = $this->auth->get_credential('local', 'bob@example.com');

        $this->assertSame('Bob', $user['name']);
        $this->assertSame($user['id'], $credential['user_id']);
    }

    public function testPasswordResetFlow(): void
    {
        $credential = $this->auth->get_credential('local', 'alice@example.com');
        $token = $this->auth->update_token($credential['user_id']);

        $this->auth->passwd_reset($token, 'new-secret');
        $user = $this->auth->login('alice@example.com', 'new-secret');

        $this->assertSame('alice@example.com', $user['uid']);
    }

    public function testDeleteUserRemovesCredential(): void
    {
        $credential = $this->auth->get_credential('local', 'alice@example.com');
        $this->auth->delete($credential['user_id']);

        $this->expectException(UserException::class);
        $this->auth->login('alice@example.com', 'secret');
    }
}
