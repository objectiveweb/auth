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

    public function testLoginWithEmailProviderWhenConfiguredInLoginProviders(): void
    {
        $auth = new BasicAuth([], [
            'token' => 'token',
            'login_providers' => ['email', 'local'],
        ]);

        $auth->register('alice@example.com', 'secret', ['provider' => 'email']);
        $user = $auth->login('alice@example.com', 'secret');

        $this->assertSame('alice@example.com', $user['uid']);
    }

    public function testGetCredentialsReturnsOnlyExpectedFields(): void
    {
        $user = $this->auth->register('bob@example.com', 'secret', ['provider' => 'email']);
        $this->auth->update_credential($user['id'], 'phone', '+5511999999999', ['country' => 'BR']);

        $credentials = $this->auth->get_credentials($user['id']);
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

    public function testGetUsersByRoleReturnsMatchingUsers(): void
    {
        $admin = $this->auth->register('admin@example.com', 'secret', [
            'roles' => ['admin'],
        ]);
        $this->auth->register('viewer@example.com', 'secret', [
            'roles' => ['viewer'],
        ]);

        $admins = $this->auth->get_users_by_role('admin');

        $this->assertCount(1, $admins);
        $this->assertSame($admin['id'], $admins[0]['id']);
        $this->assertSame(['admin'], $admins[0]['roles']);
    }
}
