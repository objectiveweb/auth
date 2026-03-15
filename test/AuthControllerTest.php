<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Controller\AuthController;
use Objectiveweb\Auth\UserException;
use PHPUnit\Framework\TestCase;

class AuthControllerTest extends TestCase
{
    private BasicAuth $auth;
    private AuthController $controller;

    protected function setUp(): void
    {
        $_SESSION = [];
        $this->auth = new BasicAuth([], ['token' => 'token']);
        $this->controller = new AuthController($this->auth);
    }

    public function testPostMissingUid(): void
    {
        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->post(['password' => 'secret']);
    }

    public function testPostMissingPassword(): void
    {
        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->post(['uid' => 'a@example.com']);
    }

    public function testPostRegisterInvalidEmail(): void
    {
        $this->expectException(AuthException::class);
        $this->controller->postRegister(['uid' => 'invalid', 'password' => 'secret']);
    }

    public function testPostTokenPasswordMismatch(): void
    {
        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->postToken([
            'token' => 'abc',
            'password' => 'a',
            'confirm' => 'b',
        ]);
    }

    public function testPostPasswordForgotFlowMissingUid(): void
    {
        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->postPassword(['password' => 'a', 'confirm' => 'a']);
    }

    public function testPostPasswordForgotFlowUsesEmailCredential(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new AuthController($auth);

        $auth->register('alice@example.com', 'secret', ['provider' => 'email']);
        $result = $controller->postPassword(['uid' => 'alice@example.com']);

        $this->assertSame([], $result);
    }

    public function testPostPasswordForgotFlowUsesPhoneCredential(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new AuthController($auth);

        $auth->register('+5511999999999', 'secret', ['provider' => 'phone']);
        $result = $controller->postPassword(['uid' => '+5511999999999']);

        $this->assertSame([], $result);
    }

    public function testPostPasswordForgotFlowUsesLocalCredentialByDefault(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new AuthController($auth);

        $auth->register('local@example.com', 'secret', ['provider' => 'local']);
        $result = $controller->postPassword(['uid' => 'local@example.com']);

        $this->assertSame([], $result);
    }

    public function testPostRegisterStripsRolesByDefault(): void
    {
        $user = $this->controller->postRegister([
            'uid' => 'safe@example.com',
            'password' => 'secret',
            'roles' => ['admin'],
        ]);

        $this->assertSame([], $user['roles'] ?? []);
    }

    public function testPostRegisterRejectsWhenRegisterScopeIsAuthenticated(): void
    {
        $controller = new AuthController(new BasicAuth([], [
            'token' => 'token',
            'register_scope' => \Objectiveweb\Auth::AUTHENTICATED,
        ]));

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(401);
        $controller->postRegister([
            'uid' => 'blocked@example.com',
            'password' => 'secret',
        ]);
    }

    public function testIndexReturnsUserWithCredentialsWhenLoggedIn(): void
    {
        $this->auth->register('alice@example.com', 'secret', ['provider' => 'local']);
        $this->auth->update_credential(1, 'phone', '+5511999999999', ['country' => 'BR']);
        $this->auth->login('alice@example.com', 'secret');

        $result = $this->controller->index();

        $this->assertSame(1, $result['id']);
        $this->assertArrayHasKey('credentials', $result);
        $this->assertCount(2, $result['credentials']);
    }
}
