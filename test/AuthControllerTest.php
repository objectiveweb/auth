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
}
