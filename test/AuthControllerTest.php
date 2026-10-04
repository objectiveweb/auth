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

    private array $originalServer;

    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
        unset($_SERVER['REQUEST_METHOD'], $_SERVER['CONTENT_TYPE'], $_SERVER['HTTP_X_CSRF_TOKEN']);
        $_SESSION = [];
        $this->auth = new BasicAuth([], ['token' => 'token']);
        $this->controller = new AuthController($this->auth);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;
        $_SESSION = [];
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

    public function testAuthenticatedPasswordChangeRequiresCsrfToken(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');

        $this->expectException(UserException::class);
        $this->expectExceptionCode(403);
        $this->controller->postPassword([
            'current_password' => 'old-secret',
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]);
    }

    public function testAuthenticatedPasswordChangeRejectsInvalidCsrfToken(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');
        $_SERVER['HTTP_X_CSRF_TOKEN'] = 'invalid';

        $this->expectException(UserException::class);
        $this->expectExceptionCode(403);
        $this->controller->postPassword([
            'current_password' => 'old-secret',
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]);
    }

    public function testAuthenticatedPasswordChangeRejectsMissingCurrentPassword(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $this->auth->management_csrf_token();

        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->postPassword([
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]);
    }

    public function testAuthenticatedPasswordChangeRejectsIncorrectCurrentPassword(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $this->auth->management_csrf_token();

        try {
            $this->controller->postPassword([
                'current_password' => 'wrong-secret',
                'password' => 'new-secret',
                'confirm' => 'new-secret',
            ]);
            $this->fail('Incorrect current password was accepted');
        } catch (AuthException $exception) {
            $this->assertSame(403, $exception->getCode());
        }

        $this->assertTrue(password_verify('old-secret', $this->auth->get(1)['password']));
        $this->assertFalse(password_verify('new-secret', $this->auth->get(1)['password']));
    }

    public function testAuthenticatedPasswordChangeRejectsMismatchedConfirmation(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $this->auth->management_csrf_token();

        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->postPassword([
            'current_password' => 'old-secret',
            'password' => 'new-secret',
            'confirm' => 'different',
        ]);
    }

    public function testAuthenticatedPasswordChangeSucceedsAndRequiresNewPasswordOnNextLogin(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');

        $current = $this->controller->index();
        $this->assertIsString($current['_csrf']);
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $current['_csrf'];

        $this->assertTrue($this->controller->postPassword([
            'current_password' => 'old-secret',
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]));

        $this->auth->logout();
        try {
            $this->auth->login('alice@example.com', 'old-secret');
            $this->fail('Old password still works');
        } catch (AuthException) {
            // Expected.
        }
        $this->assertSame(1, $this->auth->login('alice@example.com', 'new-secret')['id']);
    }

    public function testPasswordlessOAuthAccountRequiresVerifiedResetFlow(): void
    {
        $user = $this->auth->register('oauth@example.com', null, ['provider' => 'google']);
        $this->auth->establish_session($this->auth->get($user['id']));
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $this->auth->management_csrf_token();

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(403);
        $this->controller->postPassword([
            'current_password' => 'anything',
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]);
    }

    public function testAuthenticatedPasswordChangeRejectsFormEncodedHttpRequest(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $this->auth->management_csrf_token();

        $this->expectException(UserException::class);
        $this->expectExceptionCode(415);
        $this->controller->postPassword([
            'current_password' => 'old-secret',
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]);
    }

    public function testAuthenticatedPasswordChangeAcceptsJsonHttpRequest(): void
    {
        $this->auth->register('alice@example.com', 'old-secret');
        $this->auth->login('alice@example.com', 'old-secret');
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/json; charset=utf-8';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $this->auth->management_csrf_token();

        $this->assertTrue($this->controller->postPassword([
            'current_password' => 'old-secret',
            'password' => 'new-secret',
            'confirm' => 'new-secret',
        ]));
        $this->assertTrue(password_verify('new-secret', $this->auth->get(1)['password']));
    }

    public function testPostPasswordForgotFlowMissingUid(): void
    {
        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->controller->postPassword(['password' => 'a', 'confirm' => 'a']);
    }

    public function testPostPasswordForgotFlowDoesNotRevealUnknownCredential(): void
    {
        $callbackCalls = 0;
        $auth = new BasicAuth([], [
            'token' => 'token',
            'token_callback' => function () use (&$callbackCalls): void {
                $callbackCalls++;
            },
        ]);
        $controller = new AuthController($auth);

        $result = $controller->postPassword(['uid' => 'missing@example.com']);

        $this->assertSame([], $result);
        $this->assertSame(0, $callbackCalls);
    }

    public function testPostPasswordForgotFlowIgnoresCallbackReturnValue(): void
    {
        $auth = new BasicAuth([], [
            'token' => 'token',
            'token_callback' => fn (): array => ['account_exists' => true],
        ]);
        $controller = new AuthController($auth);
        $auth->register('alice@example.com', 'secret', ['provider' => 'email']);

        $result = $controller->postPassword(['uid' => 'alice@example.com']);

        $this->assertSame([], $result);
    }

    public function testPostPasswordForgotFlowHidesDeliveryFailure(): void
    {
        $auth = new BasicAuth([], [
            'token' => 'token',
            'token_callback' => function (): void {
                throw new \RuntimeException('mail transport unavailable');
            },
        ]);
        $controller = new AuthController($auth);
        $auth->register('alice@example.com', 'secret', ['provider' => 'email']);

        $result = $controller->postPassword(['uid' => 'alice@example.com']);

        $this->assertSame([], $result);
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
