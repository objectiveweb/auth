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

    public function testLogoutWithoutRedirectEndsSession(): void
    {
        $this->auth->register('logout@example.com', 'secret');
        $this->auth->login('logout@example.com', 'secret');

        $this->assertSame([], $this->controller->getLogout());
        $this->assertFalse($this->auth->check());
    }

    public function testLogoutRejectsUnsafeRedirectsBeforeEndingSession(): void
    {
        $this->auth->register('logout@example.com', 'secret');
        $this->auth->login('logout@example.com', 'secret');

        $invalid = [
            'https://evil.example/',
            'http://evil.example/',
            '//evil.example/',
            '\\evil.example\\path',
            '/\\evil.example/path',
            'javascript:alert(1)',
            'account',
            "/safe\r\nLocation: https://evil.example/",
        ];

        foreach ($invalid as $redirect) {
            try {
                $this->controller->getLogout(['redirect' => $redirect]);
                $this->fail("Unsafe redirect was accepted: {$redirect}");
            } catch (UserException $exception) {
                $this->assertSame(400, $exception->getCode());
                $this->assertSame('Invalid redirect', $exception->getMessage());
                $this->assertTrue($this->auth->check());
            }
        }
    }

    public function testLogoutRedirectValidatorAcceptsSameOriginPaths(): void
    {
        $controller = new class($this->auth) extends AuthController {
            public function validateRedirect(mixed $redirect): string
            {
                return $this->normalizeLogoutRedirect($redirect);
            }
        };

        $this->assertSame('/', $controller->validateRedirect('/'));
        $this->assertSame(
            '/account/logout?done=1#top',
            $controller->validateRedirect('/account/logout?done=1#top')
        );
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

    public function testCredentialTokenRedemptionDoesNotAuthenticateAUser(): void
    {
        $user = $this->auth->register('verify@example.com', 'secret');
        $token = $this->auth->issue_credential_token($user['id'], 'local', 'verify@example.com');

        $this->assertSame(['verified' => true], $this->controller->postVerifyCredential([
            'provider' => 'local',
            'uid' => 'verify@example.com',
            'token' => $token,
        ]));
        $this->assertFalse($this->auth->check());
        $this->assertNotEmpty($this->auth->get_credential('local', 'verify@example.com')['verified_at']);

        try {
            $this->controller->postVerifyCredential([
                'provider' => 'local',
                'uid' => 'verify@example.com',
                'token' => $token,
            ]);
            $this->fail('Reused token was accepted');
        } catch (UserException $e) {
            $this->assertSame(400, $e->getCode());
        }
    }

    public function testCredentialTokenRedemptionRejectsMalformedAndMismatchedInputs(): void
    {
        $user = $this->auth->register('verify@example.com', 'secret');
        $token = $this->auth->issue_credential_token($user['id'], 'local', 'verify@example.com');

        foreach ([
            ['provider' => 'local', 'uid' => 'verify@example.com', 'token' => 'wrong'],
            ['provider' => 'email', 'uid' => 'verify@example.com', 'token' => $token],
            ['provider' => 'local', 'uid' => 'else@example.com', 'token' => $token],
            ['provider' => 'local', 'uid' => 'verify@example.com', 'token' => []],
        ] as $form) {
            try {
                $this->controller->postVerifyCredential($form);
                $this->fail('Invalid token request was accepted');
            } catch (UserException $e) {
                $this->assertSame(400, $e->getCode());
            }
        }
        $this->assertNull($this->auth->get_credential('local', 'verify@example.com')['verified_at'] ?? null);
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
            $this->assertSame(401, $exception->getCode());
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
        $user = $auth->register('alice@example.com', 'secret', ['provider' => 'email']);
        $auth->mark_credential_verified($user['id'], 'email', 'alice@example.com');

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
        $user = $auth->register('alice@example.com', 'secret', ['provider' => 'email']);
        $auth->mark_credential_verified($user['id'], 'email', 'alice@example.com');

        $result = $controller->postPassword(['uid' => 'alice@example.com']);

        $this->assertSame([], $result);
    }

    public function testPasswordRecoveryDeliveryLogsNoSensitiveExceptionDetails(): void
    {
        $recoveryToken = null;
        $auth = new BasicAuth([], [
            'token' => 'token',
            'token_callback' => function (array $credential) use (&$recoveryToken): void {
                $recoveryToken = $credential['token'];
                throw new \RuntimeException(
                    'Failed to deliver to private@example.com: '
                    . 'https://app.example/reset?token=' . $recoveryToken
                );
            },
        ]);
        $user = $auth->register('private@example.com', 'secret', ['provider' => 'email']);
        $auth->mark_credential_verified($user['id'], 'email', 'private@example.com');
        $controller = new AuthController($auth);

        $logFile = tempnam(sys_get_temp_dir(), 'ow-auth-recovery-');
        $this->assertNotFalse($logFile);
        $previousLogFile = ini_get('error_log');
        try {
            $this->assertNotFalse(ini_set('error_log', $logFile));
            $this->assertSame([], $controller->postPassword(['uid' => 'private@example.com']));

            $logged = file_get_contents($logFile);
            $this->assertIsString($logged);
            $this->assertMatchesRegularExpression(
                '/Password recovery delivery failed \[ref=[0-9a-f]{16}\]: RuntimeException/',
                $logged
            );
            $this->assertNotNull($recoveryToken);
            $this->assertStringNotContainsString($recoveryToken, $logged);
            $this->assertStringNotContainsString('private@example.com', $logged);
            $this->assertStringNotContainsString('https://app.example/reset', $logged);
        } finally {
            ini_set('error_log', (string) $previousLogFile);
            unlink($logFile);
        }
    }

    public function testPostPasswordForgotFlowUsesEmailCredential(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new AuthController($auth);

        $user = $auth->register('alice@example.com', 'secret', ['provider' => 'email']);
        $auth->mark_credential_verified($user['id'], 'email', 'alice@example.com');
        $result = $controller->postPassword(['uid' => 'alice@example.com']);

        $this->assertSame([], $result);
    }

    public function testPostPasswordForgotFlowUsesPhoneCredential(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new AuthController($auth);

        $user = $auth->register('+5511999999999', 'secret', ['provider' => 'phone']);
        $auth->mark_credential_verified($user['id'], 'phone', '+5511999999999');
        $result = $controller->postPassword(['uid' => '+5511999999999']);

        $this->assertSame([], $result);
    }

    public function testPostPasswordForgotFlowUsesLocalCredentialByDefault(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new AuthController($auth);

        $user = $auth->register('local@example.com', 'secret', ['provider' => 'local']);
        $auth->mark_credential_verified($user['id'], 'local', 'local@example.com');
        $result = $controller->postPassword(['uid' => 'local@example.com']);

        $this->assertSame([], $result);
    }

    public function testAnonymousRecoveryRejectsUnverifiedLocalWithoutRotatingResetToken(): void
    {
        $deliveries = [];
        $auth = new BasicAuth([], [
            'token' => 'token',
            'token_callback' => static function (array $credential) use (&$deliveries): void {
                $deliveries[] = $credential;
            },
        ]);
        $user = $auth->register('legacy@example.com', 'secret');
        $controller = new AuthController($auth);

        // An admin-issued invitation/reset token must not be replaced by
        // anonymous recovery to an unverified local identifier.
        $existingToken = $auth->update_token($user['id']);
        $existingDigest = $auth->get($user['id'])['token'];

        $this->assertSame([], $controller->postPassword(['uid' => 'legacy@example.com']));
        $this->assertSame([], $controller->postPassword(['uid' => 'missing@example.com']));
        $this->assertSame([], $deliveries);
        $this->assertSame($existingDigest, $auth->get($user['id'])['token']);

        // Recovery becomes available only after independent channel proof.
        $proof = $auth->issue_credential_token($user['id'], 'local', 'legacy@example.com');
        $this->assertTrue($auth->verify_credential_token('local', 'legacy@example.com', $proof));
        $this->assertSame([], $controller->postPassword(['uid' => 'legacy@example.com']));
        $this->assertCount(1, $deliveries);
        $this->assertSame('local', $deliveries[0]['provider']);
        $this->assertNotSame($existingToken, $deliveries[0]['token']);
        $this->assertTrue(password_verify($deliveries[0]['token'], $auth->get($user['id'])['token']));
    }

    public function testAnonymousRecoverySkipsUnverifiedLocalInFavorOfVerifiedEmail(): void
    {
        $deliveries = [];
        $auth = new BasicAuth([], [
            'token' => 'token',
            'token_callback' => static function (array $credential) use (&$deliveries): void {
                $deliveries[] = $credential;
            },
        ]);
        $user = $auth->register('shared@example.com', 'secret');
        $auth->create_credential($user['id'], 'email', 'shared@example.com');
        $proof = $auth->issue_credential_token($user['id'], 'email', 'shared@example.com');
        $this->assertTrue($auth->verify_credential_token('email', 'shared@example.com', $proof));
        $this->assertNull($auth->get_credential('local', 'shared@example.com')['verified_at']);

        $controller = new AuthController($auth);
        $this->assertSame([], $controller->postPassword(['uid' => 'shared@example.com']));
        $this->assertCount(1, $deliveries);
        $this->assertSame('email', $deliveries[0]['provider']);
    }

    public function testPublicRegistrationCreatesOnlyLocalCredential(): void
    {
        $user = $this->controller->postRegister([
            'uid' => 'new@example.com',
            'password' => 'secret',
            'name' => 'New user',
        ]);

        $this->assertNotFalse($this->auth->get_credential('local', 'new@example.com'));
        $this->assertFalse($this->auth->get_credential('email', 'new@example.com'));
        $this->assertSame('New user', $user['name']);
    }

    public function testPublicRegistrationRejectsProviderAndPrivilegedAttributes(): void
    {
        $payloads = [
            ['provider' => 'google'],
            ['provider' => 'email'],
            ['provider' => 'local'],
            ['profile' => ['email_verified' => true]],
            ['id' => 100],
            ['uuid' => 'fake-uuid'],
            ['disabled_at' => null],
            ['token' => 'forged'],
            ['context' => ['admin' => true]],
        ];

        foreach ($payloads as $i => $payload) {
            $uid = "forbidden-{$i}@example.com";
            try {
                $this->controller->postRegister(array_merge([
                    'uid' => $uid,
                    'password' => 'secret',
                ], $payload));
                $this->fail('Untrusted registration field was accepted');
            } catch (UserException $e) {
                $this->assertSame(400, $e->getCode());
            }
            $this->assertFalse($this->auth->get_credential('local', $uid));
            $this->assertFalse($this->auth->get_credential('email', $uid));
            $this->assertFalse($this->auth->get_credential('google', $uid));
        }
    }

    public function testPublicRegistrationNeverAllowsRoleGrants(): void
    {
        $auth = new BasicAuth([], [
            'token' => 'token',
            'register_allow_grants' => true,
        ]);
        $controller = new AuthController($auth);
        $user = $controller->postRegister([
            'uid' => 'no-admin@example.com',
            'password' => 'secret',
            'roles' => ['admin'],
        ]);
        $this->assertSame([], $user['roles'] ?? []);
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
