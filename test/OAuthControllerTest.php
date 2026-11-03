<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Controller\OAuthController;
use PHPUnit\Framework\TestCase;

class OAuthTrackingBasicAuth extends BasicAuth
{
    public bool $sessionRegenerated = false;

    protected function regenerateSessionId(): void
    {
        $this->sessionRegenerated = true;
    }
}

class OAuthControllerTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
    }

    public function testGetWithInvalidProviderThrows(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthController($auth, []);

        $this->expectException(\Exception::class);
        $this->expectExceptionCode(406);
        $controller->get('missing-provider', []);
    }

    public function testOAuthLoginRejectsSuspendedUser(): void
    {
        $auth = new OAuthTrackingBasicAuth([], [
            'token' => 'token',
            'disabled_at' => 'disabled_at',
        ]);
        $auth->register('google-user-id', null, [
            'provider' => 'google',
            'disabled_at' => '2026-09-27 12:00:00',
        ]);

        $controller = new OAuthController($auth, []);
        $resourceOwner = $this->resourceOwner('google-user-id');

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(403);

        $this->invokeOAuthLogin($controller, 'google', $resourceOwner);
    }

    public function testOAuthLoginRegeneratesSessionBeforeStoringPrincipal(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $user = $auth->register('google-user-id', null, ['provider' => 'google']);

        $controller = new OAuthController($auth, []);
        $logged = $this->invokeOAuthLogin(
            $controller,
            'google',
            $this->resourceOwner('google-user-id')
        );

        $this->assertTrue($auth->sessionRegenerated);
        $this->assertTrue($auth->check());
        $this->assertSame($user['id'], $logged['id']);
        $this->assertSame($user['id'], $auth->user()['id']);
    }

    private function invokeOAuthLogin(
        OAuthController $controller,
        string $provider,
        object $resourceOwner
    ): array {
        $method = new ReflectionMethod($controller, 'login');
        return $method->invoke($controller, $provider, $resourceOwner);
    }

    private function resourceOwner(string $id, ?string $email = null): object
    {
        return new class ($id, $email) {
            public function __construct(
                private string $id,
                private ?string $email
            ) {
            }

            public function getId(): string
            {
                return $this->id;
            }

            public function getEmail(): ?string
            {
                return $this->email;
            }

            public function getName(): string
            {
                return 'OAuth User';
            }

            public function getAvatar(): string
            {
                return 'https://example.com/avatar.png';
            }

            public function getPictureUrl(): string
            {
                return 'https://example.com/avatar.png';
            }

            public function toArray(): array
            {
                return ['id' => $this->id, 'email' => $this->email];
            }
        };
    }
}
