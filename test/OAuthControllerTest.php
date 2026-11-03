<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';
require_once __DIR__ . '/OAuthTestProvider.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Controller\OAuthController;
use League\OAuth2\Client\Provider\Test as OAuthTestProvider;
use PHPUnit\Framework\TestCase;

class OAuthTrackingBasicAuth extends BasicAuth
{
    public bool $sessionRegenerated = false;

    protected function regenerateSessionId(): void
    {
        $this->sessionRegenerated = true;
    }
}

class OAuthTestController extends OAuthController
{
    public ?string $redirectedTo = null;

    protected function redirect(string $location): void
    {
        $this->redirectedTo = $location;
    }
}

class OAuthControllerTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
        $_SERVER = [];
        OAuthTestProvider::$lastConfig = [];
        OAuthTestProvider::$resourceOwner = null;
        OAuthTestProvider::$state = 'test-oauth-state';
    }

    public function testGetWithInvalidProviderThrows(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthController($auth, []);

        $this->expectException(\Exception::class);
        $this->expectExceptionCode(406);
        $controller->get('missing-provider', []);
    }

    public function testAuthorizationUsesConfiguredRedirectUriAndStoresState(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);

        $controller->get('test', []);

        $this->assertSame('https://app.example/oauth/test', OAuthTestProvider::$lastConfig['redirectUri']);
        $this->assertSame('test-oauth-state', $_SESSION['oauth2state']);
        $this->assertSame('https://oauth.example/authorize', $controller->redirectedTo);
    }

    public function testAuthorizationDerivesRedirectUriWhenNotConfigured(): void
    {
        $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https, http';
        $_SERVER['HTTP_HOST'] = 'app.example';
        $_SERVER['PHP_SELF'] = '/index.php/oauth';
        $_SERVER['PATH_INFO'] = '/test';

        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
            ],
        ]);

        $controller->get('test', []);

        $this->assertSame(
            'https://app.example/oauth/test',
            OAuthTestProvider::$lastConfig['redirectUri']
        );
    }

    public function testOAuthCallbackConsumesStateAndLinksExistingEmailUser(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $user = $auth->register('linked@example.com', 'secret', ['provider' => 'email']);

        OAuthTestProvider::$resourceOwner = $this->resourceOwner(
            'provider-user-id',
            'linked@example.com'
        );
        $_SESSION['oauth2state'] = 'test-oauth-state';

        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);

        $controller->get('test', [
            'code' => 'oauth-code',
            'state' => 'test-oauth-state',
        ]);

        $this->assertArrayNotHasKey('oauth2state', $_SESSION);
        $this->assertSame('/', $controller->redirectedTo);
        $this->assertTrue($auth->sessionRegenerated);
        $this->assertSame($user['id'], $auth->user()['id']);

        $credential = $auth->get_credential('test', 'provider-user-id');
        $this->assertNotFalse($credential);
        $this->assertSame($user['id'], $credential['user_id']);
    }

    public function testInvalidOAuthStateIsCleared(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $_SESSION['oauth2state'] = 'expected-state';

        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);

        try {
            $controller->get('test', [
                'code' => 'oauth-code',
                'state' => 'wrong-state',
            ]);
            $this->fail('Expected invalid OAuth state to be rejected');
        } catch (\Exception $exception) {
            $this->assertSame(406, $exception->getCode());
        }

        $this->assertArrayNotHasKey('oauth2state', $_SESSION);
    }

    public function testLoggedInUserCanLinkOAuthCredential(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $user = $auth->register('local@example.com', 'secret');
        $auth->login('local@example.com', 'secret');

        $controller = new OAuthController($auth, []);
        $logged = $this->invokeOAuthLogin(
            $controller,
            'google',
            $this->resourceOwner('google-linked-id')
        );

        $credential = $auth->get_credential('google', 'google-linked-id');
        $this->assertNotFalse($credential);
        $this->assertSame($user['id'], $credential['user_id']);
        $this->assertSame($user['id'], $logged['id']);
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
