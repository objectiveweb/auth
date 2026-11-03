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
        OAuthTestProvider::$lastAuthorizationOptions = [];
        OAuthTestProvider::$lastTokenOptions = [];
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
        $flow = $_SESSION['oauth2flows']['test'];
        $this->assertSame('test-oauth-state', $flow['state']);
        $this->assertNull($flow['principal']);
        $this->assertGreaterThanOrEqual(43, strlen($flow['code_verifier']));
        $this->assertSame('S256', OAuthTestProvider::$lastAuthorizationOptions['code_challenge_method']);
        $expectedChallenge = rtrim(
            strtr(base64_encode(hash('sha256', $flow['code_verifier'], true)), '+/', '-_'),
            '='
        );
        $this->assertSame($expectedChallenge, OAuthTestProvider::$lastAuthorizationOptions['code_challenge']);
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

    public function testFirstTimeOAuthOffersAccountChoiceWithoutCreatingUser(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $existing = $auth->register('linked@example.com', 'secret', ['provider' => 'email']);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner(
            'provider-user-id', 'linked@example.com'
        );
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
        $this->assertSame('/?oauth=choose-account', $controller->redirectedTo);
        $this->assertFalse($auth->check());
        $this->assertFalse($auth->get_credential('test', 'provider-user-id'));
        $this->assertSame($existing['id'], $auth->get_credential('email', 'linked@example.com')['user_id']);

        $choice = $controller->getPendingAccount();
        $this->assertSame('account_choice_required', $choice['status']);
        $this->assertSame(['create', 'existing'], $choice['choices']);
        $this->assertSame('test', $choice['provider']);
        $this->assertSame('linked@example.com', $choice['email_hint']);
        $this->assertNotEmpty($choice['_csrf']);
        $this->assertArrayNotHasKey('uid', $choice);
        $this->assertArrayNotHasKey('profile', $choice);
    }

    public function testMinimalLeagueResourceOwnerDoesNotRequireOptionalMethods(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = new class {
            public function getId(): string { return 'minimal-provider-subject'; }
            public function toArray(): array { return ['id' => 'minimal-provider-subject']; }
        };

        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $pending = $controller->getPendingAccount();
        $this->assertSame('account_choice_required', $pending['status']);
        $this->assertNull($pending['name']);
        $this->assertNull($pending['image'] ?? null);
        $this->assertNull($pending['email_hint']);
        $this->assertFalse($auth->get_credential('test', 'minimal-provider-subject'));

        $this->withLinkHeaders($auth);
        $created = $controller->postCreateAccount();
        $this->assertSame('created', $created['status']);
        $this->assertSame(
            $created['user']['id'],
            $auth->get_credential('test', 'minimal-provider-subject')['user_id']
        );
        $this->assertNotEmpty($auth->get_credential('test', 'minimal-provider-subject')['verified_at']);
    }

    public function testLeagueProfileArraySuppliesSafeNameAvatarAndEmailHints(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = new class {
            public function getId(): int { return 92735; }
            public function toArray(): array
            {
                return [
                    'name' => '  Profile Name  ',
                    'avatar_url' => 'https://example.com/avatar.png',
                    'email' => 'profile@example.com',
                ];
            }
        };

        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $pending = $controller->getPendingAccount();
        $this->assertSame('Profile Name', $pending['name']);
        $this->assertSame('profile@example.com', $pending['email_hint']);
        $this->assertSame('https://example.com/avatar.png', $_SESSION['oauth2pending']['image']);
        $this->assertArrayNotHasKey('uid', $pending);

        $this->withLinkHeaders($auth);
        $result = $controller->postCreateAccount();
        $this->assertSame('Profile Name', $result['user']['name']);
        $this->assertSame('https://example.com/avatar.png', $result['user']['image']);
        $this->assertNotFalse($auth->get_credential('test', '92735'));
    }

    public function testNestedPictureAndSplitNameProfileFallbacks(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = new class {
            public function getId(): string { return 'nested-fields'; }
            public function toArray(): array
            {
                return [
                    'given_name' => ' Alice ',
                    'family_name' => 'Smith',
                    'picture' => ['data' => ['url' => 'https://cdn.example.com/photo.jpg']],
                    'email_address' => 'alice@example.com',
                ];
            }
        };
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $pending = $controller->getPendingAccount();
        $this->assertSame('Alice Smith', $pending['name']);
        $this->assertSame('alice@example.com', $pending['email_hint']);
        $this->assertSame('https://cdn.example.com/photo.jpg', $_SESSION['oauth2pending']['image']);
    }

    public function testMalformedOrThrowingOptionalGettersSafelyFallBackToProfile(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = new class {
            public function getId(): string { return 'broken-optional-fields'; }
            public function getName(): string { throw new \RuntimeException('Name unavailable'); }
            public function getAvatar(): array { return ['unexpected' => 'value']; }
            public function getPictureUrl(): string { throw new \RuntimeException('Picture unavailable'); }
            public function getEmail(): array { return ['bad' => 'value']; }
            public function toArray(): array
            {
                return [
                    'display_name' => '  Resilient User  ',
                    'picture_url' => 'javascript:alert(1)',
                    'image_url' => 'https://images.example.com/photo.jpg',
                    'mail' => ' valid@example.com ',
                ];
            }
        };

        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $pending = $controller->getPendingAccount();
        $this->assertSame('Resilient User', $pending['name']);
        $this->assertSame('valid@example.com', $pending['email_hint']);
        $this->assertSame('https://images.example.com/photo.jpg', $_SESSION['oauth2pending']['image']);
    }

    public function testUnsafeAvatarAndInvalidEmailHintsAreIgnored(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = new class {
            public function getId(): string { return 'unsafe-fields'; }
            public function toArray(): array
            {
                return [
                    'name' => ['not' => 'text'],
                    'picture' => 'data:image/svg+xml;base64,PHN2Zz4=',
                    'avatar_url' => 'javascript:alert(1)',
                    'email' => 'not-an-email',
                ];
            }
        };

        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $pending = $controller->getPendingAccount();
        $this->assertNull($pending['name']);
        $this->assertNull($pending['email_hint']);
        $this->assertNull($_SESSION['oauth2pending']['image']);
    }

    public function testInvalidProviderSubjectTypeIsRejected(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = $this->testController($auth);
        $owner = new class {
            public function getId(): array { return ['not' => 'an id']; }
            public function toArray(): array { return []; }
        };
        $this->expectException(AuthException::class);
        $this->expectExceptionCode(401);
        $this->invokeOAuthLogin($controller, 'test', $owner);
    }

    public function testFirstTimeOAuthCanExplicitlyCreateNewAccount(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $local = $auth->register('matching@example.com', 'old-password');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner(
            'new-oauth-subject', 'matching@example.com'
        );
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $this->withLinkHeaders($auth);
        $result = $controller->postCreateAccount(['name' => 'New OAuth Account']);
        $this->assertSame('created', $result['status']);
        $created = $result['user'];
        $this->assertNotSame($local['id'], $created['id']);
        $this->assertSame('New OAuth Account', $created['name']);
        $this->assertSame($created['id'], $auth->get_credential('test', 'new-oauth-subject')['user_id']);
        $this->assertNotEmpty($auth->get_credential('test', 'new-oauth-subject')['verified_at']);
        $this->assertSame($local['id'], $auth->get_credential('local', 'matching@example.com')['user_id']);
        $this->assertFalse($auth->get_credential('local', 'new-oauth-subject'));
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
        $this->assertTrue($auth->check());
    }

    public function testFirstTimeOAuthCanAuthenticateExistingAccountAndLink(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $local = $auth->register('old@example.com', 'local-secret');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner(
            'pending-oauth-subject', 'provider-email@example.com'
        );
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $this->withLinkHeaders($auth);
        try {
            $controller->postExistingAccount(['uid' => 'old@example.com', 'password' => 'wrong']);
            $this->fail('Incorrect local password was accepted');
        } catch (AuthException $e) {
            $this->assertSame(401, $e->getCode());
        }
        $this->assertFalse($auth->check());
        $this->assertArrayHasKey('oauth2pending', $_SESSION);
        $this->assertFalse($auth->get_credential('test', 'pending-oauth-subject'));

        $result = $controller->postExistingAccount([
            'uid' => 'old@example.com',
            'password' => 'local-secret',
        ]);
        $this->assertSame('linked', $result['status']);
        $this->assertSame($local['id'], $result['user']['id']);
        $this->assertSame($local['id'], $auth->get_credential('test', 'pending-oauth-subject')['user_id']);
        $this->assertNotEmpty($auth->get_credential('test', 'pending-oauth-subject')['verified_at']);
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
        $this->assertTrue($auth->check());
    }


    public function testPendingAccountCannotBeCreatedWithoutExplicitChoice(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('new-id');
        $controller = $this->testController($auth);

        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $this->assertFalse($auth->get_credential('test', 'new-id'));
        $this->assertFalse($auth->check());

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        try {
            $controller->postCreateAccount();
            $this->fail('Creating without CSRF token succeeded');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(403, $e->getCode());
        }
        $this->assertFalse($auth->get_credential('test', 'new-id'));

        $this->withLinkHeaders($auth);
        try {
            $controller->postCreateAccount(['provider' => 'local']);
            $this->fail('Provider injection during OAuth account creation succeeded');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(400, $e->getCode());
        }
        $this->assertArrayHasKey('oauth2pending', $_SESSION);
    }

    public function testPendingAccountCreationHonorsRegistrationPolicy(): void
    {
        $auth = new BasicAuth([], [
            'token' => 'token',
            'register_scope' => \Objectiveweb\Auth::AUTHENTICATED,
        ]);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('restricted-id');
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $this->withLinkHeaders($auth);

        try {
            $controller->postCreateAccount();
            $this->fail('Restricted account creation succeeded');
        } catch (\Objectiveweb\Auth\AuthException $e) {
            $this->assertSame(401, $e->getCode());
        }
        $this->assertFalse($auth->get_credential('test', 'restricted-id'));
    }

    public function testPendingAccountExpiresAndIsRemoved(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('expiring-id');
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $_SESSION['oauth2pending']['created_at'] = time() - 601;

        try {
            $controller->getPendingAccount();
            $this->fail('Expired pending account still available');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(410, $e->getCode());
        }
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
        $this->assertFalse($auth->get_credential('test', 'expiring-id'));
    }

    public function testAccountChoiceCannotBeReplayedOrUsedAfterCancellation(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('choice-id');
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $this->withLinkHeaders($auth);
        $this->assertSame('cancelled', $controller->postCancelPendingAccount()['status']);
        try {
            $controller->postCreateAccount();
            $this->fail('Cancelled account choice still usable');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(410, $e->getCode());
        }

        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $result = $controller->postCreateAccount();
        $this->assertSame('created', $result['status']);
        $auth->logout();
        try {
            $controller->postExistingAccount(['uid' => 'other@example.com', 'password' => 'secret']);
            $this->fail('A consumed OAuth proof was reused');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(410, $e->getCode());
        }
    }

    public function testAccountChoiceRejectsPreviouslyLinkedProviderIdentity(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $owner = $auth->register('existing@example.com', 'password');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('race-id');
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        // A different request associates the identity while the choice is pending.
        $auth->create_credential($owner['id'], 'test', 'race-id');
        $auth->mark_credential_verified($owner['id'], 'test', 'race-id');
        $this->withLinkHeaders($auth);
        try {
            $controller->postCreateAccount();
            $this->fail('Duplicate OAuth identity was accepted');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(409, $e->getCode());
        }
        $this->assertSame($owner['id'], $auth->get_credential('test', 'race-id')['user_id']);
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
    }

    public function testExistingAccountChoiceRejectsInvalidPayloadAndUntrustedMethods(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $auth->register('existing@example.com', 'secret');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('pending-id');
        $controller = $this->testController($auth);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $this->withLinkHeaders($auth);
        $_SERVER['REQUEST_METHOD'] = 'GET';
        try {
            $controller->postExistingAccount(['uid' => 'existing@example.com', 'password' => 'secret']);
            $this->fail('GET linked a provider credential');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(405, $e->getCode());
        }
        $_SERVER['REQUEST_METHOD'] = 'POST';
        try {
            $controller->postExistingAccount([
                'uid' => 'existing@example.com',
                'password' => 'secret',
                'provider' => 'test',
            ]);
            $this->fail('Provider injection accepted in existing-account choice');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(400, $e->getCode());
        }
        $this->assertFalse($auth->get_credential('test', 'pending-id'));
        $this->assertArrayHasKey('oauth2pending', $_SESSION);
    }

    public function testPendingChoiceRedirectRejectsExternalUrl(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(400);
        $this->testController(new BasicAuth(), '//attacker.example/receive');
    }

    public function testUnverifiedOAuthCredentialCannotBeUsedToLogInAnotherAccount(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $victim = $auth->register('victim@example.com', 'secret');
        $auth->create_credential($victim['id'], 'google', 'attacker-provider-subject');

        $controller = new OAuthController($auth);
        $this->expectException(AuthException::class);
        $this->expectExceptionCode(403);
        $this->invokeOAuthLogin($controller, 'google', $this->resourceOwner('attacker-provider-subject'));
    }

    public function testAuthenticatedAccountCanConfirmItsOwnPendingOAuthCredential(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $owner = $auth->register('owner@example.com', 'secret');
        $auth->create_credential($owner['id'], 'test', 'owner-subject');
        $auth->login('owner@example.com', 'secret');
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('owner-subject');

        $this->withLinkHeaders($auth);
        $linkResponse = $controller->postLink('test');
        $this->assertSame('https://oauth.example/authorize', $linkResponse['authorization_url']);
        $this->assertSame('link', $_SESSION['oauth2flows']['test']['intent']);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $this->assertSame($owner['id'], $auth->user()['id']);
        $this->assertNotEmpty($auth->get_credential('test', 'owner-subject')['verified_at']);
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
    }

    public function testSignedInUserCannotSwitchToDifferentVerifiedOAuthAccount(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $other = $auth->register('other-subject', null, ['provider' => 'google']);
        $auth->mark_credential_verified($other['id'], 'google', 'other-subject');
        $auth->register('current@example.com', 'secret');
        $auth->login('current@example.com', 'secret');
        $controller = new OAuthController($auth);

        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $this->expectExceptionCode(409);
        $this->invokeOAuthLogin($controller, 'google', $this->resourceOwner('other-subject'));
    }

    public function testInvalidOAuthStateIsCleared(): void
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
        try {
            $controller->get('test', [
                'code' => 'oauth-code',
                'state' => 'wrong-state',
            ]);
            $this->fail('Expected invalid OAuth state to be rejected');
        } catch (\Exception $exception) {
            $this->assertSame(406, $exception->getCode());
        }

        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
    }

    public function testOAuthCallbackStateIsProviderSpecific(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'first', 'clientSecret' => 'first',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
            'other' => [
                'clientId' => 'second', 'clientSecret' => 'second',
                'redirectUri' => 'https://app.example/oauth/other',
            ],
        ]);
        // Initiating a flow for one provider does not authorize another.
        $controller->get('test', []);
        try {
            $controller->get('other', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('State from a different provider was accepted');
        } catch (\Exception $e) {
            $this->assertSame(406, $e->getCode());
        }
        $this->assertArrayHasKey('test', $_SESSION['oauth2flows']);
    }

    public function testOAuthCallbackRejectsExpiredState(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthTestController($auth, [
            'test' => ['clientId' => 'id', 'clientSecret' => 'secret',
                'redirectUri' => 'https://app.example/oauth/test'],
        ]);
        $controller->get('test', []);
        $_SESSION['oauth2flows']['test']['created_at'] = time() - 601;

        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('Expired state was accepted');
        } catch (\Exception $e) {
            $this->assertSame(406, $e->getCode());
        }
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
    }

    public function testOAuthCallbackRejectsPrincipalChangesDuringFlow(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $auth->register('first@example.com', 'one');
        $auth->register('second@example.com', 'two');
        $auth->login('first@example.com', 'one');
        $controller = new OAuthTestController($auth, [
            'test' => ['clientId' => 'id', 'clientSecret' => 'secret',
                'redirectUri' => 'https://app.example/oauth/test'],
        ]);
        $controller->get('test', []);
        $auth->logout();
        $auth->login('second@example.com', 'two');

        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('Changed principal was allowed to complete provider linking');
        } catch (\Exception $e) {
            $this->assertSame(403, $e->getCode());
        }
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
        $this->assertFalse($auth->get_credential('test', 'provider-user-id'));
    }

    public function testOAuthCallbackRejectsReplay(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('new-subject');
        $controller = new OAuthTestController($auth, [
            'test' => ['clientId' => 'id', 'clientSecret' => 'secret',
                'redirectUri' => 'https://app.example/oauth/test'],
        ]);
        $controller->get('test', []);
        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
        $this->assertNotEmpty(OAuthTestProvider::$lastTokenOptions['code_verifier']);
        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('OAuth state could be replayed');
        } catch (\Exception $e) {
            $this->assertSame(406, $e->getCode());
        }
    }

    public function testLoggedInUserCanLinkOAuthCredential(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $user = $auth->register('local@example.com', 'secret');
        $auth->login('local@example.com', 'secret');

        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('new-linked-id');
        $this->withLinkHeaders($auth);
        $linkResponse = $controller->postLink('test');
        $this->assertSame('link', $_SESSION['oauth2flows']['test']['intent']);
        $this->assertSame((string) $user['id'], $_SESSION['oauth2flows']['test']['principal']);
        $this->assertSame('https://oauth.example/authorize', $linkResponse['authorization_url']);

        $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);

        $credential = $auth->get_credential('test', 'new-linked-id');
        $this->assertNotFalse($credential);
        $this->assertSame($user['id'], $credential['user_id']);
        $this->assertNotEmpty($credential['verified_at']);
        $this->assertSame($user['id'], $auth->user()['id']);
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
        $this->assertNotEmpty(OAuthTestProvider::$lastTokenOptions['code_verifier']);
    }

    public function testOrdinaryOAuthLoginCannotLinkNewCredentialToLoggedInUser(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $owner = $auth->register('local@example.com', 'secret');
        $auth->login('local@example.com', 'secret');
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('unrelated-subject');

        $controller->get('test', ['link' => '1']);
        $this->assertSame('login', $_SESSION['oauth2flows']['test']['intent']);
        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state', 'intent' => 'link']);
            $this->fail('OAuth login silently linked a credential');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(409, $e->getCode());
        }

        $this->assertFalse($auth->get_credential('test', 'unrelated-subject'));
        $this->assertSame($owner['id'], $auth->user()['id']);
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
    }

    public function testOrdinaryOAuthLoginCannotConfirmPendingCredential(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $owner = $auth->register('local@example.com', 'secret');
        $auth->create_credential($owner['id'], 'test', 'pending-subject');
        $auth->login('local@example.com', 'secret');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('pending-subject');
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);

        $controller->get('test', []);
        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('Unverified OAuth credential was confirmed without explicit linking');
        } catch (AuthException $e) {
            $this->assertSame(403, $e->getCode());
        }
        $this->assertEmpty($auth->get_credential('test', 'pending-subject')['verified_at']);
    }

    public function testLinkRequiresAuthenticationAndCsrfProtectedPost(): void
    {
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        try {
            $controller->postLink('test');
            $this->fail('Anonymous account was allowed to link a credential');
        } catch (AuthException $e) {
            $this->assertSame(401, $e->getCode());
        }

        $auth->register('owner@example.com', 'secret');
        $auth->login('owner@example.com', 'secret');
        try {
            $controller->postLink('test');
            $this->fail('CSRF-free account linking was accepted');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(403, $e->getCode());
        }

        $_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->management_csrf_token();
        $_SERVER['REQUEST_METHOD'] = 'GET';
        try {
            $controller->postLink('test');
            $this->fail('GET was allowed to initiate linking');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(405, $e->getCode());
        }

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
        try {
            $controller->postLink('test');
            $this->fail('Cross-origin form POST was accepted');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(415, $e->getCode());
        }

        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows'] ?? []);
    }

    public function testLinkCannotTakeOverProviderCredentialOfAnotherUser(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $victim = $auth->register('victim@example.com', 'secret');
        $auth->create_credential($victim['id'], 'test', 'victim-subject');
        $auth->mark_credential_verified($victim['id'], 'test', 'victim-subject');
        $attacker = $auth->register('attacker@example.com', 'secret');
        $auth->login('attacker@example.com', 'secret');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('victim-subject');
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);

        $this->withLinkHeaders($auth);
        $controller->postLink('test');
        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('Linked credential was stolen from another user');
        } catch (\Objectiveweb\Auth\UserException $e) {
            $this->assertSame(409, $e->getCode());
        }
        $this->assertSame($victim['id'], $auth->get_credential('test', 'victim-subject')['user_id']);
        $this->assertSame($attacker['id'], $auth->user()['id']);
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);
    }

    public function testExplicitLinkRejectsChangedSessionAndCannotBeReplayed(): void
    {
        $auth = new OAuthTrackingBasicAuth([], ['token' => 'token']);
        $auth->register('first@example.com', 'secret');
        $auth->register('second@example.com', 'secret');
        $auth->login('first@example.com', 'secret');
        OAuthTestProvider::$resourceOwner = $this->resourceOwner('provider-subject');
        $controller = new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ]);

        $this->withLinkHeaders($auth);
        $controller->postLink('test');
        $auth->logout();
        $auth->login('second@example.com', 'secret');
        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('Switched user completed someone else\'s OAuth linking flow');
        } catch (\Exception $e) {
            $this->assertSame(403, $e->getCode());
        }
        $this->assertFalse($auth->get_credential('test', 'provider-subject'));
        $this->assertArrayNotHasKey('test', $_SESSION['oauth2flows']);

        try {
            $controller->get('test', ['code' => 'oauth-code', 'state' => 'test-oauth-state']);
            $this->fail('Linking callback replayed');
        } catch (\Exception $e) {
            $this->assertSame(406, $e->getCode());
        }
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
        $auth->mark_credential_verified($user['id'], 'google', 'google-user-id');

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

    private function testController(BasicAuth $auth, string $pendingRedirect = '/?oauth=choose-account'): OAuthTestController
    {
        return new OAuthTestController($auth, [
            'test' => [
                'clientId' => 'client-id',
                'clientSecret' => 'client-secret',
                'redirectUri' => 'https://app.example/oauth/test',
            ],
        ], $pendingRedirect);
    }

    private function withLinkHeaders(BasicAuth $auth): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/json; charset=utf-8';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->management_csrf_token();
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
