<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Controller\OAuthController;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Uses real League Google/Facebook provider implementations with intercepted
 * HTTP requests. No provider credentials, network calls, or live user data.
 *
 * The provider packages are optional in production; only the dedicated CI
 * integration job installs them. Standard auth tests remain independent.
 */
class RealOAuthProviderController extends OAuthController
{
    public ?string $redirectedTo = null;

    public function __construct(
        BasicAuth $auth,
        array $providers,
        private object $testHttpClient
    ) {
        parent::__construct($auth, $providers, '/account/choose');
    }

    protected function createProvider(string $class, array $config): object
    {
        // Real provider, not a mock subclass. Only transport is replaced.
        return new $class($config, ['httpClient' => $this->testHttpClient]);
    }

    protected function redirect(string $location): void
    {
        $this->redirectedTo = $location;
    }
}

final class RealOAuthProviderTest extends TestCase
{
    protected function setUp(): void
    {
        if (!class_exists(\League\OAuth2\Client\Provider\Google::class)
            || !class_exists(\League\OAuth2\Client\Provider\Facebook::class)
            || !class_exists(Client::class)) {
            $this->markTestSkipped('Optional League OAuth2 provider libraries are not installed.');
        }

        $_SESSION = [];
        $_SERVER = [];
    }

    /**
     * Use Guzzle's real request pipeline; return deterministic JSON bodies
     * at the token and profile endpoints without connecting to the network.
     *
     * @return array{0: Client, 1: array}
     */
    private function clientWithResponses(array $responses, array &$history): Client
    {
        $mock = new MockHandler(array_map(
            static fn (array $json): Response =>
                new Response(200, ['Content-Type' => 'application/json'], json_encode($json, JSON_THROW_ON_ERROR)),
            $responses
        ));
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));
        return new Client(['handler' => $stack]);
    }

    private function providerConfig(string $provider): array
    {
        $config = [
            'clientId' => 'integration-client-id',
            'clientSecret' => 'integration-client-secret',
            'redirectUri' => 'https://application.example/auth/oauth/' . $provider,
        ];
        if ($provider === 'facebook') {
            // Required by the real Facebook provider.
            $config['graphApiVersion'] = 'v22.0';
        }
        return [$provider => $config];
    }

    private function assertAuthorizationRequest(
        RealOAuthProviderController $controller,
        string $provider
    ): array {
        $uri = $controller->redirectedTo;
        $this->assertIsString($uri);
        $this->assertSame('https', parse_url($uri, PHP_URL_SCHEME));
        $this->assertSame(
            $provider === 'google' ? 'accounts.google.com' : 'www.facebook.com',
            parse_url($uri, PHP_URL_HOST)
        );
        parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);

        $this->assertSame('integration-client-id', $query['client_id']);
        $this->assertSame(
            'https://application.example/auth/oauth/' . $provider,
            $query['redirect_uri']
        );
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertArrayHasKey('state', $query);
        $this->assertNotSame('', $query['state']);

        $flow = $_SESSION['oauth2flows'][$provider];
        $this->assertSame($query['state'], $flow['state']);
        $this->assertSame('login', $flow['intent']);

        $expectedChallenge = rtrim(
            strtr(base64_encode(hash('sha256', $flow['code_verifier'], true)), '+/', '-_'),
            '='
        );
        $this->assertSame($expectedChallenge, $query['code_challenge']);

        $scopes = explode(' ', str_replace(',', ' ', $query['scope']));
        if ($provider === 'google') {
            $this->assertContains('openid', $scopes);
            $this->assertContains('email', $scopes);
            $this->assertContains('profile', $scopes);
        } else {
            $this->assertContains('public_profile', $scopes);
            $this->assertContains('email', $scopes);
        }

        return $flow;
    }

    private function assertTokenAndProfileRequests(
        array $history,
        string $provider,
        string $verifier
    ): void {
        $this->assertCount(2, $history);
        $token = $history[0]['request'];
        $profile = $history[1]['request'];
        $this->assertSame('POST', $token->getMethod());
        $this->assertSame(
            $provider === 'google' ? 'oauth2.googleapis.com' : 'graph.facebook.com',
            $token->getUri()->getHost()
        );
        $this->assertSame(
            $provider === 'google' ? '/token' : '/v22.0/oauth/access_token',
            $token->getUri()->getPath()
        );
        parse_str((string) $token->getBody(), $body);
        $this->assertSame('authorization_code', $body['grant_type']);
        $this->assertSame('integration-auth-code', $body['code']);
        $this->assertSame('integration-client-id', $body['client_id']);
        $this->assertSame(
            'https://application.example/auth/oauth/' . $provider,
            $body['redirect_uri']
        );
        $this->assertSame($verifier, $body['code_verifier']);

        $this->assertSame('GET', $profile->getMethod());
        if ($provider === 'google') {
            $this->assertSame('openidconnect.googleapis.com', $profile->getUri()->getHost());
            $this->assertSame('/v1/userinfo', $profile->getUri()->getPath());
            $this->assertSame('Bearer integration-access-token', $profile->getHeaderLine('Authorization'));
        } else {
            $this->assertSame('graph.facebook.com', $profile->getUri()->getHost());
            $this->assertSame('/v22.0/me', $profile->getUri()->getPath());
            parse_str($profile->getUri()->getQuery(), $params);
            $this->assertSame('integration-access-token', $params['access_token']);
            $this->assertNotEmpty($params['appsecret_proof']);
        }
    }

    public function testRealGoogleProviderCanCompleteFirstTimeOAuthAndLinkExistingAccount(): void
    {
        $history = [];
        $http = $this->clientWithResponses([
            ['access_token' => 'integration-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600],
            [
                'sub' => 'google-stable-subject', 'name' => 'Google Person',
                'given_name' => 'Google', 'family_name' => 'Person',
                'picture' => 'https://images.example.com/google.png',
                'email' => 'google.profile@example.com', 'email_verified' => true,
            ],
        ], $history);
        $auth = new BasicAuth([], ['token' => 'token']);
        $existing = $auth->register('existing@example.com', 'correct-password');
        $controller = new RealOAuthProviderController($auth, $this->providerConfig('google'), $http);

        $controller->get('google', []);
        $flow = $this->assertAuthorizationRequest($controller, 'google');
        $controller->get('google', [
            'code' => 'integration-auth-code',
            'state' => $flow['state'],
        ]);

        $this->assertTokenAndProfileRequests($history, 'google', $flow['code_verifier']);
        $this->assertSame('/account/choose', $controller->redirectedTo);
        $this->assertArrayNotHasKey('google', $_SESSION['oauth2flows']);
        $this->assertFalse($auth->check());
        $this->assertFalse($auth->get_credential('google', 'google-stable-subject'));
        $this->assertSame('Google Person', $controller->getPendingAccount()['name']);
        $this->assertSame('google.profile@example.com', $controller->getPendingAccount()['email_hint']);
        $this->assertSame('https://images.example.com/google.png', $_SESSION['oauth2pending']['image']);

        $this->authorizeAccountChoice($auth);
        $linked = $controller->postExistingAccount([
            'uid' => 'existing@example.com', 'password' => 'correct-password',
        ]);
        $this->assertSame('linked', $linked['status']);
        $this->assertSame($existing['id'], $linked['user']['id']);
        $credential = $auth->get_credential('google', 'google-stable-subject');
        $this->assertSame($existing['id'], $credential['user_id']);
        $this->assertNotEmpty($credential['verified_at']);
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
    }

    public function testRealFacebookProviderCanCompleteFirstTimeOAuthAndCreateAccount(): void
    {
        $history = [];
        $http = $this->clientWithResponses([
            ['access_token' => 'integration-access-token', 'token_type' => 'bearer', 'expires_in' => 3600],
            [
                'id' => 'facebook-stable-subject', 'name' => 'Facebook Person',
                'first_name' => 'Facebook', 'last_name' => 'Person',
                'email' => 'facebook.profile@example.com',
                'picture' => ['data' => [
                    'url' => 'https://images.example.com/facebook.png',
                    'is_silhouette' => false,
                ]],
            ],
        ], $history);
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new RealOAuthProviderController($auth, $this->providerConfig('facebook'), $http);

        $controller->get('facebook', []);
        $flow = $this->assertAuthorizationRequest($controller, 'facebook');
        $controller->get('facebook', [
            'code' => 'integration-auth-code',
            'state' => $flow['state'],
        ]);

        $this->assertTokenAndProfileRequests($history, 'facebook', $flow['code_verifier']);
        $this->assertSame('/account/choose', $controller->redirectedTo);
        $this->assertFalse($auth->check());
        $this->assertFalse($auth->get_credential('facebook', 'facebook-stable-subject'));
        $pending = $controller->getPendingAccount();
        $this->assertSame('Facebook Person', $pending['name']);
        $this->assertSame('facebook.profile@example.com', $pending['email_hint']);
        $this->assertSame('https://images.example.com/facebook.png', $_SESSION['oauth2pending']['image']);

        $this->authorizeAccountChoice($auth);
        $created = $controller->postCreateAccount();
        $this->assertSame('created', $created['status']);
        $this->assertTrue($auth->check());
        $this->assertSame('Facebook Person', $created['user']['name']);
        $this->assertSame('https://images.example.com/facebook.png', $created['user']['image']);
        $credential = $auth->get_credential('facebook', 'facebook-stable-subject');
        $this->assertSame($created['user']['id'], $credential['user_id']);
        $this->assertNotEmpty($credential['verified_at']);
    }

    public function testRealGoogleProviderSignsInExistingLinkedAccountWithoutNewChoice(): void
    {
        $history = [];
        $http = $this->clientWithResponses([
            ['access_token' => 'integration-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600],
            ['sub' => 'known-google-id', 'name' => 'Returning Google User', 'email' => 'returning@example.com'],
        ], $history);
        $auth = new BasicAuth([], ['token' => 'token']);
        $owner = $auth->register('returning@example.com', 'secret');
        $auth->create_credential($owner['id'], 'google', 'known-google-id');
        $auth->mark_credential_verified($owner['id'], 'google', 'known-google-id');
        $controller = new RealOAuthProviderController($auth, $this->providerConfig('google'), $http);

        $controller->get('google', []);
        $flow = $this->assertAuthorizationRequest($controller, 'google');
        $controller->get('google', [
            'code' => 'integration-auth-code', 'state' => $flow['state'],
        ]);

        $this->assertTokenAndProfileRequests($history, 'google', $flow['code_verifier']);
        $this->assertSame('/', $controller->redirectedTo);
        $this->assertTrue($auth->check());
        $this->assertSame($owner['id'], $auth->user()['id']);
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
    }

    public function testRealFacebookProviderExplicitLinkUsesSameAccountAndPkce(): void
    {
        $history = [];
        $http = $this->clientWithResponses([
            ['access_token' => 'integration-access-token', 'token_type' => 'bearer', 'expires_in' => 3600],
            ['id' => 'new-facebook-identity', 'name' => 'Linked Facebook User'],
        ], $history);
        $auth = new BasicAuth([], ['token' => 'token']);
        $owner = $auth->register('facebook-link@example.com', 'correct-password');
        $auth->login('facebook-link@example.com', 'correct-password');
        $controller = new RealOAuthProviderController($auth, $this->providerConfig('facebook'), $http);
        $this->authorizeAccountChoice($auth);

        $link = $controller->postLink('facebook');
        $this->assertArrayHasKey('authorization_url', $link);
        $controller->redirectedTo = $link['authorization_url'];
        $flow = $this->assertLinkAuthorizationRequest($controller);

        $controller->get('facebook', [
            'code' => 'integration-auth-code', 'state' => $flow['state'],
        ]);
        $this->assertTokenAndProfileRequests($history, 'facebook', $flow['code_verifier']);
        $this->assertSame('/', $controller->redirectedTo);
        $this->assertSame($owner['id'], $auth->user()['id']);
        $credential = $auth->get_credential('facebook', 'new-facebook-identity');
        $this->assertSame($owner['id'], $credential['user_id']);
        $this->assertNotEmpty($credential['verified_at']);
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
    }

    private function assertLinkAuthorizationRequest(RealOAuthProviderController $controller): array
    {
        $flow = $_SESSION['oauth2flows']['facebook'];
        $this->assertSame('link', $flow['intent']);
        $this->assertNotNull($flow['principal']);
        parse_str((string) parse_url($controller->redirectedTo, PHP_URL_QUERY), $query);
        $this->assertSame($flow['state'], $query['state']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame(
            rtrim(strtr(base64_encode(hash('sha256', $flow['code_verifier'], true)), '+/', '-_'), '='),
            $query['code_challenge']
        );
        return $flow;
    }

    public function testRealGoogleProviderRejectsWrongOAuthStateBeforeHttp(): void
    {
        $history = [];
        $http = $this->clientWithResponses([], $history);
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new RealOAuthProviderController($auth, $this->providerConfig('google'), $http);
        $controller->get('google', []);

        try {
            $controller->get('google', [
                'code' => 'integration-auth-code', 'state' => 'attacker-state',
            ]);
            $this->fail('Unexpectedly accepted mismatched provider state');
        } catch (\Exception $e) {
            $this->assertSame(406, $e->getCode());
        }
        $this->assertCount(0, $history);
        $this->assertArrayNotHasKey('google', $_SESSION['oauth2flows']);
    }

    public function testRealFacebookProviderRejectsTokenErrorsWithoutCreatingAccount(): void
    {
        $history = [];
        $mock = new MockHandler([
            new Response(400, ['Content-Type' => 'application/json'], json_encode([
                'error' => ['type' => 'OAuthException', 'message' => 'Invalid code', 'code' => 190],
            ], JSON_THROW_ON_ERROR)),
        ]);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($history));
        $http = new Client(['handler' => $stack]);
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new RealOAuthProviderController($auth, $this->providerConfig('facebook'), $http);
        $controller->get('facebook', []);
        $flow = $_SESSION['oauth2flows']['facebook'];

        try {
            $controller->get('facebook', [
                'code' => 'integration-auth-code', 'state' => $flow['state'],
            ]);
            $this->fail('Token error unexpectedly created an account');
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            $this->assertSame(190, $e->getCode());
        }

        $this->assertCount(1, $history);
        $this->assertFalse($auth->check());
        $this->assertArrayNotHasKey('oauth2pending', $_SESSION);
        $this->assertArrayNotHasKey('facebook', $_SESSION['oauth2flows']);
    }

    private function authorizeAccountChoice(BasicAuth $auth): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $auth->management_csrf_token();
    }
}
