<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Controller\AuthController;
use Objectiveweb\Router;
use PHPUnit\Framework\TestCase;

/**
 * Exercise the actual objectiveweb/router controller dispatch and attribute
 * precedence, rather than calling postRegister() directly.
 */
class RegistrationRouterTest extends TestCase
{
    private array $serverBefore;
    private mixed $postBefore;
    private mixed $getBefore;

    protected function setUp(): void
    {
        $this->serverBefore = $_SERVER;
        $this->postBefore = $_POST;
        $this->getBefore = $_GET;
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->serverBefore;
        $_POST = $this->postBefore;
        $_GET = $this->getBefore;
        $_SESSION = [];
    }

    /**
     * Router::controller() handles POST /auth/register, invokes the real
     * RequireRole middleware and parses the JSON body before dispatch.
     *
     * Override only the response writer to avoid exiting PHPUnit.
     */
    private function dispatch(BasicAuth $auth, string $uid): array
    {
        $router = new class extends Router {
            public static mixed $response = null;
            public static int $status = 0;

            public static function respond(mixed $value, int $code = 200, bool $debug = false): void
            {
                self::$response = $value;
                self::$status = $code;
            }
        };

        $_SERVER['SCRIPT_NAME'] = '/index.php';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REQUEST_URI'] = '/auth/register';
        $_SERVER['REDIRECT_URL'] = '/auth/register';
        $_SERVER['PATH_INFO'] = '/auth/register';
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        $_POST = json_encode(['uid' => $uid, 'password' => 'secret-password']);
        $_GET = [];

        $router::$response = null;
        $router::$status = 0;
        $router->controller('/auth', new AuthController($auth));

        return [$router::$status, $router::$response];
    }

    public function testAnonymousRegistrationUsesConfiguredScope(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::ANONYMOUS]);
        [$status, $response] = $this->dispatch($auth, 'anonymous@example.com');

        $this->assertSame(200, $status);
        $this->assertSame('anonymous@example.com', $response['uid']);
        $this->assertNotFalse($auth->get_credential('local', 'anonymous@example.com'));

        $auth->register('actor@example.com', 'secret-password');
        $auth->login('actor@example.com', 'secret-password');
        [$status, $response] = $this->dispatch($auth, 'not-allowed@example.com');

        $this->assertSame(403, $status);
        $this->assertInstanceOf(\Objectiveweb\Auth\AuthException::class, $response);
        $this->assertFalse($auth->get_credential('local', 'not-allowed@example.com'));
    }

    public function testAuthenticatedScopeAllowsLoggedInUsersAndDeniesAnonymous(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::AUTHENTICATED]);

        [$status, $response] = $this->dispatch($auth, 'denied@example.com');
        $this->assertSame(401, $status);
        $this->assertInstanceOf(\Objectiveweb\Auth\AuthException::class, $response);
        $this->assertFalse($auth->get_credential('local', 'denied@example.com'));

        $auth->register('actor@example.com', 'secret-password');
        $auth->login('actor@example.com', 'secret-password');

        [$status, $response] = $this->dispatch($auth, 'allowed@example.com');
        $this->assertSame(200, $status);
        $this->assertSame('allowed@example.com', $response['uid']);
        $this->assertNotFalse($auth->get_credential('local', 'allowed@example.com'));
    }

    public function testRoleScopeOnlyAllowsMatchingRole(): void
    {
        $auth = new BasicAuth([], ['register_scope' => ['admin']]);
        $auth->register('member@example.com', 'secret-password', ['roles' => ['member']]);
        $auth->register('admin@example.com', 'secret-password', ['roles' => ['admin']]);

        [$status, $response] = $this->dispatch($auth, 'anonymous-denied@example.com');
        $this->assertSame(401, $status);
        $this->assertInstanceOf(\Objectiveweb\Auth\AuthException::class, $response);

        $auth->login('member@example.com', 'secret-password');
        [$status, $response] = $this->dispatch($auth, 'member-denied@example.com');
        $this->assertSame(403, $status);
        $this->assertInstanceOf(\Objectiveweb\Auth\AuthException::class, $response);
        $this->assertFalse($auth->get_credential('local', 'member-denied@example.com'));

        $auth->login('admin@example.com', 'secret-password');
        [$status, $response] = $this->dispatch($auth, 'admin-created@example.com');
        $this->assertSame(200, $status);
        $this->assertSame('admin-created@example.com', $response['uid']);
        $this->assertNotFalse($auth->get_credential('local', 'admin-created@example.com'));
    }
}
