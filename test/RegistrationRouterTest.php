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
     * RequireRole middleware and parses JSON or HTML-form bodies before dispatch.
     *
     * Override only the response writer to avoid exiting PHPUnit.
     */
    private function dispatch(BasicAuth $auth, string $uid, array $options = []): array
    {
        $router = new class($auth) extends Router {
            public function __construct(private BasicAuth $auth)
            {
                parent::__construct();
            }

            public function create(string $name, array $args = []): object
            {
                // Supply the already configured provider to the real middleware.
                // Routing, attribute precedence and before()/after() remain real.
                if ($name === \Objectiveweb\Auth\Middleware\RequireRole::class) {
                    return new \Objectiveweb\Auth\Middleware\RequireRole($this->auth, $args[0]);
                }
                return parent::create($name, $args);
            }

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
        $contentType = $options['content_type'] ?? 'application/json';
        $_SERVER['CONTENT_TYPE'] = $contentType;
        unset($_SERVER['HTTP_X_CSRF_TOKEN']);
        if (array_key_exists('csrf_header', $options)) {
            $_SERVER['HTTP_X_CSRF_TOKEN'] = $options['csrf_header'];
        }

        $body = ['uid' => $uid, 'password' => 'secret-password'];
        if (array_key_exists('csrf_field', $options)) {
            $body['_csrf'] = $options['csrf_field'];
        }
        // PHP populates $_POST for browser-submitted forms; JSON arrives
        // as the raw body and is decoded by objectiveweb/router.
        $_POST = str_starts_with($contentType, 'application/json')
            ? json_encode($body)
            : $body;
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

        [$status, $response] = $this->dispatch($auth, 'allowed@example.com', [
            'csrf_header' => $auth->management_csrf_token(),
        ]);
        $this->assertSame(200, $status);
        $this->assertSame('allowed@example.com', $response['uid']);
        $this->assertNotFalse($auth->get_credential('local', 'allowed@example.com'));
    }

    public function testAuthenticatedRegistrationRequiresCsrf(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::AUTHENTICATED]);
        $auth->register('actor@example.com', 'secret-password');
        $auth->login('actor@example.com', 'secret-password');

        foreach ([
            ['uid' => 'no-token@example.com', 'options' => []],
            ['uid' => 'bad-header@example.com', 'options' => ['csrf_header' => 'incorrect']],
            ['uid' => 'bad-field@example.com', 'options' => [
                'content_type' => 'application/x-www-form-urlencoded',
                'csrf_field' => 'incorrect',
            ]],
            ['uid' => 'header-takes-precedence@example.com', 'options' => [
                'csrf_header' => 'incorrect',
                'csrf_field' => $auth->management_csrf_token(),
            ]],
        ] as $case) {
            [$status, $response] = $this->dispatch($auth, $case['uid'], $case['options']);
            $this->assertSame(403, $status, $case['uid']);
            $this->assertInstanceOf(\Objectiveweb\Auth\UserException::class, $response);
            $this->assertFalse($auth->get_credential('local', $case['uid']));
        }
    }

    public function testAuthenticatedRegistrationAcceptsFormAndMultipartWithoutJavascript(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::AUTHENTICATED]);
        $auth->register('actor@example.com', 'secret-password');
        $auth->login('actor@example.com', 'secret-password');
        $token = $auth->management_csrf_token();

        foreach ([
            ['application/x-www-form-urlencoded', 'form-created@example.com'],
            ['multipart/form-data; boundary=example', 'multipart-created@example.com'],
        ] as [$contentType, $uid]) {
            [$status, $response] = $this->dispatch($auth, $uid, [
                'content_type' => $contentType,
                'csrf_field' => $token,
            ]);
            $this->assertSame(200, $status, $uid);
            $this->assertSame($uid, $response['uid']);
            $this->assertArrayNotHasKey('_csrf', $response);
            $user = $auth->get($auth->get_credential('local', $uid)['user_id']);
            $this->assertArrayNotHasKey('_csrf', $user);
        }
    }

    public function testAuthenticatedRegistrationAcceptsJsonWithTokenInBody(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::AUTHENTICATED]);
        $auth->register('actor@example.com', 'secret-password');
        $auth->login('actor@example.com', 'secret-password');

        [$status, $response] = $this->dispatch($auth, 'json-body@example.com', [
            'content_type' => 'application/json; charset=utf-8',
            'csrf_field' => $auth->management_csrf_token(),
        ]);
        $this->assertSame(200, $status);
        $this->assertSame('json-body@example.com', $response['uid']);
        $this->assertArrayNotHasKey('_csrf', $response);
    }

    public function testAuthenticatedRegistrationRejectsUnsupportedContentType(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::AUTHENTICATED]);
        $auth->register('actor@example.com', 'secret-password');
        $auth->login('actor@example.com', 'secret-password');

        [$status, $response] = $this->dispatch($auth, 'invalid-type@example.com', [
            'content_type' => 'text/plain',
            'csrf_field' => $auth->management_csrf_token(),
        ]);
        $this->assertSame(415, $status);
        $this->assertInstanceOf(\Objectiveweb\Auth\UserException::class, $response);
        $this->assertFalse($auth->get_credential('local', 'invalid-type@example.com'));
    }

    public function testAnonymousFormRegistrationDoesNotRequireCsrf(): void
    {
        $auth = new BasicAuth([], ['register_scope' => Auth::ANONYMOUS]);
        [$status, $response] = $this->dispatch($auth, 'anonymous-form@example.com', [
            'content_type' => 'application/x-www-form-urlencoded',
        ]);
        $this->assertSame(200, $status);
        $this->assertSame('anonymous-form@example.com', $response['uid']);

        [$status, $response] = $this->dispatch($auth, 'anonymous-multipart@example.com', [
            'content_type' => 'multipart/form-data; boundary=example',
            'csrf_field' => 'optional-and-ignored-for-anonymous',
        ]);
        $this->assertSame(200, $status);
        $this->assertArrayNotHasKey('_csrf', $response);
        $this->assertFalse(array_key_exists(
            '_csrf',
            $auth->get($auth->get_credential('local', 'anonymous-multipart@example.com')['user_id'])
        ));
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
        [$status, $response] = $this->dispatch($auth, 'admin-created@example.com', [
            'content_type' => 'application/x-www-form-urlencoded',
            'csrf_field' => $auth->management_csrf_token(),
        ]);
        $this->assertSame(200, $status);
        $this->assertSame('admin-created@example.com', $response['uid']);
        $this->assertNotFalse($auth->get_credential('local', 'admin-created@example.com'));
    }
}
