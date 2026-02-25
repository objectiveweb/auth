<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

if (!interface_exists(\Objectiveweb\Router\MiddlewareInterface::class)) {
    eval('namespace Objectiveweb\\Router; interface MiddlewareInterface { public function before(string $method, string $fn, array $params): mixed; public function after(string $method, string $fn, array $params, array|null $response): mixed; }');
}

use Objectiveweb\Auth;
use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Middleware\RequireScope;
use PHPUnit\Framework\TestCase;

class RequireScopeTest extends TestCase
{
    private BasicAuth $auth;

    protected function setUp(): void
    {
        $_SESSION = [];
        $this->auth = new BasicAuth(
            ['admin@example.com' => 'secret'],
            ['token' => 'token']
        );
    }

    public function testBeforeAllowsAnonymousScope(): void
    {
        $mw = new RequireScope($this->auth, Auth::ANONYMOUS);
        $params = ['x' => 1];

        $out = $mw->before('GET', 'index', $params);
        $this->assertSame($params, $out);
    }

    public function testBeforeRejectsUnauthenticatedForAuthScope(): void
    {
        $mw = new RequireScope($this->auth, Auth::AUTHENTICATED);

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(401);
        $mw->before('GET', 'index', []);
    }

    public function testBeforeRejectsMissingRoleForAuthenticatedUser(): void
    {
        $this->auth->login('admin@example.com', 'secret');
        $mw = new RequireScope($this->auth, ['ADMIN']);

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(403);
        $mw->before('GET', 'index', []);
    }

    public function testBeforeAllowsCustomScopeFromUser(): void
    {
        $this->auth->register('scoped@example.com', 'secret', ['scopes' => ['ADMIN']]);
        $this->auth->login('scoped@example.com', 'secret');
        $mw = new RequireScope($this->auth, ['ADMIN']);

        $out = $mw->before('GET', 'index', ['ok' => true]);
        $this->assertSame(['ok' => true], $out);
    }

    public function testBeforeUsesConfiguredScopeFieldAndStringScopes(): void
    {
        $auth = new BasicAuth(
            [],
            [
                'token' => 'token',
                'scopes' => 'permissions',
            ]
        );
        $auth->register('scoped2@example.com', 'secret', ['permissions' => 'ADMIN,EDITOR']);
        $auth->login('scoped2@example.com', 'secret');

        $mw = new RequireScope($auth, ['EDITOR']);
        $out = $mw->before('GET', 'index', ['ok' => true]);
        $this->assertSame(['ok' => true], $out);
    }
}
