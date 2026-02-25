<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

if (!interface_exists(\Objectiveweb\Router\MiddlewareInterface::class)) {
    eval('namespace Objectiveweb\\Router; interface MiddlewareInterface { public function before(string $method, string $fn, array $params): mixed; public function after(string $method, string $fn, array $params, array|null $response): mixed; }');
}

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Middleware\RequireRole;
use PHPUnit\Framework\TestCase;

class RequireRoleTest extends TestCase
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

    public function testBeforeRejectsUnauthenticatedUser(): void
    {
        $mw = new RequireRole($this->auth, ['admin']);

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(401);
        $mw->before('GET', 'index', []);
    }

    public function testBeforeRejectsMissingRoleForAuthenticatedUser(): void
    {
        $this->auth->login('admin@example.com', 'secret');
        $mw = new RequireRole($this->auth, ['admin']);

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(403);
        $mw->before('GET', 'index', []);
    }

    public function testBeforeAllowsMatchingRoleFromUserData(): void
    {
        $this->auth->register('role@example.com', 'secret', ['roles' => ['admin']]);
        $this->auth->login('role@example.com', 'secret');
        $mw = new RequireRole($this->auth, ['admin']);

        $out = $mw->before('GET', 'index', ['ok' => true]);
        $this->assertSame(['ok' => true], $out);
    }

    public function testBeforeUsesConfiguredRoleFieldAndStringRoles(): void
    {
        $auth = new BasicAuth(
            [],
            [
                'token' => 'token',
                'roles' => 'groups',
            ]
        );
        $auth->register('role2@example.com', 'secret', ['groups' => 'admin,editor']);
        $auth->login('role2@example.com', 'secret');

        $mw = new RequireRole($auth, ['editor']);
        $out = $mw->before('GET', 'index', ['ok' => true]);
        $this->assertSame(['ok' => true], $out);
    }
}
