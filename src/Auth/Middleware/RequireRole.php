<?php

namespace Objectiveweb\Auth\Middleware;

use Objectiveweb\Auth;
use Objectiveweb\Auth\AuthException;
use Objectiveweb\Router\MiddlewareInterface;

class RequireRole implements MiddlewareInterface
{
    private array $roles;

    public function __construct(private Auth $auth, string|array $roles)
    {
        $this->roles = is_array($roles) ? $roles : [$roles];
    }

    public function after(string $method, string $fn, array $params, array|null $response): mixed
    {
        if ($this->auth->check() && is_array($response) && !isset($response['_user'])) {
            $response['_user'] = $this->auth->user();
        }

        return $response;
    }

    public function before(string $method, string $fn, array $params): mixed
    {
        if (!$this->auth->check()) {
            throw new AuthException('Forbidden', 401);
        }

        $user = $this->auth->user();
        $roleField = $this->auth->params['roles'] ?? 'roles';
        $roles = $user[$roleField] ?? [];
        if (is_string($roles)) {
            $roles = explode(',', $roles);
        }

        if (count(array_intersect($this->roles, is_array($roles) ? $roles : [])) === 0) {
            throw new AuthException('Forbidden', 403);
        }

        return $params;
    }
}
