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

    public function after(string $method, string $fn, array $params, mixed $response): mixed
    {
        if ($this->auth->check() && is_array($response) && !isset($response['_user'])) {
            $response['_user'] = $this->auth->user();
        }

        return $response;
    }

    public function before(string $method, string $fn, array $params): mixed
    {
        if ($this->auth->check()) {
            $grants = \Objectiveweb\Auth::AUTHENTICATED;
            $user = $this->auth->user();
            $roleField = $this->auth->params['roles'];
            $roles = $user[$roleField] ?? [];
            if (is_array($roles)) {
                $grants = array_merge($grants, $roles);
            }
        } else {
            $grants = \Objectiveweb\Auth::ANONYMOUS;
        }

        if (count(array_intersect($this->roles, $grants)) === 0) {
            $isAnonymous = count(array_intersect($grants, \Objectiveweb\Auth::ANONYMOUS)) > 0;
            throw new AuthException('Forbidden', $isAnonymous ? 401 : 403);
        }

        return $params;
    }
}
