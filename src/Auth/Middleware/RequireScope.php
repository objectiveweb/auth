<?php

namespace Objectiveweb\Auth\Middleware;

use Objectiveweb\Auth;
use Objectiveweb\Auth\AuthException;

use Objectiveweb\Router\MiddlewareInterface;

class RequireScope implements MiddlewareInterface
{
    private array $user = [];

    public function __construct(private Auth $auth, private string|array $scopes)
    {
        $this->scopes = is_array($scopes) ? $scopes : [$scopes];
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
        if ($this->auth->check()) {
            $scopes = \Objectiveweb\Auth::AUTHENTICATED;

            $this->user = $this->auth->user();
            $scopeField = $this->auth->params['scopes'] ?? 'scopes';
            $userScopes = $this->user[$scopeField] ?? [];
            if (is_string($userScopes)) {
                $userScopes = explode(',', $userScopes);
            }
            if (is_array($userScopes)) {
                $scopes = array_merge($scopes, $userScopes);
            }
        } else {
            $scopes = \Objectiveweb\Auth::ANONYMOUS;
        }

        if (count(array_intersect($this->scopes, $scopes)) == 0) {
            throw new AuthException("Forbidden", $scopes[0] == 'anon' ? 401 : 403);
        }

        return $params;
    }
}
