<?php

namespace Objectiveweb\Auth\Attributes;

use Objectiveweb\Auth;
use Objectiveweb\Auth\AuthException;
use Objectiveweb\Router\Middleware;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class RequireRole extends Middleware
{

    public function __construct(private Auth $auth, private string|array $role)
    {
        $this->role = is_array($role) ? $role : [$role];
    }

    public function after($method, $fn, $params, $response): mixed
    {
        if ($this->auth->check() && is_array($response) && !isset($response['_user'])) {
            $response['_user'] = $this->auth->user();
        }

        return $response;
    }

    public function before($method, $fn, $params): mixed
    {
        if ($this->auth->check()) {
            $scopes = \Objectiveweb\Auth::AUTHENTICATED;

            $this->user = $this->auth->user();

            if (is_array($this->user['scopes'])) {
                $scopes = array_merge($scopes, $this->user['scopes']);
            }
        } else {
            $scopes = \Objectiveweb\Auth::ANONYMOUS;
        }

        if (count(array_intersect($this->role, $scopes)) == 0) {
            throw new AuthException("Forbidden", $scopes[0] == 'anon' ? 401 : 403);
        }

        return $params;
    }
}
