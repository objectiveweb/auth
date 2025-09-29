<?php

namespace Objectiveweb\Auth\Attributes;

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Router\Middleware;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class RequireRole extends Middleware
{
    public \Objectiveweb\Auth $auth;

    private $role;

    public function __construct(string|array $role)
    {
        $this->role = is_array($role) ? $role : [$role];
    }

    public function before($method, $fn, ...$args): mixed
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

        return null;
    }
}
