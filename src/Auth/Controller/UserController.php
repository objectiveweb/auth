<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;
use Objectiveweb\Auth\Middleware\RequireScope;
use Objectiveweb\Auth\UserException;
use Objectiveweb\Router\Middleware;

/**
 * Class UserController
 * Simple controller to manage users using the Auth service
 *
 * @package Objectiveweb\Auth
 */
#[Middleware(RequireScope::class, ['ADMIN'])]
class UserController
{
    private array $allowedQueryFields;
    private array $allowedWriteFields;

    public function __construct(public Auth $auth)
    {
        $this->allowedQueryFields = array_values(array_unique(array_filter([
            $this->auth->params['id'] ?? 'id',
            'uid',
            'name',
            'image',
            $this->auth->params['scopes'] ?? 'scopes',
            $this->auth->params['roles'] ?? 'roles',
            $this->auth->params['created'] ?? null,
        ])));

        $this->allowedWriteFields = array_values(array_unique(array_filter([
            'uid',
            $this->auth->params['password'] ?? 'password',
            'name',
            'image',
            $this->auth->params['scopes'] ?? 'scopes',
            $this->auth->params['roles'] ?? 'roles',
            'provider',
            'profile',
        ])));
    }

    public function index()
    {
        return $this->get();
    }

    public function get($params = array())
    {
        if (is_array($params)) {
            return $this->auth->query($this->sanitizeQueryParams($params));
        } else {
            return $this->auth->get($params);
        }
    }

    public function post($data)
    {
        if (!is_array($data)) {
            throw new UserException('Invalid request', 400);
        }

        if (empty(trim((string) ($data['uid'] ?? '')))) {
            throw new UserException('Missing uid', 400);
        }

        foreach ($data as $field => $value) {
            if (!in_array((string) $field, $this->allowedWriteFields, true)) {
                throw new UserException("Invalid field `$field`", 400);
            }
            unset($value);
        }
        return $this->auth->register($data);
    }

    public function put($user_id, $data)
    {
        if (!is_array($data)) {
            throw new UserException('Invalid request', 400);
        }

        $user = $this->auth->get($user_id);

        if (!empty($data['password'])) {
            $this->auth->passwd($user[$this->auth->params['id']], $data['password']);
        }

        unset($data['password']);

        foreach (array_keys($data) as $field) {
            if (!in_array((string) $field, $this->allowedWriteFields, true)) {
                throw new UserException("Invalid field `$field`", 400);
            }
        }

        if (!empty($data)) {
            $this->auth->update($user[$this->auth->params['id']], $data);
        }

        return true;
    }

    public function delete($user_id)
    {
        $this->auth->delete($user_id);
        return true;
    }

    private function sanitizeQueryParams(array $params): array
    {
        $allowedMeta = ['page', 'size', 'sort'];
        foreach ($params as $key => $value) {
            if (in_array((string) $key, $allowedMeta, true)) {
                continue;
            }

            if (!in_array((string) $key, $this->allowedQueryFields, true)) {
                throw new UserException("Invalid filter `$key`", 400);
            }
            unset($value);
        }

        if (!empty($params['sort'])) {
            $sortFields = explode(',', (string) $params['sort']);
            foreach ($sortFields as $sortField) {
                $sortField = trim($sortField);
                if ($sortField === '') {
                    continue;
                }

                $parts = preg_split('/\s+/', $sortField);
                $field = $parts[0] ?? '';
                if (!in_array($field, $this->allowedQueryFields, true)) {
                    throw new UserException("Invalid sort field `$field`", 400);
                }

                if (isset($parts[1])) {
                    $dir = strtoupper($parts[1]);
                    if (!in_array($dir, ['ASC', 'DESC'], true)) {
                        throw new UserException("Invalid sort direction `$dir`", 400);
                    }
                }
            }
        }

        return $params;
    }
}
