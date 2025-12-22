<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;
use Objectiveweb\Auth\Middleware\RequireRole;
use Objectiveweb\Auth\UserException;
use Objectiveweb\Router\Middleware;

/**
 * Class UserController
 * Simple controller to manage users using the Auth service
 *
 * @package Objectiveweb\Auth
 */
#[Middleware(RequireRole::class, ['ADMIN'])]
class UserController
{

    public Auth $auth;

    public function index()
    {
        return $this->get();
    }

    public function get($params = array())
    {
        if (is_array($params)) {
            return $this->auth->query($params);
        } else {
            return $this->auth->get($params);
        }
    }

    public function post($data)
    {

        return $this->auth->register($data);

    }

    public function put($user_id, $data)
    {

        $user = $this->auth->get($user_id);

        if (!$user) {
            throw new UserException('User does not exist', 404);
        }

        if (!empty($data['password'])) {
            $this->auth->passwd($user[$this->auth->params['id']], $data['password']);
        }

        unset($data['password']);

        $this->auth->update($user[$this->auth->params['id']], $data);

        return true;
    }

    public function delete($user_id)
    {
        $this->auth->delete($user_id);
    }
}
