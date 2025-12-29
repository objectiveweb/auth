<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\UserException;
use Objectiveweb\Auth\Middleware\RequireScope;

use Objectiveweb\Router\Middleware;

/**
 * Class AuthController
 *
 * Authentication Controller
 *
 * @package Objectiveweb\Auth
 */
#[Middleware(RequireScope::class, Auth::ANONYMOUS)]
class AuthController
{
    function __construct(public \Objectiveweb\Auth $auth)
    {
    }

    #[Middleware(RequireScope::class, Auth::ALL)]
    function index()
    {
        if($this->auth->check()){
            return $this->auth->user();
        }
        else {
            return null;
        }
    }

    #[Middleware(RequireScope::class, Auth::AUTHENTICATED)]
    function getLogout($params = [])
    {
        $this->auth->logout();

        if (!empty($params['redirect'])) {
            header("Location: {$params['redirect']}");
            exit;
        }

        return [];
    }

    /**
     * Login a local user
     */
    function post(array $user)
    {
        $uid = $user['uid'];
        unset($user['uid']);
        $password = $user[$this->auth->params['password']];
        unset($user[$this->auth->params['password']]);

        return $this->auth->login($uid, $password);
    }

    /**
     * Register a new user
     * @param $user array
     */
    function postRegister(array $user)
    {
        $uid = @$user['uid'];
        unset($user['uid']);
        $password = @$user[$this->auth->params['password']];
        unset($user[$this->auth->params['password']]);

        if (!filter_var($uid, FILTER_VALIDATE_EMAIL)) {
            throw new AuthException('Email inválido');
        }

        $user = $this->auth->register($uid, $password, $user);

        $user['uid'] = $uid;

        if (is_callable($this->auth->params['register_callback'])) {
            call_user_func($this->auth->params['register_callback'], $user);
        }

        return $user;
    }

    #[Middleware(RequireScope::class, Auth::ALL)]
    function postToken(array $form)
    {
        if (empty($form['token'])) {
            throw new UserException('Invalid request', 400);
        }

        if (empty($form['password']) || $form['password'] != @$form['confirm']) {
            throw new UserException('Passwords don\'t match', 400);
        }

        return $this->auth->passwd_reset($form['token'], $form['password']);
    }

    #[Middleware(RequireScope::class, Auth::ALL)]
    function postPassword(array $form)
    {
        // if user is logged in, update password
        if ($this->auth->check()) {
            // TODO validar senha anterior
            if (empty($form['password']) || $form['password'] != @$form['confirm']) {
                throw new UserException('Passwords dont match', 400);
            }

            $user = $this->auth->user();

            return $this->auth->passwd($user[$this->auth->params['id']], $form['password']);
        } // Forgot password
        else {
            if (empty($form['uid'])) {
                throw new UserException('Invalid request', 400);
            }

            // find user
            $credential = $this->auth->get_credential('local', $form['uid']);

            if (!empty($credential['user_id'])) {
                // return new token
                $credential['token'] = $this->auth->update_token($credential['user_id']);

                if (is_callable($this->auth->params['token_callback'])) {
                    return call_user_func($this->auth->params['token_callback'], $credential);
                } else {
                    return $credential;
                }
            } else {
                throw new UserException('Credential not found', 404);
            }
        }
    }
}
