<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\Middleware\RequireRole;
use Objectiveweb\Auth\UserException;
use Objectiveweb\Router\Middleware;

/**
 * Class AuthController
 *
 * Authentication Controller
 *
 * @package Objectiveweb\Auth
 */
#[Middleware(RequireRole::class, Auth::ANONYMOUS)]
class AuthController
{
    function __construct(public \Objectiveweb\Auth $auth)
    {
    }

    #[Middleware(RequireRole::class, Auth::ALL)]
    function index()
    {
        if ($this->auth->check()) {
            $user = $this->auth->user();
            $user['credentials'] = $this->auth->get_credentials($user[$this->auth->params['id']]);
            return $user;
        }

        return null;
    }

    #[Middleware(RequireRole::class, Auth::AUTHENTICATED)]
    function getLogout($params = [])
    {
        if (!$this->auth->check()) {
            throw new AuthException('Forbidden', 401);
        }

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
        $uid = trim((string) ($user['uid'] ?? ''));
        if ($uid === '') {
            throw new UserException('Missing uid', 400);
        }
        unset($user['uid']);
        $passwordField = $this->auth->params['password'];
        $password = $user[$passwordField] ?? null;
        if (!is_string($password) || $password === '') {
            throw new UserException('Missing password', 400);
        }
        unset($user[$passwordField]);

        return $this->auth->login($uid, $password);
    }

    /**
     * Register a new user
     * @param $user array
     */
    function postRegister(array $user)
    {
        $this->assertCanRegister();

        $uid = trim((string) ($user['uid'] ?? ''));
        if ($uid === '') {
            throw new UserException('Missing uid', 400);
        }
        unset($user['uid']);
        $passwordField = $this->auth->params['password'];
        $password = $user[$passwordField] ?? null;
        unset($user[$passwordField]);

        if (!filter_var($uid, FILTER_VALIDATE_EMAIL)) {
            throw new AuthException('Email inválido');
        }

        if (!$this->auth->params['register_allow_grants']) {
            unset($user[$this->auth->params['roles']]);
        }

        $user = $this->auth->register($uid, $password, $user);

        $user['uid'] = $uid;

        if (is_callable($this->auth->params['register_callback'])) {
            call_user_func($this->auth->params['register_callback'], $user);
        }

        return $user;
    }

    #[Middleware(RequireRole::class, Auth::ALL)]
    function postToken(array $form)
    {
        if (empty($form['token'])) {
            throw new UserException('Invalid request', 400);
        }

        $confirm = $form['confirm'] ?? null;
        if (empty($form['password']) || $form['password'] != $confirm) {
            throw new UserException('Passwords don\'t match', 400);
        }

        return $this->auth->passwd_reset($form['token'], $form['password']);
    }

    #[Middleware(RequireRole::class, Auth::ALL)]
    function postPassword(array $form)
    {
        // if user is logged in, update password
        if ($this->auth->check()) {
            // TODO validar senha anterior
            $confirm = $form['confirm'] ?? null;
            if (empty($form['password']) || $form['password'] != $confirm) {
                throw new UserException('Passwords dont match', 400);
            }

            $user = $this->auth->user();

            return $this->auth->passwd($user[$this->auth->params['id']], $form['password']);
        } // Forgot password
        else {
            if (empty($form['uid'])) {
                throw new UserException('Invalid request', 400);
            }

            // find user by recovery channels
            $credential = false;
            $providers = $this->auth->params['recovery_providers'];
            if (!is_array($providers)) {
                $providers = [];
            }

            foreach ($providers as $provider) {
                $candidate = $this->auth->get_credential($provider, $form['uid']);
                if (empty($candidate['user_id'])) {
                    continue;
                }

                $credential = $candidate;
                break;
            }

            if (!empty($credential['user_id'])) {
                // return new token
                $credential['token'] = $this->auth->update_token($credential['user_id']);

                if (is_callable($this->auth->params['token_callback'])) {
                    return call_user_func($this->auth->params['token_callback'], $credential);
                } else {
                    return [];
                }
            } else {
                throw new UserException('Credential not found', 404);
            }
        }
    }

    private function assertCanRegister(): void
    {
        $required = $this->auth->params['register_scope'];
        $required = is_array($required) ? $required : [$required];

        if ($this->auth->check()) {
            $available = Auth::AUTHENTICATED;
            $user = $this->auth->user();
            $roleField = $this->auth->params['roles'];
            $userRoles = $user[$roleField] ?? [];
            if (is_array($userRoles)) {
                $available = array_merge($available, $userRoles);
            }
        } else {
            $available = Auth::ANONYMOUS;
        }

        if (count(array_intersect($required, $available)) === 0) {
            throw new AuthException('Forbidden', in_array('anon', $available, true) ? 401 : 403);
        }
    }
}
