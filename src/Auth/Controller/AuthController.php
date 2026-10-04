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
            $user['_csrf'] = $this->auth->management_csrf_token();
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

        if (!is_string($password) || $password === '') {
            // A password-less registration is an invitation. The backend stores
            // only a hash of the short-lived setup token and delivery happens
            // through the application callback.
            $this->auth->invite($user[$this->auth->params['id']]);
        } elseif (is_callable($this->auth->params['register_callback'])) {
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
        // The authenticated path is not a password-reset endpoint. Require
        // session-bound CSRF and proof of the account's current password.
        if ($this->auth->check()) {
            $this->assertPasswordChangeCsrf();

            $currentPassword = $form['current_password'] ?? null;
            if (!is_string($currentPassword) || $currentPassword === '') {
                throw new UserException('Current password is required', 400);
            }

            $password = $form['password'] ?? null;
            if (!is_string($password) || $password === '' || $password !== ($form['confirm'] ?? null)) {
                throw new UserException('Passwords don\'t match', 400);
            }

            $user = $this->auth->user();
            $userId = $user[$this->auth->params['id']];
            if (!$this->auth->verify_password($userId, $currentPassword)) {
                throw new AuthException('Invalid current password', 403);
            }

            return $this->auth->passwd($userId, $password);
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
                if ($credential === false && !empty($candidate['user_id'])) {
                    $credential = $candidate;
                }
            }

            if (!empty($credential['user_id'])) {
                $credential['token'] = $this->auth->update_token($credential['user_id']);

                if (is_callable($this->auth->params['token_callback'])) {
                    try {
                        call_user_func($this->auth->params['token_callback'], $credential);
                    } catch (\Throwable $exception) {
                        error_log(
                            'Password recovery delivery failed: '
                            . $exception::class
                            . ': '
                            . $exception->getMessage()
                        );
                    }
                }
            }

            // Anonymous recovery requests deliberately return the same payload
            // whether or not a credential exists. This prevents account
            // enumeration through status codes or callback return values.
            return [];
        }
    }

    /**
     * Changing an authenticated password is a session-authenticated write.
     * Always require the session token, even for direct controller calls.
     * HTTP clients must also submit JSON to avoid simple cross-origin forms.
     */
    private function assertPasswordChangeCsrf(): void
    {
        if (!empty($_SERVER['REQUEST_METHOD'])) {
            if (strtoupper((string) $_SERVER['REQUEST_METHOD']) !== 'POST') {
                throw new UserException('POST is required', 405);
            }

            $contentType = strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''), 2)[0]));
            if ($contentType !== 'application/json') {
                throw new UserException('Content-Type application/json is required', 415);
            }
        }

        $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        $expected = $this->auth->management_csrf_token();
        if (!is_string($provided) || $provided === '' || !hash_equals($expected, $provided)) {
            throw new UserException('Invalid CSRF token', 403);
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
