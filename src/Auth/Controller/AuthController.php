<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;

use Objectiveweb\Auth\AclTrait;
use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\UserException;

/**
 * Class AuthController
 *
 * Authentication Controller
 *
 * @package Objectiveweb\Auth
 */
class AuthController
{
    use AclTrait;

    function __construct(\Objectiveweb\Auth $auth)
    {
        $this->aclSetup($auth, [
            '*' => Auth::ANONYMOUS,
            'get' => Auth::ALL,
            'callback' => Auth::ALL,
            'index' => Auth::ALL,
            'postPassword' => Auth::ALL,
            'postToken' => Auth::ALL,
            'postRegister' => $auth->params['register_scope'],
            'getLogout' => Auth::AUTHENTICATED
        ]);

    }

    function index()
    {
        return $this->user;
    }

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
