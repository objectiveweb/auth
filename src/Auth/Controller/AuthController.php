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
            'index' => Auth::AUTHENTICATED,
            'getLogout' => Auth::AUTHENTICATED
        ]);

    }

    function index()
    {
        return $this->user;
    }

    function getLogout()
    {
        $this->auth->logout();
    }

    /**
     * Login a local user
     */
    function post(array $user)
    {

        $username = $user[$this->auth->params['username']];
        unset($user[$this->auth->params['username']]);
        $password = $user[$this->auth->params['password']];
        unset($user[$this->auth->params['password']]);

        return $this->auth->login($username, $password);
    }

    /**
     * Register a new user
     * @param $user array
     */
    function postRegister(array $user)
    {
        $username = @$user[$this->auth->params['username']];
        unset($user[$this->auth->params['username']]);
        $password = @$user[$this->auth->params['password']];
        unset($user[$this->auth->params['password']]);

        $user = $this->auth->register($username, $password, $user);

        return $user;
    }

    function postPassword(array $form)
    {
        if ($this->auth->check()) {
            if (empty($form['password']) || $form['password'] != @$form['confirm']) {
                throw new AuthException('Passwords dont match', 400);
            }

            $user = $this->auth->user();

            return $this->auth->passwd($user['username'], $form['password']);
        } else {
            if (!empty($form['token'])) {
                if (empty($form['password']) || $form['password'] != @$form['confirm']) {
                    throw new AuthException('Passwords dont match', 400);
                }

                $user = $this->auth->passwd_reset($form['token'], $form['password']);

                // set current session and return user
                return $this->auth->user($user);
            } else {
                if (empty($form['username'])) {
                    throw new UserException('Invalid request', 400);
                }

                // return new token
                return $this->auth->update_token($form['username']);
            }
        }

    }


}