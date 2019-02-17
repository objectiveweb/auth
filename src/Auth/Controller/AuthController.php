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

        $user = $this->auth->register($uid, $password, $user);

        return $user;
    }

    function postPassword(array $form)
    {
        if ($this->auth->check()) {
            // TODO validar senha anterior
            if (empty($form['password']) || $form['password'] != @$form['confirm']) {
                throw new AuthException('Passwords dont match', 400);
            }

            $user = $this->auth->user();

            return $this->auth->passwd($user[$this->auth->params['id']], $form['password']);
        } else {
            if (!empty($form['token'])) {
                if (empty($form['password']) || $form['password'] != @$form['confirm']) {
                    throw new AuthException('Passwords dont match', 400);
                }

                $user = $this->auth->passwd_reset($form['token'], $form['password']);

                // set current session and return user
                return $this->auth->user($user);
            } else {
                if (empty($form['uid'])) {
                    throw new UserException('Invalid request', 400);
                }

                // find user
                $account = $this->auth->get_credential('local', $form['uid']);

                if(!empty($account['user'])) {
                    // return new token
                    return $this->auth->update_token($account['user']['id']);
                } else {
                    throw new UserException('Account not found', 404);
                }
            }
        }

    }


}
