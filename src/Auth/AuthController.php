<?php

namespace Objectiveweb\Auth;

use Objectiveweb\Auth;

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

    function index() {
        return $this->user;
    }

    function getLogout() {
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
        $username = $user[$this->auth->params['username']];
        unset($user[$this->auth->params['username']]);
        $password = $user[$this->auth->params['password']];
        unset($user[$this->auth->params['password']]);


        return $this->auth->register($username, $password, $user);
    }

}
