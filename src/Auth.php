<?php

namespace Objectiveweb;

use Objectiveweb\Auth\UserNotFoundException;
use Objectiveweb\Auth\PasswordMismatchException;

class Auth
{
    private $session_key;
    private $table;

    public static function hash($password)
    {

    }

    public function __construct($table, $session_key = 'ow_auth')
    {
        $this->table = $table;
        $this->session_key = $session_key;
    }

    /**
     * Returns true if the user is logged on
     */
    public function check()
    {
        return !empty($_SESSION[$this->session_key]);
    }

    /**
     * @param array $user [ username, displayName, email, password ]
     */
    public function register(array $user)
    {
        // TODO validate inputs
    }

    /**
     * @param $username
     * @param $password
     * @throws UserNotFoundException
     * @throws PasswordMismatchException
     */
    public function login($username, $password)
    {
        // TODO verify user
        $user = array();

        $this->table->get(['username' => $username ]);

        unset($user['password']);

        $_SESSION[$this->session_key] = $user;
    }

    public function logout()
    {
        unset($_SESSION[$this->session_key]);
    }

    public function passwd($username, $password)
    {
        $this->table->update([ 'password' => Auth::hash($password)], [ 'username' => $username ]);
    }


}