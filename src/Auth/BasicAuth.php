<?php

namespace Objectiveweb\Auth;

/**
 * Class BasicAuth
 * Basic Auth implementation with hardcoded users
 *
 * @package Objectiveweb\Auth
 */
class BasicAuth extends \Objectiveweb\Auth {

    private $passwd;

    function __construct($passwd = [], $params = []) {

        parent::__construct($params);


        $this->passwd = $passwd;
    }


    public function query($params = array(), $operator = "OR")
    {
        $result = [];
        foreach ($this->passwd as $user => $pass) {
            if(strpos($user[$this->params['username']], $params['username']) !== FALSE) {
                $result[] = $user;
            }
        }
    }

    public function get($username, $key = 'username')
    {
        print_r($this->passwd);
        if(!in_array($username, array_keys($this->passwd))) {
            throw new UserException("User `$username` not found", 404);
        }

        return [
            $this->params['username'] => $username,
            $this->params['id'] => $username
        ];
    }

    public function &login($username, $password)
    {
        $user = $this->get($username);

        if($user[$this->params['password']] == $user[$this->params['password']]) {
            unset($user[$this->params['password']]);
            $this->user($user);

            return $user;
        } else {
            throw new AuthException('Invalid username or password');
        }
        // TODO: Implement login() method.
    }

    public function register($username, $password = null, $data = array())
    {
        $this->passwd[$username] = $password;

        return [
            $this->params['username'] => $username,
            $this->params['id'] => $username
        ];

    }

    public function passwd($username, $password, $key = 'username')
    {
        // TODO: Implement passwd() method.
    }

    public function passwd_reset($token, $password)
    {
        // TODO: Implement passwd_reset() method.
    }

    public function update($username, array $data, $key = 'username')
    {
        // TODO: Implement update() method.
    }

    public function delete($username, $key = 'username')
    {
        // TODO: Implement delete() method.
    }

    public function update_token($username)
    {
        // TODO: Implement update_token() method.
    }

    public function get_account($provider, $accountid)
    {
        // TODO: Implement get_account() method.
    }

    public function update_account($userid, $provider, $uid, $profile = null)
    {
        // TODO: Implement update_account() method.
    }
}