<?php

namespace Objectiveweb;

abstract class Auth {

    // Base scopes
    const ANONYMOUS        = [ 'anon' ];
    const AUTHENTICATED    = [ 'auth' ];
    const ALL              = [ 'anon', 'auth' ];

    public $params;

    function __construct($params) {
        $defaults = [
            'session_key' => 'ow_auth',
            'id' => 'id',
            'username' => 'username',
            'password' => 'password',
            'scopes' => 'scopes',
            'token' => NULL
        ];

        $this->params = array_merge($defaults, $params);
    }

    /**
     * Returns true if the user is logged on
     */
    public function check()
    {
        return !empty($_SESSION[$this->params['session_key']]);
    }

    public static function hash($password = null)
    {
        if (!$password) {
            // return a random token
            return md5(microtime(true));
        }

        return password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * Logs out the current user (unsets the session key)
     */
    public function logout()
    {
        unset($_SESSION[$this->params['session_key']]);
    }

    /**
     * Reloads current user from the backend
     */
    public function reload() {
        $user = $this->user();
        $user = $this->get($user[$this->params['id']], $this->params['id']);

        return $this->user($user);
    }

    /**
     * Returns the current logged in user or sets the current login data
     * @param $user array
     * @return array user data, sets a new user on session if
     * @throws UserException if noone is logged in
     */
    public function &user($user = null)
    {
        if ($user) {
            unset($user[$this->params['token']]);
            unset($user[$this->params['password']]);
            $_SESSION[$this->params['session_key']] = $user;
        } else {
            if (!$this->check()) {
                throw new UserException('Not logged in', 403);
            }
        }


        return $_SESSION[$this->params['session_key']];
    }

    public function validate($user) {
        $username = trim(@$user[$this->params['username']]);

        if(empty($username)) {
            throw new \Exception("Missing username", 400);
        }

        $user[$this->params['username']] = $username;

        if(isset($user[$this->params['password']])) {
            if(empty($user[$this->params['password']])) {
                throw new \Exception("Missing password", 400);
            }
        }

        return $user;
    }

    //

    abstract public function query($params = array(), $operator = "OR");

    /**
     * Retrieves a user from the database
     * @param $username String username
     * @param $key String which key to lookup (username, id, token)
     * @return array user data
     * @throws UserException
     * @throws \Exception
     */
    abstract public function get($username, $key = 'username');

    /**
     * @param $username
     * @param $password
     * @throws UserException
     * @throws PasswordMismatchException
     */
    abstract public function &login($username, $password);

    /**
     * @param string $username
     * @param string $password
     * @param array $data associative array of additional columns to store
     */
    abstract public function register($username, $password = null, $data = array());

    /**
     *
     * Update a user's password
     *
     * @param $username
     * @param $password
     * @param $key String username or id
     * @return bool TRUE on success
     * @throws UserException if no rows were updated
     */
    abstract public function passwd($username, $password, $key = 'username');

    /**
     *
     * Reset a user's password
     *
     * @param $token String
     * @param $password String new password
     * @return $user array user data on success
     * @throws UserException if no rows were updated
     */
    abstract public function passwd_reset($token, $password);

    /**
     * Update arbitrary user data
     * @param $username
     * @param array $data associative array of data
     * @param key String username or id
     * @throws UserException if no rows were updated
     */
    abstract public function update($username, array $data, $key = 'username');

    abstract public function delete($username, $key = 'username');

    /**
     * Generates a new token for the user and update the database
     * @param $username
     * @return string new token
     */
    abstract public function update_token($username);

    /**
     * Retrieves an account from ext_accounts_table
     * @param $userid String user_id
     * @param $key String which key to lookup (username, id, token)
     * @return mixed account data or null if account not found
     * @throws \Exception
     */
    abstract public function get_account($provider, $accountid);

    /**
     * Inserts a new account on $userid, or update the existing one
     *
     * @param $userid
     * @param $provider
     * @param $uid
     * @param null $profile
     * @return bool
     * @throws \Exception
     */
    abstract public function update_account($userid, $provider, $uid, $profile = null);
}