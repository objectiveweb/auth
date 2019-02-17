<?php

namespace Objectiveweb;

abstract class Auth
{

    // Base scopes
    const ANONYMOUS = ['anon'];
    const AUTHENTICATED = ['auth'];
    const ALL = ['anon', 'auth'];

    public $params;

    function __construct($params)
    {
        $defaults = [
            'session_key' => 'ow_auth',
            'id' => 'id',
            'password' => 'password',
            'scopes' => 'scopes',
            'token' => NULL
        ];

        $this->params = array_merge($defaults, $params);
    }

    public static function hash($password = null)
    {
        if (!$password) {
            // return a random token
            return md5(microtime(true));
        }

        return \password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * Returns true if the user is logged on
     */
    public function check()
    {
        return !empty($_SESSION[$this->params['session_key']]);
    }

    /**
     * @param $uid
     * @param $password
     * @throws Auth\UserException
     * @throws Auth\AuthException
     */
    public function &login($uid, $password)
    {

        $cred = $this->get_credential('local', $uid);

        if (!$cred || empty($cred['user'])) {
            throw new Auth\UserException('User does not exist', 404);
        }

        $user = $cred['user'];

        if (\password_verify($password, $user[$this->params['password']])) {

            unset($user[$this->params['password']]);
            unset($user[$this->params['token']]);

            $this->user($user);

            // TODO add login ip
            $this->update_credential($user[$this->params['id']], 'local', $uid, []);

            return $user;
        } else {
            throw new Auth\AuthException('Password invalid', 400);
        }
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
    public function reload()
    {
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
                throw new Auth\UserException('Not logged in', 403);
            }
        }


        return $_SESSION[$this->params['session_key']];
    }

    public function validate($user)
    {
        $uid = trim(@$user['uid']);

        if (empty($uid)) {
            throw new \Exception("Missing uid", 400);
        }

        $user['uid'] = $uid;

        if (isset($user[$this->params['password']])) {
            if (empty($user[$this->params['password']])) {
                throw new \Exception("Missing password", 400);
            }
        }

        return $user;
    }


    //

    abstract public function query($params = array(), $operator = "OR");

    /**
     * Retrieves a user from the database
     * @param $user_id String user_id
     * @param $key String which key to lookup (id, token)
     * @return array user data
     * @throws UserException
     * @throws \Exception
     */
    abstract public function get($user_id, $key = 'id');

    /**
     * @param string $uid
     * @param string $password
     * @param array $data associative array of additional columns to store
     */
    abstract public function register($uid, $password = null, $data = array());

    /**
     *
     * Update a user's password
     *
     * @param $user_id
     * @param $password
     * @param $key String
     * @return bool TRUE on success
     * @throws UserException if no rows were updated
     */
    abstract public function passwd($user_id, $password, $key = 'id');

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
     * @param $user_id
     * @param array $data associative array of data
     * @param key String
     * @throws UserException if no rows were updated
     */
    abstract public function update($user_id, array $data, $key = 'id');

    abstract public function delete($user_id);

    /**
     * Generates a new token for the user and update the database
     * @param $user_id
     * @return string new token
     */
    abstract public function update_token($user_id);

    /**
     * Retrieves an account from credentials_table
     * @param $provider String provider
     * @param $userid String user_id
     * @return mixed account data or null if account not found
     *    MUST include the 'user' key with the associated user (can be NULL)
     * @throws \Exception
     */
    abstract public function get_credential($provider, $accountid);

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
    abstract public function update_credential($userid, $provider, $uid, $profile = null);
}