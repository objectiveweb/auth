<?php

namespace Objectiveweb;

use Objectiveweb\Auth\UserException;
use Objectiveweb\Auth\PasswordMismatchException;

use PDO;

class Auth
{
    private $params;

    /** @var \PDO */
    private $pdo;

    const SELECT_ALL = "select * from `%s` where `%s` = %s";
    const REGISTER_QUERY = "insert into `%s` (%s) values (%s)";
    const RESET_PASSWORD = 'UPDATE `%s` SET `%s` = %s, `%s` = NULL WHERE %s = %s';
    const UPDATE_QUERY = "UPDATE `%s` SET %s WHERE `%s` = %s";
    const UPDATE_VALUE = "UPDATE `%s` SET `%s` = %s WHERE `%s` = %s";
    const USER_BY_NAME = "SELECT `%s` FROM `%s` WHERE `%s` = %s";

    public static function hash($password = null)
    {
        if (!$password) {
            // return a random token
            return md5(microtime(true));
        }

        return password_hash($password, PASSWORD_BCRYPT);
    }

    public function __construct(\PDO $pdo, $params = array())
    {
        $defaults = [
            'session_key' => 'ow_auth',
            'table' => 'ow_auth',
            'id' => 'id',
            'username' => 'username',
            'password' => 'password',
            'token' => NULL,
            'created' => NULL,
            'last_login' => NULL
        ];

        $this->pdo = $pdo;

        $this->params = array_merge($defaults, $params);

    }

    /**
     * Returns true if the user is logged on
     */
    public function check()
    {
        return !empty($_SESSION[$this->params['session_key']]);
    }

    /**
     * Retrieves a user from the database
     * @param $username username
     * @return array user data
     * @throws UserException
     */
    public function get($username) {
        $query = sprintf(self::SELECT_ALL,
            $this->params['table'],
            $this->params['username'],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            return $user;
        }
        else {
            throw new UserException('User not found');
        }
    }

    /**
     * @param $username
     * @param $password
     * @throws UserException
     * @throws PasswordMismatchException
     */
    public function &login($username, $password)
    {

        $user = $this->get($username);

        if(password_verify($password, $user[$this->params['password']])) {

            unset($user[$this->params['password']]);

            $_SESSION[$this->params['session_key']] = $user;

            if($this->params['last_login']) {
                $query = sprintf(self::UPDATE_VALUE,
                    $this->params['table'],
                    $this->params['last_login'],
                    'NOW()',
                    $this->params['id'],
                    $user[$this->params['id']]);

                $this->pdo->query($query);
            }

            return $_SESSION[$this->params['session_key']];
        }
        else {
            throw new PasswordMismatchException();
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
     * @param string $username
     * @param string $password
     * @param array $data associative array of additional columns to store
     */
    public function register($username, $password, $data = array())
    {
        $fields = [];

        // escape fields
        foreach($data as $k => $v) {
            $fields[str_replace(array('\\',"\0" ,'`'), '', $k)] = $this->pdo->quote($v);
        }

        // TODO test password complexity

        $fields[$this->params['username']] = $this->pdo->quote($username);
        $fields[$this->params['password']] = $this->pdo->quote(self::hash($password));
        if($this->params['token']) {
            $fields[$this->params['token']] = $this->pdo->quote(self::hash());
        }

        if($this->params['created']) {
            $fields[$this->params['created']] = 'NOW()';
        }

        $query = (sprintf(self::REGISTER_QUERY,
            $this->params['table'],
            implode(", ", array_keys($fields)),
            implode(", ", array_values($fields))
        ));

        if ($this->pdo->query($query)) {

            $fields[$this->params['id']] = $this->pdo->lastInsertId();

            return $fields;
        } else {
            throw new \Exception(sprintf('Error creating user %s: %s',
                $user[$this->params['username']],
                json_encode($this->pdo->errorInfo())));
        };
    }

    /**
     * Returns the current logged in user
     * @return array user data
     * @throws UserException if noone is logged in
     */
    public function &user()
    {
        if($this->check()) {
            return $_SESSION[$this->params['session_key']];
        }
        else {
            throw new UserException('Not logged in');
        }
    }

    /**
     *
     * Update a user's password
     *
     * @param $username
     * @param $password
     * @return bool TRUE on success
     * @throws UserException if no rows were updated
     */
    public function passwd($username, $password)
    {

        $query = sprintf(self::UPDATE_VALUE,
            $this->params['table'],
            $this->params['password'],
            $this->pdo->quote(self::hash($password)),
            $this->params['username'],
            $this->pdo->quote($username));


        $stmt = $this->pdo->query($query);

        if($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('User not found');
        }

        return TRUE;

    }

    /**
     *
     * Reset a user's password
     *
     * @param $token
     * @param $password new password
     * @return bool TRUE on success
     * @throws UserException if no rows were updated
     */
    public function passwd_reset($token, $password)
    {

        $query = sprintf(self::RESET_PASSWORD,
            $this->params['table'],
            $this->params['password'],
            $this->pdo->quote(self::hash($password)),
            $this->params['token'],
            $this->params['token'],
            $this->pdo->quote($token));


        $stmt = $this->pdo->query($query);

        if($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('Hash not found');
        }

        return TRUE;

    }


    /**
     * Update arbitrary user data
     * @param $username
     * @param array $data associative array of data
     * @throws UserException if no rows were updated
     */
    public function update($username, array $data) {
        $cond = [];

        foreach($data as $k => $v) {
            $cond[] = sprintf("`%s` = %s", str_replace(array('\\',"\0" ,'`'), '', $k), $this->pdo->quote($v));
        }

        $query = sprintf(self::UPDATE_QUERY,
            $this->params['table'],
            implode(', ', $cond),
            $this->params['username'],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('Error updating user: '.json_encode($this->pdo->errorInfo()));
        }

    }


    /**
     * Generates a new token for the user and update the database
     * @param $username
     * @return string new token
     */
    public function update_token($username) {
        $token = self::hash();

        $query = sprintf(self::UPDATE_VALUE,
            $this->params['table'],
            $this->params['token'],
            $this->pdo->quote($token),
            $this->params['username'],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('Token not found');
        }

        return $token;
    }
}