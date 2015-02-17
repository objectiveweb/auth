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

    const LOGIN_QUERY = "select * from `%s` where `%s` = :username";
    const REGISTER_QUERY = "insert into `%s` (%s) values (%s)";
    const UPDATE_LOGIN = 'UPDATE `%s` SET `%s` = NOW() WHERE id = %d';
    const UPDATE_PASSWORD = 'UPDATE `%s` SET `%s` = %s WHERE %s = %s';
    const USER_BY_NAME = "SELECT `%s` FROM `%s` WHERE `%s` = %s";

    public static function hash($password = null)
    {
        if (!$password) {
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
            'displayName' => 'displayName',
            'email' => 'email',
            'password' => 'password',
            'token' => 'token',
            'created' => 'created',
            'last_login' => 'last_login'
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
     * @param array $user [ username, displayName, email, password ]
     * @param array $fields array of additional fields to store on the user table
     */
    public function register(array $user, $fields = array())
    {

        foreach (['username', 'displayName', 'email'] as $f) {
            if ($this->params[$f]) {
                if (!empty($user[$f])) {
                    $fields['`' . $this->params[$f] . '`'] = $this->pdo->quote($user[$f]);
                } else {
                    throw new UserException(sprintf("%s (%s) is required", $f, $this->params[$f]), 128);
                }
            }
        }

        // TODO test password complexity
        $fields[$this->params['password']] = $this->pdo->quote(self::hash($user['password']));
        $fields[$this->params['token']] = $this->pdo->quote(md5(microtime(true)));
        $fields[$this->params['created']] = 'NOW()';

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
     * @param $username
     * @param $password
     * @throws UserNotFoundException
     * @throws PasswordMismatchException
     */
    public function login($username, $password)
    {

        $query = sprintf(self::LOGIN_QUERY,
            $this->params['table'],
            $this->params['username']);

        $stmt = $this->pdo->prepare($query);

        if ($stmt->execute([':username' => $username]) && $user = $stmt->fetch(PDO::FETCH_ASSOC)) {

            if(password_verify($password, $user[$this->params['password']])) {

                unset($user[$this->params['password']]);

                $_SESSION[$this->params['session_key']] = $user;

                $query = sprintf(self::UPDATE_LOGIN,
                    $this->params['table'],
                    $this->params['last_login'],
                    $user['id']);

                $this->pdo->query($query);


                return $user;
            }
            else {
                throw new PasswordMismatchException();
            }


        } else {
            throw new UserException(sprintf('Invalid user or user not found'));
        }

    }

    /**
     * Logs out the current user (unsets the session key)
     */
    public function logout()
    {
        unset($_SESSION[$this->params['session_key']]);
    }

    public function user()
    {
        if($this->check()) {
            return $_SESSION[$this->params['session_key']];
        }
        else {
            throw new \Exception('Not logged in');
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

        $query = sprintf(self::UPDATE_PASSWORD,
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


}