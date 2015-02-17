<?php

namespace Objectiveweb;

use Objectiveweb\Auth\UserException;
use Objectiveweb\Auth\PasswordMismatchException;

use PDO;

class Auth
{
    private $params;

    /** @var \PDO  */
    private $pdo;

    const LOGIN_QUERY = "select * from `%s` where `%s` = :username and `%s` = :password";
    const REGISTER_QUERY = "insert into `%s` (%s) values (%s)";

    public static function hash($password)
    {
        return md5($password);
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
            'token' => 'token'
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
     */
    public function register(array $user)
    {
        $fields = [];

        foreach(['username', 'displayName', 'email', 'password'] as $f) {
            if($this->params[$f]) {
                if(!empty($user[$f])) {
                    $fields['`'.$this->params[$f].'`'] = $this->pdo->quote($user[$f]);
                }
                else {
                    throw new UserException(sprintf("%s (%s) is required", $f, $this->params[$f]), 128);
                }
            }
        }


        $fields[$this->params['token']] = $this->pdo->quote(self::hash($user['password']));


        $query = (sprintf(self::REGISTER_QUERY,
            $this->params['table'],
            implode(", ", array_keys($fields)),
            implode(", ", array_values($fields))
            ));

        if($this->pdo->query($query)) {

            $fields[$this->params['id']] =  $this->pdo->lastInsertId();

            return $fields;
        }
        else {
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
            $this->params['username'],
            $this->params['password']);

        $stmt = $this->pdo->prepare($query);

        if($stmt->execute([ ':username' => $username, ':password' => $password]) && $user = $stmt->fetch(PDO::FETCH_ASSOC)) {

            unset($user[$this->params['password']]);

            $_SESSION[$this->params['session_key']] = $user;

            return $user;
        }
        else {
            throw new UserException(sprintf('Invalid user or user not found'));
        }

    }

    public function logout()
    {
        unset($_SESSION[$this->params['session_key']]);
    }

    public function passwd($username, $password)
    {
        // TODO $this->table->update([ 'password' => Auth::hash($password)], [ 'username' => $username ]);
    }


}