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

    const SELECT_ALL = "SELECT * FROM `%s` where `%s` = %s";
	const SELECT_SEARCH = "SELECT SQL_CALC_FOUND_ROWS * FROM `%s` WHERE %s";
    const REGISTER_QUERY = "INSERT INTO `%s` (%s) VALUES (%s)";
    const RESET_PASSWORD = 'UPDATE `%s` SET `%s` = %s, `%s` = NULL WHERE %s = %s';
    const UPDATE_QUERY = "UPDATE `%s` SET %s WHERE `%s` = %s";
    const UPDATE_VALUE = "UPDATE `%s` SET `%s` = %s WHERE `%s` = %s";
    const USER_BY_NAME = "SELECT `%s` FROM `%s` WHERE `%s` = %s";
	const DELETE_QUERY = "DELETE FROM `%s` WHERE `%s` = %s LIMIT 1";

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
        $defaults = array(
            'session_key' => 'ow_auth',
            'table' => 'ow_auth',
            'id' => 'id',
            'username' => 'username',
            'password' => 'password',
            'token' => NULL,
            'created' => NULL,
            'last_login' => NULL
        );

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
	 * Queries the Auth table
	 */
	public function query($params = array(), $operator = "OR") {
		
		$page = intval(@$params['page']);
		$size = intval(@$params['size']);
		$sort = @$params['sort'];
		
		unset($params['page']);
		unset($params['size']);
		unset($params['sort']);
		
		if(!$size) $size = 20;
		
		$cond = array();
		$bindings = array();
		
		foreach($params as $key => $value) {
			$cond[] = sprintf("`%s` %s :where_%s", 
					str_replace('`', '``', $key), 
					is_null($value) ? 'is' : (strpos($value, '%') !== FALSE ? 'LIKE' : '='),
					$key);
			$bindings[":where_$key"] = $value;
		}
		
		$query = sprintf(self::SELECT_SEARCH,
            $this->params['table'],
			empty($cond) ? '1=1' : implode(" $operator ", $cond)
		);
		
		$query .= sprintf(" LIMIT %d, %d", $page * $size, $size);
		
		$stmt = $this->pdo->prepare($query);
		
		$stmt->execute($bindings);

		if(!$stmt) {
			$error = $this->pdo->errorInfo();
			
			throw new \Exception($error[2]);
		}
		
		$data = $stmt->fetchAll(PDO::FETCH_ASSOC);
		
		$stmt = $this->pdo->query("SELECT FOUND_ROWS() as count");
		
		$count = $stmt->fetch(PDO::FETCH_ASSOC);
		
		if(!$count) {
			throw new \Exception("Error fetching count");
		}
		
 		$count = intval($count['count']);
		
		return array(
			'_embedded' => array(
				$this->params['table'] => $data
			),
			'page' => array(
				'size' => $size,
				'number' => $page,
				'totalElements' => $count,
				'totalPages' => ceil($count/$size)
 			)
		);
	}
	
    /**
     * Retrieves a user from the database
     * @param $username username
     * @return array user data
     * @throws UserException
	 * @throws Exception
     */
    public function get($username) {


        if(is_numeric($username)) {
            $key = 'id';
        }
        else {
            $key = 'username';
        }

        $query = sprintf(self::SELECT_ALL,
            $this->params['table'],
            $this->params[$key],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

		if(!$stmt) {
			$error = $this->pdo->errorInfo();
			
			throw new \Exception($error[2]);
		}
		
        if($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            return $user;
        }
        else {
            throw new UserException('User not found', 404);
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

        if(\password_verify($password, $user[$this->params['password']])) {

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
    public function register($username, $password = null, $data = array())
    {
		if(is_array($username)) {
			$data = $username;
			
			$username = @$data[$this->params['username']];
			unset($data[$this->params['username']]);
			
			$password = @$data['password'];
			unset($data['password']);
		}
		
        $fields = array();

        // escape fields
        foreach($data as $k => $v) {
            $fields[str_replace(array('\\',"\0" ,'`'), '', $k)] = $this->pdo->quote($v);
        }

        if(empty($username) || empty($password)) {
			throw new \Exception("Por favor informe usuário e senha");
		}

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
            unset($fields[$this->params['created']]);

            return $fields;
        } else {
            $errorInfo = $this->pdo->errorInfo();

            if($errorInfo[1] == 1062) {
                throw new \Exception(sprintf("User %s already exists", $username), 409);
            }
            else {
                throw new \Exception($errorInfo[2]);
            }
        }
    }

    /**
     * Returns the current logged in user or sets the current login data
     * @param $user array
     * @return array user data
     * @throws UserException if noone is logged in
     */
    public function &user($user = null)
    {
        if($user) {
            $_SESSION[$this->params['session_key']] = $user;
        }
        else {
            if(!$this->check()) {
                throw new UserException('Not logged in', 403);
            }
        }


        return $_SESSION[$this->params['session_key']];
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

        if(is_numeric($username)) {
            $key = 'id';
        }
        else {
            $key = 'username';
        }

        $query = sprintf(self::UPDATE_VALUE,
            $this->params['table'],
            $this->params['password'],
            $this->pdo->quote(self::hash($password)),
            $this->params[$key],
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
        $cond = array();
        unset($data[$this->params['id']]);
		unset($data[$this->params['password']]);

        if($this->params['token']) {
            unset($data[$this->params['token']]);
        }

        if($this->params['created']) {
            unset($data[$this->params['created']]);
        }

        if($this->params['last_login']) {
            unset($data[$this->params['last_login']]);
        }


        foreach($data as $k => $v) {
            $cond[] = sprintf("`%s` = %s", str_replace(array('\\',"\0" ,'`'), '', $k), $this->pdo->quote($v));
        }


        if(is_numeric($username)) {
            $key = 'id';
        }
        else {
            $key = 'username';
        }

        $query = sprintf(self::UPDATE_QUERY,
            $this->params['table'],
            implode(', ', $cond),
            $this->params[$key],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if($stmt === FALSE) {
            throw new UserException(json_encode($this->pdo->errorInfo()));
        }

    }

	public function delete($username) {

        if(is_numeric($username)) {
            $key = 'id';
        }
        else {
            $key = 'username';
        }


        if($this->check()) {
            $user = $this->user();

            if($user[$this->params[$key]] == $username) {
                throw new \Exception("Cannot delete yourself!");
            }
        }

        $query = sprintf(self::DELETE_QUERY,
            $this->params['table'],
            $this->params[$key],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new \Exception(json_encode($this->pdo->errorInfo()));
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