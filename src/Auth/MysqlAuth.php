<?php

namespace Objectiveweb\Auth;

use PDO;


class MysqlAuth extends \Objectiveweb\Auth
{

    public $params;

    /** @var \PDO */
    private $pdo;

    public function __construct(\PDO $pdo, $params = [])
    {
        $this->pdo = $pdo;

        $defaults = [
            'table' => 'ow_auth',
            'created' => NULL,
            'last_login' => NULL,
            'ext_accounts_table' => NULL,
            'with' => []
        ];

        parent::__construct(array_merge($defaults, $params));

        if(!empty($this->params['ext_accounts_table'])) {
            $this->params['with'][$this->params['ext_accounts_table']] = 'user_id';
        }

    }

    public function setup() {

        $fields = [
            "{$this->params['id']} INT UNSIGNED PRIMARY KEY AUTO_INCREMENT",
            "{$this->params['username']} VARCHAR(255) NOT NULL",
            "{$this->params['password']} VARCHAR(255)"
        ];

        if($this->params['token']) {
            $fields[] = "{$this->params['token']} CHAR(32)";
        }

        if($this->params['created']) {
            $fields[]  = "{$this->params['created']} DATETIME";
        }

        if($this->params['last_login']) {
            $fields[] = "{$this->params['last_login']} DATETIME";
        }


        $queries[] = sprintf("CREATE TABLE `%s` (%s)",
            $this->params['table'],
            implode(",", $fields));

        $queries[] = sprintf("CREATE UNIQUE INDEX %s_username_uindex ON %s (%s)",
            $this->params['table'],
            $this->params['table'],
            $this->params['username']);

        if($this->params['ext_accounts_table']) {
            $queries[] = sprintf("CREATE TABLE `%s` ( 
            user_id INT UNSIGNED NOT NULL,
            provider VARCHAR(32) NOT NULL,
            uid VARCHAR(255) NOT NULL,
	        profile text null,
            CONSTRAINT auth_accounts_uid_provider_user_id_pk PRIMARY KEY (uid, provider, user_id),
            CONSTRAINT auth_accounts_users_id_fk FOREIGN KEY (user_id) REFERENCES %s (%s))",
                $this->params['ext_accounts_table'],
                $this->params['table'],
                $this->params['id']);
        }

        return $queries;
    }

    /**
     * Queries the Auth table
     */
    public function query($params = array(), $operator = "OR")
    {

        $page = intval(@$params['page']);
        $size = intval(@$params['size']);
        $sort = @$params['sort'];

        unset($params['page']);
        unset($params['size']);
        unset($params['sort']);

        if (!$size) $size = 20;

        $cond = array();
        $bindings = array();

        foreach ($params as $key => $value) {
            $cond[] = sprintf("`%s` %s :where_%s",
                str_replace('`', '``', $key),
                is_null($value) ? 'is' : (strpos($value, '%') !== FALSE ? 'LIKE' : '='),
                $key);
            $bindings[":where_$key"] = $value;
        }

        $query = sprintf("SELECT SQL_CALC_FOUND_ROWS * FROM `%s` WHERE %s",
            $this->params['table'],
            empty($cond) ? '1=1' : implode(" $operator ", $cond)
        );

        $query .= sprintf(" LIMIT %d, %d", $page * $size, $size);

        $stmt = $this->pdo->prepare($query);

        $stmt->execute($bindings);

        if (!$stmt) {
            $error = $this->pdo->errorInfo();

            throw new \Exception($error[2]);
        }

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $stmt = $this->pdo->query("SELECT FOUND_ROWS() as count");

        $count = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$count) {
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
                'totalPages' => ceil($count / $size)
            )
        );
    }

    /**
     * Retrieves a user from the database
     * @param $username String username
     * @param $key String which key to lookup (username, id, token)
     * @return array user data
     * @throws UserException
     * @throws \Exception
     */
    public function get($username, $key = 'username')
    {

        $query = sprintf("SELECT * FROM `%s` where `%s` = %s",
            $this->params['table'],
            $this->params[$key],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if (!$stmt) {
            $error = $this->pdo->errorInfo();

            throw new \Exception($error[2]);
        }

        if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {

            foreach ($this->params['with'] as $table => $fk) {
                $query = sprintf("SELECT * FROM `%s` where `%s` = %s",
                    $table, 
                    $fk,
                    $user[$this->params['id']]
                );

                $stmt = $this->pdo->query($query);

                if (!$stmt) {
                    $error = $this->pdo->errorInfo();

                    throw new \Exception($error[2]);
                }

                $user[$table] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }

            return $user;
        } else {
            throw new UserException('User not found', 404);
        }
    }

    /**
     * @param $username
     * @param $password
     * @throws UserException
     * @throws AuthException
     */
    public function &login($username, $password)
    {
        $user = $this->get($username);

        if (\password_verify($password, $user[$this->params['password']])) {

            unset($user[$this->params['password']]);
            unset($user[$this->params['token']]);

            $this->user($user);

            if ($this->params['last_login']) {
                $query = sprintf("UPDATE `%s` SET `%s` = %s WHERE `%s` = %s",
                    $this->params['table'],
                    $this->params['last_login'],
                    'NOW()',
                    $this->params['id'],
                    $user[$this->params['id']]);

                $this->pdo->query($query);
            }

            return $user;
        } else {
            throw new AuthException('Password invalid', 400);
        }

    }

    /**
     * @param string $username
     * @param string $password
     * @param array $data associative array of additional columns to store
     */
    public function register($username, $password = null, $data = array())
    {
        if (is_array($username)) {
            $data = $username;

            $username = @$data[$this->params['username']];
            unset($data[$this->params['username']]);

            $password = @$data['password'];
            unset($data['password']);
        }

        $fields = array(
            $this->params['username'] => $username
        );

        // escape fields
        foreach ($data as $k => $v) {
            $fields[str_replace(array('\\', "\0", '`'), '', $k)] = $v;
        }

        if($password) {
            $fields[$this->params['password']] = self::hash($password);
        }

        if ($this->params['token']) {
            $fields[$this->params['token']] = self::hash();
        }

        if ($this->params['created']) {
            $fields[$this->params['created']] = date('Y-m-d H:i:s');
        }

        $fields = $this->validate($fields);

        $stmt = $this->pdo->prepare("INSERT INTO " . $this->params['table']
            . " (" . implode(array_keys($fields), ", ")
            . ") VALUES (:" . implode(array_keys($fields), ", :") . ");");

        foreach($fields as $k => $v) {
            $stmt->bindValue(":".$k, $v);
        }

        if ($stmt->execute()) {
            $fields[$this->params['id']] = $this->pdo->lastInsertId();
            unset($fields[$this->params['created']]);
            unset($fields[$this->params['password']]);
            if(!empty($fields[$this->params['scopes']])) {
                $fields['params']['scopes'] = explode(",", $fields[$this->params['scopes']]);
            }
            
            return $fields;
        } else {
            $errorInfo = $this->pdo->errorInfo();

            if ($errorInfo[1] == 1062) {
                throw new \Exception(sprintf("User %s already exists", $username), 409);
            } else {
                throw new \Exception($errorInfo[2]);
            }
        }
    }

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
    public function passwd($username, $password, $key = 'username')
    {

        $query = sprintf("UPDATE `%s` SET `%s` = %s WHERE `%s` = %s",
            $this->params['table'],
            $this->params['password'],
            $this->pdo->quote(self::hash($password)),
            $this->params[$key],
            $this->pdo->quote($username));


        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('User not found');
        }

        return TRUE;

    }

    /**
     *
     * Reset a user's password
     *
     * @param $token String
     * @param $password String new password
     * @return $user array user data on success
     * @throws UserException if no rows were updated
     */
    public function passwd_reset($token, $password)
    {

        $user = $this->get($token, $this->params['token']);

        $query = sprintf('UPDATE `%s` SET `%s` = %s, `%s` = NULL WHERE %s = %s',
            $this->params['table'],
            $this->params['password'],
            $this->pdo->quote(self::hash($password)),
            $this->params['token'],
            $this->params['token'],
            $this->pdo->quote($token));


        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('Hash not found');
        }

        return $user;

    }


    /**
     * Update arbitrary user data
     * @param $username
     * @param array $data associative array of data
     * @param key String username or id
     * @throws UserException if no rows were updated
     */
    public function update($username, array $data, $key = 'username')
    {
        $cond = array();
        unset($data[$this->params['id']]);
        unset($data[$this->params['password']]);

        if ($this->params['token']) {
            unset($data[$this->params['token']]);
        }

        if ($this->params['created']) {
            unset($data[$this->params['created']]);
        }

        if ($this->params['last_login']) {
            unset($data[$this->params['last_login']]);
        }


        foreach ($data as $k => $v) {
            $cond[] = sprintf("`%s` = %s", str_replace(array('\\', "\0", '`'), '', $k), $this->pdo->quote($v));
        }

        $query = sprintf("UPDATE `%s` SET %s WHERE `%s` = %s",
            $this->params['table'],
            implode(', ', $cond),
            $this->params[$key],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE) {
            throw new UserException(json_encode($this->pdo->errorInfo()));
        }

    }

    public function delete($username, $key = 'username')
    {

        if ($this->check()) {
            $user = $this->user();

            if ($user[$this->params[$key]] == $username) {
                throw new \Exception("Cannot delete yourself!");
            }
        }

        $query = sprintf("DELETE FROM `%s` WHERE `%s` = %s LIMIT 1",
            $this->params['table'],
            $this->params[$key],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new \Exception(json_encode($this->pdo->errorInfo()));
        }
    }

    /**
     * Generates a new token for the user and update the database
     * @param $username
     * @return string new token
     */
    public function update_token($username)
    {
        $token = self::hash();

        $query = sprintf("UPDATE `%s` SET `%s` = %s WHERE `%s` = %s",
            $this->params['table'],
            $this->params['token'],
            $this->pdo->quote($token),
            $this->params['username'],
            $this->pdo->quote($username));

        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('Token not found');
        }

        return $token;
    }

    /**
     * Retrieves an account from ext_accounts_table
     * @param $userid String user_id
     * @param $key String which key to lookup (username, id, token)
     * @return mixed account data or null if account not found
     * @throws \Exception
     */
    public function get_account($provider, $accountid)
    {
        $query = sprintf("SELECT a.user_id, a.provider, a.uid, a.profile
              FROM `%s` a WHERE a.provider = %s and a.uid = %s",
            $this->params['ext_accounts_table'],
            $this->pdo->quote($provider),
            $this->pdo->quote($accountid));

        $stmt = $this->pdo->query($query);

        if (!$stmt) {
            $error = $this->pdo->errorInfo();

            throw new \Exception($error[2]);
        }

        if ($account = $stmt->fetch(PDO::FETCH_ASSOC)) {

            if(!empty($account['profile'])) {
                $account['profile'] = json_decode($account['profile'], true);
            }

            return $account;
        } else {
            return false;
        }
    }

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
    public function update_account($userid, $provider, $uid, $profile = null)
    {

        if(is_array($profile)) {
            $profile = json_encode($profile);
        }

        $query = sprintf("INSERT INTO `%s` (
           user_id, provider, uid, profile 
        ) VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE profile = VALUES(profile)",
            $this->params['ext_accounts_table'],
            $this->pdo->quote($userid),
            $this->pdo->quote($provider),
            $this->pdo->quote($uid),
            $this->pdo->quote($profile)
        );

        if (!$this->pdo->query($query)) {
            $errorInfo = $this->pdo->errorInfo();

            throw new \Exception($errorInfo[2]);
        }

        return true;

    }

}