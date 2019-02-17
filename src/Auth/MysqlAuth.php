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
            'table' => 'user',
            'prefix' => 'ow_',
            'created' => NULL,
            'last_login' => NULL,
            'credentials_table' => 'credentials',
            'with' => []
        ];

        parent::__construct(array_merge($defaults, $params));

        $this->params['table'] = $this->params['prefix'] . $this->params['table'];
        $this->params['credentials_table'] = $this->params['prefix'] . $this->params['credentials_table'];
        $this->params['with'][$this->params['credentials_table']] = 'user_id';
    }

    /**
     * Queries the user table
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

        $query = sprintf(/** @lang text */
            "SELECT SQL_CALC_FOUND_ROWS * FROM `%s` WHERE %s",
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
     * @param $user_id String user_id
     * @param $key String which key to lookup (id, token)
     * @return array user data
     * @throws UserException
     * @throws \Exception
     */
    public function get($user_id, $key = 'id')
    {

        $key = $key == 'credential' ?

        $query = sprintf(/** @lang text */
            "SELECT * FROM `%s` where `%s` = %s",
            $this->params['table'],
            $this->params[$key],
            $this->pdo->quote($user_id));

        $stmt = $this->pdo->query($query);

        if (!$stmt) {
            $error = $this->pdo->errorInfo();

            throw new \Exception($error[2]);
        }

        if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {

            foreach ($this->params['with'] as $table => $fk) {
                $query = sprintf(/** @lang text */
                    "SELECT * FROM `%s` where `%s` = %s",
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
     *
     * TODO usar transaction, atualizar credentials
     *
     * @param string $uid
     * @param string $password
     * @param array $data associative array of additional columns to store
     */
    public function register($uid, $password = null, $data = array())
    {
        $fields = [];

        if (is_array($uid)) {
            $data = array_merge($uid, $data);

            $uid = @$data['uid'];
            unset($data['uid']);

            $password = @$data['password'];
            unset($data['password']);

        }

        $provider = empty($data['provider']) ? 'local' : $data['provider'];
        unset($data['provider']);

        $user = $this->get_credential($provider, $uid);

        if (!empty($user)) {
            $ex = new UserException('User already registered', 409);
            $ex->setUser($user['user']);
            throw $ex;
        }

        $profile = !empty($data['profile']) ? json_encode($data['profile']) : null;
        unset($data['profile']);

        // escape and encode fields
        foreach ($data as $k => $v) {
            $fields[str_replace(array('\\', "\0", '`'), '', $k)] = is_array($v) ? json_encode($v) : $v;
        }

        if ($password) {
            $fields[$this->params['password']] = self::hash($password);
        }

        if ($this->params['token']) {
            $fields[$this->params['token']] = self::hash();
        }

        if ($this->params['created']) {
            $fields[$this->params['created']] = date('Y-m-d H:i:s');
        }

        $this->pdo->beginTransaction();

        $stmt = $this->pdo->prepare("INSERT INTO " . $this->params['table']
            . " (" . implode(array_keys($fields), ", ")
            . ") VALUES (:" . implode(array_keys($fields), ", :") . ");");

        foreach ($fields as $k => $v) {
            $stmt->bindValue(":" . $k, $v);
        }

        if ($stmt->execute()) {
            $fields[$this->params['id']] = $this->pdo->lastInsertId();
            unset($fields[$this->params['created']]);
            unset($fields[$this->params['password']]);
            if (!empty($fields[$this->params['scopes']])) {
                $fields['params']['scopes'] = explode(",", $fields[$this->params['scopes']]);
            }
        } else {
            $this->pdo->rollBack();
            $errorInfo = $this->pdo->errorInfo();

            if ($errorInfo[1] == 1062) {
                throw new \Exception(sprintf("User %s already exists", $uid), 409);
            } else {
                throw new \Exception($errorInfo[2]);
            }
        }

        $stmt = $this->pdo->prepare("INSERT INTO `{$this->params['credentials_table']}` 
            (user_id, provider, uid, profile) VALUES (:user_id, :provider, :uid, :profile)");
        $stmt->bindValue(':user_id', $fields[$this->params['id']]);
        $stmt->bindValue(':provider', $provider);
        $stmt->bindValue(':uid', $uid);
        $stmt->bindValue(':profile', $profile);

        if ($stmt->execute()) {
            $this->pdo->commit();
            return $fields;
        } else {
            $this->pdo->rollBack();
            $errorInfo = $this->pdo->errorInfo();
            throw new \Exception($errorInfo[2]);
        }
    }

    /**
     *
     * Update a user's password
     *
     * @param user_id
     * @param $password
     * @param $key String id
     * @return bool TRUE on success
     * @throws UserException if no rows were updated
     */
    public function passwd($user_id, $password, $key = 'id')
    {

        $query = sprintf(/** @lang text */
            "UPDATE `%s` SET `%s` = %s WHERE `%s` = %s",
            $this->params['table'],
            $this->params['password'],
            $this->pdo->quote(self::hash($password)),
            $this->params[$key],
            $this->pdo->quote($user_id));

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

        $query = sprintf(/** @lang text */
            'UPDATE `%s` SET `%s` = %s, `%s` = NULL WHERE %s = %s',
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
     * @param $user_id
     * @param array $data associative array of data
     * @param key String
     * @throws UserException if no rows were updated
     */
    public function update($user_id, array $data, $key = 'id')
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

        $query = sprintf(/** @lang text */
            "UPDATE `%s` SET %s WHERE `%s` = %s",
            $this->params['table'],
            implode(', ', $cond),
            $this->params[$key],
            $this->pdo->quote($user_id));

        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE) {
            throw new UserException(json_encode($this->pdo->errorInfo()));
        }

    }

    public function delete($user_id)
    {

        if ($this->check()) {
            $user = $this->user();

            if ($user[$this->params[$key]] == $user_id) {
                throw new \Exception("Cannot delete yourself!");
            }
        }

        $this->pdo->beginTransaction();

        $stmt = $this->pdo->prepare(/** @lang text */
            "DELETE FROM `{$this->params['credentials_table']}` WHERE `user_id` = :user_id");

        $stmt->bindValue(':user_id', $user_id);

        if ($stmt->execute() === FALSE) {
            $this->pdo->rollBack();
            throw new \Exception(json_encode($this->pdo->errorInfo()));
        }

        $stmt = $this->pdo->prepare(/** @lang text */
            "DELETE FROM `{$this->params['table']}` WHERE `{$this->params['id']}` = :user_id LIMIT 1");

        $stmt->bindValue(':user_id', $user_id);

        if ($stmt->execute() === FALSE) {
            $this->pdo->rollBack();
            throw new \Exception(json_encode($this->pdo->errorInfo()));
        }

        $this->pdo->commit();

        return true;
    }

    /**
     * Generates a new token for the user and update the database
     * @param $user_id
     * @return string new token
     */
    public function update_token($user_id)
    {
        $token = self::hash();

        $query = sprintf(/** @lang text */
            "UPDATE `%s` SET `%s` = %s WHERE `%s` = %s",
            $this->params['table'],
            $this->params['token'],
            $this->pdo->quote($token),
            $this->params['id'],
            $this->pdo->quote($user_id));

        $stmt = $this->pdo->query($query);

        if ($stmt === FALSE || $stmt->rowCount() !== 1) {
            throw new UserException('Token not found');
        }

        return $token;
    }

    /**
     * Retrieves an account from credentials_table
     * @param $provider provider
     * @param $userid String user_id
     * @return mixed account data or null if account not found
     * @throws \Exception
     */
    public function get_credential($provider, $accountid)
    {
        $query = sprintf(/** @lang text */
            "SELECT a.user_id, a.provider, a.uid, a.profile
              FROM `%s` a 
              WHERE a.provider = %s and a.uid = %s",
            $this->params['credentials_table'],
            $this->pdo->quote($provider),
            $this->pdo->quote($accountid));

        $stmt = $this->pdo->query($query);

        if (!$stmt) {
            $error = $this->pdo->errorInfo();

            throw new \Exception($error[2], 500);
        }

        if ($account = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($account['profile'])) {
                $account['profile'] = json_decode($account['profile'], true);
            }

            if (!empty($account['user_id'])) {
                $account['user'] = $this->get($account['user_id']);
            } else {
                $account['user'] = null;
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
    public function update_credential($userid, $provider, $uid, $profile = null)
    {

        if (is_array($profile)) {
            $profile = json_encode($profile);
        }

        $query = sprintf(/** @lang text */
            "INSERT INTO `%s` (user_id, provider, uid, profile) VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE profile = VALUES(profile), modified = %s",
            $this->params['credentials_table'],
            $this->pdo->quote($userid),
            $this->pdo->quote($provider),
            $this->pdo->quote($uid),
            $this->pdo->quote($profile),
            $this->pdo->quote(date('Y-m-d H:i:s'))
        );

        if (!$this->pdo->query($query)) {
            $errorInfo = $this->pdo->errorInfo();

            throw new \Exception($errorInfo[2], 500);
        }

        return true;

    }
}
