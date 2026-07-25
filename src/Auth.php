<?php

namespace Objectiveweb;

abstract class Auth
{

    // Base access markers
    const ANONYMOUS = ['anon'];
    const AUTHENTICATED = ['auth'];
    const ALL = ['anon', 'auth'];

    public array $params;

    function __construct(array $params)
    {
        $defaults = [
            'session_key' => 'ow_auth',
            'id' => 'id',
            'password' => 'password',
            'roles' => 'roles',
            'login_providers' => ['local', 'email'],
            'token' => NULL, // Name of the field that should store user tokens
            'token_expires_field' => 'token_expires_at',
            'token_ttl' => 3600,
            'register_scope' => Auth::ANONYMOUS, // who is allowed to use /register
            'register_allow_grants' => false,
            'recovery_providers' => ['local', 'email', 'phone'],
            'register_callback' => null,
            'token_callback' => null,
            'invitation_callback' => null,
            'reset_callback' => null,
            'audit_callback' => null,
            'deletion_guard_callback' => null,
            'disabled_at' => null,
            'managed_relations' => [],
            'management_csrf' => true,
            'management_csrf_session_key' => 'ow_auth_management_csrf',
        ];

        $this->params = array_merge($defaults, $params);
    }

    public static function hash($password = null)
    {
        if ($password === null) {
            // return a random token
            return bin2hex(random_bytes(16));
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

    public function is_active(array $user): bool
    {
        $field = $this->params['disabled_at'];
        return !is_string($field) || $field === '' || empty($user[$field]);
    }

    /**
     * Reload the session principal so role and lifecycle changes take effect on
     * the very next protected request.
     */
    public function revalidate(): bool
    {
        if (!$this->check()) {
            return false;
        }

        try {
            $user = $this->reload();
        } catch (\Throwable) {
            $this->logout();
            return false;
        }

        if (!$this->is_active($user)) {
            $this->logout();
            return false;
        }

        return true;
    }

    public function management_csrf_token(): string
    {
        $key = (string) $this->params['management_csrf_session_key'];
        if (empty($_SESSION[$key]) || !is_string($_SESSION[$key])) {
            $_SESSION[$key] = bin2hex(random_bytes(32));
        }

        return $_SESSION[$key];
    }

    public function audit(string $action, int|string|null $targetUserId, array $metadata = []): void
    {
        $callback = $this->params['audit_callback'];
        if (!is_callable($callback)) {
            return;
        }

        $actorId = null;
        if ($this->check()) {
            $actorId = $this->user()[$this->params['id']] ?? null;
        }
        call_user_func($callback, $actorId, $targetUserId, $action, $metadata);
    }

    public function invite(int|string $userId, bool $reset = false): void
    {
        $user = $this->get($userId);
        $token = $this->update_token($userId);
        $credentials = $this->get_credentials($userId);
        $callback = $this->params[$reset ? 'reset_callback' : 'invitation_callback']
            ?? ($reset ? $this->params['token_callback'] : $this->params['register_callback']);

        if (is_callable($callback)) {
            call_user_func($callback, $user, $credentials, $token);
        }
    }

    public function user_can(string $ability, mixed ...$args): bool|array
    {
        if (count($args) === 0) {
            if (!$this->check()) {
                return false;
            }

            $user = $this->user();
            $roleField = $this->params['roles'];
            $roles = is_array($user[$roleField] ?? null) ? $user[$roleField] : [];

            return in_array($ability, $roles, true);
        }

        $mode = null;
        if (count($args) === 1 && is_int($args[0])) {
            $mode = 'user_relation';
        } elseif (count($args) === 1 && is_string($args[0])) {
            $mode = 'resource_list';
        } elseif (count($args) === 2 && is_string($args[0]) && is_int($args[1])) {
            $mode = 'resource_relation';
        }

        if ($mode === null) {
            throw new \InvalidArgumentException('Invalid user_can() signature');
        }

        if (!$this->check()) {
            if ($mode === 'resource_list') {
                return [];
            }

            return false;
        }

        $subjectId = $this->currentUserId();
        if ($subjectId === null) {
            if ($mode === 'resource_list') {
                return [];
            }

            return false;
        }

        if ($mode === 'user_relation') {
            return $this->userCanRelation($subjectId, 'user', $args[0], $ability);
        }

        if ($mode === 'resource_list') {
            return $this->userCanRelationList($subjectId, $args[0], $ability);
        }

        return $this->userCanRelation($subjectId, $args[0], $args[1], $ability);
    }

    private function currentUserId(): ?int
    {
        $idField = $this->params['id'];
        $user = $this->user();
        $id = $user[$idField] ?? null;
        if (is_int($id)) {
            return $id;
        }

        if (is_string($id) && ctype_digit($id)) {
            return (int) $id;
        }

        return null;
    }

    protected function userCanRelation(int $subjectId, string $resourceType, int $resourceId, string $ability): bool
    {
        return false;
    }

    protected function userCanRelationList(int $subjectId, string $resourceType, string $ability): array
    {
        return [];
    }

    /**
     * @param $uid
     * @param $password
     * @throws Auth\UserException
     * @throws Auth\AuthException
     */
    public function &login($uid, $password)
    {
        $credential = false;
        $provider = null;
        foreach ($this->params['login_providers'] as $candidateProvider) {
            $candidateCredential = $this->get_credential($candidateProvider, $uid);
            if (!$candidateCredential) {
                continue;
            }

            $credential = $candidateCredential;
            $provider = $candidateProvider;
            break;
        }

        if (!$credential) {
            throw new Auth\UserException('User does not exist', 404);
        }

        $user = $this->get($credential['user_id']);

        if (!$this->is_active($user)) {
            throw new Auth\AuthException('Account suspended', 403);
        }

        if (\password_verify($password, $user[$this->params['password']])) {

            unset($user[$this->params['password']]);
            unset($user[$this->params['token']]);

            if (session_status() === PHP_SESSION_ACTIVE) {
                session_regenerate_id(true);
            }
            $this->user($user);

            // TODO add login ip
            $this->update_credential($user[$this->params['id']], (string) $provider, $uid, null);

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
        $uid = trim((string) ($user['uid'] ?? ''));

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
     * @throws \Exception
     */
    abstract public function get_credential($provider, $accountid);

    /**
     * List all credentials for a user.
     *
     * Returned rows are normalized to:
     * - uid
     * - provider
     * - profile
     * - last_login
     * - created
     */
    abstract public function get_credentials($user_id, $key = 'id'): array;

    /**
     * List all users that have the given role name.
     *
     * @param string $roleName
     * @return array<int,array<string,mixed>>
     */
    abstract public function get_users_by_role($roleName): array;

    /**
     * List all available role names.
     *
     * @return array<int,string>
     */
    abstract public function get_roles(): array;

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

    abstract public function create_credential($userid, string $provider, string $uid, mixed $profile = null): array;

    abstract public function rename_credential(
        $userid,
        string $provider,
        string $uid,
        string $newProvider,
        string $newUid
    ): array;

    abstract public function delete_credential($userid, string $provider, string $uid): bool;

    abstract public function get_managed_relations($userId): array;

    abstract public function sync_managed_relations($userId, array $relations): array;
}
