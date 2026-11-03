<?php

namespace Objectiveweb\Auth;

use Objectiveweb\DB;
use Objectiveweb\DB\Collection;
use Objectiveweb\DB\Exception\NotFoundException;
use Objectiveweb\DB\Table;

class DBAuth extends \Objectiveweb\Auth
{
    public array $params;
    private Table $userTable;

    public function __construct(private DB $db, array $params = [])
    {
        $defaults = [
            'table' => 'user',
            'created' => 'created',
            'last_login' => null,
            'credentials_table' => 'user_credentials',
            'credentials_last_login' => 'last_login',
            'credentials_created' => 'created',
            'uuid' => 'uuid',
            'roles_table' => 'role',
            'user_roles_table' => 'user_roles',
            'user_roles_user_id' => 'user_id',
            'user_roles_role_id' => 'role_id',
            'role_id' => 'id',
            'role_name' => 'name',
            'relations' => [],
        ];

        parent::__construct(array_merge($defaults, $params));
        $this->userTable = $this->db->table(
            (string) $this->params['table'],
            ['pk' => (string) $this->params['id']]
        );
        $this->assertRoleConfig();
    }

    public function query($params = array(), $operator = "OR"): Collection
    {
        $page = max(0, (int) ($params['page'] ?? 0));
        $size = max(1, (int) ($params['size'] ?? 20));
        $sort = (string) ($params['sort'] ?? ($this->params['id'] . ' ASC'));
        $q = trim((string) ($params['q'] ?? ''));
        $role = trim((string) ($params['role'] ?? ''));
        $status = trim((string) ($params['status'] ?? ''));
        unset($params['page'], $params['size'], $params['sort'], $params['q'], $params['role'], $params['status']);

        $userTableName = (string) $this->params['table'];
        $userIdField = (string) $this->params['id'];

        [$sortField, $sortDirection] = array_pad(preg_split('/\s+/', trim($sort), 2), 2, 'ASC');
        $sortDirection = strtoupper($sortDirection);
        if (!in_array($sortDirection, ['ASC', 'DESC'], true)) {
            throw new \InvalidArgumentException('Invalid sort direction');
        }

        $where = [];
        $candidateIds = null;
        $operator = strtoupper((string) $operator);

        if ($params !== []) {
            if ($operator === 'AND') {
                foreach ($params as $key => $value) {
                    if ($key === 'uid') {
                        $credential = $this->get_credential('local', $value);
                        $candidateIds = $this->intersectUserIds(
                            $candidateIds,
                            $credential && isset($credential['user_id']) ? [$credential['user_id']] : []
                        );
                        continue;
                    }

                    $where[(string) $key] = $value;
                }
            } else {
                $filterIds = [];
                foreach ($params as $key => $value) {
                    if ($key === 'uid') {
                        $credential = $this->get_credential('local', $value);
                        if ($credential && isset($credential['user_id'])) {
                            $filterIds[] = $credential['user_id'];
                        }
                        continue;
                    }

                    // Table::select() also issues a COUNT query. For OR candidate
                    // discovery we only need IDs, so keep this as a low-level scan.
                    $rows = $this->db->select(
                        $userTableName,
                        [(string) $key => $value],
                        ['fields' => [$userIdField]]
                    )->all();
                    foreach ($rows as $row) {
                        if (array_key_exists($userIdField, $row)) {
                            $filterIds[] = $row[$userIdField];
                        }
                    }
                }
                $candidateIds = $this->intersectUserIds($candidateIds, $filterIds);
            }
        }

        if ($q !== '') {
            $searchIds = [];
            // Same rationale as above: this is candidate-ID discovery, not the
            // paginated user query itself.
            $nameRows = $this->db->select(
                $userTableName,
                ['name' => '%' . $q . '%'],
                ['fields' => [$userIdField]]
            )->all();
            foreach ($nameRows as $row) {
                if (array_key_exists($userIdField, $row)) {
                    $searchIds[] = $row[$userIdField];
                }
            }

            if (ctype_digit($q)) {
                $idRow = $this->db->select(
                    $userTableName,
                    [$userIdField => $q],
                    ['fields' => [$userIdField], 'limit' => 1]
                )->fetch();
                if ($idRow && array_key_exists($userIdField, $idRow)) {
                    $searchIds[] = $idRow[$userIdField];
                }
            }

            $credentialRows = $this->db->select(
                (string) $this->params['credentials_table'],
                ['uid' => '%' . $q . '%'],
                ['fields' => ['user_id']]
            )->all();
            foreach ($credentialRows as $row) {
                if (array_key_exists('user_id', $row)) {
                    $searchIds[] = $row['user_id'];
                }
            }

            $candidateIds = $this->intersectUserIds($candidateIds, $searchIds);
        }

        if ($role !== '') {
            if (!$this->rolesEnabled()) {
                if ($role !== 'unassigned') {
                    $candidateIds = $this->intersectUserIds($candidateIds, []);
                }
            } elseif ($role === 'unassigned') {
                $assigned = $this->db->select(
                    (string) $this->params['user_roles_table'],
                    null,
                    ['fields' => [(string) $this->params['user_roles_user_id']]]
                )->all();
                $assignedIds = array_values(array_unique(array_map(
                    fn (array $row): mixed => $row[(string) $this->params['user_roles_user_id']] ?? null,
                    $assigned
                )));
                $assignedIds = array_values(array_filter($assignedIds, fn (mixed $id): bool => $id !== null));
                if ($assignedIds !== []) {
                    $where['!' . $userIdField] = $assignedIds;
                }
            } else {
                $roleRow = $this->db->select(
                    (string) $this->params['roles_table'],
                    [(string) $this->params['role_name'] => $role],
                    ['fields' => [(string) $this->params['role_id']], 'limit' => 1]
                )->fetch();

                $roleUserIds = [];
                if ($roleRow && array_key_exists((string) $this->params['role_id'], $roleRow)) {
                    $memberships = $this->db->select(
                        (string) $this->params['user_roles_table'],
                        [(string) $this->params['user_roles_role_id'] => $roleRow[(string) $this->params['role_id']]],
                        ['fields' => [(string) $this->params['user_roles_user_id']]]
                    )->all();
                    foreach ($memberships as $membership) {
                        $id = $membership[(string) $this->params['user_roles_user_id']] ?? null;
                        if ($id !== null) {
                            $roleUserIds[] = $id;
                        }
                    }
                }
                $candidateIds = $this->intersectUserIds($candidateIds, $roleUserIds);
            }
        }

        if ($status !== '') {
            $disabledField = $this->params['disabled_at'];
            if (!is_string($disabledField) || $disabledField === '') {
                if ($status === 'suspended') {
                    $candidateIds = $this->intersectUserIds($candidateIds, []);
                }
            } elseif ($status === 'active') {
                $where[$disabledField] = null;
            } elseif ($status === 'suspended') {
                $where['!' . $disabledField] = null;
            }
        }

        if ($candidateIds !== null) {
            if ($candidateIds === []) {
                return new Collection([], $page * $size, ($page * $size) - 1, 0);
            }

            if (array_key_exists($userIdField, $where)) {
                $requestedIds = is_array($where[$userIdField])
                    ? $where[$userIdField]
                    : [$where[$userIdField]];
                $candidateIds = $this->intersectUserIds($candidateIds, $requestedIds);
                if ($candidateIds === []) {
                    return new Collection([], $page * $size, ($page * $size) - 1, 0);
                }
            }
            $where[$userIdField] = $candidateIds;
        }

        $start = $page * $size;
        $collection = $this->userTable->select(
            $where,
            [
                'sort' => [$sortField, $sortDirection],
                'range' => [$start, $start + $size - 1],
            ]
        );

        foreach ($collection as &$row) {
            $hydrated = $this->hydrateUserRow($row);
            $hydrated['credentials'] = $this->get_credentials($hydrated[$userIdField]);
            $row = $this->sanitize_user($hydrated);
        }
        unset($row);

        return $collection;
    }

    public function get($user_id, $key = 'id')
    {
        $column = (string) ($this->params[$key] ?? $key);

        if ($column === (string) $this->params['id']) {
            try {
                $row = $this->userTable->get($user_id);
            } catch (NotFoundException) {
                throw new UserException('User not found', 404);
            }
        } else {
            $rows = $this->userTable->select(
                [$column => $user_id],
                ['range' => [0, 0]]
            );
            if (count($rows) === 0) {
                throw new UserException('User not found', 404);
            }
            $row = $rows[0];
        }

        return $this->hydrateUserRow($row);
    }

    public function register($uid, $password = null, $data = array())
    {
        if (is_array($uid)) {
            $data = array_merge($uid, $data);
            $uid = $data['uid'] ?? null;
            $password = $data[$this->params['password']] ?? null;
            unset($data['uid'], $data[$this->params['password']]);
        }

        if (empty($uid)) {
            throw new UserException('Missing uid', 400);
        }

        $provider = empty($data['provider']) ? 'local' : $data['provider'];
        unset($data['provider']);

        $credential = $this->get_credential($provider, $uid);
        if (!empty($credential)) {
            $ex = new UserException('Credential already registered', 409);
            $ex->setUser($this->sanitize_user($this->get($credential['user_id'])));
            throw $ex;
        }

        if (empty($data['name'])) {
            [$name] = explode('@', (string) $uid, 2);
            $data['name'] = $name;
        }

        $profile = !empty($data['profile']) ? json_encode($data['profile']) : null;
        unset($data['profile']);

        $roleField = $this->params['roles'];
        $syncRoles = array_key_exists($roleField, $data);
        $roles = ($syncRoles && is_array($data[$roleField])) ? $data[$roleField] : [];
        unset($data[$roleField]);
        if ($syncRoles && !$this->rolesEnabled()) {
            throw new \InvalidArgumentException('Role sync requested but role tables are disabled');
        }

        $fields = [];
        foreach ($data as $key => $value) {
            $fields[$key] = is_array($value) ? json_encode($value) : $value;
        }

        if (!empty($this->params['uuid'])) {
            unset($fields[$this->params['uuid']]);
            $fields[$this->params['uuid']] = $this->uuidV4();
        }

        if ($password) {
            $fields[$this->params['password']] = self::hash($password);
        }

        if ($this->params['token']) {
            $fields[$this->params['token']] = null;
        }

        if ($this->params['created']) {
            $fields[$this->params['created']] = date('Y-m-d H:i:s');
        }

        return $this->db->transaction(function () use ($uid, $provider, $profile, $fields, $syncRoles, $roles): array {
            if ($syncRoles) {
                $this->resolveRoleIds($roles);
            }
            $inserted = $this->userTable->insert($fields);
            $idField = (string) $this->params['id'];
            $id = $inserted[$idField] ?? null;
            if ($id === null || $id === '') {
                throw new \Exception('Could not create user');
            }

            $userId = ctype_digit((string) $id) ? (int) $id : $id;
            $fields[$idField] = $userId;

            $credentialPayload = [
                'user_id' => $userId,
                'provider' => $provider,
                'uid' => $uid,
                'profile' => $profile,
            ];

            if (!empty($this->params['credentials_last_login'])) {
                $credentialPayload[$this->params['credentials_last_login']] = null;
            }
            if (!empty($this->params['credentials_created'])) {
                $credentialPayload[$this->params['credentials_created']] = date('Y-m-d H:i:s');
            }

            $this->db->insert($this->params['credentials_table'], $credentialPayload);

            if ($syncRoles) {
                $this->syncUserRoles($userId, $roles);
            }

            return $this->sanitize_user($this->get($userId));
        });
    }

    public function passwd($user_id, $password, $key = 'id')
    {
        $column = $this->params[$key] ?? $key;
        $updated = $this->userTable->update(
            [$column => $user_id],
            [$this->params['password'] => self::hash($password)]
        )['updated'];

        if ($updated !== 1) {
            throw new UserException('User not found', 404);
        }

        return true;
    }

    public function passwd_reset($token, $password)
    {
        if (empty($this->params['token'])) {
            throw new UserException('Token support is disabled', 400);
        }

        $user = $this->findUserByResetToken((string) $token);
        if ($user === null) {
            throw new UserException('Hash not found', 404);
        }

        $payload = [
            $this->params['password'] => self::hash($password),
            $this->params['token'] => null,
        ];
        $tokenExpiresField = $this->params['token_expires_field'];
        if (is_string($tokenExpiresField) && $tokenExpiresField !== '') {
            $payload[$tokenExpiresField] = null;
        }

        $updated = $this->userTable->update(
            $user[$this->params['id']],
            $payload
        )['updated'];

        if ($updated !== 1) {
            throw new UserException('Hash not found', 404);
        }

        return $this->sanitize_user($this->get($user[$this->params['id']]));
    }

    public function update($user_id, array $data, $key = 'id')
    {
        $column = $this->params[$key] ?? $key;

        unset($data[$this->params['id']], $data[$this->params['password']]);

        if ($this->params['token']) {
            unset($data[$this->params['token']]);
        }

        if ($this->params['created']) {
            unset($data[$this->params['created']]);
        }

        if ($this->params['last_login']) {
            unset($data[$this->params['last_login']]);
        }

        if (!empty($this->params['uuid'])) {
            unset($data[$this->params['uuid']]);
        }

        $roleField = $this->params['roles'];
        $syncRoles = array_key_exists($roleField, $data);
        $roles = ($syncRoles && is_array($data[$roleField])) ? $data[$roleField] : [];
        unset($data[$roleField]);
        if ($syncRoles && !$this->rolesEnabled()) {
            throw new \InvalidArgumentException('Role sync requested but role tables are disabled');
        }

        if (!empty($data)) {
            foreach ($data as $k => $v) {
                if (is_array($v)) {
                    $data[$k] = json_encode($v);
                }
            }

            $this->userTable->update([$column => $user_id], $data);
        }

        if ($syncRoles) {
            $target = $this->get($user_id, $key);
            $this->resolveRoleIds($roles);
            $this->syncUserRoles($target[$this->params['id']], $roles);
        }
    }

    public function delete($user_id)
    {
        if ($this->check()) {
            $user = $this->user();
            if (($user[$this->params['id']] ?? null) == $user_id) {
                throw new \Exception('Cannot delete yourself!');
            }
        }

        return $this->db->transaction(function () use ($user_id): bool {
            $guard = $this->params['deletion_guard_callback'];
            if (is_callable($guard)) {
                $result = call_user_func($guard, $user_id);
                if ($result === false || is_string($result)) {
                    throw new UserException(
                        is_string($result) ? $result : 'User has application history',
                        409
                    );
                }
            }
            $this->db->delete($this->params['credentials_table'], ['user_id' => $user_id]);
            if ($this->rolesEnabled()) {
                $this->db->delete(
                    $this->params['user_roles_table'],
                    [$this->params['user_roles_user_id'] => $user_id]
                );
            }
            foreach ((array) $this->params['managed_relations'] as $relation) {
                if (!is_array($relation) || empty($relation['table']) || empty($relation['subject_key'])) {
                    continue;
                }
                $this->db->delete((string) $relation['table'], [(string) $relation['subject_key'] => $user_id]);
            }
            foreach ((array) $this->params['relations'] as $relation) {
                if (!is_array($relation) || empty($relation['table'])) {
                    continue;
                }
                if (!empty($relation['subject_key'])) {
                    $this->db->delete((string) $relation['table'], [(string) $relation['subject_key'] => $user_id]);
                }
                if (!empty($relation['target_key']) && ($relation['target_is_user'] ?? false)) {
                    $this->db->delete((string) $relation['table'], [(string) $relation['target_key'] => $user_id]);
                }
            }
            $this->audit('user.deleted', $user_id);
            $deleted = $this->userTable->delete($user_id);

            if ($deleted !== 1) {
                throw new UserException('User not found', 404);
            }

            return true;
        });
    }

    public function update_token($user_id)
    {
        if (empty($this->params['token'])) {
            throw new UserException('Token support is disabled', 400);
        }

        $token = self::hash();
        $payload = [$this->params['token'] => $this->resetTokenDigest($token)];
        $tokenExpiresField = $this->params['token_expires_field'];
        if (is_string($tokenExpiresField) && $tokenExpiresField !== '') {
            $ttl = max(60, (int) $this->params['token_ttl']);
            $payload[$tokenExpiresField] = date('Y-m-d H:i:s', time() + $ttl);
        }

        $updated = $this->userTable->update($user_id, $payload)['updated'];

        if ($updated !== 1) {
            throw new UserException('Token not found', 404);
        }

        return $token;
    }

    public function get_credential($provider, $accountid)
    {
        $account = $this->db->select(
            $this->params['credentials_table'],
            [
                'provider' => $provider,
                'uid' => $accountid,
            ],
            ['limit' => 1]
        )->fetch();

        if (!$account) {
            return false;
        }

        if (!empty($account['profile'])) {
            $decoded = json_decode($account['profile'], true);
            $account['profile'] = is_array($decoded) ? $decoded : $account['profile'];
        }

        return $account;
    }

    public function update_credential($userid, $provider, $uid, $profile = null)
    {
        if (is_array($profile)) {
            $profile = json_encode($profile);
        }

        $data = [];
        if ($profile !== null) {
            $data['profile'] = $profile;
        }
        if (!empty($this->params['credentials_last_login'])) {
            $data[$this->params['credentials_last_login']] = date('Y-m-d H:i:s');
        }

        $existing = $this->get_credential($provider, $uid);
        if ($existing && ($existing['user_id'] ?? null) != $userid) {
            throw new UserException('Credential already registered', 409);
        }
        if ($existing) {
            if (empty($data)) {
                return true;
            }

            $this->db->update($this->params['credentials_table'], $data, [
                'provider' => $provider,
                'uid' => $uid,
            ]);

            return true;
        }

        $data = array_merge($data, [
            'user_id' => $userid,
            'provider' => $provider,
            'uid' => $uid,
        ]);
        if (!empty($this->params['credentials_created'])) {
            $data[$this->params['credentials_created']] = date('Y-m-d H:i:s');
        }

        $this->db->insert($this->params['credentials_table'], $data);
        return true;
    }

    public function create_credential($userid, string $provider, string $uid, mixed $profile = null): array
    {
        $this->get($userid);
        $provider = trim($provider);
        $uid = trim($uid);
        if ($provider === '' || $uid === '') {
            throw new UserException('Provider and uid are required', 400);
        }
        if ($this->get_credential($provider, $uid)) {
            throw new UserException('Credential already registered', 409);
        }
        $this->update_credential($userid, $provider, $uid, $profile);
        if (!empty($this->params['credentials_last_login'])) {
            $this->db->update($this->params['credentials_table'], [
                $this->params['credentials_last_login'] => null,
            ], [
                'user_id' => $userid,
                'provider' => $provider,
                'uid' => $uid,
            ]);
        }
        return $this->get_credential($provider, $uid);
    }

    public function rename_credential(
        $userid,
        string $provider,
        string $uid,
        string $newProvider,
        string $newUid
    ): array {
        $credential = $this->get_credential($provider, $uid);
        if (!$credential || ($credential['user_id'] ?? null) != $userid) {
            throw new UserException('Credential not found', 404);
        }
        $newProvider = trim($newProvider);
        $newUid = trim($newUid);
        if ($newProvider === '' || $newUid === '') {
            throw new UserException('Provider and uid are required', 400);
        }
        $duplicate = $this->get_credential($newProvider, $newUid);
        if (
            ($provider !== $newProvider || $uid !== $newUid)
            && $duplicate
        ) {
            throw new UserException('Credential already registered', 409);
        }
        $this->db->update($this->params['credentials_table'], [
            'provider' => $newProvider,
            'uid' => $newUid,
        ], [
            'user_id' => $userid,
            'provider' => $provider,
            'uid' => $uid,
        ]);
        return $this->get_credential($newProvider, $newUid);
    }

    public function delete_credential($userid, string $provider, string $uid): bool
    {
        $credential = $this->get_credential($provider, $uid);
        if (!$credential || ($credential['user_id'] ?? null) != $userid) {
            throw new UserException('Credential not found', 404);
        }
        if (count($this->get_credentials($userid)) <= 1) {
            throw new UserException('A user must have at least one credential', 409);
        }
        $this->db->delete($this->params['credentials_table'], [
            'user_id' => $userid,
            'provider' => $provider,
            'uid' => $uid,
        ]);
        return true;
    }

    public function get_managed_relations($userId): array
    {
        $user = $this->get($userId);
        $id = $user[$this->params['id']];
        $result = [];
        foreach ((array) $this->params['managed_relations'] as $name => $relation) {
            if (!is_array($relation) || empty($relation['table']) || empty($relation['subject_key']) || empty($relation['target_key'])) {
                continue;
            }
            $rows = $this->db->select((string) $relation['table'], [
                (string) $relation['subject_key'] => $id,
            ])->all();
            $values = array_map(
                fn (array $row): mixed => $row[(string) $relation['target_key']] ?? null,
                $rows
            );
            $result[(string) $name] = array_values(array_unique(array_filter($values, fn ($value): bool => $value !== null)));
        }
        return $result;
    }

    public function sync_managed_relations($userId, array $relations): array
    {
        $user = $this->get($userId);
        $id = $user[$this->params['id']];
        return $this->db->transaction(function () use ($id, $relations): array {
            foreach ($relations as $name => $values) {
                $relation = $this->params['managed_relations'][$name] ?? null;
                if (!is_array($relation) || !is_array($values)) {
                    throw new UserException("Invalid managed relation `$name`", 400);
                }
                $values = array_values(array_unique($values));
                if (is_callable($relation['validate_callback'] ?? null)) {
                    call_user_func($relation['validate_callback'], $values);
                }
                $table = (string) $relation['table'];
                $subjectKey = (string) $relation['subject_key'];
                $targetKey = (string) $relation['target_key'];
                $this->db->delete($table, [$subjectKey => $id]);
                foreach ($values as $value) {
                    $this->db->insert($table, [$subjectKey => $id, $targetKey => $value]);
                }
            }
            return $this->get_managed_relations($id);
        });
    }

    public function get_credentials($user_id, $key = 'id'): array
    {
        $user = $this->get($user_id, $key);
        $rows = $this->db->select(
            $this->params['credentials_table'],
            ['user_id' => $user[$this->params['id']]]
        )->all();

        $lastLoginField = $this->params['credentials_last_login'];
        $createdField = $this->params['credentials_created'];

        $result = [];
        foreach ($rows as $row) {
            $profile = $row['profile'] ?? null;
            if (is_string($profile) && $profile !== '') {
                $decoded = json_decode($profile, true);
                $profile = is_array($decoded) ? $decoded : $profile;
            }

            if (is_array($profile) && isset($profile['_auth']) && is_array($profile['_auth'])) {
                unset($profile['_auth']['token']);
            }

            $result[] = [
                'uid' => $row['uid'] ?? null,
                'provider' => $row['provider'] ?? null,
                'profile' => $profile,
                'last_login' => ($lastLoginField && array_key_exists($lastLoginField, $row))
                    ? $row[$lastLoginField]
                    : ($row['last_login'] ?? null),
                'created' => ($createdField && array_key_exists($createdField, $row))
                    ? $row[$createdField]
                    : ($row['created'] ?? null),
            ];
        }

        usort($result, function (array $a, array $b): int {
            return [$a['provider'], $a['uid']] <=> [$b['provider'], $b['uid']];
        });

        return $result;
    }

    public function get_users_by_role($roleName): array
    {
        if (!$this->rolesEnabled()) {
            return [];
        }

        $rolesTable = (string) $this->params['roles_table'];
        $userRolesTable = (string) $this->params['user_roles_table'];
        $userRolesUserId = (string) $this->params['user_roles_user_id'];
        $userRolesRoleId = (string) $this->params['user_roles_role_id'];
        $roleIdField = (string) $this->params['role_id'];
        $roleNameField = (string) $this->params['role_name'];

        $role = $this->db->select(
            $rolesTable,
            [$roleNameField => $roleName],
            ['limit' => 1]
        )->fetch();
        if (!$role || !array_key_exists($roleIdField, $role)) {
            return [];
        }

        $memberships = $this->db->select(
            $userRolesTable,
            [$userRolesRoleId => $role[$roleIdField]],
            [
                'fields' => [$userRolesUserId],
                'order' => $userRolesUserId,
            ]
        )->all();

        $result = [];
        $seen = [];
        foreach ($memberships as $membership) {
            $userId = $membership[$userRolesUserId] ?? null;
            if ($userId === null) {
                continue;
            }

            $identity = (string) $userId;
            if (isset($seen[$identity])) {
                continue;
            }
            $seen[$identity] = true;

            try {
                $user = $this->userTable->get($userId);
            } catch (NotFoundException) {
                continue;
            }

            $user[$this->params['roles']] = $this->loadUserRoles($userId);
            $result[] = $this->sanitize_user($user);
        }

        return $result;
    }

    public function get_roles(): array
    {
        if (!$this->rolesEnabled()) {
            return [];
        }

        $rolesTable = (string) $this->params['roles_table'];
        $roleIdField = (string) $this->params['role_id'];
        $roleNameField = (string) $this->params['role_name'];

        $rows = $this->db->select($rolesTable, [], ['order' => $roleNameField])->all();
        return array_values(array_map(
            fn (array $row): string => (string) ($row[$roleNameField] ?? ''),
            $rows
        ));
    }

    private function hydrateUserRow(array $row): array
    {
        $row = $this->hydrateEagerRelations($row);

        $roleField = $this->params['roles'];
        $row[$roleField] = $this->loadUserRoles($row[$this->params['id']]);

        return $row;
    }

    private function rolesEnabled(): bool
    {
        return !empty($this->params['roles_table']) && !empty($this->params['user_roles_table']);
    }

    private function assertRoleConfig(): void
    {
        $rolesTable = $this->params['roles_table'];
        $userRolesTable = $this->params['user_roles_table'];
        if (($rolesTable && !$userRolesTable) || (!$rolesTable && $userRolesTable)) {
            throw new \InvalidArgumentException('Both roles_table and user_roles_table must be configured together');
        }
    }

    private function loadUserRoles(int|string $userId): array
    {
        if (!$this->rolesEnabled()) {
            return [];
        }

        $roleName = (string) $this->params['role_name'];
        $roleId = (string) $this->params['role_id'];
        $rolesTable = (string) $this->params['roles_table'];
        $userRolesTable = (string) $this->params['user_roles_table'];
        $userRolesUserId = (string) $this->params['user_roles_user_id'];
        $userRolesRoleId = (string) $this->params['user_roles_role_id'];

        $rows = $this->db->select(
            $userRolesTable,
            [$userRolesTable . '.' . $userRolesUserId => $userId],
            [
                'fields' => ['role_name' => 'r.' . $roleName],
                'join' => [
                    [
                        'type' => 'inner',
                        'table' => $rolesTable,
                        'alias' => 'r',
                        'on' => $userRolesTable . '.' . $userRolesRoleId . ' = r.' . $roleId,
                    ],
                ],
                'order' => 'r.' . $roleName,
            ]
        )->all();

        return array_values(array_map(
            fn (array $entry): string => (string) ($entry['role_name'] ?? ''),
            $rows
        ));
    }

    private function syncUserRoles(int|string $userId, array $roles): void
    {
        if (!$this->rolesEnabled()) {
            return;
        }

        $userRolesTable = (string) $this->params['user_roles_table'];
        $userRolesUserId = (string) $this->params['user_roles_user_id'];
        $userRolesRoleId = (string) $this->params['user_roles_role_id'];

        $this->db->delete($userRolesTable, [$userRolesUserId => $userId]);

        foreach ($this->resolveRoleIds($roles) as $roleId) {
            $this->db->insert($userRolesTable, [
                $userRolesUserId => $userId,
                $userRolesRoleId => $roleId,
            ]);
        }
    }

    private function resolveRoleIds(array $roles): array
    {
        if (!$this->rolesEnabled()) {
            return [];
        }

        $roleIds = [];
        $rolesTable = (string) $this->params['roles_table'];
        $roleIdField = (string) $this->params['role_id'];
        $roleNameField = (string) $this->params['role_name'];

        foreach ($roles as $roleName) {
            $existing = $this->db->select($rolesTable, [$roleNameField => $roleName], ['limit' => 1])->fetch();
            if ($existing && isset($existing[$roleIdField])) {
                $roleIds[] = $existing[$roleIdField];
                continue;
            }

            $inserted = $this->db->insert($rolesTable, [$roleNameField => $roleName]);
            if ($inserted !== null) {
                $roleIds[] = ctype_digit((string) $inserted) ? (int) $inserted : $inserted;
                continue;
            }
            throw new UserException("Unknown role `$roleName`", 400);
        }

        return array_values(array_unique($roleIds));
    }

    protected function userCanRelation(int $subjectId, string $resourceType, int $resourceId, string $ability): bool
    {
        $relation = $this->getRelationConfig($resourceType);
        if ($relation === null) {
            throw new \InvalidArgumentException("Unknown relation type `$resourceType`");
        }

        $rows = $this->db->select(
            $relation['table'],
            [
                $relation['subject_key'] => $subjectId,
                $relation['target_key'] => $resourceId,
            ]
        )->all();

        return $this->rowsAllowAbility($rows, $relation, $ability);
    }

    protected function userCanRelationList(int $subjectId, string $resourceType, string $ability): array
    {
        $relation = $this->getRelationConfig($resourceType);
        if ($relation === null) {
            throw new \InvalidArgumentException("Unknown relation type `$resourceType`");
        }

        $rows = $this->db->select(
            $relation['table'],
            [$relation['subject_key'] => $subjectId]
        )->all();

        $ids = [];
        foreach ($rows as $row) {
            if (!$this->rowAllowsAbility($row, $relation, $ability)) {
                continue;
            }

            $targetId = $row[$relation['target_key']] ?? null;
            if (is_int($targetId)) {
                $ids[] = $targetId;
                continue;
            }

            if (is_string($targetId) && ctype_digit($targetId)) {
                $ids[] = (int) $targetId;
            }
        }

        $ids = array_values(array_unique($ids));
        sort($ids);
        return $ids;
    }

    private function getRelationConfig(string $resourceType): ?array
    {
        $relations = $this->params['relations'];
        $relation = $relations[$resourceType] ?? null;
        if (!is_array($relation)) {
            return null;
        }

        $table = $relation['table'] ?? null;
        $subjectKey = $relation['subject_key'] ?? null;
        $targetKey = $relation['target_key'] ?? null;
        if (!is_string($table) || !is_string($subjectKey) || !is_string($targetKey)) {
            return null;
        }

        if (!isset($relation['ability_key']) && !isset($relation['role_key'])) {
            return null;
        }

        return $relation;
    }

    private function rowsAllowAbility(array $rows, array $relation, string $ability): bool
    {
        foreach ($rows as $row) {
            if ($this->rowAllowsAbility($row, $relation, $ability)) {
                return true;
            }
        }

        return false;
    }

    private function rowAllowsAbility(array $row, array $relation, string $ability): bool
    {
        $abilityKey = $relation['ability_key'] ?? null;
        if (is_string($abilityKey)) {
            return (($row[$abilityKey] ?? null) === $ability);
        }

        $roleKey = $relation['role_key'] ?? null;
        if (!is_string($roleKey)) {
            return false;
        }

        $role = (string) ($row[$roleKey] ?? '');
        if ($role === '') {
            return false;
        }

        $roleAbilities = $relation['role_abilities'] ?? [];
        if (!is_array($roleAbilities)) {
            return false;
        }

        $abilities = $roleAbilities[$role] ?? [];
        if (!is_array($abilities)) {
            return false;
        }

        return in_array($ability, $abilities, true);
    }

    private function hydrateEagerRelations(array $row): array
    {
        $relations = $this->params['relations'];
        if (!is_array($relations)) {
            return $row;
        }

        $subjectId = $row[$this->params['id']] ?? null;
        if (!is_int($subjectId)) {
            if (is_string($subjectId) && ctype_digit($subjectId)) {
                $subjectId = (int) $subjectId;
            } else {
                return $row;
            }
        }

        foreach ($relations as $relationName => $relation) {
            if (!is_array($relation) || !array_key_exists('eager', $relation)) {
                continue;
            }

            $eager = $relation['eager'];
            if ($eager === false || $eager === null) {
                continue;
            }

            if ($eager === true) {
                $eagerParams = [];
            } elseif (is_array($eager)) {
                $eagerParams = $eager;
            } else {
                throw new \InvalidArgumentException("Invalid eager config for relation `$relationName`");
            }

            $targetIds = $this->relationTargetIdsForSubject($relation, $subjectId);
            if ($targetIds === []) {
                $row[(string) $relationName] = [];
                continue;
            }

            $eagerTable = $relation['table'] ?? null;
            $subjectKey = $relation['subject_key'] ?? null;
            $eagerKey = $relation['target_key'] ?? null;
            if (!is_string($eagerTable) || !is_string($subjectKey) || !is_string($eagerKey)) {
                throw new \InvalidArgumentException("Invalid relation table/key config for relation `$relationName`");
            }

            $row[(string) $relationName] = $this->db->select(
                $eagerTable,
                [
                    $subjectKey => $subjectId,
                    $eagerKey => $targetIds,
                ],
                $eagerParams
            )->all();
        }

        return $row;
    }

    private function relationTargetIdsForSubject(array $relation, int $subjectId): array
    {
        $table = $relation['table'] ?? null;
        $subjectKey = $relation['subject_key'] ?? null;
        $targetKey = $relation['target_key'] ?? null;
        if (!is_string($table) || !is_string($subjectKey) || !is_string($targetKey)) {
            return [];
        }

        $rows = $this->db->select($table, [$subjectKey => $subjectId])->all();
        $ids = [];
        foreach ($rows as $entry) {
            $targetId = $entry[$targetKey] ?? null;
            if (is_int($targetId)) {
                $ids[] = $targetId;
            } elseif (is_string($targetId) && ctype_digit($targetId)) {
                $ids[] = (int) $targetId;
            }
        }

        $ids = array_values(array_unique($ids));
        sort($ids);
        return $ids;
    }

    private function findUserByResetToken(string $token): ?array
    {
        $tokenField = (string) $this->params['token'];
        $tokenExpiresField = $this->params['token_expires_field'];

        $rows = $this->userTable->select(
            [$tokenField => $this->resetTokenDigest($token)],
            ['range' => [0, 0]]
        );
        if (count($rows) === 0) {
            return null;
        }
        $row = $rows[0];

        if (is_string($tokenExpiresField) && $tokenExpiresField !== '') {
            $expiresAt = $row[$tokenExpiresField] ?? null;
            if (!is_string($expiresAt) || $expiresAt < date('Y-m-d H:i:s')) {
                return null;
            }
        }

        return $row;
    }

    private function resetTokenDigest(string $token): string
    {
        return hash('sha256', $token);
    }

    private function intersectUserIds(?array $current, array $next): array
    {
        $normalize = static function (array $ids): array {
            $normalized = [];
            foreach ($ids as $id) {
                if ($id === null) {
                    continue;
                }
                $normalized[(string) $id] = $id;
            }
            return $normalized;
        };

        $nextMap = $normalize($next);
        if ($current === null) {
            return array_values($nextMap);
        }

        $currentMap = $normalize($current);
        return array_values(array_intersect_key($currentMap, $nextMap));
    }

    private function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

}
