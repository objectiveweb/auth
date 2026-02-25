<?php

namespace Objectiveweb\Auth;

use Objectiveweb\DB;

class DBAuth extends \Objectiveweb\Auth
{
    public array $params;

    public function __construct(private DB $db, array $params = [])
    {
        $defaults = [
            'table' => 'user',
            'created' => null,
            'last_login' => null,
            'credentials_table' => 'user_credentials',
            'credentials_last_login' => null,
            'uuid' => 'uuid',
            'roles_table' => null,
            'user_roles_table' => null,
            'user_roles_user_id' => 'user_id',
            'user_roles_role_id' => 'role_id',
            'role_id' => 'id',
            'role_name' => 'name',
            'with' => [],
        ];

        parent::__construct(array_merge($defaults, $params));
    }

    public function query($params = array(), $operator = "OR")
    {
        $page = max(0, (int) ($params['page'] ?? 0));
        $size = max(1, (int) ($params['size'] ?? 20));
        $sort = $params['sort'] ?? null;

        unset($params['page'], $params['size'], $params['sort']);

        if (strtoupper($operator) === 'OR' && count($params) > 1) {
            $rowsById = [];
            foreach ($params as $key => $value) {
                $rows = $this->db->select($this->params['table'], [$key => $value], [
                    'order' => $sort,
                ])->all();

                foreach ($rows as $row) {
                    if (!isset($row[$this->params['id']])) {
                        continue;
                    }
                    $rowsById[$row[$this->params['id']]] = $this->hydrateUserRow($row);
                }
            }

            $data = array_values($rowsById);
            $count = count($data);
            $slice = array_slice($data, $page * $size, $size);
        } else {
            $filter = $params;
            $queryParams = [
                'order' => $sort,
                'offset' => $page * $size,
                'limit' => $size,
            ];

            $slice = $this->db->select($this->params['table'], $filter, $queryParams)->all();
            $slice = array_map(fn (array $row): array => $this->hydrateUserRow($row), $slice);
            $count = $this->db->count($this->params['table'], $filter);
        }

        return [
            '_embedded' => [
                $this->params['table'] => $slice,
            ],
            'page' => [
                'size' => $size,
                'number' => $page,
                'totalElements' => $count,
                'totalPages' => (int) ceil($count / $size),
            ],
        ];
    }

    public function get($user_id, $key = 'id')
    {
        $column = $this->params[$key] ?? $key;
        $row = $this->db->select($this->params['table'], [$column => $user_id], ['limit' => 1])->fetch();

        if (!$row) {
            throw new UserException('User not found', 404);
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
            $ex->setUser($this->get($credential['user_id']));
            throw $ex;
        }

        if (empty($data['name'])) {
            [$name] = explode('@', (string) $uid, 2);
            $data['name'] = $name;
        }

        $profile = !empty($data['profile']) ? json_encode($data['profile']) : null;
        unset($data['profile']);

        $with = [];
        foreach ($this->params['with'] as $table => $fk) {
            if (!empty($data[$table])) {
                $with[$table] = $data[$table];
                unset($data[$table], $fk);
            }
        }

        $roleField = $this->params['roles'] ?? 'roles';
        $syncRoles = array_key_exists($roleField, $data);
        $roles = $syncRoles ? $this->normalizeRoleNames($data[$roleField]) : [];
        unset($data[$roleField]);

        $fields = [];
        foreach ($data as $key => $value) {
            if ($key === $this->params['scopes'] && is_array($value)) {
                $fields[$key] = implode(',', $value);
                continue;
            }
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
            $fields[$this->params['token']] = self::hash();
        }

        if ($this->params['created']) {
            $fields[$this->params['created']] = date('Y-m-d H:i:s');
        }

        if (!array_key_exists($this->params['scopes'], $fields)) {
            $fields[$this->params['scopes']] = '';
        }

        return $this->db->transaction(function () use ($uid, $provider, $profile, $fields, $with, $syncRoles, $roles): array {
            $id = $this->db->insert($this->params['table'], $fields);
            if (!$id) {
                throw new \Exception('Could not create user');
            }

            $userId = ctype_digit((string) $id) ? (int) $id : $id;
            $fields[$this->params['id']] = $userId;

            foreach ($with as $withTable => $withContent) {
                $fk = $this->params['with'][$withTable];
                $payload = [$fk => $userId];
                foreach ($withContent as $k => $v) {
                    $payload[$k] = $v;
                }
                $this->db->insert($withTable, $payload);
            }

            $credentialPayload = [
                'user_id' => $userId,
                'provider' => $provider,
                'uid' => $uid,
                'profile' => $profile,
            ];

            if (!empty($this->params['credentials_last_login'])) {
                $credentialPayload[$this->params['credentials_last_login']] = date('Y-m-d H:i:s');
            }

            $this->db->insert($this->params['credentials_table'], $credentialPayload);

            if ($syncRoles) {
                $this->syncUserRoles($userId, $roles);
            }

            return $this->get($userId);
        });
    }

    public function passwd($user_id, $password, $key = 'id')
    {
        $column = $this->params[$key] ?? $key;
        $updated = $this->db->update(
            $this->params['table'],
            [$this->params['password'] => self::hash($password)],
            [$column => $user_id]
        );

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

        $user = $this->get($token, $this->params['token']);
        $updated = $this->db->update(
            $this->params['table'],
            [
                $this->params['password'] => self::hash($password),
                $this->params['token'] => null,
            ],
            [$this->params['token'] => $token]
        );

        if ($updated !== 1) {
            throw new UserException('Hash not found', 404);
        }

        return $user;
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

        $roleField = $this->params['roles'] ?? 'roles';
        $syncRoles = array_key_exists($roleField, $data);
        $roles = $syncRoles ? $this->normalizeRoleNames($data[$roleField]) : [];
        unset($data[$roleField]);

        if (!empty($data)) {
            if (isset($data[$this->params['scopes']]) && is_array($data[$this->params['scopes']])) {
                $data[$this->params['scopes']] = implode(',', $data[$this->params['scopes']]);
            }

            foreach ($data as $k => $v) {
                if (is_array($v)) {
                    $data[$k] = json_encode($v);
                }
            }

            $this->db->update($this->params['table'], $data, [$column => $user_id]);
        }

        if ($syncRoles) {
            $target = $this->get($user_id, $key);
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
            $this->db->delete($this->params['credentials_table'], ['user_id' => $user_id]);
            if ($this->rolesEnabled()) {
                $this->db->delete(
                    $this->params['user_roles_table'],
                    [$this->params['user_roles_user_id'] => $user_id]
                );
            }
            $deleted = $this->db->delete($this->params['table'], [$this->params['id'] => $user_id]);

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
        $updated = $this->db->update(
            $this->params['table'],
            [$this->params['token'] => $token],
            [$this->params['id'] => $user_id]
        );

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

        $data = ['profile' => $profile];
        if (!empty($this->params['credentials_last_login'])) {
            $data[$this->params['credentials_last_login']] = date('Y-m-d H:i:s');
        }

        if ($this->get_credential($provider, $uid)) {
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

        $this->db->insert($this->params['credentials_table'], $data);
        return true;
    }

    private function normalizeUserRow(array $row): array
    {
        $scopeField = $this->params['scopes'];
        if (!empty($row[$scopeField]) && is_string($row[$scopeField])) {
            $row[$scopeField] = explode(',', $row[$scopeField]);
        }

        return $row;
    }

    private function hydrateUserRow(array $row): array
    {
        $row = $this->normalizeUserRow($row);

        foreach ($this->params['with'] as $table => $fk) {
            $row[$table] = $this->db->select($table, [$fk => $row[$this->params['id']]])->all();
        }

        $roleField = $this->params['roles'] ?? 'roles';
        $row[$roleField] = $this->loadUserRoles($row[$this->params['id']]);

        return $row;
    }

    private function rolesEnabled(): bool
    {
        return !empty($this->params['roles_table']) && !empty($this->params['user_roles_table']);
    }

    private function loadUserRoles(int|string $userId): array
    {
        if (!$this->rolesEnabled()) {
            return [];
        }

        $roleName = $this->assertIdentifier((string) $this->params['role_name']);
        $roleId = $this->assertIdentifier((string) $this->params['role_id']);
        $rolesTable = $this->assertIdentifier((string) $this->params['roles_table']);
        $userRolesTable = $this->assertIdentifier((string) $this->params['user_roles_table']);
        $userRolesUserId = $this->assertIdentifier((string) $this->params['user_roles_user_id']);
        $userRolesRoleId = $this->assertIdentifier((string) $this->params['user_roles_role_id']);

        $query = $this->db->query(
            sprintf(
                'SELECT r.%s AS role_name
                 FROM %s r
                 INNER JOIN %s ur ON ur.%s = r.%s
                 WHERE ur.%s = :user_id
                 ORDER BY r.%s',
                $roleName,
                $rolesTable,
                $userRolesTable,
                $userRolesRoleId,
                $roleId,
                $userRolesUserId,
                $roleName
            )
        );
        $query->exec(['user_id' => $userId]);

        $rows = $query->all();
        return array_values(array_map(
            fn (array $entry): string => (string) $entry['role_name'],
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

            $created = $this->db->select($rolesTable, [$roleNameField => $roleName], ['limit' => 1])->fetch();
            if ($created && isset($created[$roleIdField])) {
                $roleIds[] = $created[$roleIdField];
            }
        }

        return array_values(array_unique($roleIds));
    }

    private function normalizeRoleNames(mixed $roles): array
    {
        if (is_string($roles)) {
            $roles = explode(',', $roles);
        }

        if (!is_array($roles)) {
            return [];
        }

        return array_values(array_unique(array_filter(array_map(
            fn (mixed $role): string => trim((string) $role),
            $roles
        ))));
    }

    private function assertIdentifier(string $value): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $value)) {
            throw new \InvalidArgumentException("Invalid SQL identifier `$value`");
        }

        return $value;
    }

    private function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
